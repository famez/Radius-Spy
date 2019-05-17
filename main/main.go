package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"radius/packet"
	"strconv"
)

//UDPData holds information about the received packet
type UDPData struct {
	buff       []byte
	senderAddr net.UDPAddr
	dstPort    int
}

//SessionData dsd
type SessionData struct {
	clientAddr net.UDPAddr
	connection *net.UDPConn
	mappedPort int //Port in case that direct mapping is not possible (port already in use)
}

const authPort = 1812
const accPort = 1813

const protocol = "udp"

const hostName = "169.254.63.10"

//Receives UDP packets and writes the result in a channel for asyncronous management of the packets
func receiveUDPPacket(conn *net.UDPConn, dstPort int, channel chan UDPData) {

	buff := make([]byte, 2048)

	for {
		n, addr, err := conn.ReadFromUDP(buff)
		if n > 0 {
			res := make([]byte, n)
			// Copy the buffer so it doesn't get changed while read by the recipient.
			copy(res, buff[:n])

			udpData := UDPData{
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

func hijackSession(filterFunc func(packet packet.RadiusPacket) (bool, packet.RadiusPacket)) {

	var clientSessions []SessionData

	authServerConn := setupUDPServer(authPort)
	accServerConn := setupUDPServer(accPort)

	defer authServerConn.Close()
	defer accServerConn.Close()

	serverConnections := make(map[int]*net.UDPConn)

	serverConnections[authPort] = authServerConn
	serverConnections[accPort] = accServerConn

	udpChan := make(chan UDPData)

	go receiveUDPPacket(authServerConn, authPort, udpChan) //Start receiving packets from client towards port 1812 (Authentication)
	go receiveUDPPacket(accServerConn, accPort, udpChan)   //Start receiving packets from client towards port 1813 (Accounting)

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

		if data.senderAddr.IP.Equal(net.ParseIP(hostName)) && (data.senderAddr.Port == authPort || data.senderAddr.Port == accPort) { //Came from authenticator server RADIUS

			fmt.Println("From authenticator server")

			//Check if address already seen
			for _, session := range clientSessions {
				if session.mappedPort == data.dstPort {
					fmt.Println("Send to client", session.clientAddr)
					serverConnections[data.senderAddr.Port].WriteToUDP(data.buff, &session.clientAddr) //Redirect to client
					break
				}
			}

		} else { //From authenticator

			fmt.Println("From authenticator ")

			found := false

			var session SessionData

			//Check if address already seen
			for _, session = range clientSessions {
				if session.clientAddr.IP.Equal(data.senderAddr.IP) && session.clientAddr.Port == data.senderAddr.Port {
					fmt.Println("Session found.")
					found = true
					break
				}
			}

			if !found {
				//Create session

				fmt.Println("Session not found. Creating... ")

				//Determine free port

				freePort := false
				mappedPort := data.senderAddr.Port //First we try with the sender's port

				for !freePort {
					freePort = true
					for _, session := range clientSessions {
						if session.mappedPort == mappedPort {
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

				authAddr, err := net.ResolveUDPAddr(protocol, hostName+":"+strconv.FormatUint(uint64(data.dstPort), 10))

				if err != nil {
					fmt.Println("Error authAddr ", err)
					return
				}

				conn, err := net.DialUDP(protocol, &localAddr, authAddr)

				if err != nil {
					fmt.Println("Error net.DialUDP ", err)
					return
				}

				session = SessionData{
					clientAddr: data.senderAddr,
					connection: conn,
					mappedPort: mappedPort,
				}

				clientSessions = append(clientSessions, session)

				go receiveUDPPacket(session.connection, mappedPort, udpChan) //Start receiving packets from radius server

			}

			fmt.Println("Sending to Radius Server...", session.connection.RemoteAddr().String())

			var incomingPacket packet.RadiusPacket

			incomingPacket.Decode(data.buff)

			filterPassed, filterPacket := filterFunc(incomingPacket)

			if filterPassed {
				session.connection.Write(filterPacket.Encode()) //Redirect to server
			}

		}

	}

}

func filter(packet packet.RadiusPacket) (bool, packet.RadiusPacket) {
	return true, packet
}

func main() {

	hijackSession(filter)

}
