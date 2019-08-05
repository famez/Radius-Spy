package session

import (
	"net"

	"github.com/golang/glog"
)

type ContextStatus uint8

//TLSContext will hold the context of the TLS session originated by EAP-PEAP message
//We create a loopback tunnel to be able to send the data generated
//by TLS protocol into the EAP message instead of sending it directly to the network
type TLSContext struct {
	storedNASPayload    []byte
	nasPayloadLen       uint32
	storedServerPayload []byte
	serverPayloadLen    uint32
	session             *TLSSession
}

//EAPContext will hold the context of the EAP message exchange
type EAPContext struct {
	method      uint8
	identity    string
	tls         *TLSContext
	peapVersion byte
	msChap      MsChapV2Context
}

//MsChapV2Context Context to track the challenge-response process
type MsChapV2Context struct {
	authChallenge [16]byte
	peerChallenge [16]byte
	ntResponse    [24]byte
	serverMessage string
}

//ContextInfo defines the contextual data extracted from the communication between client-server session
//This can be trivial data such as IP addresses or sensitive data such as the secret between NAS-Server
//or session keys used between STA and NAS
type ContextInfo struct {
	server          net.UDPAddr
	nas             net.UDPAddr
	nasPortType     uint32
	nasPort         uint32
	nasIP           net.IP
	state           []byte
	accSessionID    string
	framedMTU       uint32
	calledStation   string
	callingStation  string
	connectInfo     string
	key             string
	eap             EAPContext
	lastServerMsgId byte     //Id for the illicit messages we are trying to generate from/to the Server
	lastNASMsgId    byte     //Id for the illicit messages we are trying to generate from/to the NAS
	lastServerEapId byte     //Id for Eap messages from server
	lastNASEapId    byte     //Id for Eap messages from NAS
	lastAuthMsg     [16]byte //The last auth msg got from the client
	lastGenAuthMsg  [16]byte //The last auth msg that we have generated as fake client
	userName        string   //User name used by the STA to authenticate
	secret          string
	derivedKey      []byte //Derived key to be used between NAS and STA to encrypt WIFI communications
}

var contexts []*ContextInfo

func AddContext(nas, server net.UDPAddr) {

	context := &ContextInfo{
		server:      server,
		nas:         nas,
		nasPortType: 0xFFFF,
		nasPort:     0xFFFF,
		framedMTU:   0,
	}

	context.eap.tls = new(TLSContext)

	contexts = append(contexts, context)

}

func GetContextByClient(client net.UDPAddr) *ContextInfo {

	for _, context := range contexts {
		{

			if context.nas.IP.Equal(client.IP) && context.nas.Port == client.Port {
				return context
			}
		}

	}

	return nil

}

func (context *ContextInfo) SetLastAuthMsg(authMsg [16]byte) {

	context.lastAuthMsg = authMsg

}

func (context ContextInfo) GetLastAuthMsg() [16]byte {

	return context.lastAuthMsg

}

func (context *ContextInfo) SetLastGenAuthMsg(authMsg [16]byte) {

	context.lastGenAuthMsg = authMsg

}

func (context ContextInfo) GetLastGenAuthMsg() [16]byte {

	return context.lastGenAuthMsg

}

func (context *ContextInfo) SetLastServerEapId(id byte) {

	context.lastServerEapId = id

}

func (context ContextInfo) GetLastServerEapId() byte {

	return context.lastServerEapId

}

func (context *ContextInfo) SetLastNASEapId(id byte) {

	context.lastNASEapId = id

}

func (context ContextInfo) GetLastNASEapId() byte {

	return context.lastNASEapId

}

func (context *ContextInfo) SetLastServerMsgId(id byte) {

	context.lastServerMsgId = id

}

func (context ContextInfo) GetLastServerMsgId() byte {

	return context.lastServerMsgId

}

func (context *ContextInfo) SetLastNASMsgId(id byte) {

	context.lastNASMsgId = id

}

func (context ContextInfo) GetLastNASMsgId() byte {

	return context.lastNASMsgId

}

func (context *ContextInfo) SetFramedMTU(framedMTU uint32) {

	context.framedMTU = framedMTU

}

func (context ContextInfo) GetFramedMTU() uint32 {

	return context.framedMTU

}

func (context *ContextInfo) SetState(state []byte) {

	context.state = make([]byte, len(state))
	copy(context.state, state)

}

func (context ContextInfo) GetState() []byte {

	retval := make([]byte, len(context.state))

	copy(retval, context.state)

	return retval

}

func (context *ContextInfo) SetSecret(secret string) {

	context.secret = secret

}

func (context ContextInfo) GetSecret() string {

	return context.secret

}

func (context *ContextInfo) SetAccSessionID(accSession string) {

	context.accSessionID = accSession

}

func (context ContextInfo) GetAccSessionID() string {

	return context.accSessionID

}

func (context *ContextInfo) SetNasPort(nasPort uint32) {

	context.nasPort = nasPort

}

func (context ContextInfo) GetNasPort() uint32 {

	return context.nasPort

}

func (context *ContextInfo) SetNasIP(nasIP net.IP) {

	context.nasIP = nasIP

}

func (context ContextInfo) GetNasIP() net.IP {

	return context.nasIP

}

func (context *ContextInfo) SetNasPortType(portType uint32) {

	context.nasPortType = portType

}

func (context ContextInfo) GetNasPortType() uint32 {

	return context.nasPortType

}

func (context *ContextInfo) SetCalledStation(sta string) {

	context.calledStation = sta

}

func (context ContextInfo) GetCalledStation() string {

	return context.calledStation

}

func (context *ContextInfo) SetCallingStation(sta string) {

	context.callingStation = sta

}

func (context ContextInfo) GetCallingStation() string {

	return context.callingStation

}

func (context *ContextInfo) SetConnectInfo(info string) {

	context.connectInfo = info

}

func (context ContextInfo) GetConnectInfo() string {

	return context.connectInfo

}

func (context *ContextInfo) SetEapMethod(method uint8) {

	context.eap.method = method

}

func (context ContextInfo) GetEapMethod() uint8 {

	return context.eap.method

}

func (context *ContextInfo) SetPeapVersion(version byte) {

	context.eap.peapVersion = version

}

func (context ContextInfo) GetPeapVersion() byte {

	return context.eap.peapVersion

}

func (context ContextInfo) GetNAS() net.UDPAddr {

	return context.nas

}

func (context *ContextInfo) AddTLSNASPayload(payload []byte) {

	context.eap.tls.storedNASPayload = append(context.eap.tls.storedNASPayload, payload...)

}

func (context *ContextInfo) SetNASTLSLength(length uint32) {

	context.eap.tls.nasPayloadLen = length

}

func (context *ContextInfo) GetAndDeleteNASTLSPayloadAndLength() ([]byte, uint32) {

	payload := context.eap.tls.storedNASPayload
	length := context.eap.tls.nasPayloadLen

	context.eap.tls.storedNASPayload = nil
	context.eap.tls.nasPayloadLen = 0

	return payload, length

}

func (context *ContextInfo) AddTLSServerPayload(payload []byte) {

	context.eap.tls.storedServerPayload = append(context.eap.tls.storedServerPayload, payload...)

}

func (context *ContextInfo) SetServerTLSLength(length uint32) {

	context.eap.tls.serverPayloadLen = length

}

func (context *ContextInfo) GetAndDeleteServerTLSPayloadAndLength() ([]byte, uint32) {

	payload := context.eap.tls.storedServerPayload
	length := context.eap.tls.serverPayloadLen

	context.eap.tls.storedServerPayload = nil
	context.eap.tls.serverPayloadLen = 0

	return payload, length

}

func (context *ContextInfo) CreateTLSSession() {

	context.eap.tls.session = NewTLSSession()

}

func (context *ContextInfo) GetTLSSession() *TLSSession {

	return context.eap.tls.session

}

func (context ContextInfo) GetUserName() string {

	return context.userName

}

func (context *ContextInfo) SetUserName(user string) {

	context.userName = user

}

func (context ContextInfo) GetEAPIdentity() string {

	return context.eap.identity

}

func (context *ContextInfo) SetEAPIdentity(identity string) {

	context.eap.identity = identity

}

func (context ContextInfo) GetMsChapV2AuthChallenge() [16]byte {

	return context.eap.msChap.authChallenge

}

func (context *ContextInfo) SetMsChapV2AuthChallenge(challenge []byte) {

	if len(challenge) == 16 {
		copy(context.eap.msChap.authChallenge[:], challenge)
	}

}

func (context ContextInfo) GetMsChapV2PeerChallenge() [16]byte {

	return context.eap.msChap.peerChallenge

}

func (context *ContextInfo) SetMsChapV2PeerChallenge(challenge []byte) {
	if len(challenge) == 16 {
		copy(context.eap.msChap.peerChallenge[:], challenge)
	}

}

func (context ContextInfo) GetMsChapV2NTResponse() [24]byte {

	return context.eap.msChap.ntResponse

}

func (context *ContextInfo) SetMsChapV2NTResponse(response []byte) {

	if len(response) == 24 {
		copy(context.eap.msChap.ntResponse[:], response)
	}

}

//GetServerMessage message sent from the server to the peer to prove that the server can be trusted
// as they share both the password.
func (context ContextInfo) GetServerMessage() string {

	return context.eap.msChap.serverMessage

}

func (context *ContextInfo) SetServerMessage(serverMessage string) {

	context.eap.msChap.serverMessage = serverMessage

}

func (context ContextInfo) GetDerivedKey() []byte {
	return context.derivedKey
}

func (context *ContextInfo) SetDerivedKey(key []byte) {
	context.derivedKey = key
}

func (context ContextInfo) PrintInfo() {

	glog.V(2).Infoln("**Context info**")

	glog.V(2).Infoln("NAS:", context.nas)
	glog.V(2).Infoln("Server:", context.server)

	glog.V(2).Infoln("Secret:", context.secret)

	glog.V(2).Infoln("NAS Port Type:", context.nasPortType)
	glog.V(2).Infoln("NAS Port:", context.nasPort)
	glog.V(2).Infoln("Called STA:", context.calledStation)

	glog.V(2).Infoln("Calling Station:", context.callingStation)
	glog.V(2).Infoln("User:", context.userName)

	glog.V(2).Infoln("Connect Info:", context.connectInfo)

	glog.V(2).Infoln("Accounting Session:", context.accSessionID)

	glog.V(2).Infoln("EAP identity:", context.eap.identity)

}
