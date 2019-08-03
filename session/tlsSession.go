package session

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/golang/glog"
)

type TLSLocalTunnel struct {
	tlsPeer        net.Conn
	rawPeer        net.Conn
	readRawChannel chan []byte
	readTLSChannel chan []byte
}

type TLSSession struct {
	nasSideTunnel    TLSLocalTunnel
	serverSideTunnel TLSLocalTunnel

	nasTLSVersion uint16 //TLS version of the NAS side TLS connection

	tlsClientAvailable sync.WaitGroup

	//To derive keys from TLS session data. This data is very sensitive
	keyring KeyringData

	//To track the number of handshake packets that have been processed, so that we know if the 4-way handshake process has finished or not
	nasHandshakeStat uint
	//To track the number of handshake packets that have been processed, so that we know if the 4-way handshake process has finished or not
	serverHandshakeStat uint
}

//KeyringData to store sensitive data from TLS session
type KeyringData struct {
	randomClient    [32]byte
	randomServer    [32]byte
	masterSecret    [48]byte
	masterSecretSet bool
}

type keyRingChannelWriter struct {
	keyRingChannels map[[32]byte]chan [48]byte
}

var tlsLocalListener net.Listener
var tcpLocalListener net.Listener

var keyringWriter *keyRingChannelWriter //To keep track of the master secret used to derive WIFI session keys (when using PEAP)

func initLocalTLSServer() {

	keyringWriter = newKeyRingChannelWriter()

	cer, err := tls.LoadX509KeyPair("TestKeys/server.crt", "TestKeys/server.key")

	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		KeyLogWriter: keyringWriter,
	}
	tlsLocalListener, err = tls.Listen("tcp", "localhost:400", config)
	if err != nil {
		log.Println(err)

	}

	tcpLocalListener, err = net.Listen("tcp", "localhost:401")

	if err != nil {
		log.Println(err)

	}

}

func NewTLSSession() *TLSSession {

	tlsSession := new(TLSSession)

	tlsSession.nasHandshakeStat = 0
	tlsSession.serverHandshakeStat = 0

	tlsSession.keyring.masterSecretSet = false

	//To know whether we have access to the TLS client or not as it is being initialized asynchronously
	tlsSession.tlsClientAvailable.Add(1)

	//Initialize read channels for asyncronous reads
	tlsSession.nasSideTunnel.readRawChannel = make(chan []byte)
	tlsSession.nasSideTunnel.readTLSChannel = make(chan []byte)
	tlsSession.serverSideTunnel.readRawChannel = make(chan []byte)
	tlsSession.serverSideTunnel.readTLSChannel = make(chan []byte)

	var err error
	tlsSession.nasSideTunnel.rawPeer, err = net.Dial("tcp", "localhost:400")
	if err != nil {
		log.Println(err)

	}

	tlsSession.nasSideTunnel.tlsPeer, err = tlsLocalListener.Accept()

	conf := &tls.Config{
		InsecureSkipVerify: true, //We are the attacker, so we "trust" the server.
	}
	go func(waitgroup *sync.WaitGroup) {
		tlsSession.serverSideTunnel.tlsPeer, err = tls.Dial("tcp", "localhost:401", conf)
		if err != nil {
			log.Println(err)
		}
		glog.V(1).Infoln("SSL client ready")

		waitgroup.Done()

	}(&tlsSession.tlsClientAvailable)

	tlsSession.serverSideTunnel.rawPeer, err = tcpLocalListener.Accept()

	if err != nil {
		log.Println(err)
	}

	return tlsSession

}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}

		println(msg)

		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}

func (tunnel TLSLocalTunnel) transmit(con net.Conn, data []byte) {

	if data != nil {
		con.Write(data)
	}

}

func (tunnel TLSLocalTunnel) receive(con net.Conn) []byte {

	rxData := make([]byte, 65535)

	size, err := con.Read(rxData)

	if err != nil {
		log.Println(err)
	}

	retval := make([]byte, size)

	copy(retval, rxData)

	return retval

}

func (tunnel TLSLocalTunnel) WriteTls(tls []byte) {

	tunnel.transmit(tunnel.tlsPeer, tls)

}

func (tunnel TLSLocalTunnel) WriteRaw(raw []byte) {

	tunnel.transmit(tunnel.rawPeer, raw)

}

func (tunnel TLSLocalTunnel) ReadTls() []byte {

	return tunnel.receive(tunnel.tlsPeer)

}

func (tunnel TLSLocalTunnel) ReadRaw() []byte {

	return tunnel.receive(tunnel.rawPeer)

}

func (tunnel TLSLocalTunnel) ReadTlsAsync() {

	go func() {
		buff := tunnel.receive(tunnel.tlsPeer)

		if buff != nil {
			tunnel.readTLSChannel <- buff
		}

	}()

}

func (tunnel TLSLocalTunnel) ReadRawAysnc() {

	go func() {

		buff := tunnel.receive(tunnel.rawPeer)

		if buff != nil {
			tunnel.readRawChannel <- buff
		}

	}()

}

func (tunnel TLSLocalTunnel) GetReadRawChannel() chan []byte {
	return tunnel.readRawChannel
}

func (tunnel TLSLocalTunnel) GetReadTLSChannel() chan []byte {
	return tunnel.readTLSChannel
}

func (session TLSSession) ReadTLSFromServer() []byte {

	session.tlsClientAvailable.Wait()

	return session.serverSideTunnel.ReadTls()

}

func (session TLSSession) GetNASTunnel() TLSLocalTunnel {
	return session.nasSideTunnel
}

func (session TLSSession) GetServerTunnel() TLSLocalTunnel {
	return session.serverSideTunnel
}

func (session TLSSession) GetNASHandShakeStatus() uint {
	return session.nasHandshakeStat
}

func (session *TLSSession) SetNASHandShakeStatus(status uint) {
	session.nasHandshakeStat = status
}

func (session TLSSession) GetServerHandShakeStatus() uint {
	return session.serverHandshakeStat
}

func (session *TLSSession) SetServerHandShakeStatus(status uint) {
	session.serverHandshakeStat = status
}

func (session TLSSession) GetRandomClient() [32]byte {
	return session.keyring.randomClient
}

func (session *TLSSession) SetRandomClient(random []byte) {

	if len(random) != 32 {
		return
	}
	copy(session.keyring.randomClient[:], random)
}

func (session TLSSession) GetRandomServer() [32]byte {
	return session.keyring.randomServer
}

func (session *TLSSession) SetRandomServer(random []byte) {

	if len(random) != 32 {
		return
	}
	copy(session.keyring.randomServer[:], random)

}

func (session *TLSSession) GetMasterSecret() [48]byte {

	if !session.keyring.masterSecretSet {
		var ok bool
		if ok, session.keyring.masterSecret = keyringWriter.getMasterSecret(session.keyring.randomClient); ok {
			session.keyring.masterSecretSet = true
		}
	}

	return session.keyring.masterSecret
}

func (session TLSSession) GetNASVersion() uint16 {
	return session.nasTLSVersion
}

func (session *TLSSession) SetNASVersion(version uint16) {
	session.nasTLSVersion = version
}

//keyRingChannelWriter functions and methods

func newKeyRingChannelWriter() *keyRingChannelWriter {

	writer := &keyRingChannelWriter{}
	writer.keyRingChannels = make(map[[32]byte]chan [48]byte)
	return writer
}

func (writer *keyRingChannelWriter) Write(p []byte) (n int, err error) {

	line := string(p)

	var randomClientStr, masterSecretStr string

	fmt.Sscanf(line, "CLIENT_RANDOM %s %s\n", &randomClientStr, &masterSecretStr)

	decoded, err := hex.DecodeString(randomClientStr)

	if err != nil {
		return 0, err
	}

	var randomClient [32]byte

	copy(randomClient[:], decoded)

	decoded, err = hex.DecodeString(masterSecretStr)

	if err != nil {
		return 0, err
	}

	var masterSecret [48]byte

	copy(masterSecret[:], decoded)

	//Generate channel if it does not exist
	if writer.keyRingChannels[randomClient] == nil {
		writer.keyRingChannels[randomClient] = make(chan [48]byte, 1) //Buffer only one array to be read later in another routine
	}

	//Reference to the channel
	channel := writer.keyRingChannels[randomClient]

	//Not blocking channel
	select {
	case channel <- masterSecret:
	default:
	}

	return len(p), nil
}

func (writer *keyRingChannelWriter) getMasterSecret(randomClient [32]byte) (bool, [48]byte) {

	var retVal [48]byte

	//Check channel
	if writer.keyRingChannels[randomClient] == nil {
		return false, retVal
	}

	channel := writer.keyRingChannels[randomClient]

	//Not blocking channel
	select {
	case retVal = <-channel:
	default:
		return false, retVal
	}

	//Get the value only once
	writer.clearChannel(randomClient)

	return true, retVal
}

func (writer *keyRingChannelWriter) clearChannel(randomClient [32]byte) {

	writer.keyRingChannels[randomClient] = nil

}
