package session

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
)

type TLSLocalTunnel struct {
	tlsPeer net.Conn
	rawPeer net.Conn
}

type TLSSession struct {
	nasSideTunnel    TLSLocalTunnel
	serverSideTunnel TLSLocalTunnel
}

var tlsLocalListener net.Listener
var tcpLocalListener net.Listener

func initLocalTLSServer() {

	cer, err := tls.LoadX509KeyPair("TestKeys/server.crt", "TestKeys/server.key")

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
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

	var err error
	tlsSession.nasSideTunnel.rawPeer, err = net.Dial("tcp", "localhost:400")
	if err != nil {
		log.Println(err)

	}

	tlsSession.nasSideTunnel.tlsPeer, err = tlsLocalListener.Accept()

	conf := &tls.Config{
		//InsecureSkipVerify: true,
	}
	go func() {
		tlsSession.serverSideTunnel.tlsPeer, err = tls.Dial("tcp", "localhost:401", conf)
		if err != nil {
			log.Println(err)
		}
		fmt.Println("SSL client OK")
	}()

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

func (tunnel *TLSLocalTunnel) transmit(from, to net.Conn, data []byte) []byte {

	if data != nil {
		from.Write(data)
	}

	rxData := make([]byte, 65535)

	size, err := to.Read(rxData)

	if err != nil {
		log.Println(err)
	}

	retval := make([]byte, size)

	copy(retval, rxData)

	return retval

}

func (tunnel *TLSLocalTunnel) tLSToRaw(tls []byte) []byte {

	return tunnel.transmit(tunnel.tlsPeer, tunnel.rawPeer, tls)

}

func (tunnel *TLSLocalTunnel) rawToTLS(tls []byte) []byte {

	return tunnel.transmit(tunnel.rawPeer, tunnel.tlsPeer, tls)

}

func (session *TLSSession) NASRawToTLS(data []byte) []byte {
	return session.nasSideTunnel.rawToTLS(data)
}

func (session *TLSSession) NASTLSToRaw(data []byte) []byte {
	return session.nasSideTunnel.tLSToRaw(data)
}

func (session *TLSSession) ServerRawToTLS(data []byte) []byte {
	return session.serverSideTunnel.rawToTLS(data)
}

func (session *TLSSession) ServerTLSToRaw(data []byte) []byte {
	return session.serverSideTunnel.tLSToRaw(data)
}
