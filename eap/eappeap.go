package eap

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
)

type PeapFlags struct {
	length   bool
	moreFrag bool
	start    bool
	version  byte
}

type EapPeap struct {
	header     HeaderEap
	flags      PeapFlags
	tlsLength  uint32
	tlsPayload []byte
}

//EapTLSSession is a loopback tunnel to be able to send the data generated
//by TLS protocol into the EAP message instead of sending it directly to the network
type EapTLSSession struct {
	client net.TCPConn
	server tls.Conn
}

func NewEapPeap() *EapPeap {

	header := HeaderEap{
		msgType: Peap,
	}

	peap := &EapPeap{
		header: header,
	}

	return peap

}

func (packet *EapPeap) Encode() (bool, []byte) {
	return packet.header.Encode()
}

func (packet *EapPeap) Decode(buff []byte) bool {

	fmt.Println("func (packet *EapPeap) Decode")

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	//Decode flags
	packet.flags.length = (buff[5]&0x80 == 0x80)
	packet.flags.moreFrag = (buff[5]&0x40 == 0x40)
	packet.flags.start = (buff[5]&0x20 == 0x20)
	packet.flags.version = (buff[5] & 0x07)

	if packet.flags.length {

		//Decode TLS length
		packet.tlsLength = binary.BigEndian.Uint32(buff[6:])

		//Decode Raw TLS data
		payloadLength := packet.header.GetLength() - 10 //Substract the header data length

		if len(buff[10:]) != int(payloadLength) {
			fmt.Println("Length mismatch")

			return false
		}

		packet.tlsPayload = make([]byte, payloadLength)

		copy(packet.tlsPayload, buff[10:])

	}

	return true

}

func (packet *EapPeap) GetId() uint8 {
	return packet.header.GetId()
}

func (packet *EapPeap) GetCode() EapCode {
	return packet.header.GetCode()
}

func (packet *EapPeap) GetType() EapType {
	return packet.header.GetType()
}

func (packet *EapPeap) GetTLSPayload() []byte {
	return packet.tlsPayload
}

func (packet *EapPeap) GetLengthFlag() bool {
	return packet.flags.length
}

func (packet *EapPeap) GetMoreFlag() bool {
	return packet.flags.moreFrag
}

func (packet *EapPeap) GetStartFlag() bool {
	return packet.flags.start
}

func (packet *EapPeap) GetVersionFlag() byte {
	return packet.flags.version
}
