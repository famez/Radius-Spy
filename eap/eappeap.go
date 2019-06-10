package eap

import (
	"encoding/binary"
	"fmt"
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

func NewEapPeap() *EapPeap {

	header := HeaderEap{
		msgType: Peap,
		length:  6,
	}

	flags := PeapFlags{
		length:   false,
		moreFrag: false,
		start:    false,
		version:  0,
	}

	peap := &EapPeap{
		header: header,
		flags:  flags,
	}

	return peap

}

func (packet *EapPeap) Encode() (bool, []byte) {

	lenBytes := 0

	if packet.flags.length {
		lenBytes = 4
	}

	payloadLen := 0

	if packet.tlsPayload != nil {
		payloadLen = len(packet.tlsPayload)
	}

	packet.header.setLength(uint16(5 /*header*/ + 1 /*Flags*/ + lenBytes + payloadLen))

	//Encode header
	ok, buff := packet.header.Encode()

	if !ok {
		return false, nil
	}

	if packet.GetCode() != EAPRequest && packet.GetCode() != EAPResponse {
		return false, nil
	}

	//Encode flags
	buff[5] = 0

	if packet.flags.length {
		buff[5] |= 0x80
	}
	if packet.flags.moreFrag {
		buff[5] |= 0x40
	}
	if packet.flags.start {
		buff[5] |= 0x20
	}
	buff[5] |= (packet.flags.version & 0x07)

	if packet.flags.length {

		//Encode TLS length
		binary.BigEndian.PutUint32(buff[6:], packet.tlsLength)

	}

	//Encode Raw TLS data
	copy(buff[6+lenBytes:], packet.tlsPayload)

	return true, buff

}

func (packet *EapPeap) Decode(buff []byte) bool {

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	//Decode flags
	packet.flags.length = (buff[5]&0x80 == 0x80)
	packet.flags.moreFrag = (buff[5]&0x40 == 0x40)
	packet.flags.start = (buff[5]&0x20 == 0x20)
	packet.flags.version = (buff[5] & 0x07)

	offset := 6

	if packet.flags.length {

		//Decode TLS length
		packet.tlsLength = binary.BigEndian.Uint32(buff[6:])
		offset += 4

	}

	//Decode Raw TLS data
	payloadLength := packet.header.GetLength() - uint16(offset) //Substract the header data length

	if len(buff[offset:]) != int(payloadLength) {
		fmt.Println("Length mismatch")

		return false
	}

	packet.tlsPayload = make([]byte, payloadLength)

	copy(packet.tlsPayload, buff[offset:])

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

func (packet *EapPeap) GetTLSTotalLength() uint32 {
	return packet.tlsLength
}

func (packet *EapPeap) SetId(id uint8) {
	packet.header.SetId(id)
}

func (packet *EapPeap) SetCode(code EapCode) {
	packet.header.SetCode(code)
}

func (packet *EapPeap) SetTLSPayload(payload []byte) {
	packet.tlsPayload = append(packet.tlsPayload, payload...)

	lenBytes := 0

	if packet.flags.length {
		lenBytes = 4
	}

	payloadLen := len(packet.tlsPayload)

	length := 5 /*header*/ + 1 /*Flags*/ + lenBytes + payloadLen

	packet.header.setLength(uint16(length))

}

func (packet *EapPeap) SetLengthFlag(lengthFlag bool) {

	if lengthFlag != packet.flags.length {
		if lengthFlag {
			packet.header.setLength(packet.header.GetLength() + 4)
		} else {
			packet.header.setLength(packet.header.GetLength() - 4)
		}
	}

	packet.flags.length = lengthFlag
}

func (packet *EapPeap) SetMoreFlag(more bool) {
	packet.flags.moreFrag = more
}

func (packet *EapPeap) SetStartFlag(start bool) {
	packet.flags.start = start
}

func (packet *EapPeap) SetVersionFlag(version byte) {
	packet.flags.version = version
}

func (packet *EapPeap) SetTLSTotalLength(length uint32) {
	packet.tlsLength = length
}
