package eap

import (
	"encoding/binary"
	"fmt"
)

type EapCode uint8
type EapType uint8

const (
	EAPRequest  EapCode = 1
	EAPResponse EapCode = 2
	EAPSuccess  EapCode = 3
	EAPFailure  EapCode = 4
)

const (
	Identity  EapType = 1
	LegacyNak EapType = 3
	Peap      EapType = 25
)

type EapPacket interface {
	Decode(buff []byte) bool
	Encode() (bool, []byte)
	GetId() uint8
	GetCode() EapCode
	GetType() EapType
}

func GetEAPByType(msgType EapType) EapPacket {
	switch msgType {
	case Peap:
		return NewEapPeap()
	case Identity:
		return NewEapIdentity()
	case LegacyNak:
		return NewEapNak()
	}

	return &HeaderEap{}
}

type HeaderEap struct {
	code    EapCode
	id      uint8
	length  uint16
	msgType EapType
}

func (packet *HeaderEap) Encode() (bool, []byte) {

	buff := make([]byte, packet.length)

	buff[0] = uint8(packet.code)
	buff[1] = uint8(packet.id)

	binary.BigEndian.PutUint16(buff[2:], packet.length)

	if packet.code == EAPRequest || packet.code == EAPResponse {
		buff[4] = uint8(packet.msgType)
	}

	return true, buff

}

func (packet *HeaderEap) Decode(buff []byte) bool {

	length := binary.BigEndian.Uint16(buff[2:])

	if length != uint16(len(buff)) {
		fmt.Println("func (packet *HeaderEap) Decode(buff []byte). Length does not match")
		return false
	}

	packet.code = EapCode(buff[0])
	packet.id = uint8(buff[1])

	packet.length = length

	if len(buff) > 4 && (packet.code == EAPRequest || packet.code == EAPResponse) {
		packet.msgType = EapType(buff[4])
	}

	return true

}

func (packet *HeaderEap) GetId() uint8 {
	return packet.id
}

func (packet *HeaderEap) GetCode() EapCode {
	return packet.code
}

func (packet *HeaderEap) SetId(id uint8) {
	packet.id = id
}

func (packet *HeaderEap) SetCode(code EapCode) {
	packet.code = code
}

func (packet *HeaderEap) GetType() EapType {
	return packet.msgType
}

func (packet *HeaderEap) GetLength() uint16 {
	return packet.length
}

func (packet *HeaderEap) setType(msgType EapType) {
	packet.msgType = msgType
}

func (packet *HeaderEap) setLength(length uint16) {
	packet.length = length
}
