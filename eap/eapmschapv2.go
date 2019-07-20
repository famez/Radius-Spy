package eap

import (
	"encoding/binary"
)

type MsChapV2OpCode uint8

const (
	MsChapV2Challenge MsChapV2OpCode = 1
	MsChapV2Response  MsChapV2OpCode = 2
	MsChapV2Success   MsChapV2OpCode = 3
	MsChapV2Failure   MsChapV2OpCode = 4
	MsChapV2ChangePwd MsChapV2OpCode = 7
)

type EapMSCHAPv2 struct {
	header  HeaderEap
	opCode  MsChapV2OpCode
	msID    uint8
	value   []byte //This is challenge for Challenge packet and response for response packet
	name    string
	message string
}

func NewEapMsChapV2() *EapMSCHAPv2 {

	header := HeaderEap{
		msgType: MsChapv2,
	}

	msChapv2 := &EapMSCHAPv2{
		header: header,
	}

	return msChapv2

}

func (packet *EapMSCHAPv2) Encode() (bool, []byte) {

	buff := make([]byte, 1)

	buff[0] = byte(packet.opCode)

	if packet.GetCode() == EAPResponse && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {
		packet.header.setLength(uint16(5 /*header*/ + 1 /*OpCode*/))
		if ok, header := packet.header.Encode(); ok {
			buff := append(header[:5], buff[0])
			return true, buff
		}
		return false, nil

	}

	buff = append(buff, packet.msID, 0, 0)

	if packet.GetCode() == EAPRequest && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {

		buff = append(buff, []byte(packet.message)...)
		packet.header.setLength(uint16(5 /*header*/ + 1 /*OpCode*/ + 1 /*MsID*/ + 2 /*mslength*/ + len(packet.message)))

		binary.BigEndian.PutUint16(buff[2:], packet.header.GetLength()-5)

		if ok, header := packet.header.Encode(); ok {
			buff := append(header[:5], buff...)
			return true, buff
		}
		return false, nil

	}

	//Encode value and name if present
	if (packet.GetCode() == EAPRequest && packet.opCode == MsChapV2Challenge) ||
		(packet.GetCode() == EAPResponse && packet.opCode == MsChapV2Response) {
		buff = append(buff, byte(len(packet.value)))
		buff = append(buff, []byte(packet.value)...)
		buff = append(buff, []byte(packet.name)...)

		packet.header.setLength(uint16(5 /*header*/ + 1 /*OpCode*/ + 1 /*MsID*/ + 2 /*mslength*/ + 1 /*Value Size*/ +
			len(packet.value) + len(packet.name)))

		binary.BigEndian.PutUint16(buff[2:], packet.header.GetLength()-5)

		if ok, header := packet.header.Encode(); ok {
			buff := append(header[:5], buff...)
			return true, buff
		}
		return false, nil

	}

	return false, nil
}

func (packet *EapMSCHAPv2) Decode(buff []byte) bool {

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	packet.opCode = MsChapV2OpCode(buff[5])

	if packet.GetCode() == EAPResponse && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {
		return true //Nothing more to decode
	}

	packet.msID = buff[6]

	msLength := binary.BigEndian.Uint16(buff[7:])

	if msLength+5 != packet.header.length {
		return false
	}

	if packet.GetCode() == EAPRequest && (packet.opCode == MsChapV2Success || packet.opCode == MsChapV2Failure) {
		packet.message = string(buff[9:])
		return true //Nothing else to decode
	}

	//Decode value and name if present
	if (packet.GetCode() == EAPRequest && packet.opCode == MsChapV2Challenge) ||
		(packet.GetCode() == EAPResponse && packet.opCode == MsChapV2Response) {
		valueSize := int(buff[9])

		if (packet.opCode == MsChapV2Challenge && valueSize != 0x10) ||
			(packet.opCode == MsChapV2Response && valueSize != 0x31) {
			return false //Length does not match according to the RFC
		}

		if len(buff[10:]) <= valueSize {
			return false //Value length mismatch or name field missing
		}

		//Value
		packet.value = make([]byte, valueSize)

		copy(packet.value, buff[10:10+valueSize])

		//Assigning the name
		packet.name = string(buff[10+valueSize:])

	}

	return true

}

func (packet *EapMSCHAPv2) GetId() uint8 {
	return packet.header.GetId()
}

func (packet *EapMSCHAPv2) GetCode() EapCode {
	return packet.header.GetCode()
}

func (packet *EapMSCHAPv2) GetType() EapType {
	return packet.header.GetType()
}

func (packet *EapMSCHAPv2) GetOpCode() MsChapV2OpCode {
	return packet.opCode
}

func (packet *EapMSCHAPv2) GetMsgID() uint8 {
	return packet.msID
}

func (packet *EapMSCHAPv2) GetValue() []byte {
	retVal := make([]byte, len(packet.value))
	copy(retVal, packet.value)
	return retVal
}

func (packet *EapMSCHAPv2) GetName() string {
	return packet.name
}

func (packet *EapMSCHAPv2) GetMessage() string {
	return packet.message
}
