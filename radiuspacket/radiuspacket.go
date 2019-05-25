package radiuspacket

import (
	"encoding/binary"
	"fmt"
)

type RadiusCode uint8
type AttrType uint8

const (
	AccessRequest      RadiusCode = 1
	AccessAccept       RadiusCode = 2
	AccessReject       RadiusCode = 3
	AccountingRequest  RadiusCode = 4
	AccountingResponse RadiusCode = 5
	AccessChallenge    RadiusCode = 11
)

const (
	CalledStationId AttrType = 30
)

const headerSize = 20

//Attribute represents an attribute value pair //RFC 2865 5. Attributes
type Attribute struct {
	attrType AttrType
	value    []byte
}

/*
Format of RADIUS packet

	0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Authenticator                         |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

*/

//RadiusPacket represents a packet whose format follows the RADIUS protocol
type RadiusPacket struct {
	code          RadiusCode
	id            uint8
	length        uint16
	authenticator [16]byte
	attrs         []Attribute
}

func NewRadiusPacket() *RadiusPacket {

	packet := RadiusPacket{
		length: headerSize, //20 = Size of code + id + length + authenticator
		attrs:  nil,
	}

	return &packet

}

//Decode decodes a RADIUS packet.
//returns bool. false if the packet is malformed. true if the packet is well decoded
func (packet *RadiusPacket) Decode(buff []byte) bool {

	fmt.Println("Decoding... ")

	if len(buff) < headerSize { //20 = Size of code + id + length + authenticator
		return false //Malformed
	}

	length := binary.BigEndian.Uint16(buff[2:])

	//Check whether the length of the buffer
	//corresponds to the length retreived from the packet
	if int(length) != len(buff) {
		return false
	}

	//Decode attrs
	attrsBuff := buff[headerSize:]

	for len(attrsBuff) > 0 {

		attrLen := uint(attrsBuff[1])

		if attrLen > uint(len(attrsBuff)) {
			packet.attrs = nil //Remove already decoded attrs

			return false
		}

		attr := Attribute{
			attrType: AttrType(attrsBuff[0]),
		}

		attr.value = make([]byte, attrLen-2)

		copy(attr.value, attrsBuff[2:attrLen])

		packet.attrs = append(packet.attrs, attr)

		attrsBuff = attrsBuff[attrLen:]

	}

	//Once everything is well decoded, assign values to the packet and not before.
	//It is an atomic operation

	packet.code = RadiusCode(buff[0])
	packet.id = uint8(buff[1])
	packet.length = length
	copy(packet.authenticator[:], buff[4:])

	return true
}

func (packet *RadiusPacket) Encode() (bool, []byte) {

	fmt.Println("Encoding... ")

	buff := make([]byte, packet.length)

	buff[0] = byte(packet.code)
	buff[1] = byte(packet.id)

	binary.BigEndian.PutUint16(buff[2:], packet.length)

	copy(buff[4:], packet.authenticator[:])

	attrBuff := buff[20:]

	//Iterate by position to keep the some order of the attributes in the list
	for _, attr := range packet.attrs {

		attrLen := len(attr.value) + 2

		if len(attrBuff) < attrLen {
			return false, nil //Something went wrong
		}

		attrBuff[0] = byte(attr.attrType)
		attrBuff[1] = byte(attrLen)
		copy(attrBuff[2:], attr.value)

		attrBuff = attrBuff[attrLen:]

	}

	return true, buff

}

//Getters

//GetCode getter to obtain the code of the packet
func (packet *RadiusPacket) GetCode() RadiusCode {

	return packet.code

}

//GetId getter to obtain the id of the packet
func (packet *RadiusPacket) GetId() uint8 {

	return packet.id

}

func (packet *RadiusPacket) GetAuthenticator() [16]byte {

	return packet.authenticator

}

//GetLength getter to obtain the length of the packet
func (packet *RadiusPacket) GetLength() uint16 {

	return packet.length

}

func (packet *RadiusPacket) GetRawAttr(attrType AttrType) (bool, []byte) {

	var attr Attribute
	found := false

	for _, attr = range packet.attrs {
		if attr.attrType == attrType {
			found = true
			break
		}
	}

	if !found {
		return false, nil
	}

	retVal := make([]byte, len(attr.value))

	copy(retVal, attr.value)

	return true, retVal

}

func (packet *RadiusPacket) GetStrAttr(attrType AttrType) (bool, string) {

	success, attr := packet.GetRawAttr(attrType)

	if success {
		return true, string(attr)
	}

	return false, ""
}

//Setters

func (packet *RadiusPacket) SetRawAttr(attrType AttrType, data []byte) {

	var pos int
	var attr Attribute
	found := false

	for pos, attr = range packet.attrs {
		if attr.attrType == attrType {
			found = true
			break
		}
	}

	value := make([]byte, len(data))
	copy(value, data)

	//Found
	if found {
		//Update total length
		packet.length = packet.length + uint16(len(data)) - uint16(len(attr.value))
		packet.attrs[pos].value = value
	} else {
		packet.length += uint16(len(data) + 2)
		attr = Attribute{
			attrType: attrType,
			value:    value,
		}

		packet.attrs = append(packet.attrs, attr)
	}

}

func (packet *RadiusPacket) SetStrAttr(attrType AttrType, data string) {

	packet.SetRawAttr(attrType, []byte(data))

}
