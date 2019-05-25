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
	attrs         map[AttrType]Attribute
	//Map to respect the order in which the attributes are decoded (otherwise, they will be ordered by type)
	posToAttr map[uint]AttrType
}

func NewRadiusPacket() *RadiusPacket {

	packet := RadiusPacket{
		length:    headerSize, //20 = Size of code + id + length + authenticator
		attrs:     make(map[AttrType]Attribute),
		posToAttr: make(map[uint]AttrType),
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
	packet.attrs = make(map[AttrType]Attribute)
	packet.posToAttr = make(map[uint]AttrType)

	var position uint
	position = 0

	for len(attrsBuff) > 0 {

		attrLen := uint(attrsBuff[1])

		attr := Attribute{
			attrType: AttrType(attrsBuff[0]),
		}

		attr.value = make([]byte, attrLen-2)

		copy(attr.value, attrsBuff[2:attrLen])

		packet.attrs[attr.attrType] = attr
		packet.posToAttr[position] = attr.attrType

		position++

		if attrLen > uint(len(attrsBuff)) {
			packet.attrs = make(map[AttrType]Attribute) //Remove already decoded attrs
			packet.posToAttr = make(map[uint]AttrType)
			return false
		}

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

	//Itarete by position to keep the some order of the attributes in the list
	for position := uint(0); position < uint(len(packet.posToAttr)); position++ {

		attrType, ok := packet.posToAttr[position]

		if !ok {
			return false, nil //Something went wrong
		}

		attr, ok := packet.attrs[attrType]

		if !ok {
			return false, nil //Something went wrong
		}

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

	attr, ok := packet.attrs[attrType]

	if !ok {
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

	attr, ok := packet.attrs[attrType]

	//Not found
	if !ok {
		packet.length += uint16(len(data) + 2)
		packet.posToAttr[uint(len(packet.posToAttr))] = attrType
	} else {
		//Update total length
		packet.length = packet.length + uint16(len(data)) - uint16(len(attr.value))
	}

	packet.attrs[attrType] = Attribute{
		attrType: attrType,
		value:    data,
	}

}

func (packet *RadiusPacket) SetStrAttr(attrType AttrType, data string) {

	packet.SetRawAttr(attrType, []byte(data))

}
