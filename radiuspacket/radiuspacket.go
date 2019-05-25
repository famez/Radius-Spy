package radiuspacket

import (
	"encoding/binary"
	"fmt"
	"radius/utils"
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

const maxAttrSize = 255

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

	var retVal []byte
	found := false
	//Loop to find every attribute whose type matches (length > 255 for the attribute)
	for _, attr := range packet.attrs {
		if attr.attrType == attrType {
			retVal = append(retVal, attr.value...)
			found = true
		} else if found {
			break
		}
	}

	if retVal == nil {
		return false, nil
	}

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

	var pos, attrPos, attrNum int
	var attr Attribute

	attrNum = 0
	attrPos = len(data)

	//Loop to find every attribute whose type matches (length > 255 for the attribute)
	for pos, attr = range packet.attrs {
		if attr.attrType == attrType {
			if attrNum == 0 {
				attrPos = pos
			}
			attrNum++
			packet.length -= uint16(len(attr.value) + 2)
		} else if attrNum != 0 {
			break
		}
	}

	if attrPos != len(data) {
		copy(packet.attrs[attrPos:], packet.attrs[attrPos+attrNum:])
		packet.attrs = packet.attrs[:len(packet.attrs)-attrNum]
	}

	offset := 0
	leftLen := len(data)

	for true {

		attrLength := utils.Min(leftLen+2, maxAttrSize)

		value := make([]byte, attrLength-2)
		copy(value, data[offset:offset+attrLength-2])

		packet.length += uint16(attrLength)
		attr = Attribute{
			attrType: attrType,
			value:    value,
		}

		//Insertion
		packet.attrs = append(packet.attrs, Attribute{} /* use the zero value of the element type */)
		copy(packet.attrs[attrPos+1:], packet.attrs[attrPos:])
		packet.attrs[attrPos] = attr

		attrPos++

		//Check if there is something left to be sent
		if leftLen+2 > maxAttrSize {
			leftLen -= (maxAttrSize - 2)
			offset += (maxAttrSize - 2)
		} else {
			break
		}

	}

}

func (packet *RadiusPacket) SetStrAttr(attrType AttrType, data string) {

	packet.SetRawAttr(attrType, []byte(data))

}
