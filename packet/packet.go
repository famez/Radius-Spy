package packet

import "encoding/binary"

type RadiusCode uint8

const (
	AccessRequest   RadiusCode = 1
	AccessChallenge RadiusCode = 11
)

type AVP struct {
	attrType uint8
	length   uint8
	value    string
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

type RadiusPacket struct {
	code          RadiusCode
	id            uint8
	length        uint16
	authenticator [16]byte
	keyValAttrs   []AVP
}

func (packet *RadiusPacket) Decode(buff []byte) bool {

	if len(buff) < 20 { //20 = Size of code + id + length + autheticator
		return false
	}

	length := binary.BigEndian.Uint16(buff[2:])

	//Check whether the length of the buffer
	//corresponds to the length retreived from the packet
	if int(length) != len(buff) {
		return false
	}

	//Once everything is well decoded, assign values to the packet and not before.
	//It is an atomic operation
	packet.code = RadiusCode(buff[0])
	packet.id = uint8(buff[1])
	packet.length = length
	copy(packet.authenticator[:], buff[4:])

	return true
}

func (packet *RadiusPacket) Encode() []byte {
	return []byte{}
}

//CalcAuthenticator calculates the value of the field Authenticator by performing a HMAC-MD5 of the whole packet
//and using for it a secret that is shared between the NAS and the RADIUS server
func (packet *RadiusPacket) CalcAuthenticator(secret string) {

}
