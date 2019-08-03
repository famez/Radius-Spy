package radius

import (
	"encoding/binary"
	"net"
	"radius/utils"

	"github.com/golang/glog"
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
	UserName             AttrType = 1
	NasIp                AttrType = 4
	NASPort              AttrType = 5
	FramedMTU            AttrType = 12
	StateAttr            AttrType = 24
	VendorSpecific       AttrType = 26
	CalledStationId      AttrType = 30
	CallingStationId     AttrType = 31
	AccountSessionId     AttrType = 44
	NASPortType          AttrType = 61
	ConnectInfo          AttrType = 77
	EAPMessage           AttrType = 79
	MessageAuthenticator AttrType = 80
)

const headerSize = 20

const maxAttrSize = 255

//Attribute represents an attribute value pair //RFC 2865 5. Attributes
type Attribute struct {
	attrType AttrType
	value    []byte
}

type VendorSpecificAttr struct {
	vType   uint8
	content []byte
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

	//Initialize to 0
	for index := range packet.authenticator {
		packet.authenticator[index] = 0
	}

	return &packet

}

func (packet RadiusPacket) Clone() *RadiusPacket {

	retVal := packet

	retVal.attrs = make([]Attribute, len(packet.attrs))

	copy(retVal.attrs, packet.attrs)

	return &retVal
}

//Decode decodes a RADIUS packet.
//returns bool. false if the packet is malformed. true if the packet is well decoded
func (packet *RadiusPacket) Decode(buff []byte) bool {

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

//SetCode
func (packet *RadiusPacket) SetCode(code RadiusCode) {

	packet.code = code

}

//GetId getter to obtain the id of the packet
func (packet *RadiusPacket) GetId() uint8 {

	return packet.id

}

//SetId
func (packet *RadiusPacket) SetId(id uint8) {

	packet.id = id

}

func (packet RadiusPacket) GetAuthenticator() [16]byte {

	return packet.authenticator

}

func (packet *RadiusPacket) SetAuthenticator(auth [16]byte) {

	packet.authenticator = auth

}

//GetLength getter to obtain the length of the packet
func (packet *RadiusPacket) GetLength() uint16 {

	return packet.length

}

func (packet *RadiusPacket) GetRawAttr(attrType AttrType) (bool, [][]byte) {

	var retVal [][]byte
	found := false
	//Loop to find every attribute whose type matches (length > 255 for the attribute)
	for _, attr := range packet.attrs {
		if attr.attrType == attrType {
			var raw []byte
			raw = append(raw, attr.value...)
			retVal = append(retVal, raw)
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

//DelRawAttr deletes an attribute given its type
func (packet *RadiusPacket) DelRawAttr(attrType AttrType) {

	var pos, attrPos, attrNum int
	var attr Attribute

	attrNum = 0
	attrPos = len(packet.attrs)

	//Loop to find every attribute whose type matches
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

	if attrPos != len(packet.attrs) {
		copy(packet.attrs[attrPos:], packet.attrs[attrPos+attrNum:])
		packet.attrs = packet.attrs[:len(packet.attrs)-attrNum]
	}
}

func (packet *RadiusPacket) SetRawAttr(attrType AttrType, data [][]byte) {

	var pos, attrPos, attrNum int
	var attr Attribute

	attrNum = 0
	attrPos = len(packet.attrs)

	//Loop to find every attribute whose type matches
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

	if attrPos != len(packet.attrs) {
		copy(packet.attrs[attrPos:], packet.attrs[attrPos+attrNum:])
		packet.attrs = packet.attrs[:len(packet.attrs)-attrNum]
	}

	for _, raw := range data {

		if len(raw) > maxAttrSize {
			glog.V(1).Infoln("SetRawAttr: The data exceeds the maximum size...")
			continue
		}

		value := make([]byte, len(raw))
		copy(value, raw)

		packet.length += uint16(len(raw) + 2)

		attr = Attribute{
			attrType: attrType,
			value:    value,
		}

		//Insertion
		packet.attrs = append(packet.attrs, Attribute{})
		copy(packet.attrs[attrPos+1:], packet.attrs[attrPos:])
		packet.attrs[attrPos] = attr

		attrPos++

	}

}

func (packet *RadiusPacket) GetVendorSpecificAttrs(id uint32) (bool, []VendorSpecificAttr) {

	ok, data := packet.GetRawAttr(VendorSpecific)

	if !ok {
		return false, nil
	}

	var retVal []VendorSpecificAttr

	for _, raw := range data {
		vendorID := binary.BigEndian.Uint32(raw)

		if vendorID == id { //ID matches
			raw = raw[4:]
			vLength := raw[1]

			if int(vLength) != len(raw) {
				continue //Length mismatch
			}

			vAttr := VendorSpecificAttr{
				vType:   raw[0],
				content: raw[2:],
			}

			retVal = append(retVal, vAttr)
		}
	}

	return true, retVal

}

func (packet *RadiusPacket) SetVendorSpecificAttrs(id uint32, vAttrs []VendorSpecificAttr) {

	var rawVendorAttrs [][]byte

	for _, vAttr := range vAttrs {

		raw := make([]byte, 4)
		binary.BigEndian.PutUint32(raw, id)

		raw = append(raw, vAttr.vType)
		raw = append(raw, 2+byte(len(vAttr.content)))

		raw = append(raw, vAttr.content...)

		rawVendorAttrs = append(rawVendorAttrs, raw)

	}

	packet.SetRawAttr(VendorSpecific, rawVendorAttrs)

}

func (packet *RadiusPacket) GetMSMPPESendKey() (bool, []byte) {

	if ok, vAttrs := packet.GetVendorSpecificAttrs(311 /*Microsoft vendor*/); ok {

		for _, attr := range vAttrs {
			if attr.vType == 16 { //Type for MPPE Send Key
				return true, attr.content
			}
		}

	}

	return false, nil

}

func (packet *RadiusPacket) SetMSMPPEKeys(sendKey, recvKey []byte) {

	sendKeyAttr := VendorSpecificAttr{
		vType:   16,
		content: sendKey,
	}

	recvKeyAttr := VendorSpecificAttr{
		vType:   17,
		content: recvKey,
	}

	packet.SetVendorSpecificAttrs(311, []VendorSpecificAttr{sendKeyAttr, recvKeyAttr})

}

func (packet *RadiusPacket) GetMSMPPERecvKey() (bool, []byte) {

	if ok, vAttrs := packet.GetVendorSpecificAttrs(311 /*Microsoft vendor*/); ok {

		for _, attr := range vAttrs {
			if attr.vType == 17 { //Type for MPPE Recv Key
				return true, attr.content
			}
		}

	}

	return false, nil

}

func (packet *RadiusPacket) GetEAPMessage() (bool, []byte) {

	ok, data := packet.GetRawAttr(EAPMessage)

	if !ok {
		return false, nil
	}

	var retVal []byte

	for _, raw := range data {
		retVal = append(retVal, raw...)
	}

	return true, retVal

}

func (packet *RadiusPacket) SetEAPMessage(message []byte) {

	offset := 0
	leftLen := len(message)

	var splittedEap [][]byte

	for true {

		attrLength := utils.Min(leftLen+2, maxAttrSize)

		value := make([]byte, attrLength-2)
		copy(value, message[offset:offset+attrLength-2])

		splittedEap = append(splittedEap, value)

		//Check if there is something left to be sent
		if leftLen+2 > maxAttrSize {
			leftLen -= (maxAttrSize - 2)
			offset += (maxAttrSize - 2)
		} else {
			break
		}

	}

	packet.SetRawAttr(EAPMessage, splittedEap)

}

func (packet *RadiusPacket) GetCalledSTAID() (bool, string) {

	ok, data := packet.GetRawAttr(CalledStationId)

	if !ok {
		return false, ""
	}

	return true, string(data[0])

}

func (packet *RadiusPacket) SetCalledSTAID(sta string) {

	value := make([][]byte, 1)
	value[0] = []byte(sta)
	packet.SetRawAttr(CalledStationId, value)

}

func (packet *RadiusPacket) GetCallingSTAID() (bool, string) {

	ok, data := packet.GetRawAttr(CallingStationId)

	if !ok {
		return false, ""
	}

	return true, string(data[0])

}

func (packet *RadiusPacket) SetCallingSTAID(sta string) {

	value := make([][]byte, 1)
	value[0] = []byte(sta)
	packet.SetRawAttr(CallingStationId, value)

}

func (packet *RadiusPacket) GetUserName() (bool, string) {

	ok, data := packet.GetRawAttr(UserName)

	if !ok {
		return false, ""
	}

	return true, string(data[0])

}

func (packet *RadiusPacket) SetUserName(user string) {

	value := make([][]byte, 1)
	value[0] = []byte(user)
	packet.SetRawAttr(UserName, value)

}

func (packet *RadiusPacket) GetConnectInfo() (bool, string) {

	ok, data := packet.GetRawAttr(ConnectInfo)

	if !ok {
		return false, ""
	}

	return true, string(data[0])

}

func (packet *RadiusPacket) SetConnectInfo(connect string) {

	value := make([][]byte, 1)
	value[0] = []byte(connect)
	packet.SetRawAttr(ConnectInfo, value)

}

func (packet *RadiusPacket) GetState() (bool, []byte) {

	ok, data := packet.GetRawAttr(StateAttr)

	if !ok {
		return false, nil
	}

	return true, data[0]

}

func (packet *RadiusPacket) SetState(state []byte) {

	value := make([][]byte, 1)
	value[0] = state
	packet.SetRawAttr(StateAttr, value)

}

func (packet *RadiusPacket) GetAccountSession() (bool, string) {

	ok, data := packet.GetRawAttr(AccountSessionId)

	if !ok {
		return false, ""
	}

	return true, string(data[0])

}

func (packet *RadiusPacket) SetAccountSession(session string) {

	value := make([][]byte, 1)
	value[0] = []byte(session)
	packet.SetRawAttr(AccountSessionId, value)

}

func (packet *RadiusPacket) GetNASIp() (bool, net.IP) {

	ok, data := packet.GetRawAttr(NasIp)

	if !ok || len(data) != 1 || len(data[0]) != 4 {
		return false, net.IP{}
	}

	return true, net.IPv4(data[0][0], data[0][1], data[0][2], data[0][3])

}

func (packet *RadiusPacket) SetNASIp(addr net.IP) {

	/*if len(addr) < 16 {
		return
	}*/

	value := make([][]byte, 1)
	value[0] = append(value[0], addr[12:16]...)
	packet.SetRawAttr(NasIp, value)

}

func (packet *RadiusPacket) GetNASPort() (bool, uint32) {

	ok, data := packet.GetRawAttr(NASPort)

	if !ok || len(data) != 1 || len(data[0]) != 4 { //Not present or size unexpected
		return false, 0
	}

	return true, binary.BigEndian.Uint32(data[0])

}

func (packet *RadiusPacket) SetNASPort(port uint32) {

	value := make([][]byte, 1)
	aux := make([]byte, 4)

	binary.BigEndian.PutUint32(aux, port)

	value[0] = aux

	packet.SetRawAttr(NASPort, value)

}

func (packet *RadiusPacket) GetNASPortType() (bool, uint32) {

	ok, data := packet.GetRawAttr(NASPortType)

	if !ok || len(data) != 1 || len(data[0]) != 4 { //Not present or size unexpected
		return false, 0
	}

	return true, binary.BigEndian.Uint32(data[0])

}

func (packet *RadiusPacket) SetNASPortType(portType uint32) {

	value := make([][]byte, 1)
	aux := make([]byte, 4)

	binary.BigEndian.PutUint32(aux, portType)

	value[0] = aux

	packet.SetRawAttr(NASPortType, value)

}

func (packet *RadiusPacket) GetFramedMTU() (bool, uint32) {

	ok, data := packet.GetRawAttr(FramedMTU)

	if !ok || len(data) != 1 || len(data[0]) != 4 { //Not present or size unexpected
		return false, 0
	}

	return true, binary.BigEndian.Uint32(data[0])

}

func (packet *RadiusPacket) SetFramedMTU(mtu uint32) {

	value := make([][]byte, 1)
	aux := make([]byte, 4)

	binary.BigEndian.PutUint32(aux, mtu)

	value[0] = aux

	packet.SetRawAttr(FramedMTU, value)

}

func (packet *RadiusPacket) GetMessageAuthenticator() (bool, []byte) {

	ok, data := packet.GetRawAttr(MessageAuthenticator)

	if !ok {
		return false, nil
	}

	return true, data[0]

}

func (packet *RadiusPacket) SetMessageAuthenticator(message [16]byte) {

	value := make([][]byte, 1)
	value[0] = append(value[0], message[:]...)
	packet.SetRawAttr(MessageAuthenticator, value)

}
