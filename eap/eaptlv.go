package eap

import "encoding/binary"

type TLVResult uint16

const (
	TLVResOk   TLVResult = 1
	TLVResFail TLVResult = 2
)

type EapTLVResult struct {
	header HeaderEap
	result TLVResult
}

func NewEapTLVResult() *EapTLVResult {

	header := HeaderEap{
		msgType: TLV,
	}

	tlv := &EapTLVResult{
		header: header,
	}

	return tlv

}

func (packet *EapTLVResult) Encode() (bool, []byte) {

	packet.header.setLength(11)

	ok, buff := packet.header.Encode()

	if ok {
		buff[5] = 0x80
		buff[6] = 3
		binary.BigEndian.PutUint16(buff[7:], 2)
		binary.BigEndian.PutUint16(buff[9:], uint16(packet.result))
	}

	return true, buff

}

func (packet *EapTLVResult) Decode(buff []byte) bool {

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	if len(buff) != 11 { //Length must be fixed to 11.
		return false
	}

	if buff[5] != 0x80 { //This is mandatory for TLV result
		return false
	}

	if buff[6] != 3 { //This byte represents the type of TLV. It must be 3 for TLV result
		return false
	}

	tlvLen := binary.BigEndian.Uint16(buff[7:])

	if tlvLen != 2 { //Length must be fixed to 2.
		return false
	}

	packet.result = TLVResult(binary.BigEndian.Uint16(buff[9:]))

	return true

}

func (packet *EapTLVResult) GetId() uint8 {
	return packet.header.GetId()
}

func (packet *EapTLVResult) GetCode() EapCode {
	return packet.header.GetCode()
}

func (packet *EapTLVResult) GetType() EapType {
	return packet.header.GetType()
}

func (packet EapTLVResult) GetResult() TLVResult {
	return packet.result
}

func (packet *EapTLVResult) SetResult(result TLVResult) {
	packet.result = result
}
