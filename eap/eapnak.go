package eap

type EapNak struct {
	header          HeaderEap
	desiredAuthType EapType
}

func NewEapNak() *EapNak {

	header := HeaderEap{
		msgType: LegacyNak,
	}

	nak := &EapNak{
		header: header,
	}

	return nak

}

func (packet *EapNak) Encode() (bool, []byte) {
	return packet.header.Encode()
}

func (packet *EapNak) Decode(buff []byte) bool {

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	packet.desiredAuthType = EapType(buff[5])

	return true

}

func (packet *EapNak) GetId() uint8 {
	return packet.header.GetId()
}

func (packet *EapNak) GetCode() EapCode {
	return packet.header.GetCode()
}

func (packet *EapNak) GetType() EapType {
	return packet.header.GetType()
}

func (packet *EapNak) GetDesiredType() EapType {
	return packet.desiredAuthType
}
