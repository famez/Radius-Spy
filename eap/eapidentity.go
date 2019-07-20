package eap

type EapIdentity struct {
	header   HeaderEap
	identity string
}

func NewEapIdentity() *EapIdentity {

	header := HeaderEap{
		msgType: Identity,
	}

	identity := &EapIdentity{
		header: header,
	}

	return identity

}

func (packet *EapIdentity) Encode() (bool, []byte) {
	ok, buff := packet.header.Encode()

	if ok {
		copy(buff[5:], packet.identity)
	}

	return true, buff

}

func (packet *EapIdentity) Decode(buff []byte) bool {

	ok := packet.header.Decode(buff)

	if !ok {
		return false
	}

	packet.identity = string(buff[5:])

	return true

}

func (packet *EapIdentity) GetId() uint8 {
	return packet.header.GetId()
}

func (packet *EapIdentity) GetCode() EapCode {
	return packet.header.GetCode()
}

func (packet *EapIdentity) GetType() EapType {
	return packet.header.GetType()
}

func (packet *EapIdentity) GetIdentity() string {
	return packet.identity
}
