package tlsadditions

import (
	"encoding/binary"
	"radius/utils"
)

type TLSContentType uint8

const (
	tlsHandshake TLSContentType = 22
)

func GetRandomFromTLSData(data []byte, isClient bool) (bool, []byte) {

	for len(data) != 0 {

		//Check if whether the message is handshake or not
		if TLSContentType(data[0]) != tlsHandshake {
			return false, nil //Not a handshake message
		}

		//Skip TLS version

		//Length
		length := binary.BigEndian.Uint16(data[3:])

		if uint16(len(data)) < length+5 {
			return false, nil
		}

		handshakeType := uint8(data[5])

		if (isClient && handshakeType != 1 /*Client hello*/) || (!isClient && handshakeType != 2 /*Server hello*/) {
			data = data[length+5:]
			continue
		}

		innerLength := utils.BigEndian3BytesToUint32(data[6:])

		if innerLength+4 != uint32(length) || innerLength < 32 {
			return false, nil
		}

		//Skip TLS version again

		random := data[11:43]

		return true, random

	}

	return false, nil

}

func GetVersionFromTLSData(data []byte) (bool, uint16) {

	if len(data) < 3 { //Not enough length
		return false, 0
	}

	if TLSContentType(data[0]) != tlsHandshake {
		return false, 0 //Not a handshake message
	}

	version := binary.BigEndian.Uint16(data[1:])

	return true, version

}
