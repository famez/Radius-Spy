package radius

import (
	"crypto/hmac"
	"crypto/md5"
)

func CalculateResponseAuth(response *RadiusPacket, requestAuth [16]byte, secret string) (bool, [16]byte) {

	var retVal [16]byte

	encoded, chunk := response.Encode()

	if !encoded {
		return false, retVal
	}

	copy(chunk[4:], requestAuth[:]) //Overwrite with request auth

	chunk = append(chunk, []byte(secret)...)

	return true, md5.Sum(chunk)

}

func RecalculateMsgAuth(packet *RadiusPacket, reqAuth [16]byte, secret string) bool {

	var msgAuth [16]byte

	for index := range msgAuth {
		msgAuth[index] = 0
	}

	packet.SetMessageAuthenticator(msgAuth)

	encoded, chunk := packet.Encode()

	if !encoded {
		return false
	}

	if packet.GetCode() != AccessRequest { //If request packet, there is no need to overwrite autheticator field
		copy(chunk[4:], reqAuth[:]) //Overwrite with reqAuth
	}

	mac := hmac.New(md5.New, []byte(secret))

	mac.Write(chunk)

	result := mac.Sum(nil)

	if len(result) != 16 {
		return false
	}

	copy(msgAuth[:], result)

	packet.SetMessageAuthenticator(msgAuth)

	return true

}
