package radius

import "crypto/md5"

func CalculateResponseAuth(response RadiusPacket, requestAuth [16]byte, secret string) (bool, [16]byte) {

	var retVal [16]byte

	encoded, chunk := response.Encode()

	if !encoded {
		return false, retVal
	}

	copy(chunk[4:], requestAuth[:]) //Overwrite with request auth

	chunk = append(chunk, []byte(secret)...)

	return true, md5.Sum(chunk)

}
