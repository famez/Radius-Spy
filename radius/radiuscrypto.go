package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"io"

	"github.com/golang/glog"
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

//rfc2548 2.4.2
func DecryptKeyFromMPPE(mppeKey []byte, reqAuth [16]byte, secret string) (bool, []byte) {

	//mppeKey contains Salt+Encrypted Key

	var decryptedKey []byte

	if len(mppeKey) <= 2 { //There must be anything else appart from the salt
		glog.V(1).Infoln("Error")
		return false, nil
	}

	salt := mppeKey[:2]
	encryptedKey := mppeKey[2:]

	if (len(encryptedKey) % md5.Size) != 0 {
		glog.V(1).Infoln("Error")
		return false, nil //Must be multiple of 16.
	}

	{
		//Start decrypting key
		md5Hash := md5.New()

		io.WriteString(md5Hash, secret)
		md5Hash.Write(reqAuth[:])
		md5Hash.Write(salt)

		digest := md5Hash.Sum(nil)

		decryptedKey = append(decryptedKey, digest...)

	}

	for i := 0; i < len(encryptedKey)-md5.Size; i += md5.Size {

		md5Hash := md5.New()

		io.WriteString(md5Hash, secret)
		md5Hash.Write(encryptedKey[i : i+md5.Size])

		digest := md5Hash.Sum(nil)

		decryptedKey = append(decryptedKey, digest...)

	}

	if len(decryptedKey) != len(encryptedKey) {
		glog.V(1).Infoln("Error")
		return false, nil
	}

	for index, value := range decryptedKey {
		decryptedKey[index] = value ^ encryptedKey[index]
	}

	keyLength := decryptedKey[0]

	if int(keyLength+2) > len(decryptedKey) {
		return false, nil
	}

	return true, decryptedKey[2 : keyLength+2]
}

//rfc2548 2.4.2
func EncryptKeyToMPPE(key []byte, reqAuth [16]byte, secret string) (bool, []byte) {

	if len(key) == 0 || len(key) > 0xFF {
		return false, nil
	}

	encryptedKey := make([]byte, len(key)+1)

	encryptedKey[0] = byte(len(key))

	copy(encryptedKey[1:], key)

	//Generate random salt
	var salt [2]byte

	_, err := rand.Read(salt[:])

	if err != nil {
		glog.V(1).Infoln("Error in random function", err)
		return false, nil
	}

	//MSb must be set to 1
	salt[0] |= 0x80

	//0 padding to make length a multiple of 16.
	for i := 0; i < (len(encryptedKey) % md5.Size); i++ {
		encryptedKey = append(encryptedKey, 0)
	}

	{
		//Start encrypting key
		md5Hash := md5.New()

		io.WriteString(md5Hash, secret)
		md5Hash.Write(reqAuth[:])
		md5Hash.Write(salt[:])

		digest := md5Hash.Sum(nil)

		for i, v := range digest {
			encryptedKey[i] ^= v
		}

	}

	for i := md5.Size; i < len(encryptedKey); i += md5.Size {

		md5Hash := md5.New()

		io.WriteString(md5Hash, secret)
		md5Hash.Write(encryptedKey[i-md5.Size : i])

		digest := md5Hash.Sum(nil)

		for j, v := range digest {
			encryptedKey[i+j] ^= v
		}

	}

	return true, append(salt[:], encryptedKey...)

}
