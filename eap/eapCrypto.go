package eap

import (
	"crypto/des"
	"crypto/sha1"
	"fmt"
	"io"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

//rfc2759 8.2
func msChapV2CryptoChallengeHash(peerChallenge [16]byte, authChallenge [16]byte, username string) []byte {

	h := sha1.New()

	h.Write(peerChallenge[:])
	h.Write(authChallenge[:])
	io.WriteString(h, username)

	challenge := h.Sum(nil)
	return challenge[:8]

}

//rfc2759 8.3
func msChapV2CryptoNtPasswordHash(password string) []byte {

	//Transform password to UCS2 encoding
	encoding := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	psswdEncoded, _, err := transform.String(encoding.NewEncoder(), password)

	if err != nil {
		return nil
	}

	h := md4.New()
	io.WriteString(h, psswdEncoded)

	return h.Sum(nil)

}

//rfc2759 8.5
func msChapV2CryptoChallengeResponse(challenge []byte, psswdHash []byte) []byte {

	var psswdHashZ [21]byte

	response := make([]byte, 24)

	copy(psswdHashZ[:16], psswdHash[:])

	for i := 16; i < len(psswdHashZ); i++ {
		psswdHashZ[i] = 0
	}

	for i := 0; i < 3; i++ {

		//Get key for DES algorithm
		key := psswdHashZ[i*7 : (i+1)*7]

		//Add parity bits
		pkey := make([]byte, 8)

		next := byte(0)

		for j := uint(0); j < 7; j++ {
			tmp := key[j]
			//Obtain groups of 7 bits and clear the last bit
			pkey[j] = ((tmp >> j) | next) & 0xFE
			count := 0

			//Verify parity for the current byte
			for k := uint(1); k < 8; k++ {
				if (pkey[j]>>k)&1 == 1 {
					count++
				}
			}

			//If even, set parity bit to 1.
			if count%2 == 0 {
				pkey[j] = pkey[j] | 1
			}

			//Calculate the part of the current byte that we are trailing
			next = tmp << (7 - j)

		}

		count := 0

		pkey[7] = next
		//Verify parity for the last byte
		for k := uint(1); k < 8; k++ {
			if (pkey[7]>>k)&1 == 1 {
				count++
			}
		}

		//If even, set parity bit to 1.
		if count%2 == 0 {
			pkey[7] = pkey[7] | 1
		}

		desCipher, err := des.NewCipher(pkey)

		if err != nil {
			fmt.Println("err", err)
		} else {
			desCipher.Encrypt(response[i*8:(i+1)*8], challenge)
		}

	}

	return response

}

//rfc2759 8.1
func MsChapV2GenerateNTResponse(authChallenge [16]byte, peerChallenge [16]byte, username string, password string) []byte {

	challenge := msChapV2CryptoChallengeHash(peerChallenge, authChallenge, username)

	psswdHash := msChapV2CryptoNtPasswordHash(password)

	if len(challenge) == 8 && len(psswdHash) == 16 {
		response := msChapV2CryptoChallengeResponse(challenge, psswdHash)
		return response
	}
	return nil
}
