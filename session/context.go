package session

import (
	"net"
	"sync"
)

type ContextSecretStatus uint8

const (
	SecretUnknown  ContextSecretStatus = 0
	GuessingSecret ContextSecretStatus = 1
	SecretOk       ContextSecretStatus = 2
)

//ContextInfo defines the contextual data extracted from the communication between client-server session
//This can be trivial data such as IP addresses or sensitive data such as the secret between NAS-Server
//or session keys used between STA and NAS
type ContextInfo struct {
	server       net.UDPAddr
	nas          net.UDPAddr
	sta          []StaInfo
	secret       string
	secretStatus ContextSecretStatus
	mutex        sync.Mutex
}

type StaInfo struct {
	sta net.UDPAddr
	key string
}

var contexts []*ContextInfo
var contextsMutex sync.Mutex

func AddContext(context *ContextInfo) {

	contextsMutex.Lock()
	contexts = append(contexts, context)
	contextsMutex.Unlock()

}

func GetContextByClient(client net.UDPAddr) *ContextInfo {

	contextsMutex.Lock()
	defer contextsMutex.Unlock()

	for _, context := range contexts {
		{
			context.mutex.Lock()

			if context.nas.IP.Equal(client.IP) && context.nas.Port == client.Port {
				context.mutex.Unlock()
				return context
			}
			context.mutex.Unlock()
		}

	}

	return nil

}

func (context *ContextInfo) SetSecret(secret string) {

	context.mutex.Lock()
	defer context.mutex.Unlock()

	context.secret = secret

}

func (context ContextInfo) GetSecret() string {

	return context.secret

}

func (context *ContextInfo) SetSecretStatus(status ContextSecretStatus) {

	context.mutex.Lock()
	defer context.mutex.Unlock()

	context.secretStatus = status

}

func (context ContextInfo) GetSecretStatus() ContextSecretStatus {

	return context.secretStatus

}

func (context ContextInfo) GetClient() net.UDPAddr {

	return context.nas

}
