package session

type config struct {
	secretsFile string //File to perform a dictionary attack
}

var privConfig config

func SetConfig(secrets string) {
	privConfig = config{
		secretsFile: secrets,
	}
}

func GetConfig() config {
	return privConfig
}

func (config config) GetSecretsFile() string {
	return config.secretsFile
}
