package session

type config struct {
	secretsFile   string //File to perform a dictionary attack
	passwordsFile string //
}

var privConfig config

func SetConfig(secrets, passwords string) {
	privConfig = config{
		secretsFile:   secrets,
		passwordsFile: passwords,
	}
}

func GetConfig() config {
	return privConfig
}

func (config config) GetSecretsFile() string {
	return config.secretsFile
}

func (config config) GetPasswordsFile() string {
	return config.passwordsFile
}
