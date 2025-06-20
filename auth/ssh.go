package auth

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHAuth struct {
	Addr string
}

func NewSSH(ip string, port int) Authenticator {
	return &SSHAuth{Addr: fmt.Sprintf("%s:%d", ip, port)}
}

// Переборщик протокола SSH
func (authenticator *SSHAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	// Создание конфига для подключения
	var config *ssh.ClientConfig = &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	connection, err := ssh.Dial("tcp", authenticator.Addr, config)
	if err != nil {
		if strings.Contains(err.Error(), "ssh: unable to authenticate") {
			return false, nil
		}
		// Отличие сетевых ошибок
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "connection reset by peer") {
			return false, err
		}
		return false, nil
	}
	connection.Close()
	return true, nil
}
