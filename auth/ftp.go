package auth

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
)

type FTPAuth struct {
	Addr string
}

func NewFTP(ip string, port int) Authenticator {
	return &FTPAuth{Addr: fmt.Sprintf("%s:%d", ip, port)}
}

// Переборщик протокола FTP
func (authenticator *FTPAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	connection, err := ftp.Dial(authenticator.Addr, ftp.DialWithTimeout(timeout))
	if err != nil {
		return false, err
	}
	defer connection.Quit()
	if err = connection.Login(login, password); err != nil {
		// Отличие сетевых ошибок
		if err, ok := err.(net.Error); ok && err.Timeout() || strings.Contains(err.Error(), "connection refused") {
			return false, err
		}
		return false, nil
	}
	return true, nil
}
