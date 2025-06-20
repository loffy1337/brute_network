package auth

import (
	"fmt"
	"time"
)

// Интерфейс для всех протоколов
type Authenticator interface {
	// Попытка авторизации (TryAuth)
	// Возвращает: статус попытки и сетевую ошибку
	TryAuth(login string, password string, timeout time.Duration) (bool, error)
}

// Метод создания конкретного переборщика по названию протокола
func NewAuthenticator(protocol string, ip string, port int) (Authenticator, error) {
	switch protocol {
	case "ssh":
		return NewSSH(ip, port), nil
	case "ftp":
		return NewFTP(ip, port), nil
	case "telnet":
		return NewTelnet(ip, port), nil
	case "mysql":
		return NewMySQL(ip, port), nil
	case "postgresqk":
		return NewPostgreSQL(ip, port), nil
	case "mssql":
		return NewMSSQL(ip, port), nil
	// case "oracle":
	// 	return NewOracle(ip, port), nil
	default:
		return nil, fmt.Errorf("protocol (%s) not supported", protocol)
	}
}
