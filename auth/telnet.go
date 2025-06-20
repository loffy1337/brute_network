package auth

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type TelnetAuth struct {
	Addr string
}

func NewTelnet(ip string, port int) Authenticator {
	return &TelnetAuth{Addr: fmt.Sprintf("%s:%d", ip, port)}
}

// Функция для проверки на вхождение переданных строк в выводе
func exceptOption(reader *bufio.Reader, options []string) error {
	var buffer []byte = make([]byte, 0, 4096)
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return err
		}
		buffer = append(buffer, b)
		var data string = strings.ToLower(string(buffer))
		for _, option := range options {
			if strings.Contains(data, strings.ToLower(option)) {
				return nil
			}
		}
		if len(buffer) >= 4096 {
			return errors.New("enter string not found (timeout or invalid options)")
		}
	}
}

// Функция для проверки на вхождение результатов (успех, ошибка) в выводе
func exceptResult(reader *bufio.Reader) (bool, error) {
	var buffer []byte = make([]byte, 1024)
	n, _ := reader.Read(buffer)
	var output string = strings.ToLower(string(buffer[:n]))

	for _, fail := range []string{"login incorrect", "authentication failed", "invalid password", "access denied"} {
		if strings.Contains(output, fail) {
			return false, nil
		}
	}
	for _, success := range []string{">", "#", "$", "%"} {
		if strings.Contains(output, success) {
			return true, nil
		}
	}
	return false, errors.New("fail or succces strings not found")
}

// Переборщик протокола Telnet
func (authenticator *TelnetAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	// Соединение с telnet
	connection, err := net.DialTimeout("tcp", authenticator.Addr, timeout)
	if err != nil {
		return false, err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(timeout))
	// Попытка входа происходит следующим образом: ждет строку приглашения - отправляет логин, ждет вторую строку - отправляет пароль
	var reader *bufio.Reader = bufio.NewReader(connection)
	err = exceptOption(reader, []string{"login:", "username:", "user:"})
	if err != nil {
		return false, err
	}
	_, err = connection.Write([]byte(login + "\n"))
	if err != nil {
		return false, err
	}
	err = exceptOption(reader, []string{"password:"})
	if err != nil {
		return false, err
	}
	_, err = connection.Write([]byte(password + "\n"))
	if err != nil {
		return false, err
	}
	return exceptResult(reader)
}
