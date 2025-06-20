package auth

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLAuth struct {
	Dsn string
}

func NewMySQL(ip string, port int) Authenticator {
	return &MySQLAuth{Dsn: fmt.Sprintf("tcp(%s:%d)", "%s", "%s", ip, port)}
}

// Переборщик протокола MySQL
func (authenticator *MySQLAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	var dsn string = fmt.Sprintf("%s:%s@%s", login, password, authenticator.Dsn)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	db.SetConnMaxLifetime(timeout)
	err = db.Ping()
	if err != nil {
		if err == sql.ErrConnDone {
			return false, err
		}
		return false, nil
	}
	return true, nil
}
