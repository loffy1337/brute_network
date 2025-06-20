package auth

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type PostgreSQLAuth struct {
	Dsn string
}

func NewPostgreSQL(ip string, port int) Authenticator {
	return &PostgreSQLAuth{Dsn: fmt.Sprintf("host=%s port=%d sslmode=disable", ip, port)}
}

// Переборщик протокола PostgreSQL
func (authenticator *PostgreSQLAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	var dsn string = fmt.Sprintf("%s user=%s pasword=%s connect_timeout=%d", authenticator.Dsn, login, password, int(timeout.Seconds()))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	db.SetConnMaxLifetime(timeout)
	err = db.Ping()
	if err != nil {
		return false, nil
	}
	return true, nil
}
