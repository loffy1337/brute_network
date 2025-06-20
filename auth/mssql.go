package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

type MSSQLAuth struct {
	Dsn string
}

func NewMSSQL(ip string, port int) Authenticator {
	return &MSSQLAuth{Dsn: fmt.Sprintf("sqlserver://%s:%s@%s:%d?connection+timeout=5", "%s", "%s", ip, port)}
}

// Переборщик протокола MSSQL
func (authenticator *MSSQLAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	var dsn string = fmt.Sprintf(authenticator.Dsn, login, password)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()
	err = db.PingContext(ctx)
	if err != nil {
		return false, nil
	}
	return true, nil
}
