package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/sijms/go-ora/v2"
)

type OracleAuth struct {
	Dsn      string
	Serivces []string
}

func NewOracle(ip string, port int) Authenticator {
	return &OracleAuth{Dsn: fmt.Sprintf("oracle://%s:%s@%s:%d/%s", "%s", "%s", ip, port, "%s"), Serivces: []string{"ORCLPDB1", "ORCLCDB", "ORCL", "XE", "XEPDB1"}}
}

func (authenticator *OracleAuth) TryAuth(login string, password string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, service := range authenticator.Serivces {
		var dsn string = fmt.Sprintf(authenticator.Dsn, url.QueryEscape(login), url.QueryEscape(password), service)
		db, err := sql.Open("oracle", dsn)
		if err != nil {
			continue
		}
		db.SetMaxIdleConns(0)
		db.SetMaxOpenConns(1)
		db.SetConnMaxLifetime(timeout)
		err = db.PingContext(ctx)
		db.Close()
		if err == nil {
			return true, nil
		}
		switch {
		case strings.Contains(err.Error(), "ORA-01017"):
			return false, nil
		case strings.Contains(err.Error(), "ORA-12514"), strings.Contains(err.Error(), "ORA-12505"):
			continue
		case errors.Is(err, context.DeadlineExceeded),
			strings.Contains(err.Error(), "i/o timeout"),
			strings.Contains(err.Error(), "connection reset"):
			return false, err
		}
	}
	return false, nil
}
