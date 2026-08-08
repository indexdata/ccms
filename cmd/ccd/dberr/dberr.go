package dberr

import (
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

func Error(err error) error {
	switch e := err.(type) {
	case *pgconn.PgError:
		return errors.New(pgString(e))
	default:
		return errors.New(simplify(e.Error()))
	}
}

func String(err error) string {
	switch e := err.(type) {
	case *pgconn.PgError:
		return pgString(e)
	default:
		return err.Error()
	}
}

func pgString(err *pgconn.PgError) string {
	var b strings.Builder
	b.WriteString(simplify(err.Message))
	if err.Detail != "" {
		b.WriteString(": ")
		b.WriteString(err.Detail)
	}
	if err.Hint != "" {
		b.WriteString(" (")
		b.WriteString(err.Hint)
		b.WriteRune(')')
	}
	return b.String()
}

func simplify(errString string) string {
	s := strings.TrimPrefix(errString, "ERROR: ")
	return string(sqlstate.ReplaceAll([]byte(s), []byte("")))
}

var sqlstate = regexp.MustCompile(` \(SQLSTATE [0-9A-Z]+\)`)
