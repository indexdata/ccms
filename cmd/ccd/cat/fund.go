package cat

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/prop"
	"github.com/jackc/pgx/v5"
)

func CreateFund(db *dbx.DB, fund string) error {
	sql := "insert into ccms.fund (name, title) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, fund, makeTitle(fund)); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func DropFund(db *dbx.DB, fund string) error {
	fundID, err := FundID(db, fund)
	if err != nil {
		return err
	}
	if fundID == 0 {
		return errors.New("fund \"" + fund + "\" does not exist")
	}

	projects, err := ProjectsHavingFund(db, fundID)
	if err != nil {
		return err
	}
	if len(projects) != 0 {
		slices.Sort(projects)
		for i := range projects {
			projects[i] = "\"" + projects[i] + "\""
		}
		var s string
		if len(projects) > 1 {
			s = "s"
		}
		return errors.New("fund \"" + fund + "\" is used in project" + s + " " + strings.Join(projects, ", "))
	}

	sql := "delete from ccms.fund where id=$1"
	if _, err := db.Exec(db.Ctx, sql, fundID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

// returns fund ID, or 0 if fund does not exist
func FundID(db *dbx.DB, fund string) (int32, error) {
	var q = "select id from ccms.fund where name=$1"
	var id int32
	err := db.QueryRow(db.Ctx, q, fund).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, dberr.Error(err)
	default:
		return id, nil
	}
}

func Funds(db *dbx.DB) (prop.Property, error) {
	sql := "select name, title from ccms.fund"
	rows, err := db.Query(db.Ctx, sql)
	if err != nil {
		return nil, dberr.Error(err)
	}
	funds, err := pgx.CollectRows(rows, pgx.RowToStructByPos[prop.Prop])
	if err != nil {
		return nil, err
	}
	return funds, nil
}

func IsValidFundName(fund string) bool {
	if strings.ContainsRune(fund, '.') {
		return false
	}
	return true
}

func FundProperties(db *dbx.DB, fund string) ([][2]string, error) {
	var title string
	sql := `select f.title from ccms.fund f where f.name=$1`
	err := db.QueryRow(db.Ctx, sql, fund).Scan(&title)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("fund %q does not exist", fund)
	case err != nil:
		return nil, dberr.Error(err)
	default:
	}
	prop := [][2]string{
		{"name", fund},
		{"title", title},
	}
	return prop, nil
}

func AlterFundSetProperty(db *dbx.DB, fund, property, value string, stringLiteral bool) error {
	switch property {
	case "name":
		if stringLiteral || value == "" {
			return invalidValueError(property, value)
		}
	case "title":
		if !stringLiteral {
			return invalidValueError(property, value)
		}
	default:
		return errors.New("property \"" + property + "\" does not exist")
	}

	sql := "update ccms.fund set \"" + property + "\"=$1 where name=$2"
	if _, err := db.Exec(db.Ctx, sql, value, fund); err != nil {
		return dberr.Error(err)
	}
	return nil
}
