package cat

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/pair"
	"github.com/jackc/pgx/v5"
)

type Filter struct {
	Project    string
	Filter     string
	Definition string
}

func CreateFilter(db *dbx.DB, projectID int32, filter string, cmdsql, sql string) error {
	q := "insert into ccms.filter (project_id, name, command, sql) values ($1, $2, $3, $4)"
	if _, err := db.Exec(db.Ctx, q, projectID, filter, cmdsql, sql); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func FilterExists(db *dbx.DB, filter pair.Pair) (bool, error) {
	sql := "select 1 from ccms.filter where name=$1"
	var n int32
	err := db.QueryRow(db.Ctx, sql, filter.String()).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func FilterSQL(db *dbx.DB, filter string) (string, error) {
	rows, err := db.Query(db.Ctx, "select sql from ccms.filter where name=$1", filter)
	if err != nil {
		return "", dberr.Error(err)
	}
	filterSQL, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", err
	}
	if len(filterSQL) == 0 {
		return "", errors.New("filter \"" + filter + "\" does not exist")
	}
	return filterSQL[0], nil
}

func Filters(db *dbx.DB) ([]Filter, error) {
	return FiltersInProject(db, "")
}

func FiltersInProject(db *dbx.DB, project string) ([]Filter, error) {
	var rows pgx.Rows
	if project == "" {
		sql := "select p.name, f.name, f.command from ccms.filter f join ccms.project p on f.project_id=p.id"
		rows, _ = db.Query(db.Ctx, sql)
	} else {
		sql := "select p.name, f.name, f.command from ccms.filter f join ccms.project p on f.project_id=p.id where p.name=$1"
		rows, _ = db.Query(db.Ctx, sql, project)
	}
	filters, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Filter])
	if err != nil {
		return nil, err
	}
	return filters, nil
}

func SortFilters(filters []Filter) {
	slices.SortFunc(filters, func(a, b Filter) int {
		if n := strings.Compare(a.Project, b.Project); n != 0 {
			return n
		}
		return cmp.Compare(a.Filter, b.Filter)
	})
}
