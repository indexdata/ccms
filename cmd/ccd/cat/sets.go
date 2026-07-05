package cat

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/set"
	"github.com/jackc/pgx/v5"
)

func SetExists(db *dbx.DB, set set.Set) (bool, error) {
	if set.Set == "object" {
		projectID, err := ProjectID(db, set.Project)
		if err != nil {
			return false, err
		}
		return projectID != 0, nil
	}

	sql := "select 1 from ccms.sets s join ccms.project p on s.project_id=p.id where p.name=$1 and s.name=$2"
	var n int32
	err := db.QueryRow(db.Ctx, sql, set.Project, set.Set).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func IsValidTargetSet(db *dbx.DB, set set.Set) (bool, error) {
	if set.Project == "" || set.Set == "" {
		return false, nil
	}
	if set.Set == "object" {
		return false, nil
	}
	projectID, err := ProjectID(db, set.Project)
	if err != nil {
		return false, err
	}
	return projectID != 0, nil
}

// return table containing set
func SetTable(set set.Set) string {
	if set.Set == "object" {
		return set.String()
	}
	return set.Project + ".s_" + set.Set
}

func Sets(db *dbx.DB) ([]string, error) {
	sql := "select p.name||'.'||s.name from ccms.sets s join ccms.project p on s.project_id=p.id"
	rows, err := db.Query(db.Ctx, sql)
	if err != nil {
		return nil, dberr.Error(err)
	}
	sets, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}

	// add object sets
	projects, err := Projects(db)
	if err != nil {
		return nil, err
	}
	for i := range projects {
		sets = append(sets, projects[i].Name+".object")
	}

	return sets, nil
}

func SetsInProject(db *dbx.DB, project string) ([]string, error) {
	sql := "select p.name||'.'||s.name from ccms.sets s join ccms.project p on s.project_id=p.id where p.name=$1"
	rows, err := db.Query(db.Ctx, sql, project)
	if err != nil {
		return nil, dberr.Error(err)
	}
	sets, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	sets = append(sets, project+".object")
	return sets, nil
}

func sortSetNames(sets []string) {
	slices.SortFunc(sets, func(x, y string) int {
		a := !strings.ContainsRune(x, '.')
		b := !strings.ContainsRune(y, '.')
		if a && !b {
			return -1
		}
		if !a && b {
			return 1
		}
		return cmp.Compare(x, y)
	})
}

func CreateSet(db *dbx.DB, set set.Set) error {
	sql := "create table " + SetTable(set) + "(" +
		"id bigint primary key)"
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	projectID, err := ProjectID(db, set.Project)
	if err != nil {
		return err
	}
	sql = "insert into ccms.sets (project_id, name) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, projectID, set.Set); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func DropSet(db *dbx.DB, set set.Set) error {
	q := "drop table " + SetTable(set)
	if _, err := db.Exec(db.Ctx, q); err != nil {
		return dberr.Error(err)
	}
	projectID, err := ProjectID(db, set.Project)
	if err != nil {
		return err
	}
	sql := "delete from ccms.sets where project_id=$1 and name=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, set.Set); err != nil {
		return dberr.Error(err)
	}
	return nil
}
