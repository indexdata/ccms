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

type Set struct {
	Project string
	Set     string
}

func SetExists(db *dbx.DB, set pair.Pair) (bool, error) {
	if set.Second == "object" {
		projectID, err := ProjectID(db, set.First)
		if err != nil {
			return false, err
		}
		return projectID != 0, nil
	}

	sql := "select 1 from ccms.sets s join ccms.project p on s.project_id=p.id where p.name=$1 and s.name=$2"
	var n int32
	err := db.QueryRow(db.Ctx, sql, set.First, set.Second).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func IsValidTargetSet(db *dbx.DB, set pair.Pair) (bool, error) {
	if set.First == "" || set.Second == "" {
		return false, nil
	}
	if set.Second == "object" {
		return false, nil
	}
	projectID, err := ProjectID(db, set.First)
	if err != nil {
		return false, err
	}
	return projectID != 0, nil
}

// return table containing set
func SetTable(set pair.Pair) string {
	if set.Second == "object" {
		return set.String()
	}
	return set.First + ".s_" + set.Second
}

func Sets(db *dbx.DB) ([]Set, error) {
	sql := "select p.name, s.name from ccms.sets s join ccms.project p on s.project_id=p.id"
	rows, _ := db.Query(db.Ctx, sql)
	sets, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Set])
	if err != nil {
		return nil, err
	}

	// add object sets
	projects, err := Projects(db)
	if err != nil {
		return nil, err
	}
	for i := range projects {
		sets = append(sets, Set{Project: projects[i].Name, Set: "object"})
	}

	return sets, nil
}

func SetsInProject(db *dbx.DB, projectID int32, project string) ([]Set, error) {
	var rows pgx.Rows
	if projectID == 0 {
		sql := "select p.name, s.name from ccms.sets s join ccms.project p on s.project_id=p.id"
		rows, _ = db.Query(db.Ctx, sql)
	} else {
		sql := "select '" + project + "', s.name from ccms.sets s where s.project_id=$1"
		rows, _ = db.Query(db.Ctx, sql, projectID)
	}
	sets, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Set])
	if err != nil {
		return nil, err
	}

	// add object set
	sets = append(sets, Set{Project: project, Set: "object"})

	return sets, nil
}

func SortSets(sets []Set) {
	slices.SortFunc(sets, func(a, b Set) int {
		if n := strings.Compare(a.Project, b.Project); n != 0 {
			return n
		}
		return cmp.Compare(a.Set, b.Set)
	})
}

func CreateSet(db *dbx.DB, set pair.Pair) error {
	sql := "create table " + SetTable(set) + "(" +
		"id bigint primary key)"
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	projectID, err := ProjectID(db, set.First)
	if err != nil {
		return err
	}
	sql = "insert into ccms.sets (project_id, name) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, projectID, set.Second); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func DropSet(db *dbx.DB, projectID int32, set pair.Pair) error {
	q := "drop table " + SetTable(set)
	if _, err := db.Exec(db.Ctx, q); err != nil {
		return dberr.Error(err)
	}
	sql := "delete from ccms.sets where project_id=$1 and name=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, set.Second); err != nil {
		return dberr.Error(err)
	}
	return nil
}
