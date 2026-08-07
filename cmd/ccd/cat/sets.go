package cat

import (
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/jackc/pgx/v5"
)

type Set struct {
	Project string
	Set     string
	Title   string
}

func SetExists(db *dbx.DB, project, set string) (bool, error) {
	if set == "object" {
		projectID, err := ProjectID(db, project)
		if err != nil {
			return false, err
		}
		return projectID != 0, nil
	}

	setID, err := SetID(db, project, set)
	if err != nil {
		return false, err
	}
	return setID != 0, nil
}

func IsValidTargetSet(db *dbx.DB, project, set string) (bool, error) {
	if project == "" || set == "" {
		return false, nil
	}
	if set == "object" {
		return false, nil
	}
	projectID, err := ProjectID(db, project)
	if err != nil {
		return false, err
	}
	return projectID != 0, nil
}

// return table containing set
func SetTable(project, set string) string {
	if set == "object" {
		return project + "." + set
	}
	return project + ".s_" + set
}

// returns set ID, or 0 if set does not exist
func SetID(db *dbx.DB, project, set string) (int32, error) {
	sql := "select s.id from ccms.sets s join ccms.project p on s.project_id=p.id where p.name=$1 and s.name=$2"
	var id int32
	err := db.QueryRow(db.Ctx, sql, project, set).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, dberr.Error(err)
	default:
		return id, nil
	}
}

func Sets(db *dbx.DB) ([]Set, error) {
	return SetsInProject(db, 0, "")
}

func SetsInProject(db *dbx.DB, projectID int32, project string) ([]Set, error) {
	var rows pgx.Rows
	if projectID == 0 {
		sql := "select p.name, s.name, s.title from ccms.sets s join ccms.project p on s.project_id=p.id"
		rows, _ = db.Query(db.Ctx, sql)
	} else {
		sql := "select '" + project + "', s.name, s.title from ccms.sets s where s.project_id=$1"
		rows, _ = db.Query(db.Ctx, sql, projectID)
	}
	sets, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Set])
	if err != nil {
		return nil, err
	}

	// add object sets
	if projectID == 0 {
		projects, err := Projects(db)
		if err != nil {
			return nil, err
		}
		for i := range projects {
			sets = append(sets, Set{Project: projects[i].Name, Set: "object", Title: "All Objects"})
		}
	} else {
		sets = append(sets, Set{Project: project, Set: "object", Title: "All Objects"})
	}

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

func CreateSet(db *dbx.DB, project, set string) error {
	sql := "create table " + SetTable(project, set) + "(" +
		"id bigint primary key)"
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	projectID, err := ProjectID(db, project)
	if err != nil {
		return err
	}
	sql = "insert into ccms.sets (project_id, name, title) values ($1, $2, $3)"
	if _, err := db.Exec(db.Ctx, sql, projectID, set, makeTitle(set)); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func DropSet(db *dbx.DB, projectID int32, project, set string) error {
	q := "drop table " + SetTable(project, set)
	if _, err := db.Exec(db.Ctx, q); err != nil {
		return dberr.Error(err)
	}
	sql := "delete from ccms.sets where project_id=$1 and name=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, set); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func DropAllSetsInProject(db *dbx.DB, projectID int32) error {
	sets, err := Sets(db)
	if err != nil {
		return err
	}
	for i := range sets {
		project := sets[i].Project
		set := sets[i].Set
		if set == "object" {
			continue
		}
		if err := DropSet(db, projectID, project, set); err != nil {
			return err
		}
	}
	return nil
}

func AlterSetSetProperty(db *dbx.DB, setID int32, property, value string, stringLiteral bool) error {
	switch property {
	case "name":
		if stringLiteral {
			return invalidValueError(property, "'"+value+"'")
		}
		if value == "" {
			return invalidValueError(property, value)
		}
	case "title":
		if !stringLiteral {
			return invalidValueError(property, value)
		}
	default:
		return errors.New("property \"" + property + "\" does not exist")
	}

	sql := "update ccms.sets set \"" + property + "\"=$1 where id=$2"
	if _, err := db.Exec(db.Ctx, sql, value, setID); err != nil {
		return dberr.Error(err)
	}
	return nil
}
