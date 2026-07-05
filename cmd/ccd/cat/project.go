package cat

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/prop"
	"github.com/jackc/pgx/v5"
)

// returns project ID, or -1 if the project is archived or 0 if it does not exist
func ProjectID(db *dbx.DB, project string) (int32, error) {
	sql := "select id, archived from ccms.project where name=$1"
	var id int32
	var archived bool
	err := db.QueryRow(db.Ctx, sql, project).Scan(&id, &archived)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, err
	default:
		if archived {
			return -1, nil
		}
		return id, nil
	}
}

// returns project ID, or 0 if project does not exist
func ArchivedProjectID(db *dbx.DB, project string) (int32, error) {
	sql := "select id from ccms.project where name=$1 and archived=true"
	var id int32
	err := db.QueryRow(db.Ctx, sql, project).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, err
	default:
		return id, nil
	}
}

func IsValidTargetProject(project string) bool {
	if strings.ContainsRune(project, '.') {
		return false
	}
	return true
}

func Projects(db *dbx.DB, archived bool) (prop.Property, error) {
	sql := "select name, title from ccms.project where archived=$1"
	rows, err := db.Query(db.Ctx, sql, archived)
	if err != nil {
		return nil, dberr.Error(err)
	}
	projects, err := pgx.CollectRows(rows, pgx.RowToStructByPos[prop.Prop])
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func DropProject(db *dbx.DB, project string) error {
	sets, err := SetsInProject(db, project)
	if err != nil {
		return err
	}
	if len(sets) != 0 {
		return errors.New("project \"" + project + "\" contains one or more sets")
	}

	sql := "drop table " + project + ".object"
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	sql = "drop schema " + project
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	sql = "delete from ccms.project where name=$1"
	if _, err := db.Exec(db.Ctx, sql, project); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func ArchiveProject(db *dbx.DB, project string) (string, error) {
	newName := archivalProjectName(project)
	sql := "update ccms.project set name='" + newName + "', archived=true where name='" + project + "'"
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return "", dberr.Error(err)
	}
	sql = "alter schema " + project + " rename to " + newName
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return "", dberr.Error(err)
	}
	return newName, nil
}

func archivalProjectName(project string) string {
	t := time.Now().UTC()
	return t.Format(project + "_20060102_150405")
}

func CreateProject(db *dbx.DB, project string) error {
	if !IsValidTargetProject(project) {
		return errors.New("invalid project name \"" + project + "\"")
	}

	projectID, err := ProjectID(db, project)
	if err != nil {
		return err
	}
	if projectID != 0 {
		return errors.New("project \"" + project + "\" already exists")
	}

	sql := "create schema " + project
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	sql = "insert into ccms.project (name, title) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, project, makeTitle(project)); err != nil {
		return dberr.Error(err)
	}
	sql = "create table " + project + ".object (" +
		"id bigint primary key," +
		"decision boolean not null default false," +
		"fund_id integer references ccms.fund (id))"
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func AlterProjectAddToProperty(db *dbx.DB, project, property, value string, stringLiteral bool) error {
	// look up project id
	projectID, err := ProjectID(db, project)
	if err != nil {
		return err
	}
	if projectID == 0 {
		return errors.New("project \"" + project + "\" does not exist")
	}

	switch property {
	case "funds":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectAddFund(db, project, value, projectID); err != nil {
			return err
		}
	// case "locations":
	// 	if stringLiteral {
	// 		return invalidValueError(property, value)
	// 	}
	// 	if err := alterProjectAddLocation(d, project, value, projectID); err != nil {
	// 		return err
	// 	}
	case "origins":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectAddOrigin(db, project, value, projectID); err != nil {
			return err
		}
	case "destinations":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectAddDestination(db, project, value, projectID); err != nil {
			return err
		}
	case "tracks":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectAddTrack(db, project, value, projectID); err != nil {
			return err
		}
	case "title", "action", "mou_link":
		return errors.New("property \"" + property + "\" is not composite")
	default:
		return errors.New("unknown property \"" + property + "\"")
	}
	return nil
}

func AlterProjectDropFromProperty(db *dbx.DB, project, property, value string, stringLiteral bool) error {
	// look up project id
	projectID, err := ProjectID(db, project)
	if err != nil {
		return err
	}
	if projectID == 0 {
		return errors.New("project \"" + project + "\" does not exist")
	}

	switch property {
	case "funds":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectDropFund(db, project, value, projectID); err != nil {
			return err
		}
	// case "locations":
	// 	if stringLiteral {
	// 		return invalidValueError(property, value)
	// 	}
	// 	if err := alterProjectDropLocation(d, project, value, projectID); err != nil {
	// 		return err
	// 	}
	case "origins":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectDropOrigin(db, project, value, projectID); err != nil {
			return err
		}
	case "destinations":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectDropDestination(db, project, value, projectID); err != nil {
			return err
		}
	case "tracks":
		if stringLiteral {
			return invalidValueError(property, value)
		}
		if err := alterProjectDropTrack(db, project, value, projectID); err != nil {
			return err
		}
	case "title", "action", "mou_link":
		return errors.New("property \"" + property + "\" is not composite")
	default:
		return errors.New("unknown property \"" + property + "\"")
	}
	return nil
}

func alterProjectAddFund(db *dbx.DB, project, fund string, projectID int32) error {
	// look up fund id
	fundID, err := FundID(db, fund)
	if err != nil {
		return err
	}
	if fundID == 0 {
		return errors.New("fund \"" + fund + "\" does not exist")
	}
	// check if project fund exists
	projectFundExists, err := ProjectFundExists(db, projectID, fundID)
	if err != nil {
		return err
	}
	if projectFundExists {
		return nil
	}
	// add project fund
	sql := "insert into ccms.project_fund (project_id, fund_id) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, projectID, fundID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func alterProjectDropFund(db *dbx.DB, project, fund string, projectID int32) error {
	if fund == "*" {
		sql := "select f.name from ccms.project p join ccms.project_fund pf on p.id=pf.project_id join ccms.fund f on pf.fund_id=f.id where p.name=$1"
		rows, err := db.Query(db.Ctx, sql, project)
		if err != nil {
			return dberr.Error(err)
		}
		funds, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for i := range funds {
			err = alterProjectDropFund(db, project, funds[i], projectID)
			if err != nil {
				return err
			}
		}
		return nil
	}
	// look up fund id
	fundID, err := FundID(db, fund)
	if err != nil {
		return err
	}
	if fundID == 0 {
		return errors.New("fund \"" + fund + "\" does not exist")
	}
	// check if project fund exists
	projectFundExists, err := ProjectFundExists(db, projectID, fundID)
	if err != nil {
		return err
	}
	if !projectFundExists {
		return errors.New("project \"" + project + "\" does not have fund \"" + fund + "\"")
	}
	// ensure fund not being used in object
	objectFundExists, err := objectFundExists(db, project, fundID)
	if err != nil {
		return err
	}
	if objectFundExists {
		return errors.New("fund \"" + fund + "\" is referenced in set \"" + project + ".object\"")
	}
	// drop project fund
	sql := "delete from ccms.project_fund where project_id=$1 and fund_id=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, fundID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

// func alterProjectAddLocation(db *dbx.DB, project, location string, projectID int32) error {
// 	// look up location id
// 	locationID, err := LocationID(d, location)
// 	if err != nil {
// 		return err
// 	}
// 	if locationID == 0 {
// 		return errors.New("location \"" + location + "\" does not exist")
// 	}
// 	// check if project location exists
// 	projectLocationExists, err := projectLocationExists(d, projectID, locationID)
// 	if err != nil {
// 		return err
// 	}
// 	if projectLocationExists {
// 		return nil
// 	}
// 	// add project location
// 	sql := "insert into ccms.project_location (project_id, location_id) values ($1, $2)"
// 	if _, err := db.Exec(db.Ctx, sql, projectID, locationID); err != nil {
// 		return dberr.Error(err)
// 	}
// 	return nil
// }

// func alterProjectDropLocation(db *dbx.DB, project, location string, projectID int32) error {
// 	if location == "*" {
// 		sql := "delete from ccms.project_location where project_id=$1"
// 		if _, err := db.Exec(db.Ctx, sql, projectID); err != nil {
// 			return dberr.Error(err)
// 		}
// 		return nil
// 	}
// 	// look up location id
// 	locationID, err := LocationID(d, location)
// 	if err != nil {
// 		return err
// 	}
// 	if locationID == 0 {
// 		return errors.New("location \"" + location + "\" does not exist")
// 	}
// 	// check if project location exists
// 	projectLocationExists, err := projectLocationExists(d, projectID, locationID)
// 	if err != nil {
// 		return err
// 	}
// 	if !projectLocationExists {
// 		return errors.New("project \"" + project + "\" does not have location \"" + location + "\"")
// 	}
// 	// drop project location
// 	sql := "delete from ccms.project_location where project_id=$1 and location_id=$2"
// 	if _, err := db.Exec(db.Ctx, sql, projectID, locationID); err != nil {
// 		return dberr.Error(err)
// 	}
// 	return nil
// }

func alterProjectAddOrigin(db *dbx.DB, project, origin string, projectID int32) error {
	// look up origin id
	originID, err := LocationID(db, origin)
	if err != nil {
		return err
	}
	if originID == 0 {
		return errors.New("origin \"" + origin + "\" does not exist")
	}
	// check if project origin exists
	projectOriginExists, err := projectOriginExists(db, projectID, originID)
	if err != nil {
		return err
	}
	if projectOriginExists {
		return nil
	}
	// add project origin
	sql := "insert into ccms.project_origin (project_id, origin_id) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, projectID, originID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func alterProjectDropOrigin(db *dbx.DB, project, origin string, projectID int32) error {
	if origin == "*" {
		sql := "delete from ccms.project_origin where project_id=$1"
		if _, err := db.Exec(db.Ctx, sql, projectID); err != nil {
			return dberr.Error(err)
		}
		return nil
	}
	// look up origin id
	originID, err := LocationID(db, origin)
	if err != nil {
		return err
	}
	if originID == 0 {
		return errors.New("origin \"" + origin + "\" does not exist")
	}
	// check if project origin exists
	projectOriginExists, err := projectOriginExists(db, projectID, originID)
	if err != nil {
		return err
	}
	if !projectOriginExists {
		return errors.New("project \"" + project + "\" does not have origin \"" + origin + "\"")
	}
	// drop project origin
	sql := "delete from ccms.project_origin where project_id=$1 and origin_id=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, originID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func alterProjectAddDestination(db *dbx.DB, project, destination string, projectID int32) error {
	// look up location id
	locationID, err := LocationID(db, destination)
	if err != nil {
		return err
	}
	if locationID == 0 {
		return errors.New("location \"" + destination + "\" does not exist")
	}
	// check if project destination exists
	projectDestinationExists, err := projectDestinationExists(db, projectID, locationID)
	if err != nil {
		return err
	}
	if projectDestinationExists {
		return nil
	}
	// add project destination
	sql := "insert into ccms.project_destination (project_id, location_id) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, projectID, locationID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func alterProjectDropDestination(db *dbx.DB, project, destination string, projectID int32) error {
	if destination == "*" {
		sql := "delete from ccms.project_destination where project_id=$1"
		if _, err := db.Exec(db.Ctx, sql, projectID); err != nil {
			return dberr.Error(err)
		}
		return nil
	}
	// look up destination id
	destinationID, err := LocationID(db, destination)
	if err != nil {
		return err
	}
	if destinationID == 0 {
		return errors.New("destination \"" + destination + "\" does not exist")
	}
	// check if project destination exists
	projectDestinationExists, err := projectDestinationExists(db, projectID, destinationID)
	if err != nil {
		return err
	}
	if !projectDestinationExists {
		return errors.New("project \"" + project + "\" does not have destination \"" + destination + "\"")
	}
	// drop project destination
	sql := "delete from ccms.project_destination where project_id=$1 and location_id=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, destinationID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func alterProjectAddTrack(db *dbx.DB, project, track string, projectID int32) error {
	// look up track id
	trackID, err := TrackID(db, track)
	if err != nil {
		return err
	}
	if trackID == 0 {
		return errors.New("track \"" + track + "\" does not exist")
	}
	// check if project track exists
	projectTrackExists, err := projectTrackExists(db, projectID, trackID)
	if err != nil {
		return err
	}
	if projectTrackExists {
		return nil
	}
	// add project track
	sql := "insert into ccms.project_track (project_id, track_id) values ($1, $2)"
	if _, err := db.Exec(db.Ctx, sql, projectID, trackID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

func alterProjectDropTrack(db *dbx.DB, project, track string, projectID int32) error {
	if track == "*" {
		sql := "delete from ccms.project_track where project_id=$1"
		if _, err := db.Exec(db.Ctx, sql, projectID); err != nil {
			return dberr.Error(err)
		}
		return nil
	}
	// look up track id
	trackID, err := TrackID(db, track)
	if err != nil {
		return err
	}
	if trackID == 0 {
		return errors.New("track \"" + track + "\" does not exist")
	}
	// check if project track exists
	projectTrackExists, err := projectTrackExists(db, projectID, trackID)
	if err != nil {
		return err
	}
	if !projectTrackExists {
		return errors.New("project \"" + project + "\" does not have track \"" + track + "\"")
	}
	// drop project track
	sql := "delete from ccms.project_track where project_id=$1 and track_id=$2"
	if _, err := db.Exec(db.Ctx, sql, projectID, trackID); err != nil {
		return dberr.Error(err)
	}
	return nil
}

// returns location ID, or 0 if location does not exist
func LocationID(db *dbx.DB, location string) (int32, error) {
	sql := "select id from ccms.location where name=$1"
	var id int32
	err := db.QueryRow(db.Ctx, sql, location).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, dberr.Error(err)
	default:
		return id, nil
	}
}

// returns origin ID, or 0 if origin does not exist
// func OriginID(db *dbx.DB, origin string) (int32, error) {
// 	var sql = "select id from ccms.origin where name=$1"
// 	var id int32
// 	err := db.QueryRow(db.Ctx, sql, origin).Scan(&id)
// 	switch {
// 	case errors.Is(err, pgx.ErrNoRows):
// 		return 0, nil
// 	case err != nil:
// 		return 0, dberr.Error(err)
// 	default:
// 		return id, nil
// 	}
// }

// returns destination ID, or 0 if destination does not exist
// func DestinationID(db *dbx.DB, destination string) (int32, error) {
// 	sql := "select id from ccms.destination where name=$1"
// 	var id int32
// 	err := db.QueryRow(db.Ctx, sql, destination).Scan(&id)
// 	switch {
// 	case errors.Is(err, pgx.ErrNoRows):
// 		return 0, nil
// 	case err != nil:
// 		return 0, dberr.Error(err)
// 	default:
// 		return id, nil
// 	}
// }

// returns track ID, or 0 if track does not exist
func TrackID(db *dbx.DB, track string) (int32, error) {
	sql := "select id from ccms.track where name=$1"
	var id int32
	err := db.QueryRow(db.Ctx, sql, track).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, dberr.Error(err)
	default:
		return id, nil
	}
}

func ProjectFundExists(db *dbx.DB, projectID, fundID int32) (bool, error) {
	sql := "select 1 from ccms.project_fund where project_id=$1 and fund_id=$2"
	var n int32
	err := db.QueryRow(db.Ctx, sql, projectID, fundID).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func ProjectsHavingFund(db *dbx.DB, fundID int32) ([]string, error) {
	sql := "select p.name from ccms.project_fund pf join ccms.project p on pf.project_id=p.id where pf.fund_id=$1"
	rows, err := db.Query(db.Ctx, sql, fundID)
	if err != nil {
		return nil, dberr.Error(err)
	}
	projects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	return projects, nil
}

func objectFundExists(db *dbx.DB, project string, fundID int32) (bool, error) {
	sql := "select 1 from " + project + ".object where fund_id=$1 limit 1"
	var n int32
	err := db.QueryRow(db.Ctx, sql, fundID).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

// func projectLocationExists(db *dbx.DB, projectID, locationID int64) (bool, error) {
// 	sql := "select 1 from ccms.project_location where project_id=$1 and location_id=$2"
// 	var n int32
// 	err := d.Q.QueryRow(d.C, sql, projectID, locationID).Scan(&n)
// 	switch {
// 	case errors.Is(err, pgx.ErrNoRows):
// 		return false, nil
// 	case err != nil:
// 		return false, dberr.Error(err)
// 	default:
// 		return true, nil
// 	}
// }

func projectOriginExists(db *dbx.DB, projectID, originID int32) (bool, error) {
	sql := "select 1 from ccms.project_origin where project_id=$1 and origin_id=$2"
	var n int32
	err := db.QueryRow(db.Ctx, sql, projectID, originID).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func projectDestinationExists(db *dbx.DB, projectID, destinationID int32) (bool, error) {
	sql := "select 1 from ccms.project_destination where project_id=$1 and location_id=$2"
	var n int32
	err := db.QueryRow(db.Ctx, sql, projectID, destinationID).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func projectTrackExists(db *dbx.DB, projectID, trackID int32) (bool, error) {
	sql := "select 1 from ccms.project_track where project_id=$1 and track_id=$2"
	var n int32
	err := db.QueryRow(db.Ctx, sql, projectID, trackID).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}

func AlterProjectSetProperty(db *dbx.DB, project, property, value string, stringLiteral bool) error {
	switch property {
	case "funds" /*"locations",*/, "origins", "destinations", "tracks":
		return errors.New("property \"" + property + "\" is composite")
	case "title", "mou_link":
		if !stringLiteral {
			return invalidValueError(property, value)
		}
	case "action":
		if stringLiteral {
			return invalidValueError(property, value)
		}
	default:
		return errors.New("property \"" + property + "\" does not exist")
	}

	if property == "action" {
		switch value {
		case "", "acquire", "retire", "digitize", "move", "other":
			// NOP
		default:
			return errors.New("action \"" + value + "\" does not exist")
		}
	}

	sql := "update ccms.project set \"" + property + "\"=$1 where name=$2"
	if _, err := db.Exec(db.Ctx, sql, value, project); err != nil {
		return errors.New("updating project: " + dberr.String(err))
	}
	return nil
}

func ProjectProperties(db *dbx.DB, project string) ([][2]string, error) {
	var title, action, mouLink, funds /*locations,*/, origins, destinations, tracks string
	// loc as (
	//     select p.id project_id,
	//            coalesce(string_agg(l.name||':'||l.title, '|' order by l.name), '') locations
	//         from ccms.project p
	//             join ccms.project_location pl on p.id=pl.project_id
	//             join ccms.location l on pl.location_id=l.id
	//         group by p.id
	// ),
	sql := `with fnd as (
    select p.id project_id,
           coalesce(string_agg(f.name||':'||f.title, '|' order by f.name), '') funds
        from ccms.project p
            join ccms.project_fund pf on p.id=pf.project_id
            join ccms.fund f on pf.fund_id=f.id
        group by p.id
),
org as (
    select p.id project_id,
           coalesce(string_agg(l.name||':'||l.title, '|' order by l.name), '') origins
        from ccms.project p
            join ccms.project_origin pl on p.id=pl.project_id
            join ccms.location l on pl.location_id=l.id
        group by p.id
),
dst as (
    select p.id project_id,
           coalesce(string_agg(l.name||':'||l.title, '|' order by l.name), '') destinations
        from ccms.project p
            join ccms.project_destination pl on p.id=pl.project_id
            join ccms.location l on pl.location_id=l.id
        group by p.id
),
trk as (
    select p.id project_id,
           coalesce(string_agg(t.name||':'||t.title, '|' order by t.name), '') tracks
        from ccms.project p
            join ccms.project_track pl on p.id=pl.project_id
            join ccms.track t on pl.track_id=t.id
        group by p.id
)
select p.title,
       p.action,
       p.mou_link,
       coalesce(fnd.funds, '') funds,
       coalesce(org.origins, '') origins,
       coalesce(dst.destinations, '') destinations,
       coalesce(trk.tracks, '') tracks
       from ccms.project p
           left join fnd on p.id=fnd.project_id
           left join org on p.id=org.project_id
           left join dst on p.id=dst.project_id
           left join trk on p.id=trk.project_id
       where p.name=$1`
	err := db.QueryRow(db.Ctx, sql, project).Scan(&title, &action, &mouLink, &funds /*&locations,*/, &origins, &destinations, &tracks)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, fmt.Errorf("project %q does not exist", project)
	case err != nil:
		return nil, dberr.Error(err)
	default:
	}
	if action != "" {
		action = action + ":" + string(unicode.ToUpper(rune(action[0]))) + action[1:]
	}
	prop := [][2]string{
		{"title", title},
		{"action", action},
		{"mou_link", mouLink},
		{"funds", funds},
		// {"locations", locations},
		{"origins", origins},
		{"destinations", destinations},
		{"tracks", tracks},
	}
	return prop, nil
}

func invalidValueError(property, value string) error {
	return errors.New("invalid value \"" + value + "\" for property \"" + property + "\"")
}
