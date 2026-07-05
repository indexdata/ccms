package server

import (
	"errors"
	"strconv"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/set"
	"github.com/jackc/pgx/v5"
)

func updateStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.UpdateStmt) *ccms.Result {
	set := set.Parse(cmd.Set)

	if set.Set != "object" {
		return cmderr("set \"" + cmd.Set + "\" is not valid for update")
	}
	projectID, err := cat.ProjectID(db, set.Project)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}

	if projectID == 0 {
		return cmderr("project \"" + set.Project + "\" does not exist")
	}

	if cmd.IDAttr != "id" {
		return cmderr("attribute \"" + cmd.IDAttr + "\" is not valid with update")
	}

	idInt, _ := strconv.ParseInt(cmd.IDValue.Value, 10, 64)
	idExists, err := objectIDExists(db, idInt)
	if err != nil {
		return cmderr("checking if object ID exists: " + err.Error())
	}
	if !idExists {
		return cmderr("object id = " + cmd.IDValue.Value + " does not exist")
	}

	switch cmd.Attr {
	case "decision":
		if cmd.ValueNull {
			return cmderr("invalid decision \"null\"")
		}
		if cmd.Value != "false" && cmd.Value != "true" {
			return cmderr("invalid decision \"" + cmd.Value + "\"")
		}
	case "fund":
		cmd.Attr = "fund_id"
		if !cmd.ValueNull {
			// look up fund id
			var fundID int32
			fundID, err = cat.FundID(db, cmd.Value)
			if err != nil {
				return cmderr("looking up fund: " + err.Error())
			}
			if fundID == 0 {
				return cmderr("fund \"" + cmd.Value + "\" does not exist")
			}
			// ensure fund is valid for project
			var inProject bool
			inProject, err = cat.ProjectFundExists(db, projectID, fundID)
			if err != nil {
				return cmderr("looking up project fund: " + err.Error())
			}
			if !inProject {
				return cmderr("fund \"" + cmd.Value + "\" is not selected for project")
			}
			cmd.Value = strconv.FormatInt(int64(fundID), 10)
		}
	default:
		return cmderr("attribute \"" + cmd.Attr + "\" is not valid for update")
	}

	sql, err := cmd.SQL()
	if err != nil {
		return cmderr(err.Error())
	}
	if _, err := db.Exec(db.Ctx, sql); err != nil {
		return cmderr("executing update: " + err.Error())
	}

	return ccms.NewResult("update")
}

func objectIDExists(db *dbx.DB, id int64) (bool, error) {
	var q = "select 1 from ccms.reserve where id=$1"
	var n int32
	err := db.QueryRow(db.Ctx, q, id).Scan(&n)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false, nil
	case err != nil:
		return false, dberr.Error(err)
	default:
		return true, nil
	}
}
