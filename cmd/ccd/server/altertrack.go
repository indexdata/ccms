package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
)

func alterTrackStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.AlterStmt) *ccms.Result {
	trackID, err := cat.TrackID(db, cmd.Name)
	if err != nil {
		return cmderr(err.Error())
	}
	if trackID == 0 {
		return cmderr("track \"" + cmd.Name + "\" does not exist")
	}

	switch cmd.Action {
	case "set":
		if err := cat.AlterTrackSetProperty(db, cmd.Name, cmd.Property, cmd.Value, cmd.StringLiteral); err != nil {
			return cmderr(err.Error())
		}
	default:
		return cmderr("unknown action in alter track")
	}

	return ccms.NewResult("alter track")
}
