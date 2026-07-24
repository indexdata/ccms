package server

import (
	"strings"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/pair"
)

func createFilterStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.CreateFilterStmt) *ccms.Result {
	filter := pair.Parse(cmd.Filter)

	filterExists, err := cat.FilterExists(db, filter)
	if err != nil {
		return cmderr(err.Error())
	}
	if filterExists {
		return cmderr("filter \"" + cmd.Filter + "\" already exists")
	}

	// is target filter valid?
	if filter.First == "" || filter.Second == "" {
		return cmderr("invalid filter name \"" + cmd.Filter + "\"")
	}
	projectID, err := cat.ProjectID(db, filter.First)
	if err != nil {
		return cmderr(err.Error())
	}
	if projectID == 0 {
		return cmderr("invalid filter name \"" + cmd.Filter +
			"\" (project \"" + filter.First + "\" does not exist)")
	}

	if !cmd.Where.(*ast.WhereClause).Valid {
		return cmderr("required \"where\" clause is missing")
	}

	var cmdsql strings.Builder
	cmdsql.WriteString("create filter ")
	cmdsql.WriteString(cmd.Filter)
	cmdsql.WriteString(" where ")

	sql, err := cmd.SQL(db, &cmdsql)
	if err != nil {
		return cmderr(err.Error())
	}

	if err := cat.CreateFilter(db, projectID, filter.Second, cmdsql.String(), sql); err != nil {
		return cmderr(err.Error())
	}
	return ccms.NewResult("create filter")
}
