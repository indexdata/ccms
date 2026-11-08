package server

import (
	"errors"
	"strconv"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/attr"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dberr"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/util"
)

func selectVersionStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.SelectVersionStmt) *ccms.Result {
	return cmderr("\"select version()\" is no longer supported; use \"show version\"")
}

func selectStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.SelectStmt) *ccms.Result {

	f := cmd.Query.(*ast.QueryClause).Offset.(*ast.OffsetClause)
	if f.Valid {
		o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
		if !o.Valid {
			return cmderr("\"order by\" is required when \"offset\" is used")
		}
	}

	from := cmd.Query.(*ast.QueryClause).From
	fromProject, fromSet, err := util.ParsePair(from)
	if err != nil {
		return cmderr(err.Error())
	}
	projectID, err := cat.ProjectID(db, fromProject)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + fromProject + "\" does not exist")
	}
	setExists, err := cat.SetExists(db, fromProject, fromSet)
	if err != nil {
		return cmderr("checking if set exists: " + err.Error())
	}
	if !setExists {
		return cmderr("set \"" + from + "\" does not exist")
	}

	o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
	if o.Valid {
		_, ok := attr.AttrName(o.Attr)
		if !ok {
			return cmderr("attribute \"" + o.Attr + "\" does not exist")
		}
	}

	q := cmd.Query.(*ast.QueryClause)
	l := q.Limit.(*ast.LimitClause)
	if l.Valid {
		lim, _ := strconv.Atoi(l.Count)
		if lim < 0 {
			return cmderr("limit must not be negative")
		}
	}

	var filter string
	if fromSet == "object" {
		filter, err = cat.ProjectFilter(db, fromProject)
		if err != nil {
			return cmderr(err.Error())
		}
	}

	sql, atts, err := cmd.SQL(db, filter)
	if err != nil {
		return cmderr(err.Error())
	}
	switch cmd.Projection[0].(type) {
	case *ast.CountStar:
		result, err := runQueryCount(s, db, sql)
		if err != nil {
			return cmderr(err.Error())
		}
		return result
	case *ast.Name, *ast.Star:
		result, err := runQuery(s, db, sql, atts)
		if err != nil {
			return cmderr(err.Error())
		}
		return result
	default:
		return cmderr("invalid projection in select")
	}
}

func runQueryCount(s *svr, db *dbx.DB, sql string) (*ccms.Result, error) {
	var count int64
	if err := db.QueryRow(db.Ctx, sql).Scan(&count); err != nil {
		return nil, dberr.Error(err)
	}
	result := ccms.NewResult("select")
	result.AddField("count", "bigint")
	result.AddData([]any{count})
	return result, nil
}

func runQuery(s *svr, db *dbx.DB, sql string, atts []attr.Attr) (*ccms.Result, error) {
	rows, err := db.Query(db.Ctx, sql)
	if err != nil {
		return nil, dberr.Error(err)
	}
	defer rows.Close()
	result := ccms.NewResult("select")
	for i := range atts {
		result.AddField(atts[i].Name, atts[i].SQLType)
	}
	var count int
	for rows.Next() {
		numCols := len(atts)
		dest := make([]any, numCols)
		vals := make([]any, numCols)
		for i := range dest {
			dest[i] = &(vals[i])
		}
		if err = rows.Scan(dest...); err != nil {
			return nil, err
		}
		if err != nil {
			return nil, dberr.Error(err)
		}
		result.AddData(vals)
		count++
		if count > 10000 {
			return nil, errors.New("result set too large")
		}
	}
	if err = rows.Err(); err != nil {
		return nil, dberr.Error(err)
	}
	return result, nil
}
