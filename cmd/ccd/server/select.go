package server

import (
	"errors"
	"strconv"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/global"
	"github.com/indexdata/ccms/internal/set"
	"github.com/jackc/pgx/v5/pgtype/zeronull"
)

func selectVersionStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.SelectVersionStmt) *ccms.Result {
	result := ccms.NewResult("select")
	result.AddField("version", "text")
	result.AddData([]any{"CCMS " + global.Version})
	return result
}

func selectStmt(s *svr, db *dbx.DB, rqid int64, cmd *ast.SelectStmt) *ccms.Result {

	f := cmd.Query.(*ast.QueryClause).Offset.(*ast.OffsetClause)
	if f.Valid {
		o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
		if !o.Valid {
			return cmderr("\"order by\" is required when \"offset\" is used")
		}
	}

	a := cmd.AttrList.(*ast.SelectAttrList)
	if a.Attr != "*" && a.Attr != "count(*)" {
		return cmderr("selecting attributes is not yet supported")
	}

	from := cmd.Query.(*ast.QueryClause).From
	fromSet := set.Parse(from)
	projectID, err := cat.ProjectID(db, fromSet.Project)
	if err != nil {
		return cmderr("checking if project exists: " + err.Error())
	}
	if projectID == 0 {
		return cmderr("project \"" + fromSet.Project + "\" does not exist")
	}
	setExists, err := cat.SetExists(db, fromSet)
	if err != nil {
		return cmderr("checking if set exists: " + err.Error())
	}
	if !setExists {
		return cmderr("set \"" + from + "\" does not exist")
	}

	o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
	if o.Valid {
		if !cat.IsAttribute(o.Attr) {
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

	sql, err := cmd.SQL(db)
	if err != nil {
		return cmderr(err.Error())
	}

	switch a.Attr {
	case "*":
		result, err := runQuery(s, db, sql)
		if err != nil {
			return cmderr(err.Error())
		}
		return result
	case "count(*)":
		result, err := runQueryCount(s, db, sql)
		if err != nil {
			return cmderr(err.Error())
		}
		return result
	default:
		return cmderr(internalError + "invalid projection in select")
	}
}

func runQueryCount(s *svr, db *dbx.DB, sql string) (*ccms.Result, error) {
	var count int64
	if err := db.QueryRow(db.Ctx, sql).Scan(&count); err != nil {
		return nil, errors.New(internalError + err.Error())
	}
	result := ccms.NewResult("select")
	result.AddField("count", "bigint")
	result.AddData([]any{count})
	return result, nil
}

func runQuery(s *svr, db *dbx.DB, sql string) (*ccms.Result, error) {
	rows, err := db.Query(db.Ctx, sql)
	if err != nil {
		return nil, errors.New(internalError + err.Error())
	}
	defer rows.Close()
	result := ccms.NewResult("select")
	result.AddField("id", "bigint")
	result.AddField("author", "text")
	result.AddField("title", "text")
	result.AddField("full_vendor_name", "text")
	result.AddField("availability", "text")
	result.AddField("holdings_count", "smallint")
	result.AddField("decision", "boolean")
	result.AddField("fund", "text")
	var count int
	for rows.Next() {
		var id int64
		var author, title, full_vendor_name, availability, fund zeronull.Text
		var holdingsCount int16
		var decisionNull *bool
		err = rows.Scan(&id, &author, &title, &full_vendor_name, &availability, &holdingsCount, &decisionNull, &fund)
		if err != nil {
			return nil, errors.New(internalError + err.Error())
		}
		var decision bool
		if decisionNull != nil {
			decision = *decisionNull
		}
		result.AddData([]any{id, author, title, full_vendor_name, availability, holdingsCount, decision, fund})
		count++
		if count > 10000 {
			return nil, errors.New("result set too large")
		}
	}
	if err = rows.Err(); err != nil {
		return nil, errors.New(internalError + err.Error())
	}
	return result, nil
}
