package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/catalog"
)

func selectStmt(s *svr, rqid int64, cmd *ast.SelectStmt) *ccms.Result {

	f := cmd.Query.(*ast.QueryClause).Offset.(*ast.OffsetClause)
	if f.Valid {
		o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
		if !o.Valid {
			return cmderr("\"order by\" is required when \"offset\" is used")
		}
	}

	a := cmd.AttrList.(*ast.SelectAttrList)
	if a.Attr != "*" {
		return cmderr("selecting attributes is not yet supported; use \"select *\"")
	}

	if err := processQuery(s, rqid, cmd.Query.(*ast.QueryClause)); err != nil {
		return cmderr(err.Error())
	}

	o := cmd.Query.(*ast.QueryClause).Order.(*ast.OrderClause)
	if o.Valid {
		if !catalog.IsAttr(o.Attr) {
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
		maxlim := 100
		if lim > maxlim {
			return cmderr("limit currently must be no more than " + strconv.Itoa(maxlim))
		}
	} else {
		return cmderr("\"select\" statement requires a \"limit\" clause")
	}

	sql, err := cmd.SQL()
	if err != nil {
		return cmderr(err.Error())
	}
	//log.Info("[%d] %s", rqid, sql)
	rows, err := s.dp.Query(context.TODO(), sql)
	if err != nil {
		fmt.Println(sql)
		panic(fmt.Sprintf("selecting from reserve: %v", err))
	}
	defer rows.Close()
	result := ccms.NewResult("select")
	result.AddField("id", "bigint")
	result.AddField("author", "text")
	result.AddField("title", "text")
	result.AddField("full_vendor_name", "text")
	result.AddField("availability", "text")
	for rows.Next() {
		var id int64
		var author, title, full_vendor_name, availability string
		err = rows.Scan(&id, &author, &title, &full_vendor_name, &availability)
		if err != nil {
			panic(fmt.Sprintf("reading from reserve: %v", err))
		}
		result.AddData([]any{id, author, title, full_vendor_name, availability})
	}
	if err = rows.Err(); err != nil {
		panic(fmt.Sprintf("reading from reserve: %v", err))
	}
	return result
}

func processQuery(s *svr, rqid int64, query *ast.QueryClause) error {
	if !s.cat.SetExists(query.From) {
		return errors.New("set \"" + query.From + "\" does not exist")
	}

	return nil
}
