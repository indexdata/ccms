package ast

import (
	"errors"
	"fmt"
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/global"
	"github.com/indexdata/ccms/internal/set"
)

// conversion to SQL

func (s *CreateFilterStmt) SQL(db *dbx.DB, a *strings.Builder) (string, error) {
	var b strings.Builder
	if err := s.sql(db, a, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (s *CreateFilterStmt) sql(db *dbx.DB, a, b *strings.Builder) error {
	w := s.Where.(*WhereClause)
	if w.Valid {
		if err := evalExpr(db, a, b, w.Condition, true, evalState{filter: true}); err != nil {
			return err
		}
	}
	return nil
}

func (s *DeleteStmt) SQL(db *dbx.DB) (string, error) {
	var b strings.Builder
	if err := s.sql(db, new(strings.Builder), &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (s *DeleteStmt) sql(db *dbx.DB, a, b *strings.Builder) error {
	fromSet := set.Parse(s.From)

	fromTable := cat.SetTable(fromSet)
	table := dbx.ParseTable(fromTable)

	b.WriteString("delete from ")
	b.WriteString(fromTable)
	w := s.Where.(*WhereClause)
	if w.Valid {
		b.WriteString(" where id in (")
		b.WriteString("select t.id from ")
		b.WriteString(cat.SetTable(fromSet))

		b.WriteString(" t join ccms.attr a on t.id=a.id")

		b.WriteString(" left join " + table.Schema + ".object o on t.id=o.id")
		b.WriteString(" left join ccms.fund on o.fund_id=fund.id")

		b.WriteString(" where (")
		if err := evalExpr(db, a, b, w.Condition, true, evalState{}); err != nil {
			return err
		}
		b.WriteRune(')')

		b.WriteRune(')')
	}
	return nil
}

func (s *InsertStmt) SQL(db *dbx.DB) (string, error) {
	var b strings.Builder
	if err := s.sql(db, new(strings.Builder), &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (s *InsertStmt) sql(db *dbx.DB, a, b *strings.Builder) error {
	intoSet := set.Parse(s.Into)

	b.WriteString("insert into ")
	b.WriteString(cat.SetTable(intoSet))
	b.WriteString(" select a.id ")
	if err := s.Query.(*QueryClause).sql(db, a, b); err != nil {
		return err
	}
	b.WriteString(" on conflict do nothing")
	return nil
}

func (s *SelectStmt) SQL(db *dbx.DB) (string, error) {
	var b strings.Builder
	if err := s.sql(db, new(strings.Builder), &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (s *SelectStmt) sql(db *dbx.DB, a, b *strings.Builder) error {
	var projection string
	switch s.AttrList.(*SelectAttrList).Attr {
	case "*":
		// projection = "a.id, coalesce(a.author, '') as author, coalesce(a.title, '') as title, coalesce(a.full_vendor_name, '') as full_vendor_name, coalesce(a.availability, '') as availability, coalesce(fund.name, '') fund"
		projection = "a.id, a.author, a.title, a.full_vendor_name, a.availability, o.decision, fund.name||':'||fund.title fund"
	case "count(*)":
		projection = "count(*)"
	}

	b.WriteString("select ")
	b.WriteString(projection)
	b.WriteRune(' ')
	if err := s.Query.(*QueryClause).sql(db, a, b); err != nil {
		return err
	}
	return nil
}

func (s *QueryClause) sql(db *dbx.DB, a, b *strings.Builder) error {
	fromSet := set.Parse(s.From)

	fromTable := cat.SetTable(fromSet)
	table := dbx.ParseTable(fromTable)

	b.WriteString("from ")
	if table.Table == "object" {
		b.WriteString("ccms.reserve")
	} else {
		b.WriteString(fromTable)
	}
	b.WriteString(" t join ccms.attr a on t.id=a.id")

	b.WriteString(" left join " + table.Schema + ".object o on t.id=o.id")
	b.WriteString(" left join ccms.fund on o.fund_id=fund.id")

	w := s.Where.(*WhereClause)
	if w.Valid {
		b.WriteString(" where (")
		if err := evalExpr(db, a, b, w.Condition, true, evalState{}); err != nil {
			return err
		}
		b.WriteRune(')')
	}
	o := s.Order.(*OrderClause)
	if o.Valid {
		b.WriteString(" order by ")
		b.WriteString(o.Attr)
		if o.Desc {
			b.WriteString(" desc")
		}
	}
	if s.Limit.(*LimitClause).Valid {
		b.WriteString(" limit ")
		b.WriteString(s.Limit.(*LimitClause).Count)
	}
	if s.Offset.(*OffsetClause).Valid {
		b.WriteString(" offset ")
		b.WriteString(s.Offset.(*OffsetClause).Start)
	}
	return nil
}

func (u *UpdateStmt) SQL() (string, error) {
	var b strings.Builder
	if err := u.sql(&b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (u *UpdateStmt) sql(b *strings.Builder) error {
	if u.ValueNull {
		b.WriteString("update ")
		b.WriteString(u.Set)
		b.WriteString(" set ")
		b.WriteString(u.Attr)
		b.WriteString("=null where id=")
		b.WriteString(u.IDValue.Value)
	} else {
		b.WriteString("insert into ")
		b.WriteString(u.Set)
		b.WriteString(" (id, ")
		b.WriteString(u.Attr)
		b.WriteString(") values (")
		b.WriteString(u.IDValue.Value)
		b.WriteString(", ")
		b.WriteString(u.Value)
		b.WriteString(")")
		b.WriteString(" on conflict (id) do update set ")
		b.WriteString(u.Attr)
		b.WriteRune('=')
		b.WriteString(u.Value)
	}
	return nil
}

type evalState struct {
	filter bool
}

func evalExpr(db *dbx.DB, a, b *strings.Builder, expr Node, root bool, state evalState) error {
	switch e := expr.(type) {
	case *OrExpr:
		if err := evalExpr(db, a, b, e.Expr1, false, state); err != nil {
			return err
		}
		a.WriteString(" or ")
		b.WriteString(" or ")
		if err := evalExpr(db, a, b, e.Expr2, false, state); err != nil {
			return err
		}
	case *AndExpr:
		if err := evalExpr(db, a, b, e.Expr1, false, state); err != nil {
			return err
		}
		a.WriteString(" and ")
		b.WriteString(" and ")
		if err := evalExpr(db, a, b, e.Expr2, false, state); err != nil {
			return err
		}
	case *NotExpr:
		a.WriteString("not ")
		b.WriteString("not ")
		if err := evalExpr(db, a, b, e.Expr, false, state); err != nil {
			return err
		}
	case *EqualExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" = ")
		b.WriteRune('=')
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *LikeExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" like ")
		b.WriteString(" like ")
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *ILikeExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" ilike ")
		b.WriteString(" ilike ")
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *NotEqualExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" <> ")
		b.WriteString("<>")
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *LessThanExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" < ")
		b.WriteRune('<')
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *GreaterThanExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" > ")
		b.WriteRune('>')
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *LessThanOrEqualExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" <= ")
		b.WriteString("<=")
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *GreaterThanOrEqualExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" >= ")
		b.WriteString(">=")
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *FilterExpr:
		if state.filter {
			return errors.New("filter() cannot be used in filter definition")
		}

		a.WriteString("filter(")
		a.WriteString(e.Filter)
		a.WriteRune(')')

		b.WriteRune('(')

		// b.WriteString(e.Filter)
		// if err := evalExprList(b, e.ExprList); err != nil {
		// 	return err
		// }

		f, err := cat.FilterSQL(db, e.Filter)
		if err != nil {
			return err
		}
		b.WriteString(f)

		b.WriteRune(')')
	case *TagExpr:
		return fmt.Errorf("tag() is not yet supported")
		//b.WriteString("TAG(")
		//if err := evalExprList(b, e.ExprList); err != nil {
		//        return err
		//}
		//b.WriteRune(')')
	case *Name:
		if root {
			return errors.New("invalid boolean expression")
		}
		a.WriteString(e.Value)
		b.WriteString(e.Value)
	case *SLiteral:
		if root {
			return errors.New("invalid boolean expression")
		}
		a.WriteRune('\'')
		a.WriteString(global.EncodeString(e.Value))
		a.WriteRune('\'')
		b.WriteRune('\'')
		b.WriteString(global.EncodeString(e.Value))
		b.WriteRune('\'')
	case *Number:
		if root {
			return errors.New("invalid boolean expression")
		}
		a.WriteString(e.Value)
		b.WriteString(e.Value)
	case *ParenExpr:
		a.WriteRune('(')
		b.WriteRune('(')
		if err := evalExpr(db, a, b, e.Expr, root, state); err != nil {
			return err
		}
		a.WriteRune(')')
		b.WriteRune(')')
	default:
		return fmt.Errorf("unknown node %T", expr)
	}
	return nil
}

func evalExprList(db *dbx.DB, a, b *strings.Builder, exprList []Node, state evalState) error {
	for i := range exprList {
		if i != 0 {
			a.WriteString(", ")
			b.WriteRune(',')
		}
		if err := evalExpr(db, a, b, exprList[i], false, state); err != nil {
			return err
		}
	}
	return nil
}

// evaluate expr which may optionally be an attribute
// if expr is of type Name, require that it be a valid attribute name
func evalExprOptAttr(db *dbx.DB, a, b *strings.Builder, expr Node, state evalState) error {
	switch e := expr.(type) {
	case *Name:
		if cat.IsAttribute(e.Value) {
			attrSQL(a, b, e.Value)
		} else {
			if e.Value == "true" || e.Value == "false" {
				a.WriteString(e.Value)
				b.WriteString(e.Value)
			} else {
				a.WriteString(e.Value)
				b.WriteRune('\'')
				b.WriteString(e.Value)
				b.WriteRune('\'')
				// return errors.New("attribute \"" + e.Value + "\" does not exist")
			}
		}
	default:
		if err := evalExpr(db, a, b, expr, false, state); err != nil {
			return err
		}
	}
	return nil
}

func attrSQL(a, b *strings.Builder, attr string) {
	a.WriteString(attr)
	switch attr {
	case "id", "author", "title", "full_vendor_name", "availability":
		b.WriteRune('a')
		b.WriteRune('.')
		b.WriteString(attr)
	case "decision":
		b.WriteString("coalesce(")
		b.WriteRune('o')
		b.WriteRune('.')
		b.WriteString(attr)
		b.WriteString(",false)")
	case "fund":
		b.WriteString("coalesce(fund.name,'')")
	default:
		b.WriteString(attr)
	}
}
