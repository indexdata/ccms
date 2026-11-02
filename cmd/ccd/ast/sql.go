package ast

import (
	"errors"
	"fmt"
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/attr"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/global"
	"github.com/indexdata/ccms/internal/util"
)

// conversion to SQL

func (s *CreateStmt) SQL(db *dbx.DB, a *strings.Builder) (string, error) {
	switch s.Name {
	case "filter":
		var b strings.Builder
		if err := s.filterSQL(db, a, &b); err != nil {
			return "", err
		}
		return b.String(), nil
	default:
		return "", errors.New("syntax error")
	}
}

func (s *CreateStmt) filterSQL(db *dbx.DB, a, b *strings.Builder) error {
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
	fromProject, fromSet, err := util.ParsePair(s.From)
	if err != nil {
		return err
	}

	fromTable := cat.SetTable(fromProject, fromSet)
	table := dbx.ParseTable(fromTable)

	b.WriteString("delete from ")
	b.WriteString(fromTable)
	w := s.Where.(*WhereClause)
	if w.Valid {
		b.WriteString(" where id in (")
		b.WriteString("select t.id from ")
		b.WriteString(cat.SetTable(fromProject, fromSet))

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
	intoProject, intoSet, err := util.ParsePair(s.Into)
	if err != nil {
		return err
	}

	b.WriteString("insert into ")
	b.WriteString(cat.SetTable(intoProject, intoSet))
	b.WriteString(" select a.id ")
	if err := s.Query.(*QueryClause).sql(db, a, b); err != nil {
		return err
	}
	b.WriteString(" on conflict do nothing")
	return nil
}

func (s *SelectStmt) SQL(db *dbx.DB) (string, []attr.Attr, error) {
	var b strings.Builder
	atts := make([]attr.Attr, 0)
	if err := s.sql(db, new(strings.Builder), &b, &atts); err != nil {
		return "", nil, err
	}
	return b.String(), atts, nil
}

func (s *SelectStmt) sql(db *dbx.DB, a, b *strings.Builder, atts *[]attr.Attr) error {
	var projection strings.Builder
	star := false
	attMap := make(map[string]struct{})
	for i := range s.Projection {
		if i != 0 {
			projection.WriteRune(',')
		}
		switch v := s.Projection[i].(type) {
		case *Star:
			if star {
				return errors.New("\"*\" specified more than once")
			}
			i := 0
			for att := range attr.AllAttrs() {
				if att.Hide {
					break
				}
				_, ok := attMap[att.Name]
				if ok {
					return errors.New("attribute \"" + att.Name + "\" specified more than once")
				}
				if i > 0 {
					projection.WriteRune(',')
				}
				writeAttrCoalesce(&projection, att)
				*atts = append(*atts, att)
				attMap[att.Name] = struct{}{}
				i++
			}
			star = true
		case *CountStar:
			if len(s.Projection) != 1 {
				return errors.New("\"count(*)\" cannot be combined with other expressions")
			}
			projection.WriteString("count(*)")
		case *Name:
			att, ok := attr.AttrName(v.Value)
			if !ok {
				return errors.New("attribute \"" + v.Value + "\" does not exist")
			}
			_, ok = attMap[att.Name]
			if ok {
				return errors.New("attribute \"" + att.Name + "\" specified more than once")
			}
			writeAttrCoalesce(&projection, att)
			*atts = append(*atts, att)
			attMap[att.Name] = struct{}{}
		}
	}
	attMap = nil

	b.WriteString("select ")
	b.WriteString(projection.String())
	b.WriteRune(' ')
	if err := s.Query.(*QueryClause).sql(db, a, b); err != nil {
		return err
	}
	return nil
}

func writeAttrCoalesce(b *strings.Builder, att attr.Attr) {
	switch att.Type {
	case attr.Text, attr.Property:
		b.WriteString("coalesce(")
		b.WriteString(att.Projection)
		b.WriteString(",'')")
	case attr.Boolean:
		b.WriteString("coalesce(")
		b.WriteString(att.Projection)
		b.WriteString(",false)")
	default:
		b.WriteString(att.Projection)
	}
	b.WriteRune(' ')
	b.WriteString(att.Name)
}

func (s *QueryClause) sql(db *dbx.DB, a, b *strings.Builder) error {
	fromProject, fromSet, err := util.ParsePair(s.From)
	if err != nil {
		return err
	}

	fromTable := cat.SetTable(fromProject, fromSet)
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
	b.WriteString(" left join ccms.track on o.track_id=track.id")
	b.WriteString(" left join ccms.md on t.id=md.id")

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

func (u *UpdateStmt) SQL(db *dbx.DB) (string, error) {
	var b strings.Builder
	if err := u.sql(db, new(strings.Builder), &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (u *UpdateStmt) sql(db *dbx.DB, a, b *strings.Builder) error {
	project, set, err := util.ParsePair(u.Set)
	if err != nil {
		return err
	}

	// ensure rows exist before update
	b.WriteString("insert into ")
	b.WriteString(project)
	b.WriteString(".object select a.id from ")
	if set == "object" {
		b.WriteString("ccms.attr")
	} else {
		b.WriteString(cat.SetTable(project, set))
	}
	b.WriteString(" a left join ")
	b.WriteString(project)
	b.WriteString(".object o on a.id=o.id")
	b.WriteString(" left join ccms.fund on o.fund_id=fund.id")
	where := u.Where.(*WhereClause)
	if where.Valid {
		b.WriteString(" where (")
		if err := evalExpr(db, a, b, where.Condition, true, evalState{}); err != nil {
			return err
		}
		b.WriteRune(')')
	}
	b.WriteString(" on conflict (id) do nothing; ")

	// update
	b.WriteString("update ")
	b.WriteString(project)
	b.WriteString(".object oo set ")
	updateSetClauseSQL(b, u.SetClause)
	b.WriteString(" from ")

	b.WriteString(project)
	b.WriteString(".object o left join ")

	if set == "object" {
		b.WriteString("ccms.attr")
	} else {
		b.WriteString(cat.SetTable(project, set))
	}

	b.WriteString(" a on o.id=a.id left join ccms.fund on o.fund_id=fund.id where oo.id=o.id")
	if where.Valid {
		b.WriteString(" and (")
		if err := evalExpr(db, a, b, where.Condition, true, evalState{}); err != nil {
			return err
		}
		b.WriteRune(')')
	}
	b.WriteRune(';')

	return nil
}

func updateSetClauseSQL(b *strings.Builder, setClause []Node) {
	for i := range setClause {
		if i != 0 {
			b.WriteRune(',')
		}
		si := setClause[i].(*SetClause)
		b.WriteString(si.Attr)
		b.WriteRune('=')
		b.WriteString(PrimaryExpr(si.Value))
	}
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
		a.WriteString("not (")
		b.WriteString("not (")
		if err := evalExpr(db, a, b, e.Expr, true, state); err != nil {
			return err
		}
		a.WriteRune(')')
		b.WriteRune(')')
	case *EqualExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		a.WriteString(" = ")
		b.WriteRune('=')
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *IsNullExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		if e.Not {
			a.WriteString(" is not null")
			b.WriteString(" is not null")
		} else {
			a.WriteString(" is null")
			b.WriteString(" is null")
		}
	case *InExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		if e.Not {
			a.WriteString(" not in (")
			b.WriteString(" not in (")
		} else {
			a.WriteString(" in (")
			b.WriteString(" in (")
		}
		if err := evalExprValueList(db, a, b, e.ValueList, state); err != nil {
			return err
		}
		a.WriteRune(')')
		b.WriteRune(')')
	case *LikeExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		if e.Not {
			a.WriteString(" not like ")
			b.WriteString(" not like ")
		} else {
			a.WriteString(" like ")
			b.WriteString(" like ")
		}
		if err := evalExprOptAttr(db, a, b, e.Expr2, state); err != nil {
			return err
		}
	case *ILikeExpr:
		if err := evalExprOptAttr(db, a, b, e.Expr1, state); err != nil {
			return err
		}
		if e.Not {
			a.WriteString(" not ilike ")
			b.WriteString(" not ilike ")
		} else {
			a.WriteString(" ilike ")
			b.WriteString(" ilike ")
		}
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
	case *ParenExpr:
		a.WriteRune('(')
		b.WriteRune('(')
		if err := evalExpr(db, a, b, e.Expr, root, state); err != nil {
			return err
		}
		a.WriteRune(')')
		b.WriteRune(')')
	case *Name:
		att, ok := attr.AttrName(e.Value)
		if !ok {
			return errors.New("attribute \"" + e.Value + "\" does not exist")
		}
		if root && att.Type != attr.Boolean {
			return errors.New("invalid boolean expression")
		}
		v := PrimaryExpr(expr)
		a.WriteString(v)
		b.WriteString(v)
	case *SLiteral:
		if root {
			return errors.New("invalid boolean expression")
		}
		v := PrimaryExpr(expr)
		a.WriteString(v)
		b.WriteString(v)
	case *Number:
		if root {
			return errors.New("invalid boolean expression")
		}
		v := PrimaryExpr(expr)
		a.WriteString(v)
		b.WriteString(v)
	case *Boolean:
		if root {
			return errors.New("invalid boolean expression")
		}
		v := PrimaryExpr(expr)
		a.WriteString(v)
		b.WriteString(v)
	case *Null:
		v := PrimaryExpr(expr)
		a.WriteString(v)
		b.WriteString(v)
	default:
		return fmt.Errorf("unknown node %T", expr)
	}
	return nil
}

func PrimaryExpr(expr Node) string {
	switch e := expr.(type) {
	case *Name:
		return e.Value
	case *Number:
		return e.Value
	case *SLiteral:
		return "'" + global.EncodeString(e.Value) + "'"
	case *Boolean:
		if e.Value {
			return "true"
		} else {
			return "false"
		}
	case *Null:
		return "null"
	default:
		return ""
	}
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
		_, ok := attr.AttrName(e.Value)
		if ok {
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

func evalExprValueList(db *dbx.DB, a, b *strings.Builder, expr []Node, state evalState) error {
	for i := range expr {
		if i != 0 {
			a.WriteString(", ")
			b.WriteRune(',')
		}
		switch e := expr[i].(type) {
		case *Number:
			a.WriteString(e.Value)
			b.WriteString(e.Value)
		case *SLiteral:
			a.WriteRune('\'')
			a.WriteString(e.Value)
			a.WriteRune('\'')
			b.WriteRune('\'')
			b.WriteString(e.Value)
			b.WriteRune('\'')
		case *Name:
			if e.Value == "true" || e.Value == "false" {
				a.WriteString(e.Value)
				b.WriteString(e.Value)
			} else {
				return errors.New("invalid value expression \"" + e.Value + "\"")
			}
		default:
			return errors.New("invalid value expression \"" + fmt.Sprintf("%v", e) + "\"")
		}
	}
	return nil
}

func attrSQL(a, b *strings.Builder, att string) {
	a.WriteString(att)
	switch att {
	case "id", "author", "title", "full_vendor_name", "availability", "library_count", "library_holdings_count", "online_database_holdings_count", "vendor_holdings_count", "holdings_count":
		b.WriteRune('a')
		b.WriteRune('.')
		b.WriteString(att)
	case "decision":
		b.WriteString(att)
	case "fund":
		b.WriteString("fund.name")
	case "track":
		b.WriteString("track.name")
	default:
		b.WriteString(att)
	}
}
