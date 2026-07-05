package ast

import "strings"

type AlterAction int

const (
	Set AlterAction = iota
	Add
	Drop
)

/* statements */

type AlterFundStmt struct {
	Fund          string
	Property      string
	Action        AlterAction
	Value         string
	StringLiteral bool
}

func (*AlterFundStmt) node() {}

type AlterProjectStmt struct {
	Project       string
	Property      string
	Action        AlterAction
	Value         string
	StringLiteral bool
}

func (*AlterProjectStmt) node() {}

type ArchiveProjectStmt struct {
}

func (*ArchiveProjectStmt) node() {}

type CreateFilterStmt struct {
	Filter string
	Where  Node
}

func (*CreateFilterStmt) node() {}

type CreateFundStmt struct {
	Fund string
}

func (*CreateFundStmt) node() {}

type CreateProjectStmt struct {
	Project string
}

func (*CreateProjectStmt) node() {}

type CreateSetStmt struct {
	Set string
}

func (*CreateSetStmt) node() {}

type CreateUserStmt struct {
	User              string
	EncryptedPassword string
}

func (*CreateUserStmt) node() {}

type DeleteStmt struct {
	From  string
	Where Node
}

func (*DeleteStmt) node() {}

type DropFundStmt struct {
	Fund string
}

func (*DropFundStmt) node() {}

type DropProjectStmt struct {
	Project string
}

func (*DropProjectStmt) node() {}

type DropSetStmt struct {
	Set string
}

func (*DropSetStmt) node() {}

type InfoStmt struct {
	Topic string
}

func (*InfoStmt) node() {}

type InsertStmt struct {
	Into  string
	Query Node
}

func (*InsertStmt) node() {}

type PingStmt struct {
}

func (*PingStmt) node() {}

type SelectStmt struct {
	AttrList Node
	Query    Node
}

func (*SelectStmt) node() {}

type SelectVersionStmt struct {
	AttrList Node
	Query    Node
}

func (*SelectVersionStmt) node() {}

type ShowStmt struct {
	Type string
	Name string
	In   string
}

func (*ShowStmt) node() {}

/* select clauses */

type SelectAttrList struct {
	Attr string
}

func (*SelectAttrList) node() {}

type QueryClause struct {
	From   string
	Where  Node
	Order  Node
	Limit  Node
	Offset Node
}

func (*QueryClause) node() {}

type UpdateStmt struct {
	Set           string
	Attr          string
	ValueNull     bool
	Value         string
	StringLiteral bool
	IDAttr        string
	IDValue       *Number
}

func (*UpdateStmt) node() {}

type WhereClause struct {
	Valid     bool
	Condition Node
}

func (*WhereClause) node() {}

type OrderClause struct {
	Valid bool
	Attr  string
	Desc  bool
}

func (*OrderClause) node() {}

type LimitClause struct {
	Valid bool
	Count string
}

func (*LimitClause) node() {}

type OffsetClause struct {
	Valid bool
	Start string
}

func (*OffsetClause) node() {}

/* expressions */

type OrExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*OrExpr) node() {}

type AndExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*AndExpr) node() {}

type EqualExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*EqualExpr) node() {}

type LikeExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*LikeExpr) node() {}

type ILikeExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*ILikeExpr) node() {}

type NotEqualExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*NotEqualExpr) node() {}

type LessThanExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*LessThanExpr) node() {}

type GreaterThanExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*GreaterThanExpr) node() {}

type LessThanOrEqualExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*LessThanOrEqualExpr) node() {}

type GreaterThanOrEqualExpr struct {
	Expr1 Node
	Expr2 Node
}

func (*GreaterThanOrEqualExpr) node() {}

type NotExpr struct {
	Expr Node
}

func (*NotExpr) node() {}

type FilterExpr struct {
	Filter string
}

func (*FilterExpr) node() {}

type TagExpr struct {
	ExprList []Node
}

func (*TagExpr) node() {}

type ArgExprList []Node

func (*ArgExprList) node() {}

type ParenExpr struct {
	Expr Node
}

func (*ParenExpr) node() {}

type Name struct {
	Value string
}

func (*Name) node() {}

type SLiteral struct {
	Value string
}

func (*SLiteral) node() {}

type Number struct {
	Value string
}

func (*Number) node() {}

type Option struct {
	Action string
	Name   string
	Val    string
}

type ParseTree struct {
	Commands []Node
}

func (*ParseTree) node() {}

type Node interface {
	node()
}

func DecodeSLiteral(s string) string {
	return strings.ReplaceAll(s, "''", "'")
}
