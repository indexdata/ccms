%{
package parser

import (
	"strings"

	"github.com/indexdata/ccms/cmd/ccd/ast"
)

%}

%union{
	node ast.Node
	str string
	nodeList []ast.Node
}

%type <node> top_level_stmt
%type <node> basic_stmt
%type <nodeList> stmt
%type <nodeList> stmt_list
%type <node> alter_stmt
%type <node> create_stmt
%type <node> delete_stmt
%type <node> drop_stmt
%type <node> info_stmt
%type <node> ping_stmt
%type <node> insert_stmt
%type <node> select_stmt
%type <node> show_stmt
%type <node> update_stmt

%type <nodeList> select_attr_list
%type <node> query_clause
%type <node> where_clause
%type <node> order_clause
%type <node> limit_clause
%type <node> offset_clause

%type <node> expression
%type <node> logical_or_expr
%type <node> logical_and_expr
%type <node> equality_expr
%type <node> relational_expr
%type <node> unary_expr
%type <node> postfix_expr
%type <node> paren_expr
%type <node> primary_expr
%type <nodeList> arg_expr_list
%type <nodeList> arg_expr

%type <nodeList> set_clause_list
%type <nodeList> set_clause
%type <nodeList> value_expr_list
%type <nodeList> value_expr

%token GT_OR_EQUAL
%token LT_OR_EQUAL
%token NOT_EQUAL

%token ADD
%token ALL
%token ALTER
%token AND
%token ARCHIVE
%token ARCHIVED
%token ASC
%token BY
%token CASCADE
%token CREATE
%token COUNT
%token DELETE
%token DESC
%token DROP
%token ENCRYPTED
%token FALSE
%token FILTER
%token FROM
%token ILIKE
%token IN
%token INFO
%token INSERT
%token INTO
%token IS
%token LIKE
%token LIMIT
%token NOT
%token NULL
%token OFFSET
%token OR
%token ORDER
%token PASSWORD
%token PROJECTS
%token PROPERTY
%token PING
%token RETRIEVE
%token SELECT
%token SHOW
%token TAG
%token TO
%token TRUE
%token UPDATE
%token VERSION
%token WHERE
%token WITH

%type <str> name

%token <str> IDENT
%token <str> NUMBER
%token <str> SLITERAL

%start main

%%

main:
	top_level_stmt
		{
			yylex.(*lexer).node = $1
		}

top_level_stmt:
	stmt_list
		{
			$$ = &ast.ParseTree{Commands: $1}
		}

stmt_list:
	stmt
		{
			$$ = $1
		}
	| stmt_list ';'
		{
			$$ = $1
		}
	| stmt_list ';' stmt
		{
			$$ = append($1, $3...)
		}

stmt:
	basic_stmt
		{
			$$ = []ast.Node{$1}
		}

basic_stmt:
	alter_stmt
		{
			$$ = $1
		}
	| create_stmt
		{
			$$ = $1
		}
	| delete_stmt
		{
			$$ = $1
		}
	| drop_stmt
		{
			$$ = $1
		}
	| info_stmt
		{
			$$ = $1
		}
	| insert_stmt
		{
			$$ = $1
		}
	| select_stmt
		{
			$$ = $1
		}
	| show_stmt
		{
			$$ = $1
		}
	| update_stmt
		{
			$$ = $1
		}
	| ping_stmt
		{
			$$ = $1
		}

/*
archive_project_stmt:
	ARCHIVE PROJECT name
		{
			$$ = &ast.ArchiveProjectStmt{}
		}
*/

alter_stmt:
	ALTER name name ALTER PROPERTY name name name
		{
			$$ = &ast.AlterStmt{Type: $2, Name: $3, Property: $6, Action: $7, Value: $8}
		}
	| ALTER name name ALTER PROPERTY name DROP name
		{
			$$ = &ast.AlterStmt{Type: $2, Name: $3, Property: $6, Action: "drop", Value: $8}
		}
	| ALTER name name ALTER PROPERTY name name SLITERAL
		{
			$$ = &ast.AlterStmt{Type: $2, Name: $3, Property: $6, Action: $7, Value: ast.DecodeSLiteral($8), StringLiteral: true}
		}
	| ALTER name name ALTER PROPERTY name DROP ALL
		{
			$$ = &ast.AlterStmt{Type: $2, Name: $3, Property: $6, Action: "drop", Value: "*"}
		}

create_stmt:
	CREATE name name where_clause
		{
			$$ = &ast.CreateStmt{Type: $2, Name: $3, Where: $4}
		}
	| CREATE name name WITH ENCRYPTED PASSWORD SLITERAL
		{
			$$ = &ast.CreateStmt{Type: $2, User: $3, EncryptedPassword: ast.DecodeSLiteral($7)}
		}

delete_stmt:
	DELETE FROM name where_clause
		{
			$$ = &ast.DeleteStmt{From: $3, Where: $4}
		}

drop_stmt:
	DROP name name
		{
			$$ = &ast.DropStmt{Type: $2, Name: $3}
		}
	| DROP name name CASCADE
		{
			$$ = &ast.DropStmt{Type: $2, Name: $3, Cascade: true}
		}

info_stmt:
	INFO
		{
			$$ = &ast.InfoStmt{Topic: ""}
		}
	| INFO SLITERAL
		{
			$$ = &ast.InfoStmt{Topic: ast.DecodeSLiteral($2)}
		}

insert_stmt:
	INSERT INTO name SELECT '*' query_clause
		{
			$$ = &ast.InsertStmt{Into: $3, Query: $6}
		}

ping_stmt:
	PING
		{
			$$ = &ast.PingStmt{}
		}

select_stmt:
	SELECT select_attr_list query_clause
		{
			$$ = &ast.SelectStmt{Projection: $2, Query: $3}
		}
	| SELECT VERSION '(' ')'
		{
			$$ = &ast.SelectVersionStmt{}
		}

show_stmt:
	SHOW name
		{
			$$ = &ast.ShowStmt{Type: $2}
		}
	| SHOW name IN name name
		{
			$$ = &ast.ShowStmt{Type: $2, InType: $4, InName: $5}
		}
	| SHOW name name
		{
			$$ = &ast.ShowStmt{Type: $2, Name: $3}
		}
	| SHOW PROJECTS
		{
			$$ = &ast.ShowStmt{Type: "projects"}
		}
	| SHOW VERSION
		{
			$$ = &ast.ShowStmt{Type: "version"}
		}

update_stmt:
	UPDATE name name set_clause_list where_clause
		{
			$$ = &ast.UpdateStmt{Set: $2, Action: $3, SetClause: $4, Where: $5}
		}

set_clause_list:
	set_clause
		{
			$$ = $1
		}
	| set_clause_list ',' set_clause
		{
			$$ = append($1, $3...)
		}

set_clause:
	name '=' primary_expr
		{
			$$ = []ast.Node{&ast.SetClause{Attr: $1, Value: $3}}
		}

select_attr_list:
	arg_expr_list
		{
			// $$ = &ast.SelectAttrList{Attr: $1}
			$$ = $1
		}
	| COUNT '(' '*' ')'
		{
			// $$ = &ast.SelectAttrList{Attr: "count(*)"}
			$$ = []ast.Node{&ast.CountStar{}}
		}

query_clause:
	FROM name where_clause order_clause limit_clause offset_clause
		{
			$$ = &ast.QueryClause{From: $2, Where: $3, Order: $4, Limit: $5, Offset: $6}
		}

where_clause:
	WHERE expression
		{
			$$ = &ast.WhereClause{Valid: true, Condition: $2}
		}
	|
		{
			$$ = &ast.WhereClause{}
		}

order_clause:
	ORDER BY name
		{
			$$ = &ast.OrderClause{Valid: true, Attr: $3, Desc: false}
		}
	| ORDER BY name ASC
		{
			$$ = &ast.OrderClause{Valid: true, Attr: $3, Desc: false}
		}
	| ORDER BY name DESC
		{
			$$ = &ast.OrderClause{Valid: true, Attr: $3, Desc: true}
		}
	|
		{
			$$ = &ast.OrderClause{}
		}

limit_clause:
	LIMIT NUMBER
		{
			$$ = &ast.LimitClause{Valid: true, Count: $2}
		}
	|
		{
			$$ = &ast.LimitClause{}
		}

offset_clause:
	OFFSET NUMBER
		{
			$$ = &ast.OffsetClause{Valid: true, Start: $2}
		}
	|
		{
			$$ = &ast.OffsetClause{}
		}

expression:
	logical_or_expr
		{
			$$ = $1
		}

logical_or_expr:
	logical_and_expr
		{
			$$ = $1
		}
	| logical_or_expr OR logical_and_expr
		{
			$$ = &ast.OrExpr{Expr1: $1, Expr2: $3}
		}

logical_and_expr:
	unary_expr
		{
			$$ = $1
		}
	| logical_and_expr AND unary_expr
		{
			$$ = &ast.AndExpr{Expr1: $1, Expr2: $3}
		}

unary_expr:
	equality_expr
		{
			$$ = $1
		}
	| NOT unary_expr
		{
			$$ = &ast.NotExpr{Expr: $2}
		}

equality_expr:
	relational_expr
		{
			$$ = $1
		}
	| equality_expr '=' relational_expr
		{
			$$ = &ast.EqualExpr{Expr1: $1, Expr2: $3}
		}
	| equality_expr LIKE relational_expr
		{
			$$ = &ast.LikeExpr{Expr1: $1, Expr2: $3}
		}
	| equality_expr NOT LIKE relational_expr
		{
			$$ = &ast.LikeExpr{Expr1: $1, Expr2: $4, Not: true}
		}
	| equality_expr ILIKE relational_expr
		{
			$$ = &ast.ILikeExpr{Expr1: $1, Expr2: $3}
		}
	| equality_expr NOT ILIKE relational_expr
		{
			$$ = &ast.ILikeExpr{Expr1: $1, Expr2: $4, Not: true}
		}
	| equality_expr NOT_EQUAL relational_expr
		{
			$$ = &ast.NotEqualExpr{Expr1: $1, Expr2: $3}
		}
	| equality_expr IN '(' value_expr_list ')'
		{
			$$ = &ast.InExpr{Expr1: $1, ValueList: $4}
		}
	| equality_expr NOT IN '(' value_expr_list ')'
		{
			$$ = &ast.InExpr{Expr1: $1, ValueList: $5, Not: true}
		}
	| equality_expr IS NULL
		{
			$$ = &ast.IsNullExpr{Expr1: $1}
		}
	| equality_expr IS NOT NULL
		{
			$$ = &ast.IsNullExpr{Expr1: $1, Not: true}
		}

value_expr_list:
	value_expr
		{
			$$ = $1
		}
	| value_expr_list ',' value_expr
		{
			$$ = append($1, $3...)
		}

value_expr:
	primary_expr
		{
			$$ = []ast.Node{$1}
		}

relational_expr:
	postfix_expr
		{
			$$ = $1
		}
	| relational_expr '<' postfix_expr
		{
			$$ = &ast.LessThanExpr{Expr1: $1, Expr2: $3}
		}
	| relational_expr '>' postfix_expr
		{
			$$ = &ast.GreaterThanExpr{Expr1: $1, Expr2: $3}
		}
	| relational_expr LT_OR_EQUAL postfix_expr
		{
			$$ = &ast.LessThanOrEqualExpr{Expr1: $1, Expr2: $3}
		}
	| relational_expr GT_OR_EQUAL postfix_expr
		{
			$$ = &ast.GreaterThanOrEqualExpr{Expr1: $1, Expr2: $3}
		}

postfix_expr:
	paren_expr
		{
			$$ = $1
		}
	| FILTER '(' name ')'
		{
			$$ = &ast.FilterExpr{Filter: $3}
		}
	| TAG '(' name ')'
		{
			$$ = &ast.TagExpr{Tag: $3}
		}

paren_expr:
	primary_expr
		{
			$$ = $1
		}
	| '(' expression ')'
		{
			$$ = &ast.ParenExpr{Expr: $2}
		}

primary_expr:
	name
		{
			$$ = &ast.Name{Value: $1}
		}
	| SLITERAL
		{
			$$ = &ast.SLiteral{Value: ast.DecodeSLiteral($1)}
		}
	| NUMBER
		{
			$$ = &ast.Number{Value: $1}
		}
	| TRUE
		{
			$$ = &ast.Boolean{Value: true}
		}
	| FALSE
		{
			$$ = &ast.Boolean{}
		}
	| NULL
		{
			$$ = &ast.Null{}
		}

arg_expr_list:
	arg_expr
		{
			$$ = $1
		}
	| arg_expr_list ',' arg_expr
		{
			$$ = append($1, $3...)
		}

arg_expr:
	name
		{
			$$ = []ast.Node{&ast.Name{Value: $1}}
		}
	| '*'
		{
			// $$ = &ast.SelectAttrList{Attr: "*"}
			$$ = []ast.Node{&ast.Star{}}
		}

name:
	IDENT
		{
			$$ = strings.ToLower($1)
		}
