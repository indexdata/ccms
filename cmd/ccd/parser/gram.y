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
%type <node> alter_fund_stmt
%type <node> alter_project_stmt
%type <node> archive_project_stmt
%type <node> create_filter_stmt
%type <node> create_fund_stmt
%type <node> create_project_stmt
%type <node> create_set_stmt
%type <node> create_user_stmt
%type <node> delete_stmt
%type <node> drop_fund_stmt
%type <node> drop_project_stmt
%type <node> drop_set_stmt
%type <node> info_stmt
%type <node> ping_stmt
%type <node> insert_stmt
%type <node> select_stmt
%type <node> show_stmt
%type <node> update_stmt

%type <node> select_attr_list
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
%type <node> primary_expr
%type <nodeList> arg_expr_list
%type <nodeList> arg_expr

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
%token CREATE
%token COUNT
%token DELETE
%token DESC
%token DROP
%token ENCRYPTED
%token FILTER
%token FROM
%token FUND
%token ILIKE
%token IN
%token INFO
%token INSERT
%token INTO
%token LIKE
%token LIMIT
%token NOT
%token NULL
%token OFFSET
%token OR
%token ORDER
%token PASSWORD
%token PROJECT
%token PROJECTS
%token PROPERTY
%token PING
%token RETRIEVE
%token SELECT
%token SET
%token SHOW
%token TAG
%token TO
%token UPDATE
%token USER
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
	| stmt_list stmt
		{
			$$ = append($1, $2...)
		}

stmt:
	basic_stmt
		{
			$$ = []ast.Node{$1}
		}

basic_stmt:
	alter_fund_stmt
		{
			$$ = $1
		}
	| alter_project_stmt
		{
			$$ = $1
		}
	| archive_project_stmt
		{
			$$ = $1
		}
	| create_filter_stmt
		{
			$$ = $1
		}
	| create_fund_stmt
		{
			$$ = $1
		}
	| create_project_stmt
		{
			$$ = $1
		}
	| create_set_stmt
		{
			$$ = $1
		}
	| create_user_stmt
		{
			$$ = $1
		}
	| delete_stmt
		{
			$$ = $1
		}
	| drop_fund_stmt
		{
			$$ = $1
		}
	| drop_project_stmt
		{
			$$ = $1
		}
	| drop_set_stmt
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
	| ';'
		{
			$$ = nil
		}

archive_project_stmt:
	ARCHIVE PROJECT name ';'
		{
			$$ = &ast.ArchiveProjectStmt{Project: $3}
		}

alter_fund_stmt:
	ALTER FUND name ALTER PROPERTY name SET name ';'
		{
			$$ = &ast.AlterFundStmt{Fund: $3, Property: $6, Action: ast.Set, Value: $8, StringLiteral: false}
		}
	| ALTER FUND name ALTER PROPERTY name SET SLITERAL ';'
		{
			$$ = &ast.AlterFundStmt{Fund: $3, Property: $6, Action: ast.Set, Value: ast.DecodeSLiteral($8), StringLiteral: true}
		}

alter_project_stmt:
	ALTER PROJECT name ALTER PROPERTY name SET name ';'
		{
			$$ = &ast.AlterProjectStmt{Project: $3, Property: $6, Action: ast.Set, Value: $8, StringLiteral: false}
		}
	| ALTER PROJECT name ALTER PROPERTY name SET SLITERAL ';'
		{
			$$ = &ast.AlterProjectStmt{Project: $3, Property: $6, Action: ast.Set, Value: ast.DecodeSLiteral($8), StringLiteral: true}
		}
	| ALTER PROJECT name ALTER PROPERTY name ADD name ';'
		{
			$$ = &ast.AlterProjectStmt{Project: $3, Property: $6, Action: ast.Add, Value: $8}
		}
	| ALTER PROJECT name ALTER PROPERTY name DROP name ';'
		{
			$$ = &ast.AlterProjectStmt{Project: $3, Property: $6, Action: ast.Drop, Value: $8}
		}
	| ALTER PROJECT name ALTER PROPERTY name DROP ALL ';'
		{
			$$ = &ast.AlterProjectStmt{Project: $3, Property: $6, Action: ast.Drop, Value: "*"}
		}

create_filter_stmt:
	CREATE FILTER name where_clause ';'
		{
			$$ = &ast.CreateFilterStmt{Filter: $3, Where: $4}
		}

create_fund_stmt:
	CREATE FUND name ';'
		{
			$$ = &ast.CreateFundStmt{Fund: $3}
		}

create_project_stmt:
	CREATE PROJECT name ';'
		{
			$$ = &ast.CreateProjectStmt{Project: $3}
		}

create_set_stmt:
	CREATE SET name ';'
		{
			$$ = &ast.CreateSetStmt{Set: $3}
		}

create_user_stmt:
	CREATE USER name WITH ENCRYPTED PASSWORD SLITERAL ';'
		{
			$$ = &ast.CreateUserStmt{User: $3, EncryptedPassword: ast.DecodeSLiteral($7)}
		}

delete_stmt:
	DELETE FROM name where_clause ';'
		{
			$$ = &ast.DeleteStmt{From: $3, Where: $4}
		}

drop_fund_stmt:
	DROP FUND name ';'
		{
			$$ = &ast.DropFundStmt{Fund: $3}
		}

drop_project_stmt:
	DROP PROJECT name ';'
		{
			$$ = &ast.DropProjectStmt{Project: $3}
		}

drop_set_stmt:
	DROP SET name ';'
		{
			$$ = &ast.DropSetStmt{Set: $3}
		}

info_stmt:
	INFO ';'
		{
			$$ = &ast.InfoStmt{Topic: ""}
		}
	| INFO SLITERAL ';'
		{
			$$ = &ast.InfoStmt{Topic: ast.DecodeSLiteral($2)}
		}

insert_stmt:
	INSERT INTO name SELECT '*' query_clause ';'
		{
			$$ = &ast.InsertStmt{Into: $3, Query: $6}
		}

ping_stmt:
	PING ';'
		{
			$$ = &ast.PingStmt{}
		}

select_stmt:
	SELECT select_attr_list query_clause ';'
		{
			$$ = &ast.SelectStmt{AttrList: $2, Query: $3}
		}
	| SELECT VERSION '(' ')' ';'
		{
			$$ = &ast.SelectVersionStmt{}
		}

show_stmt:
	SHOW name ';'
		{
			$$ = &ast.ShowStmt{Type: $2}
		}
	| SHOW name IN PROJECT name ';'
		{
			$$ = &ast.ShowStmt{Type: $2, In: $5}
		}
	| SHOW FUND name ';'
		{
			$$ = &ast.ShowStmt{Type: "fund", Name: $3}
		}
	| SHOW PROJECT name ';'
		{
			$$ = &ast.ShowStmt{Type: "project", Name: $3}
		}
	| SHOW PROJECTS ';'
		{
			$$ = &ast.ShowStmt{Type: "projects"}
		}
	| SHOW PROJECTS ARCHIVED ';'
		{
			$$ = &ast.ShowStmt{Type: "projects", Archived: true}
		}

update_stmt:
	UPDATE name SET name '=' name WHERE name '=' NUMBER ';'
		{
			$$ = &ast.UpdateStmt{Set: $2, Attr: $4, Value: $6, IDAttr: $8, IDValue: &ast.Number{Value: $10}}
		}
	| UPDATE name SET name '=' NULL WHERE name '=' NUMBER ';'
		{
			$$ = &ast.UpdateStmt{Set: $2, Attr: $4, ValueNull: true, IDAttr: $8, IDValue: &ast.Number{Value: $10}}
		}
	| UPDATE name SET FUND '=' name WHERE name '=' NUMBER ';'
		{
			$$ = &ast.UpdateStmt{Set: $2, Attr: "fund", Value: $6, IDAttr: $8, IDValue: &ast.Number{Value: $10}}
		}
	| UPDATE name SET FUND '=' NULL WHERE name '=' NUMBER ';'
		{
			$$ = &ast.UpdateStmt{Set: $2, Attr: "fund", ValueNull: true, IDAttr: $8, IDValue: &ast.Number{Value: $10}}
		}

select_attr_list:
	name
		{
			$$ = &ast.SelectAttrList{Attr: $1}
		}
	| '*'
		{
			$$ = &ast.SelectAttrList{Attr: "*"}
		}
	| COUNT '(' '*' ')'
		{
			$$ = &ast.SelectAttrList{Attr: "count(*)"}
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
	| equality_expr ILIKE relational_expr
		{
			$$ = &ast.ILikeExpr{Expr1: $1, Expr2: $3}
		}
	| equality_expr NOT_EQUAL relational_expr
		{
			$$ = &ast.NotEqualExpr{Expr1: $1, Expr2: $3}
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
	primary_expr
		{
			$$ = $1
		}
	| FILTER '(' name ')'
		{
			$$ = &ast.FilterExpr{Filter: $3}
		}
	| TAG '(' arg_expr_list ')'
		{
			$$ = &ast.TagExpr{ExprList: $3}
		}

primary_expr:
	name
		{
			$$ = &ast.Name{Value: $1}
		}
	| FUND
		{
			$$ = &ast.Name{Value: "fund"}
		}
	| SLITERAL
		{
			$$ = &ast.SLiteral{Value: ast.DecodeSLiteral($1)}
		}
	| NUMBER
		{
			$$ = &ast.Number{Value: $1}
		}
	| '(' expression ')'
		{
			$$ = &ast.ParenExpr{Expr: $2}
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

name:
	IDENT
		{
			$$ = strings.ToLower($1)
		}

/*
boolean:
	TRUE
		{
			$$ = "true"
		}
	| FALSE
		{
			$$ = "false"
		}
*/
