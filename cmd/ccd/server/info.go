package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/cmd/ccd/doc"
)

func infoStmt(s *svr, db *dbx.DB, cmd *ast.InfoStmt) *ccms.Result {
	if cmd.Topic == "" {
		result := ccms.NewResult("info")
		result.AddField("info", "text")
		result.AddData([]any{"" +
			"SQL commands:\n" +
			"        alter fund       change the definition of a fund\n" +
			"        alter project    change the definition of a project\n" +
			"        create filter    define a new filter\n" +
			"        create fund      define a new fund\n" +
			"        create project   define a new project\n" +
			"        create set       define a new set\n" +
			"        create user      define a new user\n" +
			"        delete           remove objects from set membership\n" +
			"        drop fund        remove a fund\n" +
			"        drop project     remove a project\n" +
			"        drop set         remove a set\n" +
			//"        info    show supported commands\n" +
			"        insert           insert objects into a set\n" +
			"        select           retrieve objects from a set\n" +
			"        show             list existing filters or sets\n" +
			"        update           update object attributes\n"})
		return result
	}

	var docstr string
	switch cmd.Topic {
	case "alter fund":
		docstr = doc.AlterFund()
	case "alter project":
		docstr = doc.AlterProject()
	case "create filter":
		docstr = doc.CreateFilter()
	case "create fund":
		docstr = doc.CreateFund()
	case "create project":
		docstr = doc.CreateProject()
	case "create set":
		docstr = doc.CreateSet()
	case "create user":
		docstr = doc.CreateUser()
	case "delete":
		docstr = doc.Delete()
	case "drop fund":
		docstr = doc.DropFund()
	case "drop project":
		docstr = doc.DropProject()
	case "drop set":
		docstr = doc.DropSet()
	//case "info":
	//        docstr = doc.Info()
	case "insert":
		docstr = doc.Insert()
	case "select":
		docstr = doc.Select()
	case "show":
		docstr = doc.Show()
	case "update":
		docstr = doc.Update()
	default:
		return cmderr("unknown command \"" + cmd.Topic + "\"")
	}

	result := ccms.NewResult("info")
	result.AddField("info", "text")
	result.AddData([]any{docstr})
	return result
}
