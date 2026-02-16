package server

import (
	"fmt"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/doc"
)

func infoStmt(s *svr, cmd *ast.InfoStmt) *ccms.Result {
	if cmd.Topic == "" {
		result := ccms.NewResult("info")
		result.AddField("info", "text")
		result.AddData([]any{"" +
			"SQL commands:\n" +
			"        create set  define a new set\n" +
			"        delete      remove objects from set membership\n" +
			"        drop set    remove a set\n" +
			//"        info    show supported commands\n" +
			"        insert      insert objects into a set\n" +
			"        select      retrieve objects from a set\n" +
			"        show        list existing filters or sets\n"})
	}

	var docstr string
	switch cmd.Topic {
	case "create set":
		docstr = doc.CreateSet()
	case "delete":
		docstr = doc.Delete()
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
	default:
		docstr = fmt.Sprintf("unknown command %q", cmd.Topic)
	}

	result := ccms.NewResult("info")
	result.AddField("info", "text")
	result.AddData([]any{docstr})
	return result
}
