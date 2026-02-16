package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/catalog"
	"github.com/indexdata/ccms/cmd/ccd/log"
)

func createSetStmt(s *svr, rqid int64, cmd *ast.CreateSetStmt) *ccms.Result {
	if s.cat.SetExists(cmd.SetName) {
		return cmderr("set \"" + cmd.SetName + "\" already exists")
	}

	if !catalog.IsValidTargetSet(cmd.SetName) {
		return cmderr("invalid set name \"" + cmd.SetName + "\"")
	}

	if !catalog.ProjectExists(cmd.SetName) {
		return cmderr("invalid project in  \"" + cmd.SetName + "\"")
	}

	if err := s.cat.CreateSet(cmd.SetName); err != nil {
		log.Info("[%d] %v", rqid, err)
		return cmderr("error writing set \"" + cmd.SetName + "\"")
	}

	return ccms.NewResult("create set")
}
