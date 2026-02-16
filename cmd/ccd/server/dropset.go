package server

import (
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/catalog"
	"github.com/indexdata/ccms/cmd/ccd/log"
)

func dropSetStmt(s *svr, rqid int64, cmd *ast.DropSetStmt) *ccms.Result {
	if !catalog.IsValidTargetSet(cmd.SetName) {
		return cmderr("invalid target set \"" + cmd.SetName + "\"")
	}

	if !s.cat.SetExists(cmd.SetName) {
		return cmderr("set \"" + cmd.SetName + "\" does not exist")
	}

	if err := s.cat.DropSet(cmd.SetName); err != nil {
		log.Info("[%d] %v", rqid, err)
		return cmderr("error dropping set \"" + cmd.SetName + "\"")
	}

	return ccms.NewResult("drop set")
}
