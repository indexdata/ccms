package doc

import (
	_ "embed"
	"strings"
)

//go:embed alterfund.txt
var alterFundTxt string

func AlterFund() string {
	return strings.TrimSpace(alterFundTxt)
}

//go:embed alterproject.txt
var alterProjectTxt string

func AlterProject() string {
	return strings.TrimSpace(alterProjectTxt)
}

//go:embed archiveproject.txt
var archiveProjectTxt string

func ArchiveProject() string {
	return strings.TrimSpace(archiveProjectTxt)
}

//go:embed createfilter.txt
var createFilterTxt string

func CreateFilter() string {
	return strings.TrimSpace(createFilterTxt)
}

//go:embed createfund.txt
var createFundTxt string

func CreateFund() string {
	return strings.TrimSpace(createFundTxt)
}

//go:embed createproject.txt
var createProjectTxt string

func CreateProject() string {
	return strings.TrimSpace(createProjectTxt)
}

//go:embed createset.txt
var createSetTxt string

func CreateSet() string {
	return strings.TrimSpace(createSetTxt)
}

//go:embed createuser.txt
var createUserTxt string

func CreateUser() string {
	return strings.TrimSpace(createUserTxt)
}

//go:embed delete.txt
var deleteTxt string

func Delete() string {
	return strings.TrimSpace(deleteTxt)
}

//go:embed dropfund.txt
var dropFundTxt string

func DropFund() string {
	return strings.TrimSpace(dropFundTxt)
}

//go:embed dropproject.txt
var dropProjectTxt string

func DropProject() string {
	return strings.TrimSpace(dropProjectTxt)
}

//go:embed dropset.txt
var dropSetTxt string

func DropSet() string {
	return strings.TrimSpace(dropSetTxt)
}

/*
//go:embed info.txt
var infoTxt string

func Info() string {
	return strings.TrimSpace(infoTxt)
}
*/

//go:embed insert.txt
var insertTxt string

func Insert() string {
	return strings.TrimSpace(insertTxt)
}

//go:embed select.txt
var selectTxt string

func Select() string {
	return strings.TrimSpace(selectTxt)
}

//go:embed show.txt
var showTxt string

func Show() string {
	return strings.TrimSpace(showTxt)
}

//go:embed update.txt
var updateTxt string

func Update() string {
	return strings.TrimSpace(updateTxt)
}
