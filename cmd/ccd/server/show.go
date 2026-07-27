package server

import (
	"strings"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/internal/global"
)

func showStmt(s *svr, db *dbx.DB, cmd *ast.ShowStmt) *ccms.Result {
	result := ccms.NewResult("show")
	switch cmd.Type {
	case "filters":
		var projectID int32
		if cmd.In != "" {
			var err error
			projectID, err = cat.ProjectID(db, cmd.In)
			if err != nil {
				return cmderr(err.Error())
			}
			if projectID == 0 {
				return cmderr("project \"" + cmd.In + "\" does not exist")
			}
		}
		result.AddField("project", "text")
		result.AddField("filter", "text")
		result.AddField("definition", "text")
		if err := addShowFiltersData(db, result, projectID, cmd.In); err != nil {
			return cmderr(err.Error())
		}
	case "fund":
		result.AddField("property", "text")
		result.AddField("value", "text")
		if err := addShowFundData(db, result, cmd.Name); err != nil {
			return cmderr(err.Error())
		}
	case "funds":
		result.AddField("name", "text")
		result.AddField("title", "text")
		if err := addShowFundsData(db, result); err != nil {
			return cmderr(err.Error())
		}
	//case "roles":
	//        result.AddField("name", "text")
	//        result.AddField("users", "text")
	//        addShowRolesData(s.cat, result)
	case "project":
		result.AddField("property", "text")
		result.AddField("value", "text")
		if err := addShowProjectData(db, result, cmd.Name); err != nil {
			return cmderr(err.Error())
		}
	case "projects":
		result.AddField("name", "text")
		result.AddField("title", "text")
		err := addShowProjectsData(db, result)
		if err != nil {
			return cmderr(err.Error())
		}
	case "sets":
		var projectID int32
		if cmd.In != "" {
			var err error
			projectID, err = cat.ProjectID(db, cmd.In)
			if err != nil {
				return cmderr(err.Error())
			}
			if projectID == 0 {
				return cmderr("project \"" + cmd.In + "\" does not exist")
			}
		}
		result.AddField("project", "text")
		result.AddField("set", "text")
		if err := addShowSetsData(db, result, projectID, cmd.In); err != nil {
			return cmderr(err.Error())
		}
	case "tags":
		result.AddField("name", "text")
	case "users":
		result.AddField("name", "text")
		result.AddField("superuser", "boolean")
		result.AddField("login", "boolean")
		if err := addShowUsersData(db, result); err != nil {
			return cmderr(err.Error())
		}
	case "version":
		result.AddField("version", "text")
		result.AddData([]any{"CCMS " + global.Version})
	default:
		return cmderr("unknown variable \"" + cmd.Type + "\"")
	}
	return result
}

func addShowFundData(db *dbx.DB, result *ccms.Result, fund string) error {
	prop, err := cat.FundProperties(db, fund)
	if err != nil {
		return err
	}
	for i := range prop {
		result.AddData([]any{prop[i][0], prop[i][1]})
	}
	return nil
}

func addShowFundsData(db *dbx.DB, result *ccms.Result) error {
	funds, err := cat.Funds(db)
	if err != nil {
		return err
	}
	funds.Sort()
	for i := range funds {
		result.AddData([]any{funds[i].Name, funds[i].Title})
	}
	return nil
}

func addShowRolesData(db *dbx.DB, result *ccms.Result) error {
	roles, err := cat.Roles(db)
	if err != nil {
		return err
	}
	cat.SortRoles(roles)
	for i := range roles {
		users := strings.Join(roles[i].UserNames, ", ")
		result.AddData([]any{roles[i].RoleName, users})
	}
	return nil
}

func addShowProjectData(db *dbx.DB, result *ccms.Result, project string) error {
	prop, err := cat.ProjectProperties(db, project)
	if err != nil {
		return err
	}
	for i := range prop {
		result.AddData([]any{prop[i][0], prop[i][1]})
	}
	return nil
}

func addShowProjectsData(db *dbx.DB, result *ccms.Result) error {
	projects, err := cat.Projects(db)
	if err != nil {
		return err
	}
	projects.Sort()
	for i := range projects {
		result.AddData([]any{projects[i].Name, projects[i].Title})
	}
	return nil
}

func addShowFiltersData(db *dbx.DB, result *ccms.Result, projectID int32, project string) error {
	var filters []cat.Filter
	var err error
	if project == "" {
		filters, err = cat.Filters(db)
	} else {
		filters, err = cat.FiltersInProject(db, projectID, project)
	}
	if err != nil {
		return err
	}
	cat.SortFilters(filters)
	for i := range filters {
		result.AddData([]any{filters[i].Project, filters[i].Filter, filters[i].Definition})
	}
	return nil
}

func addShowSetsData(db *dbx.DB, result *ccms.Result, projectID int32, project string) error {
	var sets []cat.Set
	var err error
	if project == "" {
		sets, err = cat.Sets(db)
	} else {
		sets, err = cat.SetsInProject(db, projectID, project)
	}
	if err != nil {
		return err
	}
	cat.SortSets(sets)
	for i := range sets {
		result.AddData([]any{sets[i].Project, sets[i].Set})
	}
	return nil
}

func addShowUsersData(db *dbx.DB, result *ccms.Result) error {
	users, err := cat.Users(db)
	if err != nil {
		return err
	}
	cat.SortUsers(users)
	for i := range users {
		result.AddData([]any{users[i].UserName, users[i].Superuser, users[i].Login})
	}
	return nil
}
