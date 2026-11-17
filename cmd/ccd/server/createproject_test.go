package server

import (
	"testing"
)

func TestCreateProject(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p;
show project p;
create project p;
drop project p;
`)
	if tt.status(0) != "create project" {
		tt.fatal()
	}
	if tt.status(1) != "show" {
		tt.fatal()
	}
	if tt.status(2) != "error" {
		tt.fatal()
	}
}
