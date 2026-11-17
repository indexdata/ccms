package server

import (
	"testing"
)

func TestCreateFilter(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p;
create filter p.f where id > 100;
show filters;
create filter p.f;
create filter f;
drop project p cascade;
`)
	if tt.status(1) != "create filter" {
		tt.fatal()
	}
	if tt.result(2, 0, 0) != "p" {
		tt.fatal()
	}
	if tt.result(2, 0, 1) != "f" {
		tt.fatal()
	}
	if tt.result(2, 0, 2) != "create filter p.f where id > 100" {
		tt.fatal()
	}
	if tt.status(3) != "error" {
		tt.fatal()
	}
	tt.send(`
create project p;
create filter f where id > 100;
drop project p cascade;
`)
	if tt.status(1) != "error" {
		tt.fatal()
	}
}
