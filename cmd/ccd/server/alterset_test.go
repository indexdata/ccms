package server

import (
	"testing"
)

func TestAlterSet(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p;
create set p.f;
alter set p.f alter property name set ff;
alter set p.ff alter property title set 'Test Set';
show sets;
drop project p cascade;
`)
	if tt.status(1) != "create set" {
		tt.fatal()
	}
	if tt.status(2) != "alter set" {
		tt.fatal()
	}
	if tt.status(3) != "alter set" {
		tt.fatal()
	}
	if tt.result(4, 0, 0) != "p" {
		tt.fatal()
	}
	if tt.result(4, 0, 1) != "ff" {
		tt.fatal()
	}
	if tt.result(4, 0, 2) != "Test Set" {
		tt.fatal()
	}
}
