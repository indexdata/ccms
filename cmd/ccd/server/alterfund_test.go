package server

import (
	"testing"
)

func TestAlterFund(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create fund f;
alter fund f alter property name set ff;
alter fund ff alter property title set 'Test Fund';
show funds;
drop fund ff;
`)
	if tt.status(0) != "create fund" {
		tt.fatal()
	}
	if tt.status(1) != "alter fund" {
		tt.fatal()
	}
	if tt.status(2) != "alter fund" {
		tt.fatal()
	}
	if tt.result(3, 0, 0) != "ff" {
		tt.fatal()
	}
	if tt.result(3, 0, 1) != "Test Fund" {
		tt.fatal()
	}
}
