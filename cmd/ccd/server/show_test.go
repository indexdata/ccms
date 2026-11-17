package server

import (
	"strings"
	"testing"
)

func TestShowFilters(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p;
create filter p.f1 where id > 100;
create filter p.f2 where id > 200;
show filters;
drop project p cascade;
`)
	if tt.result(3, 0, 0) != "p" {
		tt.fatal()
	}
	if tt.result(3, 0, 1) != "f1" {
		tt.fatal()
	}
	if tt.result(3, 0, 2) != "create filter p.f1 where id > 100" {
		tt.fatal()
	}
	if tt.result(3, 1, 0) != "p" {
		tt.fatal()
	}
	if tt.result(3, 1, 1) != "f2" {
		tt.fatal()
	}
	if tt.result(3, 1, 2) != "create filter p.f2 where id > 200" {
		tt.fatal()
	}
}

func TestShowFiltersInProject(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p1;
create project p2;
create filter p1.f1 where id > 100;
create filter p1.f2 where id > 200;
create filter p2.f3 where id > 300;
show filters in project p1;
show filters in project p2;
drop project p2 cascade;
drop project p1 cascade;
`)
	if tt.result(5, 0, 0) != "p1" {
		tt.fatal()
	}
	if tt.result(5, 0, 1) != "f1" {
		tt.fatal()
	}
	if tt.result(5, 0, 2) != "create filter p1.f1 where id > 100" {
		tt.fatal()
	}
	if tt.result(5, 1, 0) != "p1" {
		tt.fatal()
	}
	if tt.result(5, 1, 1) != "f2" {
		tt.fatal()
	}
	if tt.result(5, 1, 2) != "create filter p1.f2 where id > 200" {
		tt.fatal()
	}
	if tt.result(5, 2, 0) != "" {
		tt.fatal()
	}

	if tt.result(6, 0, 0) != "p2" {
		tt.fatal()
	}
	if tt.result(6, 0, 1) != "f3" {
		tt.fatal()
	}
	if tt.result(6, 0, 2) != "create filter p2.f3 where id > 300" {
		tt.fatal()
	}
	if tt.result(6, 1, 0) != "" {
		tt.fatal()
	}
}

func TestShowFund(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create fund f;
show fund f;
drop fund f;
`)
	if tt.status(1) != "show" {
		tt.fatal()
	}
	if tt.result(1, 0, 0) != "name" {
		tt.fatal()
	}
	if tt.result(1, 0, 1) == "" {
		tt.fatal()
	}
}

func TestShowFunds(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create fund f1;
create fund f2;
show funds;
drop fund f2;
drop fund f1;
`)
	if tt.result(2, 0, 0) != "f1" {
		tt.fatal()
	}
	if tt.result(2, 0, 1) == "" {
		tt.fatal()
	}
	if tt.result(2, 1, 0) != "f2" {
		tt.fatal()
	}
	if tt.result(2, 1, 1) == "" {
		tt.fatal()
	}
}

func TestShowProject(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p;
show project p;
drop project p;
`)
	if tt.status(1) != "show" {
		tt.fatal()
	}
	if tt.result(1, 0, 0) != "title" {
		tt.fatal()
	}
	if tt.result(1, 0, 1) == "" {
		tt.fatal()
	}
}

func TestShowProjects(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p1;
create project p2;
show projects;
drop project p2;
drop project p1;
`)
	if tt.result(2, 0, 0) != "p1" {
		tt.fatal()
	}
	if tt.result(2, 0, 1) == "" {
		tt.fatal()
	}
	if tt.result(2, 1, 0) != "p2" {
		tt.fatal()
	}
	if tt.result(2, 1, 1) == "" {
		tt.fatal()
	}
	if tt.result(2, 2, 0) != "" {
		tt.fatal()
	}
}

func TestShowSets(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p;
create set p.s1;
create set p.s2;
show sets;
drop project p cascade;
`)
	if tt.result(3, 1, 0) != "p" {
		tt.fatal()
	}
	if tt.result(3, 1, 1) != "s1" {
		tt.fatal()
	}
	if tt.result(3, 1, 2) == "" {
		tt.fatal()
	}
	if tt.result(3, 2, 0) != "p" {
		tt.fatal()
	}
	if tt.result(3, 2, 1) != "s2" {
		tt.fatal()
	}
	if tt.result(3, 2, 2) == "" {
		tt.fatal()
	}
	if tt.result(3, 3, 0) != "" {
		tt.fatal()
	}
}

func TestShowSetsInProject(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create project p1;
create project p2;
create set p1.s1;
create set p1.s2;
create set p2.s3;
show sets in project p1;
show sets in project p2;
drop project p2 cascade;
drop project p1 cascade;
`)
	if tt.result(5, 1, 0) != "p1" {
		tt.fatal()
	}
	if tt.result(5, 1, 1) != "s1" {
		tt.fatal()
	}
	if tt.result(5, 1, 2) == "" {
		tt.fatal()
	}
	if tt.result(5, 2, 0) != "p1" {
		tt.fatal()
	}
	if tt.result(5, 2, 1) != "s2" {
		tt.fatal()
	}
	if tt.result(5, 2, 2) == "" {
		tt.fatal()
	}
	if tt.result(5, 3, 0) != "" {
		tt.fatal()
	}

	if tt.result(6, 1, 0) != "p2" {
		tt.fatal()
	}
	if tt.result(6, 1, 1) != "s3" {
		tt.fatal()
	}
	if tt.result(6, 1, 2) == "" {
		tt.fatal()
	}
	if tt.result(6, 2, 0) != "" {
		tt.fatal()
	}
}

func TestShowTrack(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create track t;
show track t;
drop track t;
`)
	if tt.status(1) != "show" {
		tt.fatal()
	}
	if tt.result(1, 0, 0) != "name" {
		tt.fatal()
	}
	if tt.result(1, 0, 1) == "" {
		tt.fatal()
	}
}

func TestShowTracks(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create track t1;
create track t2;
show tracks;
drop track t2;
drop track t1;
`)
	if tt.result(2, 0, 0) != "t1" {
		tt.fatal()
	}
	if tt.result(2, 0, 1) == "" {
		tt.fatal()
	}
	if tt.result(2, 1, 0) != "t2" {
		tt.fatal()
	}
	if tt.result(2, 1, 1) == "" {
		tt.fatal()
	}
}

func TestShowUsers(t *testing.T) {
	tt := newtest(t)
	tt.send(`
show users;
`)
	if tt.result(0, 0, 0) != "admin" {
		tt.fatal()
	}
}

func TestShowVersion(t *testing.T) {
	tt := newtest(t)
	tt.send(`
show version;
`)
	if !strings.HasPrefix(tt.result(0, 0, 0), "CCMS ") {
		tt.fatal()
	}
}
