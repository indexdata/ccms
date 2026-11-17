package server

import (
	"testing"
)

func TestAlterTrack(t *testing.T) {
	tt := newtest(t)
	tt.send(`
create track t;
alter track t alter property name set tt;
alter track tt alter property title set 'Test Track';
show tracks;
drop track tt;
`)
	if tt.status(0) != "create track" {
		tt.fatal()
	}
	if tt.status(1) != "alter track" {
		tt.fatal()
	}
	if tt.status(2) != "alter track" {
		tt.fatal()
	}
	if tt.result(3, 0, 0) != "tt" {
		tt.fatal()
	}
	if tt.result(3, 0, 1) != "Test Track" {
		tt.fatal()
	}
}
