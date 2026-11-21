module github.com/indexdata/ccms

go 1.27.4

require (
	github.com/chzyer/readline v1.5.1
	github.com/essentialkaos/ek/v13 v13.38.3
	github.com/jackc/pgx/v5 v5.9.2
	github.com/nassibnassar/goharvest v0.0.0-20160726165741-cbaf6f70f07d
	github.com/spf13/cobra v1.8.1
	golang.org/x/crypto v0.59.0
	golang.org/x/term v0.48.0
	gopkg.in/ini.v1 v1.67.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/kisielk/errcheck v1.30.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.org/x/vuln v1.9.0 // indirect
)

tool (
	github.com/kisielk/errcheck
	golang.org/x/tools/cmd/goyacc
	golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow
	golang.org/x/vuln/cmd/govulncheck
)
