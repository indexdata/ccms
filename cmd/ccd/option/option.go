package option

type Global struct {
}

type Init struct {
	Datadir string
	Global
}

type Server struct {
	Debug     bool
	Trace     bool
	Datadir   string
	Listen    string
	Port      string
	TLSCert   string
	TLSKey    string
	NoTLS     bool
	NoHarvest bool
	Program   string
	Test      bool
	Global
}

type Stop struct {
	Datadir string
	Global
}
