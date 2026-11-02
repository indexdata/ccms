package attr

import "iter"

type AttrType int

const (
	NoType AttrType = iota
	SmallInt
	BigInt
	Text
	Boolean
	Property
)

type Attr struct {
	Name       string
	Projection string
	Type       AttrType
	SQLType    string
	Hide       bool
}

var AttrSlice = []Attr{
	{Name: "id", Projection: "a.id", Type: BigInt, SQLType: "bigint"},
	{Name: "author", Projection: "a.author", Type: Text, SQLType: "text"},
	{Name: "title", Projection: "a.title", Type: Text, SQLType: "text"},
	{Name: "full_vendor_name", Projection: "a.full_vendor_name", Type: Text, SQLType: "text"},
	{Name: "availability", Projection: "a.availability", Type: Text, SQLType: "text"},
	{Name: "library_count", Projection: "a.library_count", Type: SmallInt, SQLType: "smallint"},
	{Name: "library_holdings_count", Projection: "a.library_holdings_count", Type: SmallInt, SQLType: "smallint"},
	{Name: "online_database_holdings_count", Projection: "a.online_database_holdings_count", Type: SmallInt, SQLType: "smallint"},
	{Name: "vendor_holdings_count", Projection: "a.vendor_holdings_count", Type: SmallInt, SQLType: "smallint"},
	{Name: "holdings_count", Projection: "a.holdings_count", Type: SmallInt, SQLType: "smallint"},
	{Name: "decision", Projection: "o.decision", Type: Boolean, SQLType: "boolean"},
	{Name: "fund", Projection: "fund.name||':'||fund.title", Type: Property, SQLType: "text"},
	{Name: "track", Projection: "track.name||':'||track.title", Type: Property, SQLType: "text"},
	{Name: "source_record", Projection: "md.data", Type: Text, SQLType: "text", Hide: true},
}

var AttrMap map[string]Attr

func init() {
	AttrMap = make(map[string]Attr)
	for i := range AttrSlice {
		AttrMap[AttrSlice[i].Name] = AttrSlice[i]
	}
}

func AttrName(name string) (Attr, bool) {
	att, ok := AttrMap[name]
	return att, ok
}

// func IsAttr(name string) bool {
// 	_, ok := AttrMap[name]
// 	return ok
// }

// return an iterator over all attributes
func AllAttrs() iter.Seq[Attr] {
	return func(yield func(Attr) bool) {
		for i := range AttrSlice {
			if !yield(AttrSlice[i]) {
				return
			}
		}
	}
}
