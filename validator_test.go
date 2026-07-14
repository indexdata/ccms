package ccms_test

import (
	"github.com/indexdata/ccms"
)

func ExampleValidator() {
	client := &ccms.Client{
		// etc.
	}

	var v ccms.Validator
	cmd := "create filter " + v.Ident("piano") +
		" where " + v.Ident("title") + " ilike " + v.String("%piano%")
	// validation errors are reported by SendValid()
	_, err := client.SendValid(cmd, v)
	if err != nil {
		panic(err)
	}
}
