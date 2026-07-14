package ccms

import (
	"errors"
	"regexp"

	"github.com/indexdata/ccms/internal/global"
)

// helper class to validate and encode command inputs
type Validator struct {
	err error
}

// reset validator to be reused for new commands
func (c *Validator) Reset() {
	c.err = nil
}

func (c *Validator) Int(intstr string) string {
	if !intRegexp.MatchString(intstr) {
		c.error("invalid integer \"" + intstr + "\"")
		return ""
	}
	return intstr
}

func (c *Validator) Ident(ident string) string {
	if !identRegexp.MatchString(ident) {
		c.error("invalid identifier \"" + ident + "\"")
		return ""
	}
	return ident
}

func (c *Validator) String(str string) string {
	return "'" + global.EncodeString(str) + "'"
}

func (c *Validator) error(errorString string) {
	if c.err == nil {
		c.err = errors.New(errorString)
	}
}

var intRegexp = regexp.MustCompile(`^-?[0-9]+$`)
var identRegexp = regexp.MustCompile(`^[A-Za-z][0-9A-Za-z_.]*$`)
