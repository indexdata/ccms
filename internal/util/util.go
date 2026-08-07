package util

import (
	"fmt"
	"strings"
)

// parse input string in the form a.b; returning a and b, or error if
// input is invalid
func ParsePair(pairString string) (string, string, error) {
	s := strings.Split(pairString, ".")
	if len(s) != 2 {
		return "", "", fmt.Errorf("invalid input \"" + pairString + "\"")
	}
	return s[0], s[1], nil
}
