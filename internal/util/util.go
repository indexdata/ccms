package util

import "strings"

// parse input string in the form a.b; returning a and b, or empty strings if
// input is invalid
func ParsePair(pairString string) (string, string) {
	s := strings.Split(pairString, ".")
	if len(s) != 2 {
		return "", ""
	}
	return s[0], s[1]
}
