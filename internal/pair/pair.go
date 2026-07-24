package pair

import "strings"

type Pair struct {
	First  string
	Second string
}

func Parse(pairString string) Pair {
	s := strings.Split(pairString, ".")
	if len(s) == 2 {
		return Pair{First: s[0], Second: s[1]}
	} else {
		return Pair{}
	}
}

func (p Pair) String() string {
	return p.First + "." + p.Second
}
