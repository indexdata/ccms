package marcxml

import (
	"encoding/xml"
	"strings"
)

type MARCXML struct {
	XMLName       xml.Name       `xml:"record"`
	Leader        Leader         `xml:"leader"`
	Controlfields []Controlfield `xml:"controlfield"`
	Datafields    []Datafield    `xml:"datafield"`
}

type Leader struct {
	XMLName xml.Name `xml:"leader"`
	Value   string   `xml:",chardata"`
}

type Controlfield struct {
	XMLName xml.Name `xml:"controlfield"`
	Tag     string   `xml:"tag,attr"`
	Value   string   `xml:",chardata"`
}

type Datafield struct {
	XMLName   xml.Name   `xml:"datafield"`
	Tag       string     `xml:"tag,attr"`
	Ind1      string     `xml:"ind1,attr"`
	Ind2      string     `xml:"ind2,attr"`
	Subfields []Subfield `xml:"subfield"`
}

type Subfield struct {
	XMLName xml.Name `xml:"subfield"`
	Code    string   `xml:"code,attr"`
	Value   string   `xml:",chardata"`
}

func Unmarshal(data []byte) (*MARCXML, error) {
	var marc MARCXML
	if err := xml.Unmarshal(data, &marc); err != nil {
		return nil, err
	}
	return &marc, nil
}

func (m *MARCXML) LookupHoldingsCount() int16 {
	var count int16
	df := m.Datafields
	for i := range df {
		if df[i].Tag == "999" && df[i].Ind1 == "1" && df[i].Ind2 == "0" {
			count++
		}
	}
	return count
}

func (m *MARCXML) Lookup(tag, ind1, ind2, subfield string) string {
	content := make([]string, 0)
	cf := m.Controlfields
	for i := range cf {
		if cf[i].Tag == tag {
			content = append(content, strings.TrimSpace(cf[i].Value))
		}
	}
	df := m.Datafields
	for i := range df {
		if len(content) != 0 {
			break
		}
		if ind1 != "" && ind1 != df[i].Ind1 {
			continue
		}
		if ind2 != "" && ind2 != df[i].Ind2 {
			continue
		}
		if df[i].Tag != tag {
			continue
		}
		sf := df[i].Subfields
		for j := range sf {
			if sf[j].Code == subfield {
				content = append(content, strings.TrimSpace(sf[j].Value))
			}
		}
	}
	return strings.Join(content, "\n")
}
