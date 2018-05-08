package cve

import (
	"encoding/json"
	"reflect"
	"testing"
)

var typesCfgStr = `
	{
		"circl": {
			"ID": "id", "Published": "Published", "References": "references", "Description": "summary"
		},
		"redhat": {
			"ID": "CVE", "Published": "public_date", "References": "resource_url", "Description": "bugzilla_description"
		}
	}`

func TestTypeCfgParse(t *testing.T) {
	cfg := map[string]interface{}{}

	if err := json.Unmarshal([]byte(typesCfgStr), &cfg); err != nil {
		t.Fatalf("Config decode error: %s", err)
	}

	typesCfg, err := parseTypesCfg(cfg)
	if err != nil {
		t.Fatalf("parseTypesCfg error: %s", err)
	}

	expected := map[string]SourceType{
		"circl":  SourceType{ID: "id", Published: "Published", References: "references", Description: "summary"},
		"redhat": SourceType{ID: "CVE", Published: "public_date", References: "resource_url", Description: "bugzilla_description"},
	}

	if !reflect.DeepEqual(expected, typesCfg) {
		t.Fatalf("Expect %#v,\n got %#v", expected, typesCfg)
	}
}

var srcCfgStr = `
	[
		{ "name": "circle src", "url": "http://cve.circl.lu/api/last/2", "type": "circl"},
		{ "name": "redhat src","url": "http://access.redhat.com/labs/securitydataapi/2018-05-28", "type": "redhat"}
	]
`

func TestParseSourcesCfg(t *testing.T) {
	var typesCfg map[string]interface{}
	if err := json.Unmarshal([]byte(typesCfgStr), &typesCfg); err != nil {
		t.Fatalf("Type config decode error: %s", err)
	}

	var srcCfg []map[string]string
	if err := json.Unmarshal([]byte(srcCfgStr), &srcCfg); err != nil {
		t.Fatalf("Source config decode error: %s (%#v)", err, srcCfg)
	}

	sources, err := ParseSourcesCfg(typesCfg, srcCfg)
	if err != nil {
		t.Fatal(err)
	}

	expected := []Source{
		Source{Name: "circle src", BaseURL: "http://cve.circl.lu/api/last/2", SourceTypeName: "circl",
			Type: SourceType{ID: "id", Published: "Published", References: "references", Description: "summary"},
		},
		Source{Name: "redhat src", BaseURL: "http://access.redhat.com/labs/securitydataapi/2018-05-28", SourceTypeName: "redhat",
			Type: SourceType{ID: "CVE", Published: "public_date", References: "resource_url", Description: "bugzilla_description"},
		},
	}

	if !reflect.DeepEqual(expected, sources) {
		t.Fatalf("Expect %#v\n got %#v", expected, sources)
	}

}
