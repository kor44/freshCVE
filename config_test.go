package main

import (
	"freshCVE/cve"
	"strings"
	"testing"
	"time"

	"github.com/go-test/deep"
)

func TestReadConfig(t *testing.T) {
	result, err := readConfigFile(strings.NewReader(confTempl))

	if err != nil {
		t.Fatalf("%#v\n", err)
	}

	expected := &Config{}

	expected.Server.Address = ""
	expected.Server.Port = 8080

	expected.Timers.RequestTimeout = 2 * time.Second
	expected.Timers.CacheUpdateInterval = 60 * time.Second

	expected.SourcesTypes = map[string]interface{}{
		"circl": map[string]interface{}{
			"ID": "id", "Published": "Published", "References": "references", "Description": "summary",
		},
		"redhat": map[string]interface{}{
			"ID": "CVE", "Published": "public_date", "References": "resource_url", "Description": "bugzilla_description",
		},
	}

	expected.SourcesList = []map[string]string{
		map[string]string{
			"name": "circle source (last two days)",
			"url":  "http://cve.circl.lu/api/last/2",
			"type": "circl",
		},
		map[string]string{
			"name":         "redhat source",
			"url":          "http://access.redhat.com/labs/securitydataapi/cve.json",
			"type":         "redhat",
			"query_params": "?after={{ lastNDays 2 \"2006-01-02\" }}",
		},
	}

	queryParam, _ := cve.Parse("?after={{ lastNDays 2 \"2006-01-02\" }}")

	expected.Sources = []cve.Source{
		cve.Source{
			Name: "circle source (last two days)", BaseURL: "http://cve.circl.lu/api/last/2", SourceTypeName: "circl",
			Type: cve.SourceType{"id", "Published", "references", "summary"},
		},

		cve.Source{
			Name: "redhat source", BaseURL: "http://access.redhat.com/labs/securitydataapi/cve.json", SourceTypeName: "redhat",
			Type:       cve.SourceType{"CVE", "public_date", "resource_url", "bugzilla_description"},
			QueryParam: queryParam,
		},
	}

	if diff := deep.Equal(expected, result); diff != nil {
		t.Error("Result not equal expected. Differences:")
		for _, d := range diff {
			t.Log(d)
		}
		t.Fail()
	}

	for i, _ := range expected.Sources {
		if expected.Sources[i].URL() != result.Sources[i].URL() {
			t.Errorf("Result not equal expected. Differences: %s != %s", expected.Sources[i].URL(), result.Sources[i].URL())
			t.Fail()
		}
	}
}
