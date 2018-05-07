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
		t.Fatalf("%#v\n)", err)
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
			"name": "redhat source",
			"url":  "http://access.redhat.com/labs/securitydataapi/2018-05-28",
			"type": "redhat",
		},
	}

	expected.Sources = []cve.Source{
		cve.Source{
			"circle source (last two days)", "http://cve.circl.lu/api/last/2", "circl",
			cve.SourceType{"id", "Published", "references", "summary"},
		},

		cve.Source{
			"redhat source", "http://access.redhat.com/labs/securitydataapi/2018-05-28", "redhat",
			cve.SourceType{"CVE", "public_date", "resource_url", "bugzilla_description"},
		},
	}

	if diff := deep.Equal(expected, result); diff != nil {
		t.Error("Result not equal expected. Differences:")
		for _, d := range diff {
			t.Log(d)
		}
		t.Fail()

	}
}
