package main

import (
	"strings"
	"testing"

	"github.com/kor44/freshCVE/cve"

	"github.com/go-test/deep"
)

func TestReadConfig(t *testing.T) {
	result, err := readConfigFile(strings.NewReader(defaultConfig))

	if err != nil {
		t.Fatalf("%#v\n", err)
	}

	expected := Config{}

	expected.Server.Address = "localhost"
	expected.Server.Port = 8080
	expected.Server.Endpoint = "/api/v1/cves"

	expected.Log.Level = "debug"

	expected.Timers.RequestTimeout = 2
	expected.Timers.CacheUpdateInterval = 60

	expected.SourcesTypes = map[string]cve.SourceType{
		"circl": cve.SourceType{
			ID: "id", Published: "Published", References: "references", Description: "summary",
		},
		"redhat": cve.SourceType{
			ID: "CVE", Published: "public_date", References: "resource_url", Description: "bugzilla_description",
		},
	}

	//queryParam, _ := cve.Parse("?after={{ lastNDays 2 \"2006-01-02\" }}")

	expected.Sources = map[string]cve.Source{
		"circl": cve.Source{
			Description: "circle source (last two days)", BaseURL: "http://cve.circl.lu/api/last/2", TypeName: "circl",
			Type: expected.SourcesTypes["circl"],
		},

		"redhat": cve.Source{
			Description: "redhat source", BaseURL: "http://access.redhat.com/labs/securitydataapi/cve.json", TypeName: "redhat",
			Type:       expected.SourcesTypes["redhat"],
			QueryParam: "?after={{ lastNDays 2 \"2006-01-02\" }}",
		},
	}

	if diff := deep.Equal(&expected, result); diff != nil {
		t.Error("Result not equal expected. Differences:")
		for _, d := range diff {
			t.Log(d)
		}
		t.Fail()
	}

	if len(expected.Sources) != len(result.Sources) {
		t.Fatalf("Result not equal expected. Different length: %#v != %#v", expected.Sources, result.Sources)
	}

}
