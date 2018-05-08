package cve

import (
	"testing"
	"time"

	"github.com/go-test/deep"
)

func TestQueryParams(t *testing.T) {
	testCases := []struct {
		Name     string
		Input    string
		Expected string
	}{
		{"lastNDays", `?date={{ lastNDays 2 "2006-01-02"}}`,
			"?date=" + time.Now().Add(-2*24*time.Hour).Format("2006-01-02")},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := Parse(tc.Input)
			if err != nil {
				t.Error(err)
				t.Fail()
			}

			if diff := deep.Equal(tc.Expected, result.Value()); diff != nil {
				t.Error("Result not equal expected. Differences:")
				for _, d := range diff {
					t.Log(d)
				}
				t.Fail()
			}
		})
	}
}
