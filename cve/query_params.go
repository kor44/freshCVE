package cve

import (
	"bytes"
	"text/template"
	"time"

	"github.com/pkg/errors"
)

func lastNDays(days int, format string) string {
	return time.Now().Add(time.Duration(-days) * 24 * time.Hour).Format(format)
}

var tmpl = template.New("query_params").Funcs(template.FuncMap{
	"lastNDays": lastNDays,
})

type QueryParam struct {
	tmpl *template.Template
}

func (param *QueryParam) Value() string {
	var w bytes.Buffer
	tmpl.Execute(&w, nil)
	return string(w.Bytes())
}

func Parse(param string) (*QueryParam, error) {
	t, err := tmpl.Parse(param)
	if err != nil {
		return nil, errors.Wrap(err, "Wrong query param syntax")
	}
	return &QueryParam{t}, nil
}
