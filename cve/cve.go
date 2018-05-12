package cve

import (
	"github.com/pkg/errors"
)

// Item is used to store one CVE item
type Item struct {
	ID          string      `json:"id"`
	Source      string      `json:"source"`
	Published   interface{} `json:"published"`
	References  interface{} `json:"references"`
	Description interface{} `json:"description"`
}

// SourceType defines json field maping
type SourceType struct {
	ID          string
	Published   string
	References  string
	Description string
}

// Source of CVE
type Source struct {
	Description string      `hcl:"description"`
	BaseURL     string      `hcl:"url"`
	TypeName    string      `hcl:"type"`
	Type        SourceType  `hcl:"-"`
	QueryParam  string      `hcl:"query_param"`
	queryParam  *QueryParam `hcl:"-"`
}

func (src *Source) URL() string {
	if src.queryParam == nil {
		return src.BaseURL
	}

	url := src.BaseURL + src.queryParam.Value()

	return url
}

// Parse data from http responce
func (src *Source) ParseData(data []map[string]interface{}) ([]Item, error) {
	var items []Item

	for _, r := range data {
		item := Item{
			ID:          r[src.Type.ID].(string),
			Source:      src.BaseURL,
			Published:   r[src.Type.Published],
			References:  r[src.Type.References],
			Description: r[src.Type.Description],
		}

		items = append(items, item)
	}

	return items, nil
}

func ParseConfig(srcTypes map[string]SourceType, srcs map[string]Source) error {
	// check all fields of type configuration is not empty
	for typeName, typeCfg := range srcTypes {
		if typeCfg.ID == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'ID' parameter", typeName)
		}
		if typeCfg.Description == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'Description' parameter", typeName)
		}
		if typeCfg.Published == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'Published' parameter", typeName)
		}
		if typeCfg.References == "" {
			return errors.Errorf("Source type '%s' configuration error. Need config 'References' parameter", typeName)
		}
	}

	// check source configuration is correct
	for srcName, srcCfg := range srcs {
		if srcCfg.TypeName == "" {
			return errors.Errorf("Source '%s' configuration error. Need config  source type", srcName)
		}

		srcType, ok := srcTypes[srcCfg.TypeName]
		if !ok {
			return errors.Errorf("Source '%s' configuration error. Unknown source type '%s'", srcName, srcCfg.TypeName)
		}
		srcCfg.Type = srcType

		// check query parameter
		query, err := ParseQueryParam(srcCfg.QueryParam)
		if err != nil {
			err := errors.Errorf("incorrect 'query_param' value: %s", err)
			return err
		}
		srcCfg.queryParam = query

		// OK
		srcs[srcName] = srcCfg
	}

	return nil
}
