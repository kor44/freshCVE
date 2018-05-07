package cve

import (
	"github.com/pkg/errors"
)

// Source of CVE
type Source struct {
	Name    string
	URL     string
	SourceTypeName string
	Type  SourceType
}

// Parse data from http responce
func (src *Source) ParseData(data []map[string]interface{}) ([]Item, error) {
	var items []Item

	for _, r := range data {
		item := Item{
			ID:          r[src.Type.ID].(string),
			Source:      src.URL,
			Published:   r[src.Type.Published],
			References:  r[src.Type.References],
			Description: r[src.Type.Description],
		}

		items = append(items, item)
	}

	return items, nil
}

// Parse source configuration. Also make some additional checks
func ParseSourcesCfg(types map[string]interface{}, srcs []map[string]string) ([]Source, error) {
	srcTypes, err := parseTypesCfg(types)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse source configuration")
	}

	sources := []Source{}
	for _, srcCfg := range srcs {
		var src Source
		for k, v := range srcCfg {
			switch k {
			case "name":
				src.Name = v
			case "url":
				src.URL = v
			case "type":
				src.SourceTypeName = v
				typeFields, ok := srcTypes[v]
				if !ok {
					return nil, errors.Errorf("Unknown source type: %s", v)
				}
				src.Type = typeFields

			default:
				err := errors.Errorf("Unknown param in source description: %s", k)
				return nil, err
			}
		}
		sources = append(sources, src)
	}

	return sources, nil
}

type SourceType struct {
	ID          string
	Published   string
	References  string
	Description string
}

func parseTypesCfg(cfg map[string]interface{}) (map[string]SourceType, error) {
	srcTypes := map[string]SourceType{}

	for typeName, fields := range cfg {
		fields := fields.(map[string]interface{})

		t := SourceType{}
		for fieldName, srcFieldName := range fields {
			srcFieldName, ok := srcFieldName.(string)
			if !ok {
				return nil, errors.Errorf("Field '%s' incorrect value '%'", fieldName, srcFieldName)
			}

			switch fieldName {
			case "ID":
				//t["ID"] = srcFieldName
				t.ID = srcFieldName
			case "Published":
				//t["Published"] = srcFieldName
				t.Published = srcFieldName
			case "References":
				//t["References"] = srcFieldName
				t.References = srcFieldName
			case "Description":
				//t["Description"] = srcFieldName
				t.Description = srcFieldName
			default:
				return nil, errors.Errorf("Unknow field name: %s", fieldName)
			}
		}
		srcTypes[typeName] = t
	}

	return srcTypes, nil
}

// Item is used to store one CVE item
type Item struct {
	ID          string      `json:"id"`
	Source      string      `json:"source"`
	Published   interface{} `json:"published"`
	References  interface{} `json:"references"`
	Description interface{} `json:"description"`
}