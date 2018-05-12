package main

var defaultConfig = `
// Address and port to listen
// address: TCP address to listen on (default - localhost)
// port: TCP port to listen on (default - 8080)
// endpoint: (default /api/v1/cves)
server {
	address = "localhost"
	port = 8080
	endpoint = "/api/v1/cves"
}

// Log configuration
// file: name of log file. If empty output to stdout
// level: panic, fatal, error, warn, info, debug (default - info)
log {
	file  = ""
	level = "debug"
}

// Timers
timers {
	// Timeout for request sending to source (seconds)
	request_timeout = 2
	
	// Period to update data from source (seconds)
	cache_update_interval = 60
}

// Source type configuratio Need specify mapping from source JSON fields to target
// Only JSON format is supported
sources_types {
	"circl" {
		ID 		    = "id"
		Published   = "Published"
		References  = "references"
		Description = "summary"
	}
	
	"redhat" {
		"ID" = "CVE"
		"Published"= "public_date"
		"References" = "resource_url"
		"Description" = "bugzilla_description"
	}
}
	
// List of CVE sources
sources {
	circl {
		// Description of source
		description = "circle source (last two days)"
		
		url = "http://cve.circl.lu/api/last/2"
		
		// Type must match one of configured above
		type = "circl"
	}
	
	redhat {
		description = "redhat source"
		
		url = "http://access.redhat.com/labs/securitydataapi/cve.json"
		
		type = "redhat"
		
		// Specify additional query parameter string 
		// For example at 5 May 2018: ?after={{ lastNDays 2 \"2006-01-02\" }} produces ?after=2018-05-03
		query_param = "?after={{ lastNDays 2 \"2006-01-02\" }}"
	}
}
`
