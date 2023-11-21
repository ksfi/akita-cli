package trace

import (
	"regexp"
	"strings"

	"github.com/akitasoftware/akita-cli/learn"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/trackers"
)

func compileRegex(matchers []*regexp.Regexp) *regexp.Regexp {
	matchersStr := make([]string, 0, len(matchers))
	for _, r := range matchers {
		matchersStr = append(matchersStr, r.String())
	}
	ret, _ := regexp.Compile(strings.Join(matchersStr, "|"))
	return ret
}

// Filters out HTTP paths.
func NewHTTPPathFilterCollector(matchers []*regexp.Regexp, col Collector) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			if r.URL != nil {
				compiledRegex := compileRegex(matchers)
				return !compiledRegex.MatchString(r.URL.Path)
			}
			return true
		},
	}
}

// Filter out matching HTTP hosts
func NewHTTPHostFilterCollector(matchers []*regexp.Regexp, col Collector) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			compiledRegex := compileRegex(matchers)
			return !compiledRegex.MatchString(r.Host)
		},
	}
}

// Allows only matching paths
func NewHTTPPathAllowlistCollector(matchers []*regexp.Regexp, col Collector) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			if r.URL != nil {
				compiledRegex := compileRegex(matchers)
				return compiledRegex.MatchString(r.URL.Path)
			}
			return false
		},
	}
}

// Allows only matching hosts
func NewHTTPHostAllowlistCollector(matchers []*regexp.Regexp, col Collector) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			compiledRegex := compileRegex(matchers)
			return compiledRegex.MatchString(r.URL.Path)
		},
	}
}

// Filters out third-party trackers.
func New3PTrackerFilterCollector(col Collector) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			if r.URL != nil {
				return !trackers.IsTrackerDomain(r.URL.Host)
			}
			return true
		},
	}
}

// Generic filter collector to filter out requests that match a custom filter
// function. Handles filtering out the corresponding responses as well.
type genericRequestFilter struct {
	Collector Collector

	// Returns true if the request should be included.
	filterFunc func(akinet.HTTPRequest) bool

	// Records witness IDs of filtered requests so we can filter out the
	// corresponding responses.
	// NOTE: we're assuming that we always see the request before the
	// corresponding response, which should be generally true, with the exception
	// of observing a response without request due to packet capture starting
	// mid-connection.
	filteredIDs map[akid.WitnessID]struct{}
}

func (fc *genericRequestFilter) Process(t akinet.ParsedNetworkTraffic) error {
	include := true
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		if fc.filterFunc != nil && !fc.filterFunc(c) {
			include = false

			if fc.filteredIDs == nil {
				fc.filteredIDs = map[akid.WitnessID]struct{}{}
			}
			fc.filteredIDs[learn.ToWitnessID(c.StreamID, c.Seq)] = struct{}{}
		}
	case akinet.HTTPResponse:
		if _, ok := fc.filteredIDs[learn.ToWitnessID(c.StreamID, c.Seq)]; ok {
			include = false
		}
	}

	if include {
		return fc.Collector.Process(t)
	}
	return nil
}

func (fc *genericRequestFilter) Close() error {
	return fc.Collector.Close()
}
