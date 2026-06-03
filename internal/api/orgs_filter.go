package api

import "strings"

// OrgFilterOptions controls which organizations are included when scanning all orgs.
type OrgFilterOptions struct {
	NameFilter string
	GroupID    string
	Exclude    []string
}

// OrgMatchesFilter reports whether an organization matches the include name/slug filter.
func OrgMatchesFilter(org Organization, filter string) bool {
	if filter == "" {
		return true
	}
	needle := strings.ToLower(strings.TrimSpace(filter))
	return strings.Contains(strings.ToLower(org.Attrs.Name), needle) ||
		strings.Contains(strings.ToLower(org.Attrs.Slug), needle)
}

// OrgIsExcluded reports whether an organization matches any exclude pattern.
func OrgIsExcluded(org Organization, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if strings.EqualFold(org.ID, pattern) || strings.Contains(strings.ToLower(org.ID), pattern) {
			return true
		}
		if strings.Contains(strings.ToLower(org.Attrs.Name), pattern) {
			return true
		}
		if strings.Contains(strings.ToLower(org.Attrs.Slug), pattern) {
			return true
		}
	}
	return false
}

// ApplyOrgFilters returns organizations matching include filters and not excluded.
func ApplyOrgFilters(orgs []Organization, opts OrgFilterOptions) []Organization {
	filtered := make([]Organization, 0, len(orgs))
	for _, org := range orgs {
		if !OrgMatchesFilter(org, opts.NameFilter) {
			continue
		}
		if OrgIsExcluded(org, opts.Exclude) {
			continue
		}
		filtered = append(filtered, org)
	}
	return filtered
}

// ParseExcludePatterns splits a comma-separated exclude list into patterns.
func ParseExcludePatterns(exclude string) []string {
	if exclude == "" {
		return nil
	}
	parts := strings.Split(exclude, ",")
	patterns := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			patterns = append(patterns, part)
		}
	}
	return patterns
}

// FilterOrganizations returns organizations matching the optional name/slug filter.
func FilterOrganizations(orgs []Organization, filter string) []Organization {
	return ApplyOrgFilters(orgs, OrgFilterOptions{NameFilter: filter})
}
