package utils

import "strings"

// ReservedSlugs is a list of slugs that cannot be used as custom short URLs
// These are reserved for system routes, API endpoints, and common administrative paths
var ReservedSlugs = []string{
	// System routes
	"health",
	"metrics",
	"cache",
	"shorten",
	"api",
	"v1",
	"v2",

	// Administrative
	"admin",
	"dashboard",
	"settings",
	"config",
	"status",

	// Analytics & Stats
	"stats",
	"analytics",
	"reports",
	"logs",

	// Documentation
	"docs",
	"documentation",
	"swagger",
	"openapi",
	"help",
	"about",

	// Static assets
	"static",
	"assets",
	"public",
	"images",
	"css",
	"js",
	"fonts",

	// Features
	"qr",
	"preview",
	"redirect",
	"short",
	"link",
	"url",

	// Authentication (future)
	"login",
	"logout",
	"register",
	"signup",
	"signin",
	"auth",
	"user",
	"account",
	"profile",

	// Common words to avoid confusion
	"home",
	"index",
	"root",
	"test",
	"example",
	"demo",
	"sample",
}

// IsReservedSlug checks if a slug is in the reserved list
// Case-insensitive comparison
func IsReservedSlug(slug string) bool {
	slugLower := strings.ToLower(slug)
	for _, reserved := range ReservedSlugs {
		if slugLower == reserved {
			return true
		}
	}
	return false
}
