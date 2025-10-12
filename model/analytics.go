package model

// UserAnalytics represents aggregated user analytics data
type UserAnalytics struct {
	TotalURLs        int                `json:"totalUrls"`        // Total number of URLs created
	ActiveURLs       int                `json:"activeUrls"`       // Number of active URLs
	TotalClicks      int64              `json:"totalClicks"`      // Total clicks across all URLs
	ClicksByDay      []TimeSeriesPoint  `json:"clicksByDay"`      // Time-series data for clicks
	DeviceBreakdown  map[string]int     `json:"deviceBreakdown"`  // Clicks by device type (mobile/desktop/tablet)
	BrowserBreakdown map[string]int     `json:"browserBreakdown"` // Clicks by browser
	TopURLs          []URLStats         `json:"topUrls"`          // Top performing URLs by clicks
	RecentActivity   []ActivityLog      `json:"recentActivity"`   // Recent user activities
}

// TimeSeriesPoint represents a point in time-series data
type TimeSeriesPoint struct {
	Date  string `json:"date"`  // Date in "YYYY-MM-DD" format
	Value int64  `json:"value"` // Number of clicks on this date
}

// URLStats represents statistics for a single URL
type URLStats struct {
	ShortURL     string `json:"shortURL"`     // Short URL identifier
	OriginalURL  string `json:"originalURL"`  // Original destination URL
	Clicks       int    `json:"clicks"`       // Total number of clicks
	LastAccessed string `json:"lastAccessed"` // Last access timestamp (ISO 8601)
}
