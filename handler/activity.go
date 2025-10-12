package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"short-url-generator/model"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
)

// LogActivity logs a user activity to Redis
func (uh *UserHandler) LogActivity(ctx context.Context, userID, action, ip, userAgent string, details map[string]interface{}) error {
	activity := model.ActivityLog{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
		IP:        ip,
		UserAgent: userAgent,
		Location:  "", // Can be enhanced with IP geolocation service
	}

	activityJSON, err := json.Marshal(activity)
	if err != nil {
		return fmt.Errorf("failed to marshal activity log: %w", err)
	}

	// Store in Redis list for the user (key: activity:{userID})
	key := fmt.Sprintf("activity:%s", userID)

	// Add to the beginning of the list (most recent first)
	if err := uh.redis.LPush(ctx, key, activityJSON).Err(); err != nil {
		return fmt.Errorf("failed to store activity log: %w", err)
	}

	// Keep only last 1000 activity logs per user
	if err := uh.redis.LTrim(ctx, key, 0, 999).Err(); err != nil {
		return fmt.Errorf("failed to trim activity log: %w", err)
	}

	// Set expiration to 90 days
	if err := uh.redis.Expire(ctx, key, 90*24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to set expiration on activity log: %w", err)
	}

	return nil
}

// GetActivityLogs retrieves activity logs for a user with pagination
func (uh *UserHandler) GetActivityLogs(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from JWT token
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		SendJSONError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"), "Authentication required")
		return
	}

	// Parse pagination parameters
	page := 1
	limit := 50
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Calculate Redis list range
	start := int64((page - 1) * limit)
	stop := int64(page*limit - 1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := fmt.Sprintf("activity:%s", userID)

	// Get total count
	total, err := uh.redis.LLen(ctx, key).Result()
	if err != nil && err != redis.Nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve activity logs")
		return
	}

	// Get activity logs
	activityStrings, err := uh.redis.LRange(ctx, key, start, stop).Result()
	if err != nil && err != redis.Nil {
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to retrieve activity logs")
		return
	}

	// Parse activity logs
	activities := make([]model.ActivityLog, 0, len(activityStrings))
	for _, activityStr := range activityStrings {
		var activity model.ActivityLog
		if err := json.Unmarshal([]byte(activityStr), &activity); err != nil {
			continue
		}
		activities = append(activities, activity)
	}

	// Filter by action type if specified
	if actionFilter := r.URL.Query().Get("action"); actionFilter != "" {
		filtered := make([]model.ActivityLog, 0)
		for _, activity := range activities {
			if activity.Action == actionFilter {
				filtered = append(filtered, activity)
			}
		}
		activities = filtered
	}

	// Calculate pagination metadata
	totalPages := int(total) / limit
	if int(total)%limit != 0 {
		totalPages++
	}

	response := map[string]interface{}{
		"activities": activities,
		"pagination": map[string]interface{}{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"totalPages": totalPages,
		},
	}

	SendJSONSuccess(w, http.StatusOK, response)
}

// GetRecentActivity retrieves the most recent activity logs (for dashboard)
func (uh *UserHandler) GetRecentActivity(ctx context.Context, userID string, limit int) ([]model.ActivityLog, error) {
	key := fmt.Sprintf("activity:%s", userID)

	// Get most recent logs
	activityStrings, err := uh.redis.LRange(ctx, key, 0, int64(limit-1)).Result()
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("failed to retrieve activity logs: %w", err)
	}

	// Parse activity logs
	activities := make([]model.ActivityLog, 0, len(activityStrings))
	for _, activityStr := range activityStrings {
		var activity model.ActivityLog
		if err := json.Unmarshal([]byte(activityStr), &activity); err != nil {
			continue
		}
		activities = append(activities, activity)
	}

	return activities, nil
}
