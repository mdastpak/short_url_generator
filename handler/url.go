package handler

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	mathRand "math/rand"
	"net/http"
	"strconv"
	"time"

	"short-url-generator/config"
	"short-url-generator/model"
	redisClient "short-url-generator/redis"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
)

var rdb *redis.Client
var charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

func InitHandlers(cfg config.RedisConfig) {
	rdb = redisClient.NewClient(cfg)
}

func generateRandomString(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}

func CreateShortURL(w http.ResponseWriter, r *http.Request) {
	// Parse JSON data
	var input struct {
		OriginalURL string `json:"originalURL"`
		Expiry      string `json:"expiry"`
		MaxUsage    string `json:"maxUsage"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		log.Printf("Error parsing JSON data: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	originalURL := input.OriginalURL
	if originalURL == "" {
		log.Println("Original URL is empty")
		http.Error(w, "Bad Request: Original URL is required", http.StatusBadRequest)
		return
	}
	expiry := input.Expiry
	maxUsage := input.MaxUsage

	var url model.URL
	url.OriginalURL = originalURL
	var err error
	if expiry != "" {
		url.Expiry, err = time.Parse(time.RFC3339, expiry)
		if err != nil {
			log.Printf("Error parsing expiry time: %v", err)
			http.Error(w, "Bad Request: Invalid expiry time format", http.StatusBadRequest)
			return
		}
	}
	if maxUsage != "" {
		url.MaxUsage, err = strconv.Atoi(maxUsage)
		if err != nil {
			log.Printf("Error parsing max usage: %v", err)
			http.Error(w, "Bad Request: Invalid max usage format", http.StatusBadRequest)
			return
		}
	}

	// Generate a short URL
	shortURLLength := 8 + mathRand.Intn(3)
	url.ShortURL, err = generateRandomString(shortURLLength)
	if err != nil {
		log.Printf("Error generating short URL: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	url.CreatedAt = time.Now()

	// Convert URL to JSON for storage
	urlData, err := json.Marshal(url)
	if err != nil {
		log.Printf("Error marshalling URL data: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Store URL data in Redis
	if err := rdb.Set(context.Background(), url.ShortURL, urlData, 0).Err(); err != nil {
		log.Printf("Error storing URL data in Redis: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	fullShortURL := fmt.Sprintf("%s://%s/%s", "http", r.Host, url.ShortURL)
	log.Printf("Short URL created: %s -> %s", fullShortURL, url.OriginalURL)

	response := map[string]string{
		"originalURL": url.OriginalURL,
		"shortURL":    fullShortURL,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RedirectURL(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	shortURL := vars["shortURL"]

	// Fetch the URL data from Redis
	urlData, err := rdb.Get(context.Background(), shortURL).Bytes()
	if err == redis.Nil {
		log.Printf("URL not found: %s", shortURL)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "URL not found"}`, http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("Error retrieving URL data from Redis: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	var url model.URL
	if err := json.Unmarshal(urlData, &url); err != nil {
		log.Printf("Error unmarshalling URL data: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Check for expiry
	if !url.Expiry.IsZero() && time.Now().After(url.Expiry) {
		log.Printf("URL expired: %s", shortURL)
		// Transfer to expired list
		if err := rdb.RPush(context.Background(), "expired_urls", shortURL).Err(); err != nil {
			log.Printf("Error transferring URL to expired list: %v", err)
		}
		if err := rdb.Del(context.Background(), shortURL).Err(); err != nil {
			log.Printf("Error deleting expired URL from Redis: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "URL expired"}`, http.StatusGone)
		return
	}

	// Check usage limit
	if url.MaxUsage > 0 && url.CurrentUsage >= url.MaxUsage {
		log.Printf("URL usage limit exceeded: %s", shortURL)
		// Transfer to used up list
		if err := rdb.RPush(context.Background(), "usedup_urls", shortURL).Err(); err != nil {
			log.Printf("Error transferring URL to used up list: %v", err)
		}
		if err := rdb.Del(context.Background(), shortURL).Err(); err != nil {
			log.Printf("Error deleting used up URL from Redis: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "URL usage limit exceeded"}`, http.StatusForbidden)
		return
	}

	// Increment usage count
	url.CurrentUsage++
	urlData, err = json.Marshal(url)
	if err != nil {
		log.Printf("Error marshalling URL data: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}
	if err := rdb.Set(context.Background(), shortURL, urlData, 0).Err(); err != nil {
		log.Printf("Error updating URL usage in Redis: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Log the access
	logEntry := model.URLLog{
		ShortURL:   shortURL,
		AccessedAt: time.Now(),
		IP:         r.RemoteAddr,
		UserAgent:  r.Header.Get("User-Agent"),
		Referer:    r.Header.Get("Referer"),
	}
	logData, err := json.Marshal(logEntry)
	if err != nil {
		log.Printf("Error marshalling log data: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}
	if err := rdb.RPush(context.Background(), "logs:"+shortURL, logData).Err(); err != nil {
		log.Printf("Error logging URL access in Redis: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error": "Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("Redirecting to: %s", url.OriginalURL)
	http.Redirect(w, r, url.OriginalURL, http.StatusMovedPermanently)
}
