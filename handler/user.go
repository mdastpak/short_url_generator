package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"short-url-generator/auth"
	"short-url-generator/email"
	"short-url-generator/model"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// UserHandler handles user authentication and management
type UserHandler struct {
	redis        *redis.Client
	jwtManager   *auth.JWTManager
	emailService *email.EmailService
	otpDuration  time.Duration
}

// NewUserHandler creates a new user handler
func NewUserHandler(rdb *redis.Client, jwtManager *auth.JWTManager, emailService *email.EmailService, otpDuration time.Duration) *UserHandler {
	return &UserHandler{
		redis:        rdb,
		jwtManager:   jwtManager,
		emailService: emailService,
		otpDuration:  otpDuration,
	}
}

// Register handles POST /api/auth/register
// @Summary Register a new user
// @Description Register with email and password, sends OTP for verification
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.RegisterRequest true "Registration data"
// @Success 200 {object} map[string]string "OTP sent message"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 409 {object} model.ErrorResponse "Email already exists"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/register [post]
func (uh *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req model.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate email
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		SendJSONError(w, http.StatusBadRequest, errors.New("invalid email"), "Please provide a valid email address")
		return
	}

	// Validate password
	if len(req.Password) < 8 {
		SendJSONError(w, http.StatusBadRequest, errors.New("weak password"), "Password must be at least 8 characters")
		return
	}

	// Check if email already exists
	emailKey := "user:email:" + req.Email
	existingUserID, err := uh.redis.Get(ctx, emailKey).Result()
	if err != redis.Nil {
		if err == nil {
			// Email exists - check if verified
			userKey := "user:" + existingUserID
			userData, _ := uh.redis.Get(ctx, userKey).Result()
			var existingUser model.User
			json.Unmarshal([]byte(userData), &existingUser)

			if existingUser.Verified {
				SendJSONError(w, http.StatusConflict, errors.New("email exists"), "An account with this email already exists. Please login.")
				return
			} else {
				// Unverified account - allow re-registration (will send new OTP)
				log.Info().Str("email", req.Email).Msg("Re-registering unverified account")
			}
		} else {
			log.Error().Err(err).Msg("Failed to check email existence")
			SendJSONError(w, http.StatusInternalServerError, err, "Failed to process registration")
			return
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to process registration")
		return
	}

	// Create user
	userID := uuid.New().String()
	user := model.User{
		ID:           userID,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Verified:     false,
		CreatedAt:    time.Now(),
		Active:       true,
	}

	// Save user to Redis
	userJSON, _ := json.Marshal(user)
	userKey := "user:" + userID
	if err := uh.redis.Set(ctx, userKey, userJSON, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to save user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to process registration")
		return
	}

	// Save email -> userID mapping
	if err := uh.redis.Set(ctx, emailKey, userID, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to save email mapping")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to process registration")
		return
	}

	// Generate and send OTP
	otpCode, err := email.GenerateOTP()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate OTP")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to send verification code")
		return
	}

	// Save OTP to Redis with expiration
	otp := model.OTP{
		Email:     req.Email,
		Code:      otpCode,
		ExpiresAt: time.Now().Add(uh.otpDuration),
		Attempts:  0,
	}
	otpJSON, _ := json.Marshal(otp)
	otpKey := "otp:" + req.Email
	if err := uh.redis.Set(ctx, otpKey, otpJSON, uh.otpDuration).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to save OTP")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to send verification code")
		return
	}

	// Send OTP email
	if err := uh.emailService.SendOTP(req.Email, otpCode); err != nil {
		log.Error().Err(err).Msg("Failed to send OTP email")
		// Don't fail the request if email fails in development
	}

	log.Info().
		Str("email", req.Email).
		Str("user_id", userID).
		Msg("User registered, OTP sent")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "Registration successful. Please check your email for the verification code.",
		"email":   req.Email,
	})
}

// VerifyOTP handles POST /api/auth/verify-otp
// @Summary Verify OTP code
// @Description Verify email with OTP code sent during registration
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.VerifyOTPRequest true "OTP verification data"
// @Success 200 {object} map[string]string "Verification success message"
// @Failure 400 {object} model.ErrorResponse "Invalid request or OTP"
// @Failure 404 {object} model.ErrorResponse "OTP not found or expired"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/verify-otp [post]
func (uh *UserHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req model.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.OTP = strings.TrimSpace(req.OTP)

	// Get OTP from Redis
	otpKey := "otp:" + req.Email
	otpData, err := uh.redis.Get(ctx, otpKey).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("otp expired"), "Verification code expired or not found. Please request a new code.")
		return
	} else if err != nil {
		log.Error().Err(err).Msg("Failed to get OTP")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify code")
		return
	}

	var otp model.OTP
	if err := json.Unmarshal([]byte(otpData), &otp); err != nil {
		log.Error().Err(err).Msg("Failed to parse OTP")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify code")
		return
	}

	// Check expiration
	if time.Now().After(otp.ExpiresAt) {
		uh.redis.Del(ctx, otpKey)
		SendJSONError(w, http.StatusBadRequest, errors.New("otp expired"), "Verification code has expired. Please request a new code.")
		return
	}

	// Check attempts
	if otp.Attempts >= 5 {
		uh.redis.Del(ctx, otpKey)
		SendJSONError(w, http.StatusBadRequest, errors.New("too many attempts"), "Too many failed attempts. Please request a new code.")
		return
	}

	// Verify OTP
	if otp.Code != req.OTP {
		// Increment attempts
		otp.Attempts++
		otpJSON, _ := json.Marshal(otp)
		uh.redis.Set(ctx, otpKey, otpJSON, time.Until(otp.ExpiresAt))

		SendJSONError(w, http.StatusBadRequest, errors.New("invalid otp"), "Invalid verification code. Please try again.")
		return
	}

	// OTP is valid - mark user as verified
	emailKey := "user:email:" + req.Email
	userID, err := uh.redis.Get(ctx, emailKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user ID")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify account")
		return
	}

	userKey := "user:" + userID
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify account")
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify account")
		return
	}

	// Update user as verified
	user.Verified = true
	userJSON, _ := json.Marshal(user)
	if err := uh.redis.Set(ctx, userKey, userJSON, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to update user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to verify account")
		return
	}

	// Delete OTP
	uh.redis.Del(ctx, otpKey)

	// Send welcome email
	uh.emailService.SendWelcomeEmail(req.Email)

	log.Info().
		Str("email", req.Email).
		Str("user_id", userID).
		Msg("User verified successfully")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully! You can now login.",
	})
}

// Login handles POST /api/auth/login
// @Summary Login
// @Description Login with email and password, returns access and refresh tokens
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "Login credentials"
// @Success 200 {object} model.LoginResponse "Login successful with tokens"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 401 {object} model.ErrorResponse "Invalid credentials"
// @Failure 403 {object} model.ErrorResponse "Email not verified or account inactive"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/login [post]
func (uh *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Get user by email
	emailKey := "user:email:" + req.Email
	userID, err := uh.redis.Get(ctx, emailKey).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("invalid credentials"), "Invalid email or password")
		return
	} else if err != nil {
		log.Error().Err(err).Msg("Failed to get user ID")
		SendJSONError(w, http.StatusInternalServerError, err, "Login failed")
		return
	}

	userKey := "user:" + userID
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONError(w, http.StatusInternalServerError, err, "Login failed")
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONError(w, http.StatusInternalServerError, err, "Login failed")
		return
	}

	// Check if verified
	if !user.Verified {
		SendJSONError(w, http.StatusForbidden, errors.New("not verified"), "Please verify your email before logging in")
		return
	}

	// Check if active
	if !user.Active {
		SendJSONError(w, http.StatusForbidden, errors.New("account inactive"), "Your account has been disabled. Please contact support.")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("invalid credentials"), "Invalid email or password")
		return
	}

	// Generate tokens
	accessToken, err := uh.jwtManager.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		SendJSONError(w, http.StatusInternalServerError, err, "Login failed")
		return
	}

	refreshToken, err := uh.jwtManager.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate refresh token")
		SendJSONError(w, http.StatusInternalServerError, err, "Login failed")
		return
	}

	// Update last login time
	user.LastLoginAt = time.Now()
	userJSON, _ := json.Marshal(user)
	uh.redis.Set(ctx, userKey, userJSON, 0)

	log.Info().
		Str("email", req.Email).
		Str("user_id", userID).
		Msg("User logged in successfully")

	SendJSONSuccess(w, http.StatusOK, model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user.ToResponse(),
	})
}

// RefreshToken handles POST /api/auth/refresh
// @Summary Refresh access token
// @Description Get a new access token using refresh token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} map[string]string "New access token"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 401 {object} model.ErrorResponse "Invalid or expired refresh token"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/refresh [post]
func (uh *UserHandler) ServeUserPanel(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "handler/user_panel.html")
}

func (uh *UserHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req model.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate refresh token
	claims, err := uh.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		SendJSONError(w, http.StatusUnauthorized, err, "Invalid or expired refresh token")
		return
	}

	// Generate new access token
	accessToken, err := uh.jwtManager.GenerateAccessToken(claims.UserID, claims.Email)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		SendJSONError(w, http.StatusInternalServerError, err, "Token refresh failed")
		return
	}

	log.Info().
		Str("user_id", claims.UserID).
		Msg("Access token refreshed")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"accessToken": accessToken,
	})
}

// ResendOTP handles POST /api/auth/resend-otp
// @Summary Resend OTP code
// @Description Resend verification code to email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body map[string]string true "Email address"
// @Success 200 {object} map[string]string "OTP sent message"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 404 {object} model.ErrorResponse "User not found"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/resend-otp [post]
func (uh *UserHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Check if user exists
	emailKey := "user:email:" + req.Email
	_, err := uh.redis.Get(ctx, emailKey).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("user not found"), "No account found with this email")
		return
	}

	// Generate new OTP
	otpCode, err := email.GenerateOTP()
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate OTP")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to send verification code")
		return
	}

	// Save OTP to Redis
	otp := model.OTP{
		Email:     req.Email,
		Code:      otpCode,
		ExpiresAt: time.Now().Add(uh.otpDuration),
		Attempts:  0,
	}
	otpJSON, _ := json.Marshal(otp)
	otpKey := "otp:" + req.Email
	if err := uh.redis.Set(ctx, otpKey, otpJSON, uh.otpDuration).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to save OTP")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to send verification code")
		return
	}

	// Send OTP email
	if err := uh.emailService.SendOTP(req.Email, otpCode); err != nil {
		log.Error().Err(err).Msg("Failed to send OTP email")
	}

	log.Info().Str("email", req.Email).Msg("OTP resent")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "Verification code sent. Please check your email.",
	})
}

// GetUserURLs handles GET /api/user/urls
// @Summary Get all URLs for authenticated user
// @Description Retrieve all short URLs created by the authenticated user
// @Tags User
// @Security BearerAuth
// @Produce json
// @Success 200 {object} map[string]interface{} "List of user's URLs"
// @Failure 401 {object} model.ErrorResponse "Unauthorized"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/urls [get]
func (uh *UserHandler) GetUserURLs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get userID from context (set by auth middleware)
	userID := r.Context().Value("userID")
	if userID == nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("user not authenticated"), "")
		return
	}

	userIDStr := userID.(string)

	// Get all URL keys from Redis
	keys, err := uh.redis.Keys(ctx, "*").Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get URL keys")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to fetch URLs")
		return
	}

	// Filter URLs belonging to this user
	var userURLs []model.URL
	var totalClicks int64
	var activeCount int
	var scheduledCount int

	for _, key := range keys {
		// Skip non-URL keys (otp, user, logs, etc.)
		if strings.HasPrefix(key, "otp:") || strings.HasPrefix(key, "user:") ||
			strings.HasPrefix(key, "logs:") || strings.HasPrefix(key, "url_index") ||
			strings.HasPrefix(key, "management_index") || strings.HasPrefix(key, "security:") ||
			key == "admin_api_key" || key == "malicious_urls" || key == "blocked_ips" ||
			strings.HasSuffix(key, "_urls") {
			continue
		}

		// Get URL data
		urlData, err := uh.redis.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var urlObj model.URL
		if err := json.Unmarshal(urlData, &urlObj); err != nil {
			continue
		}

		// Check if URL belongs to this user
		if urlObj.UserID == userIDStr {
			userURLs = append(userURLs, urlObj)
			totalClicks += int64(urlObj.CurrentUsage)

			if urlObj.Active {
				activeCount++
			}

			if !urlObj.ScheduledStart.IsZero() || !urlObj.ScheduledEnd.IsZero() {
				scheduledCount++
			}
		}
	}

	// Calculate stats
	stats := map[string]interface{}{
		"totalUrls":     len(userURLs),
		"activeUrls":    activeCount,
		"totalClicks":   totalClicks,
		"scheduledUrls": scheduledCount,
		"urls":          userURLs,
	}

	SendJSONSuccess(w, http.StatusOK, stats)
}
