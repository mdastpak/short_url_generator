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

	// Log activity
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		details := map[string]interface{}{
			"method": "password",
		}
		if err := uh.LogActivity(activityCtx, userID, model.ActivityUserLogin, getIP(r), r.UserAgent(), details); err != nil {
			log.Error().Err(err).Msg("Failed to log login activity")
		}
	}()

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

// ForgotPassword handles POST /api/auth/forgot-password
// @Summary Request password reset
// @Description Send password reset magic link to email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.ForgotPasswordRequest true "Email address"
// @Success 200 {object} map[string]string "Reset link sent message"
// @Failure 400 {object} model.ErrorResponse "Invalid request"
// @Failure 429 {object} model.ErrorResponse "Too many requests"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/forgot-password [post]
func (uh *UserHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req model.ForgotPasswordRequest
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

	// Rate limiting: max 3 requests per hour per email
	rateLimitKey := "reset_attempts:" + req.Email
	attempts, err := uh.redis.Incr(ctx, rateLimitKey).Result()
	if err == nil {
		if attempts == 1 {
			uh.redis.Expire(ctx, rateLimitKey, time.Hour)
		}
		if attempts > 3 {
			SendJSONError(w, http.StatusTooManyRequests, errors.New("rate limit exceeded"), "Too many reset requests. Please try again in 1 hour.")
			return
		}
	}

	// Check if user exists (but don't reveal if they don't for security)
	emailKey := "user:email:" + req.Email
	userID, err := uh.redis.Get(ctx, emailKey).Result()
	if err == redis.Nil {
		// User doesn't exist, but return success message anyway (security best practice)
		SendJSONSuccess(w, http.StatusOK, map[string]string{
			"message": "If an account exists with this email, a password reset link has been sent.",
		})
		return
	} else if err != nil {
		log.Error().Err(err).Msg("Failed to get user ID")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to process request")
		return
	}

	// Get user data
	userKey := "user:" + userID
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONSuccess(w, http.StatusOK, map[string]string{
			"message": "If an account exists with this email, a password reset link has been sent.",
		})
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONSuccess(w, http.StatusOK, map[string]string{
			"message": "If an account exists with this email, a password reset link has been sent.",
		})
		return
	}

	// Generate reset token (UUID v4)
	token := uuid.New().String()

	// Create reset token object
	resetToken := model.ResetToken{
		Token:      token,
		UserID:     userID,
		Email:      req.Email,
		RequestIP:  getIP(r),
		UserAgent:  r.UserAgent(),
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * time.Minute), // 30 minutes expiration
		Used:       false,
	}

	// Save reset token to Redis
	tokenJSON, _ := json.Marshal(resetToken)
	tokenKey := "reset_token:" + token
	if err := uh.redis.Set(ctx, tokenKey, tokenJSON, 30*time.Minute).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to save reset token")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to process request")
		return
	}

	// Send password reset email
	if err := uh.emailService.SendPasswordReset(&user, token); err != nil {
		log.Error().Err(err).Msg("Failed to send password reset email")
		// Don't fail the request if email fails
	}

	log.Info().
		Str("email", req.Email).
		Str("user_id", userID).
		Str("ip", getIP(r)).
		Msg("Password reset requested")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "If an account exists with this email, a password reset link has been sent.",
	})
}

// ValidateResetToken handles GET /api/auth/reset-password?token=xxx
// @Summary Validate password reset token
// @Description Check if reset token is valid and not expired
// @Tags Authentication
// @Produce json
// @Param token query string true "Reset token (UUID)"
// @Success 200 {object} map[string]interface{} "Token valid"
// @Failure 400 {object} model.ErrorResponse "Invalid token format"
// @Failure 404 {object} model.ErrorResponse "Token not found or expired"
// @Failure 410 {object} model.ErrorResponse "Token already used"
// @Router /api/auth/reset-password [get]
func (uh *UserHandler) ValidateResetToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	token := r.URL.Query().Get("token")
	if token == "" {
		SendJSONError(w, http.StatusBadRequest, errors.New("missing token"), "Reset token is required")
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(token); err != nil {
		SendJSONError(w, http.StatusBadRequest, errors.New("invalid token format"), "Invalid reset token format")
		return
	}

	// Get token from Redis
	tokenKey := "reset_token:" + token
	tokenData, err := uh.redis.Get(ctx, tokenKey).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("token not found"), "Reset token not found or expired")
		return
	} else if err != nil {
		log.Error().Err(err).Msg("Failed to get reset token")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to validate token")
		return
	}

	var resetToken model.ResetToken
	if err := json.Unmarshal([]byte(tokenData), &resetToken); err != nil {
		log.Error().Err(err).Msg("Failed to parse reset token")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to validate token")
		return
	}

	// Check if token is already used
	if resetToken.Used {
		SendJSONError(w, http.StatusGone, errors.New("token already used"), "This reset link has already been used")
		return
	}

	// Check if token is expired
	if time.Now().After(resetToken.ExpiresAt) {
		uh.redis.Del(ctx, tokenKey)
		SendJSONError(w, http.StatusNotFound, errors.New("token expired"), "Reset token has expired. Please request a new one.")
		return
	}

	SendJSONSuccess(w, http.StatusOK, map[string]interface{}{
		"valid": true,
		"email": resetToken.Email,
	})
}

// ResetPassword handles POST /api/auth/reset-password
// @Summary Reset password with token
// @Description Reset user password using reset token from email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body model.ResetPasswordRequest true "Reset token and new password"
// @Success 200 {object} map[string]string "Password reset successful"
// @Failure 400 {object} model.ErrorResponse "Invalid request or weak password"
// @Failure 404 {object} model.ErrorResponse "Token not found or expired"
// @Failure 410 {object} model.ErrorResponse "Token already used"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/auth/reset-password [post]
func (uh *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var req model.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate token format
	if _, err := uuid.Parse(req.Token); err != nil {
		SendJSONError(w, http.StatusBadRequest, errors.New("invalid token format"), "Invalid reset token format")
		return
	}

	// Validate password strength
	if len(req.NewPassword) < 8 {
		SendJSONError(w, http.StatusBadRequest, errors.New("weak password"), "Password must be at least 8 characters")
		return
	}

	// Get token from Redis
	tokenKey := "reset_token:" + req.Token
	tokenData, err := uh.redis.Get(ctx, tokenKey).Result()
	if err == redis.Nil {
		SendJSONError(w, http.StatusNotFound, errors.New("token not found"), "Reset token not found or expired")
		return
	} else if err != nil {
		log.Error().Err(err).Msg("Failed to get reset token")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to reset password")
		return
	}

	var resetToken model.ResetToken
	if err := json.Unmarshal([]byte(tokenData), &resetToken); err != nil {
		log.Error().Err(err).Msg("Failed to parse reset token")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to reset password")
		return
	}

	// Check if token is already used
	if resetToken.Used {
		SendJSONError(w, http.StatusGone, errors.New("token already used"), "This reset link has already been used")
		return
	}

	// Check if token is expired
	if time.Now().After(resetToken.ExpiresAt) {
		uh.redis.Del(ctx, tokenKey)
		SendJSONError(w, http.StatusNotFound, errors.New("token expired"), "Reset token has expired. Please request a new one.")
		return
	}

	// Get user data
	userKey := "user:" + resetToken.UserID
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to reset password")
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to reset password")
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to reset password")
		return
	}

	// Update user password
	user.PasswordHash = string(hashedPassword)
	userJSON, _ := json.Marshal(user)
	if err := uh.redis.Set(ctx, userKey, userJSON, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to update user password")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to reset password")
		return
	}

	// Delete reset token immediately (single-use)
	uh.redis.Del(ctx, tokenKey)

	// Invalidate all refresh tokens for this user (force re-login everywhere)
	// Note: This requires implementing session management in future
	// For now, access tokens will expire naturally

	// Send password change alert email
	if err := uh.emailService.SendPasswordChangeAlert(&user, getIP(r), r.UserAgent()); err != nil {
		log.Error().Err(err).Msg("Failed to send password change alert")
	}

	// Log activity
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		details := map[string]interface{}{
			"method": "password_reset",
		}
		if err := uh.LogActivity(activityCtx, resetToken.UserID, model.ActivityPasswordChanged, getIP(r), r.UserAgent(), details); err != nil {
			log.Error().Err(err).Msg("Failed to log password reset activity")
		}
	}()

	log.Info().
		Str("email", resetToken.Email).
		Str("user_id", resetToken.UserID).
		Str("ip", getIP(r)).
		Msg("Password reset successful")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "Password reset successful. Please login with your new password.",
	})
}

// ChangePassword handles POST /api/user/change-password
// @Summary Change password
// @Description Change user password (requires current password)
// @Tags User
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body model.ChangePasswordRequest true "Current and new password"
// @Success 200 {object} map[string]string "Password changed successfully"
// @Failure 400 {object} model.ErrorResponse "Invalid request or weak password"
// @Failure 401 {object} model.ErrorResponse "Invalid current password or not authenticated"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/change-password [post]
func (uh *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID := r.Context().Value("userID")
	if userID == nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("not authenticated"), "Authentication required")
		return
	}
	userIDStr := userID.(string)

	var req model.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate new password strength
	if len(req.NewPassword) < 8 {
		SendJSONError(w, http.StatusBadRequest, errors.New("weak password"), "Password must be at least 8 characters")
		return
	}

	// Get user data
	userKey := "user:" + userIDStr
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to change password")
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to change password")
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("invalid password"), "Current password is incorrect")
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Failed to hash password")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to change password")
		return
	}

	// Update user password
	user.PasswordHash = string(hashedPassword)
	userJSON, _ := json.Marshal(user)
	if err := uh.redis.Set(ctx, userKey, userJSON, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to update user password")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to change password")
		return
	}

	// Send password change alert email
	if err := uh.emailService.SendPasswordChangeAlert(&user, getIP(r), r.UserAgent()); err != nil {
		log.Error().Err(err).Msg("Failed to send password change alert")
	}

	// Log activity
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		details := map[string]interface{}{
			"method": "manual_change",
		}
		if err := uh.LogActivity(activityCtx, userIDStr, model.ActivityPasswordChanged, getIP(r), r.UserAgent(), details); err != nil {
			log.Error().Err(err).Msg("Failed to log password change activity")
		}
	}()

	log.Info().
		Str("email", user.Email).
		Str("user_id", userIDStr).
		Str("ip", getIP(r)).
		Msg("Password changed successfully")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "Password changed successfully",
	})
}

// SetSecurityPhrase handles PUT /api/user/security-phrase
// @Summary Set security phrase
// @Description Set or update user's security phrase for email verification
// @Tags User
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body model.SetSecurityPhraseRequest true "Security phrase (3-50 characters)"
// @Success 200 {object} map[string]string "Security phrase updated"
// @Failure 400 {object} model.ErrorResponse "Invalid phrase"
// @Failure 401 {object} model.ErrorResponse "Not authenticated"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/security-phrase [put]
func (uh *UserHandler) SetSecurityPhrase(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID := r.Context().Value("userID")
	if userID == nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("not authenticated"), "Authentication required")
		return
	}
	userIDStr := userID.(string)

	var req model.SetSecurityPhraseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendJSONError(w, http.StatusBadRequest, err, "Invalid request body")
		return
	}

	// Validate and sanitize phrase
	phrase := strings.TrimSpace(req.SecurityPhrase)
	if len(phrase) < 3 || len(phrase) > 50 {
		SendJSONError(w, http.StatusBadRequest, errors.New("invalid phrase length"), "Security phrase must be 3-50 characters")
		return
	}

	// Sanitize phrase (remove HTML, control characters)
	phrase = sanitizeSecurityPhrase(phrase)

	// Get user data
	userKey := "user:" + userIDStr
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update security phrase")
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update security phrase")
		return
	}

	// Update security phrase
	user.SecurityPhrase = phrase
	userJSON, _ := json.Marshal(user)
	if err := uh.redis.Set(ctx, userKey, userJSON, 0).Err(); err != nil {
		log.Error().Err(err).Msg("Failed to update user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to update security phrase")
		return
	}

	// Log activity
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		details := map[string]interface{}{
			"phrase_length": len(phrase),
		}
		if err := uh.LogActivity(activityCtx, userIDStr, model.ActivitySecurityPhraseSet, getIP(r), r.UserAgent(), details); err != nil {
			log.Error().Err(err).Msg("Failed to log security phrase activity")
		}
	}()

	log.Info().
		Str("user_id", userIDStr).
		Msg("Security phrase updated")

	SendJSONSuccess(w, http.StatusOK, map[string]string{
		"message": "Security phrase updated successfully",
		"phrase":  phrase,
	})
}

// GetProfile handles GET /api/user/profile
// @Summary Get user profile
// @Description Get current user's profile information
// @Tags User
// @Security BearerAuth
// @Produce json
// @Success 200 {object} model.UserResponse "User profile"
// @Failure 401 {object} model.ErrorResponse "Not authenticated"
// @Failure 500 {object} model.ErrorResponse "Internal server error"
// @Router /api/user/profile [get]
func (uh *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get authenticated user ID
	userID := r.Context().Value("userID")
	if userID == nil {
		SendJSONError(w, http.StatusUnauthorized, errors.New("not authenticated"), "Authentication required")
		return
	}
	userIDStr := userID.(string)

	// Get user data
	userKey := "user:" + userIDStr
	userData, err := uh.redis.Get(ctx, userKey).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to load profile")
		return
	}

	var user model.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		log.Error().Err(err).Msg("Failed to parse user")
		SendJSONError(w, http.StatusInternalServerError, err, "Failed to load profile")
		return
	}

	SendJSONSuccess(w, http.StatusOK, user.ToResponse())
}

// Helper functions

// getIP extracts IP address from request
func getIP(r *http.Request) string {
	// Check X-Forwarded-For header first (reverse proxy)
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		// Get first IP if multiple
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	// Fall back to RemoteAddr
	ip = r.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}

// sanitizeSecurityPhrase removes dangerous characters from security phrase
func sanitizeSecurityPhrase(phrase string) string {
	// Remove control characters
	phrase = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, phrase)

	// Remove HTML tags (simple regex)
	// This is basic - for production, use a proper HTML sanitizer library
	phrase = strings.ReplaceAll(phrase, "<", "")
	phrase = strings.ReplaceAll(phrase, ">", "")

	return phrase
}
