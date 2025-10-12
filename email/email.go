package email

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/smtp"

	"github.com/rs/zerolog/log"
)

// EmailService handles sending emails
type EmailService struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
	Enabled      bool
}

// NewEmailService creates a new email service
func NewEmailService(host, port, username, password, fromEmail, fromName string, enabled bool) *EmailService {
	return &EmailService{
		SMTPHost:     host,
		SMTPPort:     port,
		SMTPUsername: username,
		SMTPPassword: password,
		FromEmail:    fromEmail,
		FromName:     fromName,
		Enabled:      enabled,
	}
}

// SendOTP sends an OTP code via email
func (es *EmailService) SendOTP(toEmail, otpCode string) error {
	if !es.Enabled {
		log.Warn().Msg("Email service disabled - OTP not sent")
		// In development, just log the OTP
		log.Info().Str("email", toEmail).Str("otp", otpCode).Msg("OTP Code (email disabled)")
		return nil
	}

	subject := "Your Verification Code"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .otp-code { background: #667eea; color: white; font-size: 32px; font-weight: bold; padding: 20px; text-align: center; border-radius: 8px; letter-spacing: 8px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Email Verification</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Thank you for registering with Short URL Generator. Please use the following code to verify your email address:</p>
            <div class="otp-code">%s</div>
            <p>This code will expire in <strong>10 minutes</strong>.</p>
            <p>If you didn't request this code, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2025 Short URL Generator. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, otpCode)

	return es.sendEmail(toEmail, subject, body)
}

// SendWelcomeEmail sends a welcome email after successful verification
func (es *EmailService) SendWelcomeEmail(toEmail string) error {
	if !es.Enabled {
		log.Warn().Msg("Email service disabled - Welcome email not sent")
		return nil
	}

	subject := "Welcome to Short URL Generator!"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 Welcome!</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Your email has been successfully verified! Welcome to Short URL Generator.</p>
            <p>You can now:</p>
            <ul>
                <li>Create unlimited short URLs</li>
                <li>Manage your URLs from the dashboard</li>
                <li>Set custom domains</li>
                <li>Password-protect your URLs</li>
                <li>Schedule URL activation</li>
                <li>Create URL aliases</li>
            </ul>
            <p>Get started by logging into your dashboard.</p>
        </div>
        <div class="footer">
            <p>© 2025 Short URL Generator. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`)

	return es.sendEmail(toEmail, subject, body)
}

// sendEmail sends an email using SMTP
func (es *EmailService) sendEmail(to, subject, body string) error {
	from := fmt.Sprintf("%s <%s>", es.FromName, es.FromEmail)

	msg := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"\r\n"+
			"%s\r\n",
		from, to, subject, body,
	))

	auth := smtp.PlainAuth("", es.SMTPUsername, es.SMTPPassword, es.SMTPHost)
	addr := fmt.Sprintf("%s:%s", es.SMTPHost, es.SMTPPort)

	err := smtp.SendMail(addr, auth, es.FromEmail, []string{to}, msg)
	if err != nil {
		log.Error().Err(err).Str("to", to).Msg("Failed to send email")
		return err
	}

	log.Info().Str("to", to).Str("subject", subject).Msg("Email sent successfully")
	return nil
}

// SendPasswordReset sends a password reset email with magic link
func (es *EmailService) SendPasswordReset(user interface{}, token string) error {
	if !es.Enabled {
		log.Warn().Msg("Email service disabled - Password reset email not sent")
		log.Info().Str("token", token).Msg("Reset token (email disabled)")
		return nil
	}

	// Type assert to get user email and security phrase
	// We need to import model package, but to avoid circular dependency,
	// we'll accept interface{} and extract fields we need
	userMap, ok := user.(interface{ GetEmail() string; GetSecurityPhrase() string })
	if !ok {
		// Fallback: try to get email field directly using reflection would be complex
		// For now, accept we need model.User - will fix import
		log.Error().Msg("Invalid user type for password reset email")
		return fmt.Errorf("invalid user type")
	}

	toEmail := userMap.GetEmail()
	securityPhrase := userMap.GetSecurityPhrase()
	if securityPhrase == "" {
		securityPhrase = "(Not set - Please set a security phrase in your profile)"
	}

	// Build reset link (assuming running on localhost:8080 for now)
	// In production, this should come from config
	resetLink := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", token)

	subject := "Reset Your Password - Short URL Generator"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .security-banner { background: #f0f9ff; border: 2px solid #0ea5e9; border-radius: 8px; padding: 15px; margin: 20px 0; }
        .security-phrase { color: #0369a1; font-weight: bold; font-size: 18px; margin: 10px 0; }
        .reset-button { background: #667eea; color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; font-weight: 600; }
        .warning { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px; margin: 15px 0; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        code { background: #e5e7eb; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Reset Your Password</h1>
        </div>
        <div class="content">
            <p>Hi there,</p>
            <p>We received a request to reset your password for Short URL Generator.</p>

            <div class="security-banner">
                🔐 <strong>Your Security Phrase:</strong>
                <div class="security-phrase">%s</div>
                <small style="color: #64748b;">
                    If this phrase is missing or incorrect, this email is a phishing attempt.
                    Do NOT click any links.
                </small>
            </div>

            <p>Click the button below to reset your password:</p>

            <a href="%s" class="reset-button">Reset Password</a>

            <p style="color: #64748b; font-size: 14px;">
                Or copy this link:<br>
                <code>%s</code>
            </p>

            <div class="warning">
                ⚠️ <strong>Security Notice:</strong>
                <ul style="margin: 10px 0;">
                    <li>This link expires in 30 minutes</li>
                    <li>Can only be used once</li>
                    <li>If you didn't request this, ignore this email</li>
                </ul>
            </div>
        </div>
        <div class="footer">
            <p>© 2025 Short URL Generator. All rights reserved.</p>
            <p style="color: #94a3b8; font-size: 11px;">
                This is an automated email. Please do not reply.
            </p>
        </div>
    </div>
</body>
</html>
`, securityPhrase, resetLink, resetLink)

	return es.sendEmail(toEmail, subject, body)
}

// SendPasswordChangeAlert sends an alert when password is changed
func (es *EmailService) SendPasswordChangeAlert(user interface{}, ip, userAgent string) error {
	if !es.Enabled {
		log.Warn().Msg("Email service disabled - Password change alert not sent")
		return nil
	}

	// Type assert to get user email and security phrase
	userMap, ok := user.(interface{ GetEmail() string; GetSecurityPhrase() string })
	if !ok {
		log.Error().Msg("Invalid user type for password change alert")
		return fmt.Errorf("invalid user type")
	}

	toEmail := userMap.GetEmail()
	securityPhrase := userMap.GetSecurityPhrase()
	if securityPhrase == "" {
		securityPhrase = "(Not set - Please set a security phrase in your profile)"
	}

	// Parse user agent (basic parsing)
	device := "Unknown"
	if len(userAgent) > 50 {
		device = userAgent[:50] + "..."
	} else {
		device = userAgent
	}

	subject := "⚠️ Security Alert: Your Password Was Changed"
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc2626; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .security-banner { background: #f0f9ff; border: 2px solid #0ea5e9; border-radius: 8px; padding: 15px; margin: 20px 0; }
        .security-phrase { color: #0369a1; font-weight: bold; font-size: 18px; margin: 10px 0; }
        .alert-box { background: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 15px 0; }
        .info-table { width: 100%%; border-collapse: collapse; margin: 15px 0; }
        .info-table td { padding: 10px; border-bottom: 1px solid #e5e7eb; }
        .info-table td:first-child { font-weight: 600; width: 120px; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚠️ Security Alert</h1>
        </div>
        <div class="content">
            <p>Hello,</p>

            <div class="security-banner">
                🔐 <strong>Your Security Phrase:</strong>
                <div class="security-phrase">%s</div>
            </div>

            <div class="alert-box">
                <strong>Your password was recently changed.</strong>
            </div>

            <p>If this was you, you can safely ignore this email. If you didn't change your password, your account may be compromised.</p>

            <table class="info-table">
                <tr>
                    <td>Time:</td>
                    <td>Just now</td>
                </tr>
                <tr>
                    <td>IP Address:</td>
                    <td>%s</td>
                </tr>
                <tr>
                    <td>Device:</td>
                    <td style="font-size: 12px;">%s</td>
                </tr>
            </table>

            <p><strong>If this wasn't you:</strong></p>
            <ol>
                <li>Reset your password immediately</li>
                <li>Check your email account security</li>
                <li>Enable 2FA on your email account</li>
                <li>Contact support if needed</li>
            </ol>

            <p style="color: #dc2626; font-weight: 600;">
                ⚠️ If you didn't make this change, someone else may have access to your account.
            </p>
        </div>
        <div class="footer">
            <p>© 2025 Short URL Generator. All rights reserved.</p>
            <p style="color: #94a3b8; font-size: 11px;">
                This is an automated security alert. Please do not reply.
            </p>
        </div>
    </div>
</body>
</html>
`, securityPhrase, ip, device)

	return es.sendEmail(toEmail, subject, body)
}

// GenerateOTP generates a random 6-digit OTP code
func GenerateOTP() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}

	// Ensure it's always 6 digits by padding with zeros
	return fmt.Sprintf("%06d", n.Int64()), nil
}
