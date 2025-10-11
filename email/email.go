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
