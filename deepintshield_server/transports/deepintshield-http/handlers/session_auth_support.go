package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

const googleCertsURL = "https://www.googleapis.com/oauth2/v1/certs"

type smtpConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	FromEmail string
	FromName  string
}

func loadSMTPConfig() smtpConfig {
	port := 587
	if rawPort := strings.TrimSpace(os.Getenv("SMTP_PORT")); rawPort != "" {
		if parsedPort, err := strconv.Atoi(rawPort); err == nil {
			port = parsedPort
		}
	}
	return smtpConfig{
		Host:      strings.TrimSpace(os.Getenv("SMTP_HOST")),
		Port:      port,
		Username:  strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: strings.TrimSpace(os.Getenv("SMTP_FROM_EMAIL")),
		FromName:  strings.TrimSpace(os.Getenv("SMTP_FROM_NAME")),
	}
}

func (c smtpConfig) IsConfigured() bool {
	return c.Host != "" && c.Port > 0 && c.FromEmail != ""
}

func (c smtpConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c smtpConfig) auth() smtp.Auth {
	if c.Username == "" {
		return nil
	}
	return smtp.PlainAuth("", c.Username, c.Password, c.Host)
}

func (c smtpConfig) formattedFrom() string {
	if c.FromName == "" {
		return c.FromEmail
	}
	return fmt.Sprintf("%s <%s>", c.FromName, c.FromEmail)
}

func sendVerificationEmail(cfg smtpConfig, toEmail, fullName, verificationURL, purpose string) error {
	if !cfg.IsConfigured() {
		return fmt.Errorf("SMTP is not configured")
	}

	greeting := strings.TrimSpace(fullName)
	if greeting == "" {
		greeting = "there"
	}

	subject := "Verify your DeepintShield email"
	headline := "Verify your email"
	intro := "Welcome to DeepintShield. Confirm this email so we can finish setting up your account."
	ctaLabel := "Verify email"
	footnote := "This link expires in 24 hours. If you didn't request this, you can safely ignore this message."
	textBody := fmt.Sprintf(
		"Hello %s,\r\n\r\nVerify your DeepintShield account by opening the link below:\r\n%s\r\n\r\nThis link expires in 24 hours.\r\n\r\nIf you did not request this, you can ignore this email.\r\n",
		greeting, verificationURL,
	)

	if purpose == tables.EmailVerificationPurposeEmailChange {
		subject = "Confirm your new DeepintShield email"
		headline = "Confirm your new email"
		intro = "We received a request to update the email address on your DeepintShield account. Click below to confirm this is you."
		ctaLabel = "Confirm new email"
		footnote = "Your current account access stays active until this new address is verified. This link expires in 24 hours. If you didn't request this, you can safely ignore this message."
		textBody = fmt.Sprintf(
			"Hello %s,\r\n\r\nConfirm your new DeepintShield email address by opening the link below:\r\n%s\r\n\r\nYour current account access will stay active until this new address is verified. This link expires in 24 hours.\r\n\r\nIf you did not request this change, you can ignore this email.\r\n",
			greeting, verificationURL,
		)
	}

	htmlBody := transactionalEmailHTML(transactionalEmailContent{
		PreviewText: intro,
		Greeting:    greeting,
		Headline:    headline,
		Body:        intro,
		CTAURL:      verificationURL,
		CTALabel:    ctaLabel,
		Footnote:    footnote,
	})

	message, err := buildMultipartEmail(cfg, toEmail, subject, textBody, htmlBody)
	if err != nil {
		return err
	}

	if cfg.Port == 465 {
		return sendMailWithImplicitTLS(cfg, toEmail, message)
	}
	return smtp.SendMail(cfg.Address(), cfg.auth(), cfg.FromEmail, []string{toEmail}, message)
}

func sendWorkspaceInvitationEmail(cfg smtpConfig, toEmail, invitedByName, organizationName, signupURL, role string) error {
	if !cfg.IsConfigured() {
		return fmt.Errorf("SMTP is not configured")
	}

	displayRole := strings.ToLower(strings.TrimSpace(role))
	switch displayRole {
	case tables.UserRoleAdmin:
		displayRole = "Admin"
	default:
		displayRole = "Viewer"
	}
	if strings.TrimSpace(invitedByName) == "" {
		invitedByName = "A workspace admin"
	}
	if strings.TrimSpace(organizationName) == "" {
		organizationName = "DeepIntShield"
	}

	subject := fmt.Sprintf("You're invited to %s on DeepintShield", organizationName)
	intro := fmt.Sprintf(
		"%s invited you to join <strong>%s</strong> on DeepintShield as <strong>%s</strong>. Click below to create your account.",
		htmlEscapeForEmail(invitedByName), htmlEscapeForEmail(organizationName), htmlEscapeForEmail(displayRole),
	)
	textBody := fmt.Sprintf(
		"%s invited you to join %s on DeepintShield as %s.\r\n\r\nCreate your account using the link below:\r\n%s\r\n\r\nYou will need to finish signup and verify your email before you can sign in.\r\n",
		invitedByName,
		organizationName,
		displayRole,
		signupURL,
	)
	htmlBody := transactionalEmailHTML(transactionalEmailContent{
		PreviewText: fmt.Sprintf("Join %s on DeepintShield", organizationName),
		Greeting:    "there",
		Headline:    fmt.Sprintf("Join %s on DeepintShield", organizationName),
		Body:        intro,
		CTAURL:      signupURL,
		CTALabel:    "Accept invitation",
		Footnote:    "You'll finish signup and verify your email before you can sign in. If you weren't expecting this invitation, you can safely ignore this message.",
	})

	message, err := buildMultipartEmail(cfg, toEmail, subject, textBody, htmlBody)
	if err != nil {
		return err
	}

	if cfg.Port == 465 {
		return sendMailWithImplicitTLS(cfg, toEmail, message)
	}
	return smtp.SendMail(cfg.Address(), cfg.auth(), cfg.FromEmail, []string{toEmail}, message)
}

func sendMailWithImplicitTLS(cfg smtpConfig, toEmail string, message []byte) error {
	conn, err := tls.Dial("tcp", cfg.Address(), &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("failed to open SMTPS connection: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if auth := cfg.auth(); auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("failed to authenticate with SMTP server: %w", err)
			}
		}
	}

	if err := client.Mail(cfg.FromEmail); err != nil {
		return fmt.Errorf("failed to set SMTP sender: %w", err)
	}
	if err := client.Rcpt(toEmail); err != nil {
		return fmt.Errorf("failed to set SMTP recipient: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to open SMTP data writer: %w", err)
	}
	if _, err := writer.Write(message); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write SMTP payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize SMTP payload: %w", err)
	}
	return client.Quit()
}

func publicAppBaseURL(ctx *fasthttp.RequestCtx) string {
	if configured := strings.TrimSpace(os.Getenv("APP_BASE_URL")); configured != "" {
		return strings.TrimRight(configured, "/")
	}

	proto := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-Proto")))
	if proto == "" {
		if ctx.IsTLS() {
			proto = "https"
		} else {
			proto = "http"
		}
	}

	host := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-Host")))
	if host == "" {
		host = string(ctx.Host())
	}
	return fmt.Sprintf("%s://%s", proto, host)
}

type googleIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	FirstName     string
	LastName      string
	HostedDomain  string
}

type googleCertCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

var cachedGoogleCerts = &googleCertCache{}

func verifyGoogleIDToken(ctx context.Context, rawToken, audience string) (*googleIdentity, error) {
	if strings.TrimSpace(audience) == "" {
		return nil, fmt.Errorf("Google sign-in is not configured")
	}

	claims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		return googlePublicKey(ctx, token)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(audience))
	if err != nil {
		return nil, fmt.Errorf("failed to validate Google credential: %w", err)
	}
	if !parsedToken.Valid {
		return nil, fmt.Errorf("Google credential is invalid")
	}

	issuer, err := claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("Google credential is missing an issuer")
	}
	if issuer != "accounts.google.com" && issuer != "https://accounts.google.com" {
		return nil, fmt.Errorf("Google credential issuer is invalid")
	}

	email, _ := claims["email"].(string)
	subject, _ := claims["sub"].(string)
	firstName, _ := claims["given_name"].(string)
	lastName, _ := claims["family_name"].(string)
	hostedDomain, _ := claims["hd"].(string)
	if email == "" || subject == "" {
		return nil, fmt.Errorf("Google credential is missing required claims")
	}

	return &googleIdentity{
		Subject:       subject,
		Email:         strings.ToLower(strings.TrimSpace(email)),
		EmailVerified: claimBool(claims["email_verified"]),
		FirstName:     firstName,
		LastName:      lastName,
		HostedDomain:  hostedDomain,
	}, nil
}

func googlePublicKey(ctx context.Context, token *jwt.Token) (*rsa.PublicKey, error) {
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("Google credential is missing key id")
	}

	keys, err := loadGoogleCerts(ctx, false)
	if err != nil {
		return nil, err
	}
	if key, ok := keys[kid]; ok {
		return key, nil
	}

	keys, err = loadGoogleCerts(ctx, true)
	if err != nil {
		return nil, err
	}
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("Google signing certificate not found")
	}
	return key, nil
}

func loadGoogleCerts(ctx context.Context, forceRefresh bool) (map[string]*rsa.PublicKey, error) {
	cachedGoogleCerts.mu.RLock()
	if !forceRefresh && len(cachedGoogleCerts.keys) > 0 && time.Now().Before(cachedGoogleCerts.expiresAt) {
		keys := cachedGoogleCerts.keys
		cachedGoogleCerts.mu.RUnlock()
		return keys, nil
	}
	cachedGoogleCerts.mu.RUnlock()

	cachedGoogleCerts.mu.Lock()
	defer cachedGoogleCerts.mu.Unlock()

	if !forceRefresh && len(cachedGoogleCerts.keys) > 0 && time.Now().Before(cachedGoogleCerts.expiresAt) {
		return cachedGoogleCerts.keys, nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, googleCertsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build Google certs request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Google certs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Google certs: status %d", resp.StatusCode)
	}

	var payload map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("failed to decode Google certs: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(payload))
	for kid, certificate := range payload {
		key, err := parseGoogleCert(certificate)
		if err != nil {
			return nil, err
		}
		keys[kid] = key
	}

	expiry := time.Now().Add(10 * time.Minute)
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		if maxAge := parseMaxAge(cacheControl); maxAge > 0 {
			expiry = time.Now().Add(maxAge)
		}
	}

	cachedGoogleCerts.keys = keys
	cachedGoogleCerts.expiresAt = expiry
	return keys, nil
}

func parseGoogleCert(certificate string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to decode Google signing certificate")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Google signing certificate: %w", err)
	}
	publicKey, ok := parsedCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Google signing certificate is not RSA")
	}
	return publicKey, nil
}

func parseMaxAge(cacheControl string) time.Duration {
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "max-age=") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(part, "max-age="))
		seconds, err := strconv.Atoi(value)
		if err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return 0
}

func claimBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}
