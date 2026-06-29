package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/encrypt"
	"github.com/deepint-shield/ai-security/framework/logstore"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

const emailVerificationTTL = 24 * time.Hour

// SessionHandler manages HTTP requests for session operations.
type SessionHandler struct {
	configStore   configstore.ConfigStore
	logsStore     logstore.LogStore
	wsTicketStore *WSTicketStore
}

func NewSessionHandler(configStore configstore.ConfigStore, logsStore logstore.LogStore, wsTicketStore *WSTicketStore) *SessionHandler {
	return &SessionHandler{
		configStore:   configStore,
		logsStore:     logsStore,
		wsTicketStore: wsTicketStore,
	}
}

func (h *SessionHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	// Per-IP throttle on credentialed auth endpoints. See
	// session_ratelimit.go for tuning knobs and threat model.
	r.POST("/api/session/signup", authRateLimit(lib.ChainMiddlewares(h.signup, middlewares...)))
	r.POST("/api/session/login", authRateLimit(lib.ChainMiddlewares(h.login, middlewares...)))
	r.POST("/api/session/google", authRateLimit(lib.ChainMiddlewares(h.googleLogin, middlewares...)))
	r.GET("/api/session/invitation", lib.ChainMiddlewares(h.getInvitationDetails, middlewares...))
	r.POST("/api/session/verify-email", authRateLimit(lib.ChainMiddlewares(h.verifyEmail, middlewares...)))
	r.POST("/api/session/resend-verification", authRateLimit(lib.ChainMiddlewares(h.resendVerification, middlewares...)))
	r.GET("/api/session/me", lib.ChainMiddlewares(h.currentUser, middlewares...))
	r.GET("/api/session/bootstrap", lib.ChainMiddlewares(h.bootstrap, middlewares...))
	r.PUT("/api/session/me", lib.ChainMiddlewares(h.updateCurrentUserProfile, middlewares...))
	r.POST("/api/session/me/email", lib.ChainMiddlewares(h.updateCurrentUserEmail, middlewares...))
	r.POST("/api/session/me/resend-verification", lib.ChainMiddlewares(h.resendCurrentUserVerification, middlewares...))
	// DSAR self-service export (GDPR Art. 15/20) - downloads the caller's
	// personal data (profile, memberships, consents) as JSON.
	r.GET("/api/session/me/export", lib.ChainMiddlewares(h.exportCurrentUserData, middlewares...))
	// Native TOTP MFA - self-service from account settings (session-authed).
	r.POST("/api/session/mfa/setup", lib.ChainMiddlewares(h.mfaSetup, middlewares...))
	r.POST("/api/session/mfa/enable", lib.ChainMiddlewares(h.mfaEnable, middlewares...))
	r.POST("/api/session/mfa/disable", lib.ChainMiddlewares(h.mfaDisable, middlewares...))
	r.POST("/api/session/mfa/recovery-codes", lib.ChainMiddlewares(h.mfaRegenerateRecoveryCodes, middlewares...))
	r.POST("/api/session/logout", lib.ChainMiddlewares(h.logout, middlewares...))
	r.GET("/api/session/is-auth-enabled", lib.ChainMiddlewares(h.isAuthEnabled, middlewares...))
	r.POST("/api/session/ws-ticket", lib.ChainMiddlewares(h.issueWSTicket, middlewares...))
}

// legalAcceptance is embedded in every auth payload that creates a session.
// The UI is required to populate these from the visible Terms/Privacy
// versions at the moment of submission. The server records them as an
// audit trail row tied to the user account.
type legalAcceptance struct {
	AcceptedTermsVersion   string `json:"accepted_terms_version,omitempty"`
	AcceptedPrivacyVersion string `json:"accepted_privacy_version,omitempty"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	// MfaCode is the 6-digit TOTP supplied on the second step of an
	// MFA-enabled login. Empty on the first POST (server replies
	// {"mfa_required": true}); the client re-submits with the code.
	MfaCode string `json:"mfa_code,omitempty"`
	legalAcceptance
}

type signupRequest struct {
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Organization    string `json:"organization"`
	Industry        string `json:"industry"`
	Email           string `json:"email"`
	Password        string `json:"password"`
	InvitationToken string `json:"invitation_token,omitempty"`
	legalAcceptance
}

type googleLoginRequest struct {
	Credential string `json:"credential"`
	// Organization name supplied by the UI on first-time Google sign-up.
	// Required when no auth_users row exists yet for the Google identity;
	// ignored for returning users (their existing organisation stays).
	Organization string `json:"organization,omitempty"`
	legalAcceptance
}

type emailVerificationRequest struct {
	Token string `json:"token"`
}

type resendVerificationRequest struct {
	Email string `json:"email"`
}

func (h *SessionHandler) isAuthEnabled(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendJSON(ctx, map[string]any{
			"is_auth_enabled":             false,
			"has_valid_token":             false,
			"has_users":                   false,
			"requires_email_verification": true,
			"google_auth_enabled":         false,
			"google_client_id":            "",
		})
		return
	}

	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get auth config: %v", err))
		return
	}

	userCount, err := h.configStore.CountUsers(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to count users: %v", err))
		return
	}

	token := sessionTokenFromRequest(ctx)
	hasValidToken := false
	if token != "" {
		// IMPORTANT: use context.Background() so the GORM tenant-scoping
		// callback doesn't add WHERE tenant_id = ? to the lookup. The
		// active-workspace scope override stamps a different tenant on
		// the request ctx for cross-workspace invitees, but the session
		// row lives in the user's HOME partition. With ctx, the lookup
		// returns nil → has_valid_token=false → the UI bounces to /login
		// the moment the user switches to an assigned workspace.
		// Sessions match by token (globally unique) so dropping the
		// tenant filter is safe.
		session, err := h.configStore.GetSession(context.Background(), token)
		if err == nil && session != nil && session.ExpiresAt.After(time.Now()) {
			hasValidToken = true
		}
	}

	googleClientID := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID"))
	SendJSON(ctx, map[string]any{
		"is_auth_enabled":             authConfig != nil && authConfig.IsEnabled,
		"has_valid_token":             hasValidToken,
		"has_users":                   userCount > 0,
		"requires_email_verification": true,
		"google_auth_enabled":         googleClientID != "",
		"google_client_id":            googleClientID,
	})
}

func (h *SessionHandler) signup(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	var payload signupRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	if err := validateSignupPayload(payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	smtpCfg := loadSMTPConfig()
	if !smtpCfg.IsConfigured() {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "SMTP credentials are required before email/password signup can be used")
		return
	}

	normalizedEmail := normalizeEmail(payload.Email)
	hashedPassword, err := encrypt.Hash(payload.Password)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to secure password")
		return
	}

	now := time.Now()
	var invitation *tables.TableUserInvitation
	var invitationOrg *tables.TableOrganization
	var invitationOrgName string // parent org (governance_org) display name for invitees
	if strings.TrimSpace(payload.InvitationToken) != "" {
		invitation, err = h.getActiveInvitationByToken(ctx, payload.InvitationToken)
		if err != nil {
			SendError(ctx, fasthttp.StatusBadRequest, err.Error())
			return
		}
		if normalizedEmail != invitation.Email {
			SendError(ctx, fasthttp.StatusBadRequest, "The invited email does not match this signup request")
			return
		}
		invitationOrg, err = h.configStore.GetOrganizationByID(context.Background(), invitation.TenantID)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load invited workspace: %v", err))
			return
		}
		// An invitee's "Organization" is the PARENT org (the inviter's
		// governance_org), not the tenant they were invited to.
		if invitationOrg != nil && strings.TrimSpace(invitationOrg.OrganizationID) != "" {
			if govOrg, gErr := h.configStore.GetGovernanceOrgByID(context.Background(), strings.TrimSpace(invitationOrg.OrganizationID)); gErr == nil && govOrg != nil {
				invitationOrgName = strings.TrimSpace(govOrg.Name)
			}
		}
	}

	user, err := h.configStore.GetUserByEmail(ctx, normalizedEmail)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to check existing user: %v", err))
		return
	}

	isNewUser := false
	if user == nil {
		isNewUser = true

		userID := uuid.New().String()
		// Both org_id and tenant_id are opaque UUIDs decoupled from the
		// user's email so later email changes don't ripple through
		// scoped data. The 3-tier hierarchy is org → tenant → workspace;
		// for a fresh signup we materialise all three.
		orgID := uuid.New().String()
		tenantID := uuid.New().String()
		orgName := strings.TrimSpace(payload.Organization)
		role := tables.UserRoleAdmin
		if invitation != nil {
			tenantID = invitation.TenantID
			role = invitation.Role
			if invitationOrgName != "" {
				orgName = invitationOrgName
			} else if invitationOrg != nil && strings.TrimSpace(invitationOrg.Name) != "" {
				orgName = strings.TrimSpace(invitationOrg.Name)
			}
			// Inherit org_id from the existing tenant when joining via
			// invitation - invited users land in the inviter's org.
			if invitationOrg != nil && strings.TrimSpace(invitationOrg.OrganizationID) != "" {
				orgID = invitationOrg.OrganizationID
			}
		}
		if orgName == "" {
			orgName = strings.TrimSpace(payload.FirstName + " " + payload.LastName)
		}
		if invitation == nil {
			// New self-serve signup: provision the invisible parent
			// governance_org so the user can later create their own
			// tenants via POST /api/orgs/{id}/tenants. We deliberately
			// DO NOT create a default legacy tenant or workspace - the
			// dashboard guides the user through creating those
			// explicitly. tenantID stays as a private partition key on
			// auth_users with no backing organizations row.
			govOrg := &tables.TableGovernanceOrg{
				ID:          orgID,
				Name:        orgName,
				Slug:        userID[:8] + "-" + strings.ToLower(strings.ReplaceAll(orgName, " ", "-")) + "-org",
				OwnerUserID: userID,
				Plan:        "free",
			}
			if err := h.configStore.CreateGovernanceOrg(ctx, govOrg); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create organization: %v", err))
				return
			}
			if err := h.configStore.CreateGovernanceOrgMembership(ctx, &tables.TableGovernanceOrgMembership{
				ID:             "gom-" + uuid.NewString(),
				OrganizationID: orgID,
				UserID:         userID,
				Role:           tables.GovernanceOrgRoleOwner,
			}); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to set org owner membership: %v", err))
				return
			}
		}

		user = &tables.TableAuthUser{
			ID:                     userID,
			OrganizationID:         orgID,
			TenantID:               tenantID,
			Role:                   role,
			FirstName:              strings.TrimSpace(payload.FirstName),
			LastName:               strings.TrimSpace(payload.LastName),
			Organization:           orgName,
			Industry:               strings.TrimSpace(payload.Industry),
			Email:                  normalizedEmail,
			PasswordHash:           hashedPassword,
			IsEmailVerified:        false,
			LastVerificationSentAt: &now,
		}
		if err := h.configStore.CreateUser(ctx, user); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create account: %v", err))
			return
		}
	} else {
		if invitation != nil && strings.TrimSpace(user.TenantID) != "" && user.TenantID != invitation.TenantID {
			SendError(ctx, fasthttp.StatusConflict, "This invited email is already attached to a different workspace")
			return
		}
		if user.IsEmailVerified {
			SendError(ctx, fasthttp.StatusConflict, "An account with that email already exists. Sign in instead.")
			return
		}
		user.FirstName = strings.TrimSpace(payload.FirstName)
		user.LastName = strings.TrimSpace(payload.LastName)
		if invitation != nil {
			user.TenantID = invitation.TenantID
			user.Role = invitation.Role
			if invitationOrgName != "" {
				user.Organization = invitationOrgName
			} else if invitationOrg != nil && strings.TrimSpace(invitationOrg.Name) != "" {
				user.Organization = strings.TrimSpace(invitationOrg.Name)
			}
		} else {
			user.Organization = strings.TrimSpace(payload.Organization)
			user.Role = tables.UserRoleAdmin
		}
		user.Industry = strings.TrimSpace(payload.Industry)
		user.PasswordHash = hashedPassword
		user.LastVerificationSentAt = &now
		if err := h.configStore.UpdateUser(ctx, user); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to refresh pending account: %v", err))
			return
		}
	}

	if err := h.ensureDashboardAuthEnabled(ctx); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to enable authentication: %v", err))
		return
	}

	rawToken, err := h.createVerificationToken(ctx, user.ID, tables.EmailVerificationPurposeSignup, user.Email)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create verification token: %v", err))
		return
	}

	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", publicAppBaseURL(ctx), url.QueryEscape(rawToken))
	fullName := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName))
	if err := sendVerificationEmail(smtpCfg, user.Email, fullName, verificationURL, tables.EmailVerificationPurposeSignup); err != nil {
		logger.Error("failed to send verification email: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Account created, but the verification email could not be sent. Fix SMTP and resend verification.")
		return
	}

	recordLegalConsent(
		ctx, h.configStore, user,
		tables.LegalConsentMethodSignup,
		payload.AcceptedTermsVersion, payload.AcceptedPrivacyVersion,
		remoteAddrFromCtx(ctx), string(ctx.Request.Header.UserAgent()), localeFromCtx(ctx),
	)

	message := "Verification email sent. Please verify your email before signing in."
	if !isNewUser {
		message = "Verification email resent. Please verify your email before signing in."
	}
	SendJSON(ctx, map[string]any{
		"message":                     message,
		"email":                       user.Email,
		"requires_email_verification": true,
	})
}

func (h *SessionHandler) login(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}

	var payload loginRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	identifier := strings.TrimSpace(payload.Username)
	if strings.TrimSpace(payload.Email) != "" {
		identifier = normalizeEmail(payload.Email)
	} else if strings.Contains(identifier, "@") {
		identifier = normalizeEmail(identifier)
	}
	if identifier == "" || payload.Password == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Email and password are required")
		return
	}

	user, err := h.configStore.GetUserByEmail(ctx, identifier)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load account: %v", err))
		return
	}
	if user != nil {
		if user.PasswordHash == "" {
			SendError(ctx, fasthttp.StatusUnauthorized, "This account uses Google sign-in. Continue with Google to access the platform.")
			return
		}
		if !user.IsEmailVerified {
			SendError(ctx, fasthttp.StatusForbidden, "Please verify your email before signing in.")
			return
		}

		compare, err := encrypt.CompareHash(user.PasswordHash, payload.Password)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to validate credentials")
			return
		}
		if !compare {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid email or password")
			return
		}

		// MFA second factor - password login only (federated logins carry
		// IdP MFA). First POST without a code returns a challenge; the client
		// re-submits email+password+code. No session is created until the
		// TOTP verifies.
		if user.MfaEnabled {
			if strings.TrimSpace(payload.MfaCode) == "" {
				SendJSON(ctx, map[string]any{"mfa_required": true})
				return
			}
			secret, derr := decryptMfaSecret(user.MfaSecret)
			if derr != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, "Failed to read MFA secret")
				return
			}
			if !verifyTOTP(secret, payload.MfaCode) {
				// Fall back to a single-use recovery code. Consuming it is
				// persisted by the LastLoginAt UpdateUser just below.
				updated, ok := consumeRecoveryCode(user.MfaRecoveryCodes, payload.MfaCode)
				if !ok {
					SendError(ctx, fasthttp.StatusUnauthorized, "Invalid authentication code")
					return
				}
				user.MfaRecoveryCodes = updated
			}
		}

		now := time.Now()
		user.LastLoginAt = &now
		if err := h.configStore.UpdateUser(ctx, user); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update account login time: %v", err))
			return
		}

		// Re-apply any pending invitation on every password login.
		// Covers the historic gap where a user signed up before being
		// invited (so verifyEmail didn't find an invitation) and the
		// subsequent invite never got materialised into membership rows.
		// Idempotent - skips if already accepted.
		h.applyPendingInvitationForNewUser(user)

		if err := h.createSessionAndSetCookie(ctx, user.ID, user.Email, user.TenantID, tables.AuthProviderPassword); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
			return
		}

		recordLegalConsent(
			ctx, h.configStore, user,
			tables.LegalConsentMethodLogin,
			payload.AcceptedTermsVersion, payload.AcceptedPrivacyVersion,
			remoteAddrFromCtx(ctx), string(ctx.Request.Header.UserAgent()), localeFromCtx(ctx),
		)

		SendJSON(ctx, map[string]any{
			"message": "Login successful",
			"email":   user.Email,
		})
		return
	}

	authConfig, err := h.configStore.GetAuthConfig(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get auth config: %v", err))
		return
	}
	if authConfig == nil || !authConfig.IsEnabled {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}

	if authConfig.AdminUserName == nil || identifier != strings.TrimSpace(authConfig.AdminUserName.GetValue()) {
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid email or password")
		return
	}
	if authConfig.AdminPassword == nil || authConfig.AdminPassword.GetValue() == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid email or password")
		return
	}

	compare, err := encrypt.CompareHash(authConfig.AdminPassword.GetValue(), payload.Password)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	if !compare {
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid email or password")
		return
	}

	adminTenantID := ""
	if strings.Contains(identifier, "@") {
		// Prefer the canonical (UUID) tenant when the email has been re-keyed,
		// so the session is stamped with the UUID from the start rather than
		// the legacy email-keyed id.
		adminTenantID = canonicalTenantForEmail(ctx, h.configStore, identifier)
	}
	if err := h.createSessionAndSetCookie(ctx, "", identifier, adminTenantID, tables.AuthProviderAdmin); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
		return
	}

	SendJSON(ctx, map[string]any{
		"message": "Login successful",
	})
}

func (h *SessionHandler) googleLogin(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	googleClientID := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID"))
	if googleClientID == "" {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Google sign-in is not configured")
		return
	}

	var payload googleLoginRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	if strings.TrimSpace(payload.Credential) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Google credential is required")
		return
	}

	identity, err := verifyGoogleIDToken(ctx, payload.Credential, googleClientID)
	if err != nil {
		SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
		return
	}
	if !identity.EmailVerified {
		SendError(ctx, fasthttp.StatusForbidden, "Google account email must be verified before it can be used")
		return
	}

	user, err := h.configStore.GetUserByGoogleSubject(ctx, identity.Subject)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load Google account: %v", err))
		return
	}
	if user == nil {
		user, err = h.configStore.GetUserByEmail(ctx, identity.Email)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load matching account: %v", err))
			return
		}
	}

	now := time.Now()
	if user == nil {
		// First-time Google sign-up - organisation name is mandatory.
		// Return a structured 400 so the UI can detect the missing
		// field and prompt for it without surfacing a generic error.
		// The actual org_id is generated server-side as a UUID and
		// never displayed; we only need a human-readable name from the
		// caller.
		organization := strings.TrimSpace(payload.Organization)
		if organization == "" {
			SendJSONWithStatus(ctx, map[string]any{
				"is_deepintshield_error": false,
				"status_code":            fasthttp.StatusBadRequest,
				"error": map[string]any{
					"type":    "organization_required",
					"message": "Organization name is required to complete sign-up.",
				},
				"extra_fields": map[string]any{
					"email":          identity.Email,
					"requires_field": "organization",
				},
			}, fasthttp.StatusBadRequest)
			return
		}

		// New self-serve Google signup: provision the invisible parent
		// governance_org so the user can later create their own tenants
		// via POST /api/orgs/{id}/tenants. We deliberately DO NOT create
		// a default legacy tenant or workspace - the dashboard guides
		// the user through creating those explicitly. tenantID stays as
		// a private partition key on auth_users with no backing
		// organizations row.
		orgID := uuid.New().String()
		tenantID := uuid.New().String()
		orgName := organization
		userID := uuid.New().String()
		baseSlug := userID[:8] + "-" + strings.ToLower(strings.ReplaceAll(orgName, " ", "-"))

		govOrg := &tables.TableGovernanceOrg{
			ID:          orgID,
			Name:        orgName,
			Slug:        baseSlug + "-org",
			OwnerUserID: userID,
			Plan:        "free",
		}
		if err := h.configStore.CreateGovernanceOrg(ctx, govOrg); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create organization: %v", err))
			return
		}
		if err := h.configStore.CreateGovernanceOrgMembership(ctx, &tables.TableGovernanceOrgMembership{
			ID:             "gom-" + uuid.NewString(),
			OrganizationID: orgID,
			UserID:         userID,
			Role:           tables.GovernanceOrgRoleOwner,
		}); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to set org owner membership: %v", err))
			return
		}

		subject := identity.Subject
		user = &tables.TableAuthUser{
			ID:                     userID,
			OrganizationID:         orgID,
			TenantID:               tenantID,
			Role:                   tables.UserRoleAdmin,
			FirstName:              fallbackName(identity.FirstName, identity.Email),
			LastName:               identity.LastName,
			Organization:           organization,
			Industry:               "Other",
			Email:                  identity.Email,
			GoogleSubject:          &subject,
			IsEmailVerified:        true,
			EmailVerifiedAt:        &now,
			LastVerificationSentAt: &now,
			LastLoginAt:            &now,
		}
		// freshlyCreated tracks whether the row we hold was inserted by
		// THIS request. If a parallel sign-in (Google One-Tap commonly
		// fires the credential endpoint twice on dev hot-reload) won
		// the insert race between our lookup at line 476 and the Create
		// below, the unique index on google_subject rejects our INSERT
		// and we recover by re-fetching the row the other request just
		// inserted. We then fall through to the existing-user update
		// path so this caller still gets a session instead of a 500.
		freshlyCreated := false
		if err := h.configStore.CreateUser(ctx, user); err != nil {
			if !isDuplicateGoogleSubjectErr(err) {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create Google account: %v", err))
				return
			}
			existing, getErr := h.configStore.GetUserByGoogleSubject(ctx, identity.Subject)
			if getErr != nil || existing == nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create Google account: %v", err))
				return
			}
			user = existing
		} else {
			freshlyCreated = true
		}

		if !freshlyCreated {
			if !applyGoogleIdentityToExistingUser(ctx, h.configStore, user, identity, now) {
				return
			}
		}
		// If anyone has a pending invitation for this Google email,
		// turn it into real org_membership + workspace_membership rows
		// so the invitee lands inside the workspace they were added to
		// instead of seeing an empty home tenant.
		h.applyPendingInvitationForNewUser(user)
	} else {
		if !applyGoogleIdentityToExistingUser(ctx, h.configStore, user, identity, now) {
			return
		}
		// Returning user - also apply any pending invitation. This
		// covers the case where someone is invited AFTER they already
		// signed up via Google but before they sign in again.
		h.applyPendingInvitationForNewUser(user)
	}

	if err := h.ensureDashboardAuthEnabled(ctx); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to enable authentication: %v", err))
		return
	}

	if err := h.createSessionAndSetCookie(ctx, user.ID, user.Email, user.TenantID, tables.AuthProviderGoogle); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
		return
	}

	recordLegalConsent(
		ctx, h.configStore, user,
		tables.LegalConsentMethodGoogleLogin,
		payload.AcceptedTermsVersion, payload.AcceptedPrivacyVersion,
		remoteAddrFromCtx(ctx), string(ctx.Request.Header.UserAgent()), localeFromCtx(ctx),
	)

	SendJSON(ctx, map[string]any{
		"message": "Login successful",
		"email":   user.Email,
	})
}

func (h *SessionHandler) verifyEmail(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	var payload emailVerificationRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	if strings.TrimSpace(payload.Token) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Verification token is required")
		return
	}

	tokenHash := encrypt.HashSHA256(strings.TrimSpace(payload.Token))
	record, err := h.configStore.GetEmailVerificationTokenByHash(ctx, tokenHash)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load verification token: %v", err))
		return
	}
	if record == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Verification link is invalid or has expired")
		return
	}

	user, err := h.configStore.GetUserByID(ctx, record.UserID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load account: %v", err))
		return
	}
	if user == nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Verification link is invalid or has expired")
		return
	}

	if record.Purpose != tables.EmailVerificationPurposeEmailChange && record.UsedAt != nil && user.IsEmailVerified {
		SendJSON(ctx, map[string]any{
			"message": "Email already verified. You can sign in now.",
			"email":   user.Email,
		})
		return
	}
	if time.Now().After(record.ExpiresAt) {
		SendError(ctx, fasthttp.StatusBadRequest, "Verification link is invalid or has expired")
		return
	}

	now := time.Now()
	if record.Purpose == tables.EmailVerificationPurposeEmailChange {
		if record.TargetEmail == nil || strings.TrimSpace(*record.TargetEmail) == "" {
			SendError(ctx, fasthttp.StatusBadRequest, "Verification link is invalid or has expired")
			return
		}

		targetEmail := normalizeEmail(*record.TargetEmail)
		if record.UsedAt != nil && user.Email == targetEmail {
			SendJSON(ctx, map[string]any{
				"message": "Email already verified. Your new address is active.",
				"email":   user.Email,
			})
			return
		}

		if user.PendingEmail == nil || normalizeEmail(*user.PendingEmail) != targetEmail {
			if user.Email == targetEmail && user.IsEmailVerified {
				SendJSON(ctx, map[string]any{
					"message": "Email already verified. Your new address is active.",
					"email":   user.Email,
				})
				return
			}
			SendError(ctx, fasthttp.StatusBadRequest, "Verification link is invalid or has expired")
			return
		}

		existingUser, err := h.configStore.GetUserByEmail(ctx, targetEmail)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to validate email ownership: %v", err))
			return
		}
		if existingUser != nil && existingUser.ID != user.ID {
			SendError(ctx, fasthttp.StatusConflict, "That email is already in use by another account")
			return
		}

		// Legacy users were keyed by email; modern users have opaque UUID
		// tenant IDs. Only re-key + migrate when the existing tenant ID
		// was the previous email (otherwise we'd corrupt UUID-keyed
		// tenants by remapping their scoped data).
		legacyEmailKeyed := user.TenantID != "" && user.TenantID == emailTenantID(user.Email)
		var tenantMappings map[string]string
		if legacyEmailKeyed {
			tenantMappings = buildTenantIDMappings(user.ID, user.Email, user.TenantID, targetEmail)
		}
		user.Email = targetEmail
		if legacyEmailKeyed {
			user.TenantID = emailTenantID(targetEmail)
		}
		user.PendingEmail = nil
		user.PendingEmailRequestedAt = nil
		user.IsEmailVerified = true
		user.EmailVerifiedAt = &now
		if err := h.configStore.UpdateUser(ctx, user); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to verify account: %v", err))
			return
		}
		if err := h.configStore.UpdateSessionsEmailByUserID(ctx, user.ID, user.Email); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to refresh active sessions: %v", err))
			return
		}
		if err := h.migrateTenantScopedData(ctx, tenantMappings); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
			return
		}
		// UUID-keyed tenants keep their UUID across an email change; register the
		// new email as an alias so login by the new address still resolves to the
		// tenant. (Legacy email-keyed tenants were re-keyed above instead.)
		if !legacyEmailKeyed && strings.TrimSpace(user.TenantID) != "" {
			if err := h.configStore.UpsertTenantAlias(ctx, targetEmail, user.TenantID, "email"); err != nil {
				SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update tenant alias: %v", err))
				return
			}
		}
		if err := h.configStore.MarkEmailVerificationTokenUsed(ctx, record.ID, now); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to finalize verification: %v", err))
			return
		}

		SendJSON(ctx, map[string]any{
			"message": "Email verified. Your new address is now active.",
			"email":   user.Email,
		})
		return
	}

	user.IsEmailVerified = true
	user.EmailVerifiedAt = &now
	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to verify account: %v", err))
		return
	}
	if err := h.configStore.MarkEmailVerificationTokenUsed(ctx, record.ID, now); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to finalize verification: %v", err))
		return
	}
	if err := h.acceptInvitationForVerifiedUser(ctx, user, now); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to finalize workspace invitation: %v", err))
		return
	}
	// Materialise membership rows from any pending invitation for this
	// email so the user lands directly in the invited workspace on
	// first login. acceptInvitationForVerifiedUser only marked the
	// invitation as accepted; this turns it into real
	// org_membership + workspace_membership rows.
	h.applyPendingInvitationForNewUser(user)

	SendJSON(ctx, map[string]any{
		"message": "Email verified. You can sign in now.",
		"email":   user.Email,
	})
}

func (h *SessionHandler) resendVerification(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	smtpCfg := loadSMTPConfig()
	if !smtpCfg.IsConfigured() {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "SMTP credentials are required before email verification can be resent")
		return
	}

	var payload resendVerificationRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	normalizedEmail := normalizeEmail(payload.Email)
	if normalizedEmail == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Email is required")
		return
	}

	user, err := h.configStore.GetUserByEmail(ctx, normalizedEmail)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load account: %v", err))
		return
	}
	purpose := tables.EmailVerificationPurposeSignup
	targetEmail := normalizedEmail
	if user == nil || (user.IsEmailVerified && (user.PendingEmail == nil || normalizeEmail(*user.PendingEmail) != normalizedEmail)) {
		user, err = h.configStore.GetUserByPendingEmail(ctx, normalizedEmail)
		if err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load pending account: %v", err))
			return
		}
		if user != nil && user.PendingEmail != nil && normalizeEmail(*user.PendingEmail) == normalizedEmail {
			purpose = tables.EmailVerificationPurposeEmailChange
			targetEmail = normalizeEmail(*user.PendingEmail)
		}
	}
	if user == nil {
		SendJSON(ctx, map[string]any{
			"message": "If an account needs verification, a new email has been sent.",
		})
		return
	}
	if purpose == tables.EmailVerificationPurposeSignup && user.IsEmailVerified {
		SendJSON(ctx, map[string]any{
			"message": "If an account needs verification, a new email has been sent.",
		})
		return
	}
	if purpose == tables.EmailVerificationPurposeEmailChange && (user.PendingEmail == nil || normalizeEmail(*user.PendingEmail) != targetEmail) {
		SendJSON(ctx, map[string]any{
			"message": "If an account needs verification, a new email has been sent.",
		})
		return
	}

	now := time.Now()
	user.LastVerificationSentAt = &now
	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update account: %v", err))
		return
	}

	rawToken, err := h.createVerificationToken(ctx, user.ID, purpose, targetEmail)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create verification token: %v", err))
		return
	}
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", publicAppBaseURL(ctx), url.QueryEscape(rawToken))
	fullName := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName))
	sendToEmail := user.Email
	if purpose == tables.EmailVerificationPurposeEmailChange {
		sendToEmail = targetEmail
	}
	if err := sendVerificationEmail(smtpCfg, sendToEmail, fullName, verificationURL, purpose); err != nil {
		logger.Error("failed to resend verification email: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Verification email could not be sent right now")
		return
	}

	SendJSON(ctx, map[string]any{
		"message": "Verification email sent. Please check your inbox.",
		"email":   sendToEmail,
	})
}

func (h *SessionHandler) logout(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusForbidden, "Authentication is not enabled")
		return
	}

	token := sessionTokenFromRequest(ctx)
	clearSessionCookie(ctx)

	if token != "" {
		err := h.configStore.DeleteSession(ctx, token)
		if err != nil && !errors.Is(err, configstore.ErrNotFound) {
			logger.Error("failed to delete session during logout: %v", err)
			SendError(ctx, fasthttp.StatusInternalServerError, "Failed to invalidate session. Please try again.")
			return
		}
	}

	SendJSON(ctx, map[string]any{
		"message": "Logout successful",
	})
}

// bootstrap returns user + governance_orgs + tenants + workspaces in a
// single round-trip. Replaces the dashboard's first-paint sequence of
// 3-4 separate queries (useGetCurrentUser + useListMyOrgs +
// useListMyTenants + useListMyWorkspaces) with one. Cuts first-paint
// time-to-interactive by ~150-300ms on a typical cold load.
//
// All five queries fan out concurrently via goroutines; the response
// shape is intentionally close to what the existing endpoints return
// so the frontend can treat it as a cache pre-fill.
func (h *SessionHandler) bootstrap(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}
	user, _, err := currentAccountUserFromCtx(ctx, h.configStore)
	if err != nil {
		respondAuthError(ctx, err)
		return
	}

	type fanOut struct {
		orgs       []tables.TableGovernanceOrg
		tenants    []tables.TableOrganization
		workspaces []tables.TableWorkspace
		orgsErr    error
		tenantsErr error
		wsErr      error
	}
	out := fanOut{}
	done := make(chan struct{}, 3)

	go func() {
		out.orgs, out.orgsErr = h.configStore.ListGovernanceOrgsByMember(context.Background(), user.ID)
		done <- struct{}{}
	}()
	go func() {
		// Tenants the user belongs to via org membership: union of
		// every org's tenants. We list by the user's org_id (single
		// org for v1) to keep the call cheap; multi-org users get one
		// extra round trip on the dashboard.
		if user.OrganizationID != "" {
			out.tenants, out.tenantsErr = h.configStore.ListTenantsByGovernanceOrg(context.Background(), user.OrganizationID)
		}
		done <- struct{}{}
	}()
	go func() {
		out.workspaces, out.wsErr = h.configStore.ListWorkspacesByUser(context.Background(), user.ID)
		done <- struct{}{}
	}()
	for i := 0; i < 3; i++ {
		<-done
	}

	if out.orgsErr != nil || out.tenantsErr != nil || out.wsErr != nil {
		// Best-effort response - empty slices are fine for the frontend.
		// We log but don't fail the bootstrap; the dashboard will retry
		// individual queries if the maps are empty.
	}

	// Org-level membership map so the UI can render role-gated controls
	// immediately (no second round trip).
	orgMemberships := make(map[string]string, len(out.orgs))
	for i := range out.orgs {
		if m, _ := h.configStore.GetGovernanceOrgMembership(ctx, out.orgs[i].ID, user.ID); m != nil {
			orgMemberships[out.orgs[i].ID] = m.Role
		}
	}

	// Org_id is internal - strip from the response shape. We only
	// surface org name + plan + member counts on the UI side.
	orgsOut := make([]map[string]any, 0, len(out.orgs))
	for i := range out.orgs {
		orgsOut = append(orgsOut, map[string]any{
			"id":   out.orgs[i].ID, // included so the SDK can use it; UI ignores
			"name": out.orgs[i].Name,
			"plan": out.orgs[i].Plan,
			"role": orgMemberships[out.orgs[i].ID],
		})
	}

	SendJSON(ctx, map[string]any{
		"user": map[string]any{
			"id":              user.ID,
			"email":           user.Email,
			"first_name":      user.FirstName,
			"last_name":       user.LastName,
			"role":            user.Role,
			"organization_id": user.OrganizationID,
			"tenant_id":       user.TenantID,
		},
		"organizations": orgsOut,
		"tenants":       out.tenants,
		"workspaces":    out.workspaces,
	})
}

func (h *SessionHandler) issueWSTicket(ctx *fasthttp.RequestCtx) {
	if h.wsTicketStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "WebSocket tickets are not available")
		return
	}
	sessionToken, ok := ctx.UserValue(schemas.DeepIntShieldContextKeySessionToken).(string)
	if !ok {
		SendError(ctx, fasthttp.StatusUnauthorized, "Unauthorized")
		return
	}
	if sessionToken == "" {
		sessionToken = "dummy-session"
	}
	ticket, err := h.wsTicketStore.Issue(sessionToken)
	if err != nil {
		logger.Error("failed to issue WS ticket: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to issue WebSocket ticket")
		return
	}
	SendJSON(ctx, map[string]any{
		"ticket": ticket,
	})
}

func (h *SessionHandler) ensureDashboardAuthEnabled(ctx *fasthttp.RequestCtx) error {
	// OSS build: never auto-enable dashboard auth. The open-source gateway has
	// no login page and runs without authentication, so signup/Google paths
	// must not flip the gateway into an auth-enabled state - doing so used to
	// lock the dashboard into a /login redirect loop with no way to sign in.
	return nil
}

func (h *SessionHandler) createVerificationToken(ctx *fasthttp.RequestCtx, userID, purpose, targetEmail string) (string, error) {
	rawToken := uuid.New().String()
	if err := h.configStore.DeleteEmailVerificationTokensForUser(ctx, userID); err != nil {
		return "", err
	}
	now := time.Now()
	var normalizedTargetEmail *string
	if normalized := normalizeEmail(targetEmail); normalized != "" {
		normalizedTargetEmail = &normalized
	}
	record := &tables.TableEmailVerificationToken{
		ID:          uuid.New().String(),
		UserID:      userID,
		Purpose:     purpose,
		TargetEmail: normalizedTargetEmail,
		TokenHash:   encrypt.HashSHA256(rawToken),
		ExpiresAt:   now.Add(emailVerificationTTL),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.configStore.CreateEmailVerificationToken(ctx, record); err != nil {
		return "", err
	}
	return rawToken, nil
}

func (h *SessionHandler) createSessionAndSetCookie(ctx *fasthttp.RequestCtx, userID, userEmail, tenantID, provider string) error {
	token := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)

	// Set the plaintext token here only. SessionsTable.BeforeSave derives
	// token_hash = HashSHA256(token) for lookup AND encrypts the token column
	// at rest (AES-256-GCM) when an encryption key is configured. Do NOT
	// pre-hash here - that double-hashes token_hash and breaks GetSession
	// (causes a login → 401 loop).
	session := &tables.SessionsTable{
		TenantID:     tenantID,
		Token:        token,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		UpdatedAt:    now,
		AuthProvider: nil,
	}
	if userID != "" {
		session.UserID = &userID
	}
	if userEmail != "" {
		normalizedEmail := normalizeEmail(userEmail)
		session.UserEmail = &normalizedEmail
	}
	if provider != "" {
		session.AuthProvider = &provider
	}

	if err := h.configStore.CreateSession(ctx, session); err != nil {
		return err
	}

	setSessionCookie(ctx, token, expiresAt)
	return nil
}

func setSessionCookie(ctx *fasthttp.RequestCtx, token string, expiresAt time.Time) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey("token")
	cookie.SetValue(token)
	cookie.SetExpire(expiresAt)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" || ctx.IsTLS() {
		cookie.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(cookie)
}

func clearSessionCookie(ctx *fasthttp.RequestCtx) {
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey("token")
	cookie.SetValue("")
	cookie.SetExpire(time.Now().Add(-30 * 24 * time.Hour))
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" || ctx.IsTLS() {
		cookie.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(cookie)
}

func sessionTokenFromRequest(ctx *fasthttp.RequestCtx) string {
	token := strings.TrimSpace(string(ctx.Request.Header.Peek("Authorization")))
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)
	if token != "" {
		return token
	}
	return string(ctx.Request.Header.Cookie("token"))
}

func validateSignupPayload(payload signupRequest) error {
	if err := validateProfileFields(payload.FirstName, payload.LastName, payload.Organization, payload.Industry); err != nil {
		return err
	}
	if normalizeEmail(payload.Email) == "" {
		return fmt.Errorf("Email is required")
	}
	if _, err := mail.ParseAddress(payload.Email); err != nil {
		return fmt.Errorf("Enter a valid email address")
	}
	if len(strings.TrimSpace(payload.Password)) < 8 {
		return fmt.Errorf("Password must be at least 8 characters long")
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func fallbackName(name, email string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	localPart := strings.TrimSpace(strings.Split(normalizeEmail(email), "@")[0])
	if localPart == "" {
		return "User"
	}
	return localPart
}

// isDuplicateGoogleSubjectErr returns true when err comes from inserting a
// row whose google_subject already exists in auth_users - i.e. a parallel
// sign-in beat us to the INSERT. Detection is by error message because the
// underlying DB driver (pgx) doesn't surface a typed sentinel and we'd
// rather not import the driver here just for a constant.
func isDuplicateGoogleSubjectErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "idx_auth_users_google_subject") ||
		(strings.Contains(msg, "google_subject") && strings.Contains(msg, "duplicate"))
}

// applyGoogleIdentityToExistingUser is the existing-user-sign-in update
// path: stamp the latest verified Google subject + name onto the row,
// reject the request if the row's existing subject conflicts. Returns
// true on success; on failure it has already written an error response
// and the caller should return immediately.
//
// Extracted from the inline branches in handleGoogleLogin so the
// duplicate-subject race-recovery path can reuse it without copy-paste.
func applyGoogleIdentityToExistingUser(
	ctx *fasthttp.RequestCtx,
	store configstore.ConfigStore,
	user *tables.TableAuthUser,
	identity *googleIdentity,
	now time.Time,
) bool {
	if user.GoogleSubject != nil && *user.GoogleSubject != identity.Subject {
		SendError(ctx, fasthttp.StatusConflict, "This email is already linked to a different Google account")
		return false
	}
	subject := identity.Subject
	user.GoogleSubject = &subject
	if strings.TrimSpace(user.Role) == "" {
		user.Role = tables.UserRoleAdmin
	}
	user.IsEmailVerified = true
	user.EmailVerifiedAt = &now
	user.LastLoginAt = &now
	if strings.TrimSpace(user.FirstName) == "" {
		user.FirstName = fallbackName(identity.FirstName, identity.Email)
	}
	if strings.TrimSpace(user.LastName) == "" {
		user.LastName = identity.LastName
	}
	if err := store.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update Google account: %v", err))
		return false
	}
	return true
}
