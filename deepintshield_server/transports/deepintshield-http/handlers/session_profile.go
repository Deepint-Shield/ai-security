package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/valyala/fasthttp"
)

var (
	errSessionNotAccount   = errors.New("current session is not tied to a personal account")
	errUnauthorizedSession = errors.New("unauthorized")
)

type updateCurrentUserProfileRequest struct {
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Organization string `json:"organization"`
	Industry     string `json:"industry"`
	// ThemePreference is optional. nil = leave unchanged; "" = clear and
	// fall back to app default; "light" / "dark" / "system" = persist.
	ThemePreference *string `json:"theme_preference,omitempty"`
}

type updateCurrentUserEmailRequest struct {
	Email string `json:"email"`
}

func (h *SessionHandler) currentUser(ctx *fasthttp.RequestCtx) {
	user, session, err := h.currentAccountUser(ctx)
	if err != nil {
		if errors.Is(err, errSessionNotAccount) {
			SendJSON(ctx, map[string]any{"user": nil})
			return
		}
		if errors.Is(err, errUnauthorizedSession) {
			SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	// Self-heal stuck invitees: when a user has zero org_memberships,
	// re-apply any pending invitation for their email. Covers the case
	// where verifyEmail's old call order (acceptInvitationForVerifiedUser
	// before applyPendingInvitationForNewUser) marked the invitation
	// accepted but never created the membership rows - symptom was an
	// empty tenant switcher / "No tenants available" on every dashboard
	// load. Idempotent and cheap (two DB reads when memberships exist).
	if memberships, mErr := h.configStore.ListOrgMembershipsByUser(context.Background(), user.ID); mErr == nil && len(memberships) == 0 {
		h.applyPendingInvitationForNewUser(user)
	}

	// Determine whether this user is the founder of their tenant - i.e.
	// the owner_user_id on the user's governance_orgs row. SSO/SCIM
	// configuration is restricted to the founder regardless of role
	// (admins added via User Manager and JIT-provisioned SSO users do
	// NOT get SCIM admin access). See gating in scim/layout.tsx +
	// sidebar.tsx + the duplicate-domain guard in scim.go createProvider.
	isTenantOwner := false
	isOrgOwner := false
	orgID := strings.TrimSpace(user.OrganizationID)
	orgName := ""
	if orgID != "" {
		if org, lookupErr := h.configStore.GetGovernanceOrgByID(auditStoreContext(ctx), orgID); lookupErr == nil && org != nil {
			isTenantOwner = strings.TrimSpace(org.OwnerUserID) == user.ID
			orgName = org.Name
		}
		// is_org_owner gates the "Make super admin" action in the User
		// Manager. It is the org-level OWNER membership (not just the
		// founder), so a promoted co-owner can also transfer the role -
		// keyed on user UUID + org UUID, never the email.
		if m, mErr := h.configStore.GetGovernanceOrgMembership(auditStoreContext(ctx), orgID, user.ID); mErr == nil && m != nil {
			isOrgOwner = strings.EqualFold(strings.TrimSpace(m.Role), tables.GovernanceOrgRoleOwner)
		}
	}

	payload := serializeCurrentUser(user, session)
	payload["is_tenant_owner"] = isTenantOwner
	// Surface the org identity (UUID + name) so account settings can display
	// it read-only. org_id is the governance_orgs UUID - the billing/identity
	// anchor above the tenant; it is never the user's email.
	payload["org_id"] = orgID
	payload["org_name"] = orgName
	payload["is_org_owner"] = isOrgOwner
	SendJSON(ctx, map[string]any{
		"user": payload,
	})
}

// exportCurrentUserData is the self-service DSAR endpoint (GDPR Art. 15/20 -
// right of access + portability). It returns the signed-in user's personal
// data - profile, org/tenant/workspace memberships, and consent records - as a
// downloadable JSON file. Secrets (password hash, MFA secret) are never
// included.
func (h *SessionHandler) exportCurrentUserData(ctx *fasthttp.RequestCtx) {
	user, session, err := h.currentAccountUser(ctx)
	if err != nil {
		mfaAccountError(ctx, err)
		return
	}
	bg := context.Background()
	orgs, _ := h.configStore.ListGovernanceOrgsByMember(bg, user.ID)
	tenantMems, _ := h.configStore.ListOrgMembershipsByUser(bg, user.ID)
	wsMems, _ := h.configStore.ListWorkspaceMembershipsByUser(bg, user.ID)
	consents, _ := h.configStore.GetLegalConsentsForUser(bg, user.ID)

	profile := serializeCurrentUser(user, session)
	delete(profile, "has_password") // derived; keep the export to stored facts

	export := map[string]any{
		"format":                "DeepIntShield personal-data export (DSAR) v1",
		"generated_at":          time.Now().UTC(),
		"profile":               profile,
		"organizations":         orgs,
		"tenant_memberships":    tenantMems,
		"workspace_memberships": wsMems,
		"consents":              consents,
	}
	body, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to build export")
		return
	}
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.Response.Header.Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"deepintshield-data-export-%s.json\"", user.ID))
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(body)
}

func (h *SessionHandler) updateCurrentUserProfile(ctx *fasthttp.RequestCtx) {
	user, session, err := h.currentAccountUser(ctx)
	if err != nil {
		if errors.Is(err, errSessionNotAccount) {
			SendError(ctx, fasthttp.StatusForbidden, "This session is not tied to a personal account")
			return
		}
		if errors.Is(err, errUnauthorizedSession) {
			SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	var payload updateCurrentUserProfileRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}
	if err := validateProfileFields(payload.FirstName, payload.LastName, payload.Organization, payload.Industry); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}

	user.FirstName = strings.TrimSpace(payload.FirstName)
	user.LastName = strings.TrimSpace(payload.LastName)
	user.Organization = strings.TrimSpace(payload.Organization)
	user.Industry = strings.TrimSpace(payload.Industry)
	if payload.ThemePreference != nil {
		normalized := strings.ToLower(strings.TrimSpace(*payload.ThemePreference))
		switch normalized {
		case "light", "dark", "system":
			user.ThemePreference = &normalized
		case "":
			user.ThemePreference = nil
		default:
			SendError(ctx, fasthttp.StatusBadRequest, "theme_preference must be one of: light, dark, system")
			return
		}
	}

	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update account: %v", err))
		return
	}

	SendJSON(ctx, map[string]any{
		"message": "Account settings updated successfully.",
		"user":    serializeCurrentUser(user, session),
	})
}

func (h *SessionHandler) updateCurrentUserEmail(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	smtpCfg := loadSMTPConfig()
	if !smtpCfg.IsConfigured() {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "SMTP credentials are required before email updates can be sent for verification")
		return
	}

	user, session, err := h.currentAccountUser(ctx)
	if err != nil {
		if errors.Is(err, errSessionNotAccount) {
			SendError(ctx, fasthttp.StatusForbidden, "This session is not tied to a personal account")
			return
		}
		if errors.Is(err, errUnauthorizedSession) {
			SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	var payload updateCurrentUserEmailRequest
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request format: %v", err))
		return
	}

	normalizedEmail := normalizeEmail(payload.Email)
	if normalizedEmail == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Email is required")
		return
	}
	if _, err := mail.ParseAddress(payload.Email); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, "Enter a valid email address")
		return
	}

	currentEmail := normalizeEmail(user.Email)
	pendingEmail := ""
	if user.PendingEmail != nil {
		pendingEmail = normalizeEmail(*user.PendingEmail)
	}

	if normalizedEmail == currentEmail {
		if pendingEmail == "" {
			SendJSON(ctx, map[string]any{
				"message": "That email is already active on your account.",
				"user":    serializeCurrentUser(user, session),
			})
			return
		}

		user.PendingEmail = nil
		user.PendingEmailRequestedAt = nil
		if err := h.configStore.UpdateUser(ctx, user); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update account: %v", err))
			return
		}
		if err := h.configStore.DeleteEmailVerificationTokensForUser(ctx, user.ID); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to clear pending verification: %v", err))
			return
		}

		SendJSON(ctx, map[string]any{
			"message": "Pending email change removed. Your current address stays active.",
			"user":    serializeCurrentUser(user, session),
		})
		return
	}

	existingUser, err := h.configStore.GetUserByEmail(ctx, normalizedEmail)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to validate email ownership: %v", err))
		return
	}
	if existingUser != nil && existingUser.ID != user.ID {
		SendError(ctx, fasthttp.StatusConflict, "That email is already in use by another account")
		return
	}

	existingPendingUser, err := h.configStore.GetUserByPendingEmail(ctx, normalizedEmail)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to validate pending email ownership: %v", err))
		return
	}
	if existingPendingUser != nil && existingPendingUser.ID != user.ID {
		SendError(ctx, fasthttp.StatusConflict, "That email is already being verified by another account")
		return
	}

	now := time.Now()
	user.PendingEmail = &normalizedEmail
	user.PendingEmailRequestedAt = &now
	user.LastVerificationSentAt = &now

	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update account: %v", err))
		return
	}

	rawToken, err := h.createVerificationToken(ctx, user.ID, tables.EmailVerificationPurposeEmailChange, normalizedEmail)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create verification token: %v", err))
		return
	}

	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", publicAppBaseURL(ctx), url.QueryEscape(rawToken))
	fullName := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName))
	if err := sendVerificationEmail(smtpCfg, normalizedEmail, fullName, verificationURL, tables.EmailVerificationPurposeEmailChange); err != nil {
		logger.Error("failed to send email-change verification: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "The new email was saved, but the verification email could not be sent. Fix SMTP and resend verification.")
		return
	}

	SendJSON(ctx, map[string]any{
		"message": "Verification email sent to your new address. Your current sign-in email stays active until you confirm the change.",
		"email":   normalizedEmail,
		"user":    serializeCurrentUser(user, session),
	})
}

func (h *SessionHandler) resendCurrentUserVerification(ctx *fasthttp.RequestCtx) {
	if h.configStore == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "Authentication store is not available")
		return
	}

	smtpCfg := loadSMTPConfig()
	if !smtpCfg.IsConfigured() {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "SMTP credentials are required before email verification can be resent")
		return
	}

	user, session, err := h.currentAccountUser(ctx)
	if err != nil {
		if errors.Is(err, errSessionNotAccount) {
			SendError(ctx, fasthttp.StatusForbidden, "This session is not tied to a personal account")
			return
		}
		if errors.Is(err, errUnauthorizedSession) {
			SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
			return
		}
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
		return
	}

	purpose := tables.EmailVerificationPurposeSignup
	targetEmail := user.Email
	if user.PendingEmail != nil && normalizeEmail(*user.PendingEmail) != "" {
		purpose = tables.EmailVerificationPurposeEmailChange
		targetEmail = normalizeEmail(*user.PendingEmail)
	} else if user.IsEmailVerified {
		SendError(ctx, fasthttp.StatusBadRequest, "Your current email is already verified")
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
	if err := sendVerificationEmail(smtpCfg, targetEmail, fullName, verificationURL, purpose); err != nil {
		logger.Error("failed to resend current-user verification email: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Verification email could not be sent right now")
		return
	}

	SendJSON(ctx, map[string]any{
		"message": "Verification email sent. Please check your inbox.",
		"email":   targetEmail,
		"user":    serializeCurrentUser(user, session),
	})
}

func (h *SessionHandler) currentAccountUser(ctx *fasthttp.RequestCtx) (*tables.TableAuthUser, *tables.SessionsTable, error) {
	if h.configStore == nil {
		return nil, nil, fmt.Errorf("authentication store is not available")
	}

	sessionToken := ""
	if token, ok := ctx.UserValue(schemas.DeepIntShieldContextKeySessionToken).(string); ok {
		sessionToken = strings.TrimSpace(token)
	}
	if sessionToken == "" {
		sessionToken = sessionTokenFromRequest(ctx)
	}
	if sessionToken == "" {
		// OSS no-auth mode: return the implicit single-tenant local admin so
		// /api/session/me succeeds with 200 instead of 401 - the open-source
		// build has no login page. When auth is enabled, behavior is unchanged.
		if cfg, cfgErr := h.configStore.GetAuthConfig(context.Background()); cfgErr == nil && (cfg == nil || !cfg.IsEnabled) {
			return anonymousLocalUser(h.configStore), nil, nil
		}
		return nil, nil, errUnauthorizedSession
	}

	// IMPORTANT: bypass the GORM tenant-scoping callback for these
	// auth re-lookups by passing a context without a tenant_id stamp.
	// session.token and auth_users.id are globally unique, so tenant
	// filtering is incidental - and breaks when the active workspace
	// override has rewritten ctx.tenant_id to the workspace's owner
	// partition (cross-workspace invitee case): the GORM filter would
	// look for the session row in the WORKSPACE owner's partition,
	// while the row actually lives in the invitee's HOME partition.
	// Result: 0 rows → 401 → UI auto-logout loop.
	authCtx := context.Background()
	session, err := h.configStore.GetSession(authCtx, sessionToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load session: %w", err)
	}
	if session == nil || session.ExpiresAt.Before(time.Now()) {
		return nil, nil, errUnauthorizedSession
	}
	if session.UserID == nil || strings.TrimSpace(*session.UserID) == "" {
		return nil, session, errSessionNotAccount
	}

	user, err := h.configStore.GetUserByID(authCtx, strings.TrimSpace(*session.UserID))
	if err != nil {
		return nil, session, fmt.Errorf("failed to load account: %w", err)
	}
	if user == nil {
		return nil, session, errUnauthorizedSession
	}

	return user, session, nil
}

func serializeCurrentUser(user *tables.TableAuthUser, session *tables.SessionsTable) map[string]any {
	authProvider := ""
	if session != nil && session.AuthProvider != nil {
		authProvider = strings.TrimSpace(*session.AuthProvider)
	}
	if authProvider == "" {
		switch {
		case user.EntraSubject != nil && strings.TrimSpace(*user.EntraSubject) != "":
			authProvider = tables.AuthProviderEntra
		case user.GoogleSubject != nil && strings.TrimSpace(*user.GoogleSubject) != "":
			authProvider = tables.AuthProviderGoogle
		case user.PasswordHash != "":
			authProvider = tables.AuthProviderPassword
		default:
			authProvider = tables.AuthProviderAdmin
		}
	}

	fullName := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName))
	return map[string]any{
		"id":                         user.ID,
		"tenant_id":                  user.TenantID,
		"customer_id":                user.CustomerID,
		"role":                       tables.NormalizeAuthUserRole(user.Role),
		"first_name":                 user.FirstName,
		"last_name":                  user.LastName,
		"full_name":                  fullName,
		"organization":               user.Organization,
		"industry":                   user.Industry,
		"email":                      user.Email,
		"pending_email":              user.PendingEmail,
		"is_email_verified":          user.IsEmailVerified,
		"email_verified_at":          user.EmailVerifiedAt,
		"pending_email_requested_at": user.PendingEmailRequestedAt,
		"last_verification_sent_at":  user.LastVerificationSentAt,
		"last_login_at":              user.LastLoginAt,
		"auth_provider":              authProvider,
		"has_password":               user.PasswordHash != "",
		"google_linked":              user.GoogleSubject != nil && strings.TrimSpace(*user.GoogleSubject) != "",
		"entra_linked":               user.EntraSubject != nil && strings.TrimSpace(*user.EntraSubject) != "",
		"entra_connection_id":        user.EntraConnectionID,
		"mfa_enabled":                user.MfaEnabled,
		"theme_preference":           user.ThemePreference,
		"created_at":                 user.CreatedAt,
		"updated_at":                 user.UpdatedAt,
	}
}

func validateProfileFields(firstName, lastName, organization, industry string) error {
	if strings.TrimSpace(firstName) == "" {
		return fmt.Errorf("First name is required")
	}
	if strings.TrimSpace(lastName) == "" {
		return fmt.Errorf("Last name is required")
	}
	if strings.TrimSpace(organization) == "" {
		return fmt.Errorf("Organization is required")
	}
	if strings.TrimSpace(industry) == "" {
		return fmt.Errorf("Industry is required")
	}
	return nil
}
