package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/core/schemas"
	"github.com/deepint-shield/ai-security/framework/configstore"
	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"github.com/deepint-shield/ai-security/framework/tenantctx"
	"github.com/deepint-shield/ai-security/transports/deepintshield-http/lib"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

// Compile-time guard so an accidental future rename of lib.* surfaces here.
var _ = lib.ChainMiddlewares

// LegalHandler exposes endpoints for Terms-of-Service / Privacy-Policy
// acceptance retrieval. Acceptance *recording* happens inline inside the
// session login/signup paths - auditors should see the consent row land at
// the same moment the session is created, not after a separate round-trip.
type LegalHandler struct {
	configStore configstore.ConfigStore
}

func NewLegalHandler(configStore configstore.ConfigStore) *LegalHandler {
	return &LegalHandler{configStore: configStore}
}

func (h *LegalHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.DeepIntShieldHTTPMiddleware) {
	r.GET("/api/legal/consents/me", lib.ChainMiddlewares(h.getMyConsents, middlewares...))
	r.GET("/api/legal/consents", lib.ChainMiddlewares(h.listConsents, middlewares...))
}

// getMyConsents returns every recorded acceptance for the calling user. Used
// by the user's own "what did I accept and when" view.
func (h *LegalHandler) getMyConsents(ctx *fasthttp.RequestCtx) {
	userID := strings.TrimSpace(tenantctx.UserIDFromContext(ctx))
	if userID == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "Authentication required")
		return
	}
	rows, err := h.configStore.GetLegalConsentsForUser(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load consents: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{"consents": rows})
}

// listConsents is the admin audit endpoint. Auth + RBAC are enforced by the
// audit-route middleware chain; this handler additionally checks that the
// caller has an admin/superadmin role on their auth user record.
//
// Filters (all optional, mix freely):
//
//	user_id, email, document_type, document_version, consent_method,
//	from (RFC3339), to (RFC3339), limit (default 100, max 1000), offset.
func (h *LegalHandler) listConsents(ctx *fasthttp.RequestCtx) {
	userID := strings.TrimSpace(tenantctx.UserIDFromContext(ctx))
	if userID == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "Authentication required")
		return
	}
	user, err := h.configStore.GetUserByID(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to load caller: %v", err))
		return
	}
	if user == nil || !isLegalAuditViewer(user.Role) {
		SendError(ctx, fasthttp.StatusForbidden, "Audit access requires admin or superadmin role")
		return
	}
	q := configstore.LegalConsentQuery{
		UserID:          string(ctx.QueryArgs().Peek("user_id")),
		Email:           strings.ToLower(string(ctx.QueryArgs().Peek("email"))),
		DocumentType:    string(ctx.QueryArgs().Peek("document_type")),
		DocumentVersion: string(ctx.QueryArgs().Peek("document_version")),
		ConsentMethod:   string(ctx.QueryArgs().Peek("consent_method")),
		Limit:           parseIntQuery(ctx, "limit", 100, 1000),
		Offset:          parseIntQuery(ctx, "offset", 0, 0),
	}
	if from := string(ctx.QueryArgs().Peek("from")); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			q.From = &t
		}
	}
	if to := string(ctx.QueryArgs().Peek("to")); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			q.To = &t
		}
	}
	rows, total, err := h.configStore.ListLegalConsents(ctx, q)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list consents: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"consents": rows,
		"total":    total,
		"limit":    q.Limit,
		"offset":   q.Offset,
	})
}

func isLegalAuditViewer(role string) bool {
	switch role {
	case tables.UserRoleAdmin, tables.UserRoleSuperadmin:
		return true
	}
	return false
}

func parseIntQuery(ctx *fasthttp.RequestCtx, key string, defaultValue, max int) int {
	raw := string(ctx.QueryArgs().Peek(key))
	if raw == "" {
		return defaultValue
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return defaultValue
	}
	if max > 0 && v > max {
		return max
	}
	return v
}

// recordLegalConsent persists ToS + Privacy acceptance after a successful
// auth event. Errors are logged but never block the auth path - losing one
// audit row must not lock the user out.
//
// hashDocVersion stitches the version string together with a deterministic
// salt so old versions can't be silently swapped out without invalidating
// the recorded hash. Replace with a real document-text hash when the
// rendered HTML is moved server-side.
func recordLegalConsent(
	ctx context.Context,
	store configstore.ConfigStore,
	user *tables.TableAuthUser,
	method string,
	terms string,
	privacy string,
	ipAddress string,
	userAgent string,
	locale string,
) {
	if store == nil || user == nil {
		return
	}
	now := time.Now().UTC()
	tenantID := user.TenantID

	if v := strings.TrimSpace(terms); v != "" {
		_ = store.CreateLegalConsent(ctx, &tables.TableLegalConsent{
			ID:              uuid.NewString(),
			TenantID:        tenantID,
			UserID:          user.ID,
			EmailAtConsent:  user.Email,
			DocumentType:    tables.LegalDocumentTermsOfService,
			DocumentVersion: v,
			DocumentHash:    hashDocVersion(tables.LegalDocumentTermsOfService, v),
			ConsentMethod:   method,
			IPAddress:       ipAddress,
			UserAgent:       userAgent,
			Locale:          locale,
			AcceptedAt:      now,
			CreatedAt:       now,
		})
	}
	if v := strings.TrimSpace(privacy); v != "" {
		_ = store.CreateLegalConsent(ctx, &tables.TableLegalConsent{
			ID:              uuid.NewString(),
			TenantID:        tenantID,
			UserID:          user.ID,
			EmailAtConsent:  user.Email,
			DocumentType:    tables.LegalDocumentPrivacyPolicy,
			DocumentVersion: v,
			DocumentHash:    hashDocVersion(tables.LegalDocumentPrivacyPolicy, v),
			ConsentMethod:   method,
			IPAddress:       ipAddress,
			UserAgent:       userAgent,
			Locale:          locale,
			AcceptedAt:      now,
			CreatedAt:       now,
		})
	}
}

// hashDocVersion returns sha256("<doc_type>:<version>") so the audit row
// pins the document identity even if a future change to the rendered text
// happens. Once the rendered Markdown ships from the server we should hash
// the actual bytes here.
func hashDocVersion(docType, version string) string {
	h := sha256.Sum256([]byte(docType + ":" + version))
	return hex.EncodeToString(h[:])
}

// localeFromCtx returns the primary locale from the Accept-Language header,
// truncated to a reasonable length. Used for the legal-consents row so an
// auditor can see what language the user was viewing the document in.
func localeFromCtx(ctx *fasthttp.RequestCtx) string {
	raw := strings.TrimSpace(string(ctx.Request.Header.Peek("Accept-Language")))
	if raw == "" {
		return ""
	}
	if comma := strings.IndexByte(raw, ','); comma >= 0 {
		raw = raw[:comma]
	}
	if semi := strings.IndexByte(raw, ';'); semi >= 0 {
		raw = raw[:semi]
	}
	raw = strings.TrimSpace(raw)
	if len(raw) > 32 {
		raw = raw[:32]
	}
	return raw
}

// remoteAddrFromCtx extracts the best-effort client IP. Honors the
// X-Forwarded-For chain when an upstream load balancer sets it, otherwise
// falls back to the TCP peer.
func remoteAddrFromCtx(ctx *fasthttp.RequestCtx) string {
	if xff := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-For"))); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return xff
	}
	if real := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Real-IP"))); real != "" {
		return real
	}
	return ctx.RemoteAddr().String()
}
