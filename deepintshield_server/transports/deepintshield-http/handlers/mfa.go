package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/encrypt"
	"github.com/valyala/fasthttp"
)

// Native TOTP (RFC 6238) MFA - second factor for password login. The shared
// secret is AES-256-GCM encrypted at rest (auth_users.mfa_secret, json:"-")
// and only ever leaves the server during setup so the user can register an
// authenticator app. Federated logins (Entra/Google) already carry IdP MFA
// and are not challenged here.

// b32 is RFC 4648 base32 without padding - what authenticator apps expect.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type mfaCodeRequest struct {
	Code string `json:"code"`
}

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20) // 160-bit, per RFC 4226 recommendation
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

func totpCodeAt(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	val := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", val%1_000_000), nil
}

// verifyTOTP validates a 6-digit code with ±1 time-step (30s) skew tolerance.
func verifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 || strings.TrimSpace(secret) == "" {
		return false
	}
	counter := uint64(time.Now().Unix() / 30)
	for _, c := range []uint64{counter - 1, counter, counter + 1} {
		if want, err := totpCodeAt(secret, c); err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// decryptMfaSecret returns the usable TOTP secret from its stored form. When
// the platform runs without an encryption key, encrypt.Encrypt stored the
// secret verbatim and encrypt.Decrypt returns it plus
// ErrEncryptionKeyNotInitialized - which we treat as success so MFA works in
// both encrypted and key-less deployments.
func decryptMfaSecret(stored string) (string, error) {
	secret, err := encrypt.Decrypt(stored)
	if err != nil && !errors.Is(err, encrypt.ErrEncryptionKeyNotInitialized) {
		return "", err
	}
	return secret, nil
}

func otpauthURI(secret, account, issuer string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer),
	)
}

const mfaRecoveryCodeCount = 10

func normalizeRecoveryCode(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// generateRecoveryCodes returns single-use backup codes (plaintext, for
// one-time display) plus the JSON array of their SHA-256 hashes for storage.
func generateRecoveryCodes(n int) ([]string, string, error) {
	plain := make([]string, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		code := strings.ToLower(b32.EncodeToString(raw)) // 16 chars
		formatted := code[0:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:16]
		plain = append(plain, formatted)
		hashes = append(hashes, encrypt.HashSHA256(normalizeRecoveryCode(formatted)))
	}
	blob, err := json.Marshal(hashes)
	if err != nil {
		return nil, "", err
	}
	return plain, string(blob), nil
}

// consumeRecoveryCode checks code against the stored hash list; on a match it
// removes that hash and returns the updated JSON (to persist) and true.
func consumeRecoveryCode(stored, code string) (string, bool) {
	stored = strings.TrimSpace(stored)
	if stored == "" || strings.TrimSpace(code) == "" {
		return stored, false
	}
	var hashes []string
	if err := json.Unmarshal([]byte(stored), &hashes); err != nil {
		return stored, false
	}
	target := encrypt.HashSHA256(normalizeRecoveryCode(code))
	out := make([]string, 0, len(hashes))
	matched := false
	for _, h := range hashes {
		if !matched && h == target {
			matched = true
			continue // consume this one
		}
		out = append(out, h)
	}
	if !matched {
		return stored, false
	}
	blob, _ := json.Marshal(out)
	return string(blob), true
}

// mfaAccountError maps currentAccountUser errors to HTTP responses.
func mfaAccountError(ctx *fasthttp.RequestCtx, err error) {
	switch {
	case errors.Is(err, errSessionNotAccount):
		SendError(ctx, fasthttp.StatusForbidden, "This session is not tied to a personal account")
	case errors.Is(err, errUnauthorizedSession):
		SendError(ctx, fasthttp.StatusUnauthorized, err.Error())
	default:
		SendError(ctx, fasthttp.StatusInternalServerError, err.Error())
	}
}

// mfaSetup generates (or re-generates) a TOTP secret for the current user and
// returns the otpauth:// URI for QR rendering. MFA is NOT enabled until the
// user confirms a code via mfaEnable.
func (h *SessionHandler) mfaSetup(ctx *fasthttp.RequestCtx) {
	user, _, err := h.currentAccountUser(ctx)
	if err != nil {
		mfaAccountError(ctx, err)
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to generate MFA secret")
		return
	}
	enc, err := encrypt.Encrypt(secret)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to secure MFA secret")
		return
	}
	user.MfaSecret = enc
	user.MfaEnabled = false // pending until confirmed
	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to store MFA secret: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{
		"secret":      secret,
		"otpauth_uri": otpauthURI(secret, user.Email, "DeepIntShield"),
	})
}

// mfaEnable confirms the pending secret by verifying a code, then turns MFA on.
func (h *SessionHandler) mfaEnable(ctx *fasthttp.RequestCtx) {
	user, _, err := h.currentAccountUser(ctx)
	if err != nil {
		mfaAccountError(ctx, err)
		return
	}
	var req mfaCodeRequest
	_ = json.Unmarshal(ctx.PostBody(), &req)
	if strings.TrimSpace(user.MfaSecret) == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Start MFA setup before enabling")
		return
	}
	secret, derr := decryptMfaSecret(user.MfaSecret)
	if derr != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to read MFA secret")
		return
	}
	if !verifyTOTP(secret, req.Code) {
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid authentication code")
		return
	}
	user.MfaEnabled = true
	codes, hashes, gerr := generateRecoveryCodes(mfaRecoveryCodeCount)
	if gerr != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to generate recovery codes")
		return
	}
	user.MfaRecoveryCodes = hashes
	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to enable MFA: %v", err))
		return
	}
	// recovery_codes are returned ONCE - the client must show + let the user
	// save them now; only their hashes are persisted.
	SendJSON(ctx, map[string]any{
		"message":        "Two-factor authentication enabled.",
		"mfa_enabled":    true,
		"recovery_codes": codes,
	})
}

// mfaRegenerateRecoveryCodes issues a fresh set of single-use backup codes,
// invalidating any previous ones. Requires a current TOTP (or recovery) code so
// a hijacked session can't quietly mint new codes.
func (h *SessionHandler) mfaRegenerateRecoveryCodes(ctx *fasthttp.RequestCtx) {
	user, _, err := h.currentAccountUser(ctx)
	if err != nil {
		mfaAccountError(ctx, err)
		return
	}
	if !user.MfaEnabled {
		SendError(ctx, fasthttp.StatusBadRequest, "Enable MFA before generating recovery codes")
		return
	}
	var req mfaCodeRequest
	_ = json.Unmarshal(ctx.PostBody(), &req)
	secret, derr := decryptMfaSecret(user.MfaSecret)
	if derr != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to read MFA secret")
		return
	}
	if !verifyTOTP(secret, req.Code) {
		if updated, ok := consumeRecoveryCode(user.MfaRecoveryCodes, req.Code); ok {
			user.MfaRecoveryCodes = updated // consume the one used to authorize
		} else {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid authentication code")
			return
		}
	}
	codes, hashes, gerr := generateRecoveryCodes(mfaRecoveryCodeCount)
	if gerr != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to generate recovery codes")
		return
	}
	user.MfaRecoveryCodes = hashes
	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to store recovery codes: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{"message": "New recovery codes generated.", "recovery_codes": codes})
}

// mfaDisable turns MFA off and clears the secret. Requires a valid current code
// (when enabled) so a hijacked session can't silently strip the second factor.
func (h *SessionHandler) mfaDisable(ctx *fasthttp.RequestCtx) {
	user, _, err := h.currentAccountUser(ctx)
	if err != nil {
		mfaAccountError(ctx, err)
		return
	}
	var req mfaCodeRequest
	_ = json.Unmarshal(ctx.PostBody(), &req)
	if user.MfaEnabled && strings.TrimSpace(user.MfaSecret) != "" {
		secret, derr := decryptMfaSecret(user.MfaSecret)
		totpOK := derr == nil && verifyTOTP(secret, req.Code)
		// A recovery code also authorizes disable - for users who've lost
		// their authenticator. (All codes are cleared below anyway.)
		_, recoveryOK := consumeRecoveryCode(user.MfaRecoveryCodes, req.Code)
		if !totpOK && !recoveryOK {
			SendError(ctx, fasthttp.StatusUnauthorized, "Invalid authentication code")
			return
		}
	}
	user.MfaEnabled = false
	user.MfaSecret = ""
	user.MfaRecoveryCodes = ""
	if err := h.configStore.UpdateUser(ctx, user); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to disable MFA: %v", err))
		return
	}
	SendJSON(ctx, map[string]any{"message": "Two-factor authentication disabled.", "mfa_enabled": false})
}
