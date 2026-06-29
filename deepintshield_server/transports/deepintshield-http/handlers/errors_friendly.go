package handlers

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/valyala/fasthttp"
	"gorm.io/gorm"
)

// friendlyError converts an arbitrary error into a (httpStatus, userMessage)
// pair suitable for sending to the dashboard. The goal is to never surface
// raw Postgres SQLSTATEs, GORM internals, or unindexed driver text to end
// users - those are operationally useful in logs but read as gibberish in
// a UI toast.
//
// The `resourceLabel` is interpolated into the message ("tenant", "workspace",
// "virtual key", etc.) so the same helper produces consistently-worded
// errors across every CRUD handler.
//
// Usage (in a handler):
//
//	if err := store.CreateOrganization(ctx, t); err != nil {
//	    status, msg := friendlyError(err, "tenant")
//	    SendError(ctx, status, msg)
//	    return
//	}
func friendlyError(err error, resourceLabel string) (int, string) {
	if err == nil {
		return fasthttp.StatusInternalServerError, "Unknown error"
	}
	label := strings.TrimSpace(resourceLabel)
	if label == "" {
		label = "resource"
	}

	// gorm "no rows" → 404. Most callers should pre-check + 404 themselves;
	// this is a backstop for paths that don't.
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fasthttp.StatusNotFound, capitalize(label) + " not found"
	}

	// Postgres-specific SQLSTATE handling. The pgconn.PgError type is
	// what GORM/pgx surfaces; we reach into it for the well-known codes.
	// References: https://www.postgresql.org/docs/current/errcodes-appendix.html
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			// ConstraintName usually narrows what was duplicated. We try
			// to give a useful pointer ("name already exists") when we
			// recognise a known index, otherwise fall back to a generic
			// "already exists" wording.
			cn := strings.ToLower(pgErr.ConstraintName)
			switch {
			case strings.Contains(cn, "slug") || strings.Contains(cn, "name"):
				return fasthttp.StatusConflict, "A " + label + " with this name already exists. Pick a different name."
			case strings.Contains(cn, "email"):
				return fasthttp.StatusConflict, "An account with this email already exists."
			case strings.Contains(cn, "google_subject"):
				return fasthttp.StatusConflict, "This Google account is already linked to a different login."
			default:
				return fasthttp.StatusConflict, "This " + label + " already exists."
			}
		case "23503": // foreign_key_violation
			return fasthttp.StatusConflict, "Can't complete this change - the " + label + " is referenced by other records. Remove or reassign them first."
		case "23502": // not_null_violation
			return fasthttp.StatusBadRequest, "A required field is missing. Fill in every required field and try again."
		case "23514": // check_violation
			return fasthttp.StatusBadRequest, "One of the values you provided isn't allowed. Please review and try again."
		case "22001": // string_data_right_truncation (value too long)
			return fasthttp.StatusBadRequest, "One of the values you entered is too long. Shorten it and try again."
		case "40001": // serialization_failure (transaction conflict)
			return fasthttp.StatusConflict, "Another change happened at the same time. Please retry."
		case "57014": // query_canceled
			return fasthttp.StatusServiceUnavailable, "The request took too long. Please retry."
		}
	}

	// Driver-string fallback: some legacy code paths build raw errors
	// (fmt.Errorf("...")) that wrap the SQLSTATE text without a typed
	// PgError. Detect by substring as a last-resort safety net so we
	// never expose "duplicate key value violates unique constraint" to
	// the end user.
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "duplicate key"):
		return fasthttp.StatusConflict, "A " + label + " with this name already exists. Pick a different name."
	case strings.Contains(lower, "foreign key constraint"):
		return fasthttp.StatusConflict, "Can't complete this change - the " + label + " is referenced by other records."
	case strings.Contains(lower, "value too long"):
		return fasthttp.StatusBadRequest, "One of the values you entered is too long."
	case strings.Contains(lower, "context deadline exceeded"), strings.Contains(lower, "context canceled"):
		return fasthttp.StatusServiceUnavailable, "The request took too long. Please retry."
	}

	// Untyped error - send a generic 500 with a recognisable message. The
	// real error stays in server logs.
	return fasthttp.StatusInternalServerError, "Something went wrong while processing this " + label + ". Please retry; if the issue persists, contact support."
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
