package runtimeapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

const (
	HeaderTimestamp   = "X-DeepIntShield-Timestamp"
	HeaderSignature   = "X-DeepIntShield-Signature"
	HeaderContentHash = "X-DeepIntShield-Content-SHA256"

	MetadataTimestamp   = "x-deepintshield-timestamp"
	MetadataSignature   = "x-deepintshield-signature"
	MetadataContentHash = "x-deepintshield-content-sha256"

	DefaultClockSkew = 5 * time.Minute
)

func BodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func BuildSignature(operation string, at time.Time, body []byte, secret string) (string, string, string) {
	ts := strconv.FormatInt(at.UTC().Unix(), 10)
	digest := BodySHA256(body)
	if strings.TrimSpace(secret) == "" {
		return ts, "", digest
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strings.TrimSpace(operation)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(ts))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(digest))
	return ts, hex.EncodeToString(mac.Sum(nil)), digest
}

func ValidateSignature(operation string, body []byte, timestamp, signature, contentHash, secret string, now time.Time) error {
	if strings.TrimSpace(secret) == "" {
		return nil
	}
	if strings.TrimSpace(timestamp) == "" || strings.TrimSpace(signature) == "" {
		return fmt.Errorf("missing runtime authentication headers")
	}
	parsedTimestamp, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid runtime auth timestamp: %w", err)
	}
	tsTime := time.Unix(parsedTimestamp, 0).UTC()
	if now.UTC().Sub(tsTime) > DefaultClockSkew || tsTime.Sub(now.UTC()) > DefaultClockSkew {
		return fmt.Errorf("runtime auth timestamp is outside the allowed skew")
	}
	expectedContentHash := BodySHA256(body)
	if strings.TrimSpace(contentHash) != "" && !strings.EqualFold(strings.TrimSpace(contentHash), expectedContentHash) {
		return fmt.Errorf("runtime content hash mismatch")
	}
	_, expectedSignature, _ := BuildSignature(operation, tsTime, body, secret)
	if !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(signature))), []byte(strings.ToLower(expectedSignature))) {
		return fmt.Errorf("runtime signature mismatch")
	}
	return nil
}

func AttachHTTPAuth(req *http.Request, operation string, body []byte, secret string, now time.Time) {
	if req == nil || strings.TrimSpace(secret) == "" {
		return
	}
	ts, signature, digest := BuildSignature(operation, now, body, secret)
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, signature)
	req.Header.Set(HeaderContentHash, digest)
}

func AttachGRPCAuth(ctx context.Context, operation string, body []byte, secret string, now time.Time) context.Context {
	if strings.TrimSpace(secret) == "" {
		return ctx
	}
	ts, signature, digest := BuildSignature(operation, now, body, secret)
	md := metadata.Pairs(
		MetadataTimestamp, ts,
		MetadataSignature, signature,
		MetadataContentHash, digest,
	)
	return metadata.NewOutgoingContext(ctx, md)
}

func ValidateGRPCAuth(md metadata.MD, operation string, body []byte, secret string, now time.Time) error {
	if strings.TrimSpace(secret) == "" {
		return nil
	}
	if md == nil {
		return fmt.Errorf("missing runtime metadata")
	}
	return ValidateSignature(
		operation,
		body,
		firstMetadataValue(md, MetadataTimestamp),
		firstMetadataValue(md, MetadataSignature),
		firstMetadataValue(md, MetadataContentHash),
		secret,
		now,
	)
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
