package configstore

// Branded transactional email rendering (HTML + inline logo + multipart/related
// MIME) for the key-rotation notification path. Self-contained in the
// configstore package so the open-source build carries no separate branding
// dependency.

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
)

//go:embed assets/deepintshield-logo.png
var embeddedEmailLogo []byte

// emailLogoCID is the Content-ID referenced from the HTML body via
// src="cid:...". It must match the Content-ID header on the related MIME part.
const emailLogoCID = "deepintshield-logo@dis"

// emailContent feeds the shared HTML transactional template. Body may contain a
// small amount of safe inline HTML (e.g. <strong>) - the caller is responsible
// for escaping user-controlled values via escapeEmail before embedding them.
type emailContent struct {
	PreviewText string
	Greeting    string
	Headline    string
	Body        string
	CTAURL      string
	CTALabel    string
	Footnote    string
}

// escapeEmail escapes a value safely for embedding in an HTML email body.
func escapeEmail(s string) string { return html.EscapeString(s) }

// renderEmailHTML renders a branded transactional email for the
// lowest-common-denominator email client renderer: table-based layout, inline
// styles only, inline logo via cid:, hidden preview text.
func renderEmailHTML(c emailContent) string {
	preview := escapeEmail(c.PreviewText)
	greeting := escapeEmail(c.Greeting)
	headline := escapeEmail(c.Headline)
	footnote := escapeEmail(c.Footnote)
	ctaURL := escapeEmail(c.CTAURL)
	ctaLabel := escapeEmail(c.CTALabel)
	body := c.Body

	ctaBlock := ""
	if strings.TrimSpace(c.CTAURL) != "" && strings.TrimSpace(c.CTALabel) != "" {
		ctaBlock = `
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="border-radius:10px;background:linear-gradient(135deg,#21d3c4 0%,#1cb5a8 100%);">
                    <a href="` + ctaURL + `" style="display:inline-block;padding:13px 28px;font-size:15px;font-weight:600;color:#03161a;text-decoration:none;border-radius:10px;line-height:1;letter-spacing:0.005em;">` + ctaLabel + `</a>
                  </td>
                </tr>
              </table>

              <p style="margin:28px 0 0 0;font-size:12px;color:#7a8b96;line-height:1.6;">` + footnote + `</p>
              <p style="margin:16px 0 0 0;font-size:12px;color:#7a8b96;line-height:1.6;">If the button doesn't work, paste this URL into your browser:<br><a href="` + ctaURL + `" style="color:#5ed7ff;word-break:break-all;text-decoration:none;">` + ctaURL + `</a></p>`
	} else if footnote != "" {
		ctaBlock = `
              <p style="margin:28px 0 0 0;font-size:12px;color:#7a8b96;line-height:1.6;">` + footnote + `</p>`
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeepintShield</title>
</head>
<body style="margin:0;padding:0;background-color:#0b1418;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e6edf3;">
  <span style="display:none !important;visibility:hidden;mso-hide:all;font-size:1px;color:#0b1418;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">` + preview + `</span>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#0b1418;padding:32px 0;">
    <tr>
      <td align="center">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="max-width:600px;width:100%;background:linear-gradient(180deg,#0e1a20 0%,#0a1418 100%);border:1px solid rgba(255,255,255,0.08);border-radius:16px;overflow:hidden;box-shadow:0 24px 60px -32px rgba(0,0,0,0.6);">
          <tr>
            <td align="center" style="padding:32px 32px 20px 32px;background:linear-gradient(180deg,rgba(108,61,244,0.06) 0%,rgba(33,211,196,0.04) 100%);border-bottom:1px solid rgba(255,255,255,0.06);">
              <img src="cid:` + emailLogoCID + `" alt="DeepintShield - Govern, Secure, and Control Every GenAI Action" width="280" style="display:block;width:280px;max-width:80%;height:auto;border:0;outline:0;" />
            </td>
          </tr>

          <tr>
            <td style="padding:32px;">
              <p style="margin:0 0 8px 0;font-size:14px;color:#7a8b96;">Hi ` + greeting + `,</p>
              <h1 style="margin:0 0 16px 0;font-size:24px;font-weight:700;color:#e6edf3;line-height:1.3;letter-spacing:-0.01em;">` + headline + `</h1>
              <p style="margin:0 0 28px 0;font-size:15px;line-height:1.6;color:#c5cfd8;">` + body + `</p>
` + ctaBlock + `
            </td>
          </tr>

          <tr>
            <td style="padding:20px 32px;background-color:rgba(255,255,255,0.02);border-top:1px solid rgba(255,255,255,0.06);">
              <p style="margin:0;font-size:12px;color:#5d6d78;line-height:1.6;">
                <strong style="color:#a4b1bd;">DeepintShield</strong><br>
                The fastest AI security gateway - near-zero latency guardrails for prompts, agents, and tools.
              </p>
              <p style="margin:12px 0 0 0;font-size:11px;color:#4a5862;line-height:1.6;">
                This is an automated transactional email. Please do not reply.<br>
                © DeepintShield. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`
}

// emailSMTPSender carries just the headers buildMultipartEmail needs.
type emailSMTPSender interface {
	FormattedFrom() string
}

// buildMultipartEmail wraps a (text, html) pair plus the embedded brand logo
// into a properly-formed multipart/related MIME message.
func buildMultipartEmail(sender emailSMTPSender, toEmail, subject, textBody, htmlBody string) ([]byte, error) {
	relatedBoundary, err := randomEmailBoundary("rel")
	if err != nil {
		return nil, err
	}
	altBoundary, err := randomEmailBoundary("alt")
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sender.FormattedFrom())
	fmt.Fprintf(&b, "To: %s\r\n", toEmail)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/related; boundary=\"%s\"; type=\"multipart/alternative\"\r\n", relatedBoundary)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", relatedBoundary)
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", altBoundary)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", altBoundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(textBody)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", altBoundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s--\r\n", altBoundary)

	if len(embeddedEmailLogo) > 0 {
		fmt.Fprintf(&b, "--%s\r\n", relatedBoundary)
		b.WriteString("Content-Type: image/png\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		fmt.Fprintf(&b, "Content-ID: <%s>\r\n", emailLogoCID)
		b.WriteString("Content-Disposition: inline; filename=\"deepintshield-logo.png\"\r\n")
		b.WriteString("\r\n")
		writeBase64Lines(&b, embeddedEmailLogo)
	}

	fmt.Fprintf(&b, "--%s--\r\n", relatedBoundary)
	return []byte(b.String()), nil
}

func writeBase64Lines(b *strings.Builder, payload []byte) {
	encoded := base64.StdEncoding.EncodeToString(payload)
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	if len(encoded) > 0 {
		b.WriteString(encoded)
		b.WriteString("\r\n")
	}
}

func randomEmailBoundary(label string) (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate MIME boundary: %w", err)
	}
	return fmt.Sprintf("dis_%s_%s", label, hex.EncodeToString(buf)), nil
}
