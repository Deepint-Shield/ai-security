package configstore

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deepint-shield/ai-security/framework/configstore/tables"
	"gorm.io/gorm"
)

// rotationSMTPEnv mirrors the billing-side smtpEnv loader so the rotation
// worker doesn't pull the billing package (which already depends on
// configstore - that would create a cycle).
type rotationSMTPEnv struct {
	Host      string
	Port      int
	Username  string
	Password  string
	FromEmail string
	FromName  string
}

func loadRotationSMTPEnv() rotationSMTPEnv {
	port := 587
	if raw := strings.TrimSpace(os.Getenv("SMTP_PORT")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			port = v
		}
	}
	return rotationSMTPEnv{
		Host:      strings.TrimSpace(os.Getenv("SMTP_HOST")),
		Port:      port,
		Username:  strings.TrimSpace(os.Getenv("SMTP_USERNAME")),
		Password:  os.Getenv("SMTP_PASSWORD"),
		FromEmail: strings.TrimSpace(os.Getenv("SMTP_FROM_EMAIL")),
		FromName:  strings.TrimSpace(os.Getenv("SMTP_FROM_NAME")),
	}
}

func (c rotationSMTPEnv) configured() bool {
	return c.Host != "" && c.Port > 0 && c.FromEmail != ""
}

func (c rotationSMTPEnv) address() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

func (c rotationSMTPEnv) auth() smtp.Auth {
	if c.Username == "" {
		return nil
	}
	return smtp.PlainAuth("", c.Username, c.Password, c.Host)
}

func (c rotationSMTPEnv) FormattedFrom() string {
	if c.FromName == "" {
		return c.FromEmail
	}
	return fmt.Sprintf("%s <%s>", c.FromName, c.FromEmail)
}

// rotationDashboardURL is the deep-link to Virtual Keys for one-click jump
// from the email. Mirrors billingPortalURL's env-var fallback chain.
func rotationDashboardURL() string {
	for _, key := range []string{"SMTP_DASHBOARD_URL", "APP_BASE_URL", "DASHBOARD_URL"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return strings.TrimRight(v, "/") + "/workspace/governance/virtual-keys"
		}
	}
	return "http://localhost:8080/workspace/governance/virtual-keys"
}

// sendRotationMail ships a branded multipart email. Best-effort - SMTP
// failures are reported back to the worker so a missed notification is
// logged, but the rotation itself never rolls back over a mail outage.
func sendRotationMail(cfg rotationSMTPEnv, toEmail, subject, textBody string, content emailContent) error {
	if !cfg.configured() || strings.TrimSpace(toEmail) == "" {
		return nil
	}
	htmlBody := renderEmailHTML(content)
	message, err := buildMultipartEmail(cfg, toEmail, subject, textBody, htmlBody)
	if err != nil {
		return err
	}
	if cfg.Port == 465 {
		conn, err := tls.Dial("tcp", cfg.address(), &tls.Config{
			ServerName: cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return fmt.Errorf("smtps dial: %w", err)
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return fmt.Errorf("smtps client: %w", err)
		}
		defer client.Close()
		if a := cfg.auth(); a != nil {
			if ok, _ := client.Extension("AUTH"); ok {
				if err := client.Auth(a); err != nil {
					return fmt.Errorf("smtps auth: %w", err)
				}
			}
		}
		if err := client.Mail(cfg.FromEmail); err != nil {
			return err
		}
		if err := client.Rcpt(toEmail); err != nil {
			return err
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(message); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		return client.Quit()
	}
	return smtp.SendMail(cfg.address(), cfg.auth(), cfg.FromEmail, []string{toEmail}, message)
}

// resolveRotationRecipient locates an email address to notify about a
// virtual key's lifecycle. Resolution order:
//
//  1. The VK's TenantID itself if it looks like an email - most rows are
//     keyed off the dashboard user's email already (per the email-keyed
//     tenant convention).
//  2. The owner of the governance_org whose tenant contains this VK
//     (covers org-managed VKs where tenant_id is opaque).
//
// Returns ("", "") when nothing is resolvable - the worker treats that
// as "send no email this cycle, log a debug line and proceed."
func resolveRotationRecipient(ctx context.Context, db *gorm.DB, vk *tables.TableVirtualKey) (email, name string) {
	if vk == nil {
		return "", ""
	}
	tenantID := strings.TrimSpace(vk.TenantID)
	if strings.Contains(tenantID, "@") {
		// Email-keyed tenant - try to look up the auth user for a nicer name.
		var user tables.TableAuthUser
		if err := db.WithContext(ctx).Where("email = ?", tenantID).Limit(1).Take(&user).Error; err == nil {
			return user.Email, displayNameOrEmail(user)
		}
		// Fallback: send to the email-keyed tenant id itself.
		return tenantID, tenantID
	}
	// Opaque (UUID) tenant id. A VK's tenant_id is an organizations (tenant)
	// id, so resolve that owner first; fall back to governance_orgs for
	// top-tier ids. This covers UUID-keyed tenants (re-keyed and self-serve).
	var ownerUserID string
	var tenant tables.TableOrganization
	if err := db.WithContext(ctx).Where("id = ?", tenantID).Limit(1).Take(&tenant).Error; err == nil {
		ownerUserID = strings.TrimSpace(tenant.OwnerID)
	} else {
		var gov tables.TableGovernanceOrg
		if err := db.WithContext(ctx).Where("id = ?", tenantID).Limit(1).Take(&gov).Error; err == nil {
			ownerUserID = strings.TrimSpace(gov.OwnerUserID)
		}
	}
	if ownerUserID == "" {
		return "", ""
	}
	var owner tables.TableAuthUser
	if err := db.WithContext(ctx).Where("id = ?", ownerUserID).Limit(1).Take(&owner).Error; err != nil {
		return "", ""
	}
	return owner.Email, displayNameOrEmail(owner)
}

func displayNameOrEmail(u tables.TableAuthUser) string {
	display := strings.TrimSpace(strings.TrimSpace(u.FirstName) + " " + strings.TrimSpace(u.LastName))
	if display != "" {
		return display
	}
	return u.Email
}

// notifyVirtualKeyRotationUpcoming warns the tenant owner that an
// auto-rotation is scheduled inside the configured notice window. Sent
// once per rotation cycle; the worker stamps RotationNotifiedAt so
// repeated ticks within the window stay quiet.
func notifyVirtualKeyRotationUpcoming(toEmail, recipientName, keyName string, rotateAt time.Time, graceDays int) error {
	if strings.TrimSpace(toEmail) == "" {
		return nil
	}
	cfg := loadRotationSMTPEnv()
	if !cfg.configured() {
		return nil
	}
	greeting := strings.TrimSpace(recipientName)
	if greeting == "" {
		greeting = "there"
	}
	subject := fmt.Sprintf("DeepintShield: virtual key %q rotates on %s", keyName, rotateAt.UTC().Format("2 Jan 2006"))
	headline := fmt.Sprintf("%s rotates on %s", escapeEmail(keyName), escapeEmail(rotateAt.UTC().Format("2 Jan 2006 15:04 UTC")))
	body := fmt.Sprintf(
		"Your DeepintShield virtual key <strong>%s</strong> is scheduled for an automatic 90-day rotation at <strong>%s</strong>. "+
			"After rotation the previous key value stays accepted for <strong>%d day(s)</strong> so your clients have a grace window to roll over.<br><br>"+
			"No action is required - but if you'd like to rotate manually before the deadline, or extend the grace period, you can do so from the Virtual Keys page.",
		escapeEmail(keyName), escapeEmail(rotateAt.UTC().Format("2 Jan 2006 15:04 UTC")), graceDays,
	)
	textBody := fmt.Sprintf(
		"Hi %s,\r\n\r\nYour DeepintShield virtual key %q is scheduled for an automatic 90-day rotation at %s UTC.\r\n"+
			"After rotation the previous key value stays accepted for %d day(s) so your clients have a grace window to roll over.\r\n\r\n"+
			"You can rotate manually or extend the grace period from the Virtual Keys page:\r\n%s\r\n\r\n- DeepintShield Security\r\n",
		greeting, keyName, rotateAt.UTC().Format("2 Jan 2006 15:04"), graceDays, rotationDashboardURL(),
	)
	return sendRotationMail(cfg, toEmail, subject, textBody, emailContent{
		PreviewText: fmt.Sprintf("Heads-up: %s rotates on %s.", keyName, rotateAt.UTC().Format("2 Jan 2006")),
		Greeting:    greeting,
		Headline:    headline,
		Body:        body,
		CTAURL:      rotationDashboardURL(),
		CTALabel:    "Manage virtual keys",
		Footnote:    "Automatic rotation is part of the SOC 2 §3.1 control. You can change the schedule, grace window, or notice window per key.",
	})
}

// notifyVirtualKeyRotationCompleted tells the owner the rotation has
// happened and the previous key value stays accepted until the grace
// deadline. We deliberately never put the new key value in the email
// body - admins should fetch it from the dashboard after re-auth.
func notifyVirtualKeyRotationCompleted(toEmail, recipientName, keyName string, rotatedAt time.Time, previousValueExpiresAt *time.Time) error {
	if strings.TrimSpace(toEmail) == "" {
		return nil
	}
	cfg := loadRotationSMTPEnv()
	if !cfg.configured() {
		return nil
	}
	greeting := strings.TrimSpace(recipientName)
	if greeting == "" {
		greeting = "there"
	}
	subject := fmt.Sprintf("DeepintShield: virtual key %q has been rotated", keyName)
	headline := fmt.Sprintf("%s rotated", escapeEmail(keyName))

	graceLine := ""
	graceText := ""
	if previousValueExpiresAt != nil && !previousValueExpiresAt.IsZero() {
		graceLine = fmt.Sprintf(
			"<br><br>Your previous key value continues to authenticate requests until <strong>%s</strong>. After that point only the new value is accepted.",
			escapeEmail(previousValueExpiresAt.UTC().Format("2 Jan 2006 15:04 UTC")),
		)
		graceText = fmt.Sprintf(
			"\r\nYour previous key value continues to authenticate requests until %s UTC. After that point only the new value is accepted.\r\n",
			previousValueExpiresAt.UTC().Format("2 Jan 2006 15:04"),
		)
	}

	body := fmt.Sprintf(
		"The DeepintShield virtual key <strong>%s</strong> was rotated at <strong>%s</strong> as part of its scheduled 90-day rotation.%s<br><br>"+
			"Fetch the new key value from the Virtual Keys page when you're ready to roll over.",
		escapeEmail(keyName), escapeEmail(rotatedAt.UTC().Format("2 Jan 2006 15:04 UTC")), graceLine,
	)
	textBody := fmt.Sprintf(
		"Hi %s,\r\n\r\nThe DeepintShield virtual key %q was rotated at %s UTC.\r\n%s\r\nFetch the new key value from the Virtual Keys page:\r\n%s\r\n\r\n- DeepintShield Security\r\n",
		greeting, keyName, rotatedAt.UTC().Format("2 Jan 2006 15:04"), graceText, rotationDashboardURL(),
	)
	return sendRotationMail(cfg, toEmail, subject, textBody, emailContent{
		PreviewText: fmt.Sprintf("%s was rotated. Fetch the new value from the dashboard.", keyName),
		Greeting:    greeting,
		Headline:    headline,
		Body:        body,
		CTAURL:      rotationDashboardURL(),
		CTALabel:    "Fetch new key",
		Footnote:    "The previous key value remains valid during the grace window so existing clients have time to roll over.",
	})
}
