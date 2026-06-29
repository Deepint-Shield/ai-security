# Security & Compliance

This document describes DeepIntShield's security architecture, the controls
that back it, and how to report a vulnerability. It is a **controls
inventory + compliance-readiness** statement - not a certification. Where a
framework (SOC 2 / ISO 27001 / GDPR) is named, it indicates the control the
platform implements to *support* that framework; formal attestation is a
separate third-party process.

---

## Reporting a vulnerability

Please report security issues privately to **support@deepintshield.com**.
Include reproduction steps and impact. Do not open public issues for
suspected vulnerabilities. We aim to acknowledge within 2 business days.

---

## Architecture & trust boundary

DeepIntShield runs as two planes joined by a single, narrow, outbound tunnel:

- **Control plane (CP)** - vendor-managed console (`app.deepintshield.com`) and
  super-admin tooling. Renders only **signed, allow-list aggregates** of
  customer activity - never raw prompts/completions/traces.
- **Data plane (DP)** - the gateway runtime (`core` + `plugins` + `transports`,
  with `deepintshield_guard` and `deepintshield_models`). All sensitive data
  stays here, in the customer's cloud (Enterprise VPC) or the co-resident
  cloud tier.

**Data residency:** sensitive payloads never leave the DP. Self-hosted deep
traces (Langfuse) are **100% DP-local** (ClusterIP, never public ingress). The
vendor's federated read path uses a **read-only** database role
(`PERMISSION_DENIED` on writes) returning aggregates only. This supports GDPR
Art. 44+ (international transfer) and data-sovereignty requirements by
architecture rather than by policy.

---

## Identity, authentication & RBAC

### Authentication
- **Passwords:** hashed with **bcrypt** (`encrypt.Hash`, default cost); never
  stored or logged in plaintext.
- **Sessions:** the token is looked up by its **SHA-256 `token_hash`**, and the
  token column itself is **AES-256-GCM encrypted at rest** (via
  `SessionsTable.BeforeSave`) when an encryption key is configured - so a
  DB-read breach cannot reconstruct or hijack sessions. The plaintext token
  lives only in an `HttpOnly`, `Secure` (TLS), `SameSite=Lax` cookie with a
  fixed expiry. **Production must set the encryption key** so the token column
  is encrypted (without it, tokens are stored in cleartext - acceptable only
  for local dev).
- **Brute-force protection:** per-IP token-bucket rate limiting on all
  credentialed auth endpoints (`session_ratelimit.go`).
- **MFA (TOTP):** users can enable native, RFC 6238 time-based one-time
  passwords from **Account Settings → Two-factor authentication**. The shared
  secret is **AES-256-GCM encrypted at rest** (`auth_users.mfa_secret`, never
  serialized). When enabled, password login requires the 6-digit code as a
  second step. Federated logins (Entra / Google / OIDC / SAML SSO) delegate MFA
  to the IdP.
- **SSO / SCIM:** Microsoft Entra (OIDC) plus generic OIDC / Okta / Auth0 /
  SAML 2.0, with SCIM 2.0 auto-provisioning. ID tokens are signature-verified.

### Authorization (RBAC)
Authorization is **membership-based**, evaluated per scope - not derived from a
global role. The default signup role (`admin`) is **not** a cross-tenant
bypass; only an explicit platform `superadmin` bypasses membership (a tightly
held support escape-hatch, fully audited).

Scope hierarchy and roles:

```
governance_orgs (org)         owner | admin | member     ← billing + top-tier RBAC anchor
  └─ organizations (tenant)   owner | admin | member
       └─ workspaces          admin | member | viewer
```

- Guards: `CanManageOrg`, `CanManageTenant`, `CanManageWorkspace`,
  `CanReadWorkspace`.
- Org ownership is keyed on a **user UUID** (`owner_user_id`), never an email,
  and is **transferable** ("Make super admin" in the User Manager - owner-only,
  with a last-owner guard so an org can never lose its final administrator).
- Identifiers are UUIDs; the org/tenant identity is decoupled from any
  individual's email so offboarding or email reuse cannot orphan or hijack a
  tenant.

---

## Multi-tenant isolation

- **Automatic ORM-layer scoping:** a GORM `Before("gorm:query")` callback
  (`tenant_scoping.go`) stamps `tenant_id` on every read - defense-in-depth, so
  isolation does not depend on each query remembering to filter.
- **4-layer workspace isolation:** DB strict-equality + WebSocket broadcast
  gate + client connect-URL scoping + page-state reset. A bleed in any one
  layer is contained by the others.

---

## Data protection

- **At rest:** AES-256-GCM for sensitive columns (provider/VK secrets, MFA
  secrets). The database stores environment-variable *references*, not
  plaintext provider secrets.
- **In transit:** TLS (Google-managed certificates on the cloud tier).
- **PII:** context-aware detection in the guardrails engine distinguishes
  genuine PII from operational business data.

---

## Privacy / GDPR

- **Right of access & portability (Art. 15/20):** self-service export at
  **Account Settings → Download my data** (`GET /api/session/me/export`) returns
  the user's profile, org/tenant/workspace memberships, and consent records as
  JSON. Secrets are never included.
- **Right to erasure (Art. 17):** account and organization deletion
  (`DeleteUser`, `DeleteOrganization`).
- **Consent:** an append-only `legal_consents` audit table records the terms /
  privacy version, email, method, and timestamp at acceptance.

---

## Audit logging

All authentication, governance, and administrative actions are recorded via
`AuditLogsMiddleware` as structured entries (actor, event type, action, status,
severity, resource type, auth method). Supports SOC 2 CC7.2 / ISO 27001
A.12.4.

---

## Compliance-framework mapping (controls, not attestations)

| Framework | Supporting controls in this platform |
|---|---|
| **SOC 2** (CC6 logical access, CC7 monitoring) | Membership RBAC, MFA, session-hash-at-rest, audit logging, rate limiting |
| **ISO 27001** (A.9 access, A.10 crypto, A.12.4 logging) | RBAC, AES-256-GCM, bcrypt, TLS, audit trail |
| **GDPR** | DSAR export, erasure, consent audit, data residency (CP/DP), PII detection |

> **Note on claims.** Until a control set has completed an independent audit,
> we describe the platform as **controls-ready** for these frameworks rather
> than *certified*. Public certification claims must reflect completed
> attestations.

---

## Known residual items (tracked)

- **Legacy email-keyed tenant:** a small amount of pre-3-tier data may use an
  email as a tenant primary key. New identities are always UUID-keyed; the
  legacy rows are reconcilable via `MigrateTenantIDs` + `tenant_aliases`.
- **CMEK:** encryption keys are server-derived (argon2id); customer-managed
  keys (CMEK) are a roadmap item for enterprise.
- **MFA recovery codes / WebAuthn:** the current MFA factor is TOTP; backup
  codes and hardware/passkey factors are roadmap items.
