/**
 * Versions of the Terms of Service and Privacy Policy currently in force.
 *
 * Bump these when material changes ship. Both the consent record stored in
 * the database and the version a user actually saw at signup/sign-in must
 * agree, so this constant is the single source of truth shared by the
 * legal pages and the auth forms.
 *
 * Versioning rule: semver-style, with the "minor" / "patch" reserved for
 * non-material edits (typo fixes, formatting). The "major" component must
 * bump for any change that alters legal obligations or data-handling
 * practices, which also triggers re-acceptance for existing users.
 */

export const TERMS_OF_SERVICE_VERSION = "1.0.0";
export const PRIVACY_POLICY_VERSION = "1.0.0";

/** ISO date the current version came into effect. Surfaced on each page. */
export const TERMS_OF_SERVICE_EFFECTIVE_DATE = "2026-05-06";
export const PRIVACY_POLICY_EFFECTIVE_DATE = "2026-05-06";

/** Legal entity details. */
export const LEGAL_ENTITY = {
	tradeName: "The Deep Intelligence",
	additionalTradeName: "Deepint AI",
	productName: "DeepintShield",
	gstin: "29CKBPM5980N1ZD",
	address: {
		street: "Alpine Fiesta, Hoodi Main Road",
		locality: "Saketha Nagar Layout, Hoodi",
		city: "Bengaluru",
		district: "Bengaluru Urban",
		state: "Karnataka",
		pin: "560048",
		country: "India",
	},
	contact: {
		email: "legal@deepintshield.com",
		grievanceEmail: "legal@deepintshield.com",
		supportEmail: "support@deepintshield.com",
		website: "https://deepintshield.com",
	},
	governingLaw: "the laws of the Republic of India",
	jurisdiction: "the courts of Bengaluru, Karnataka, India",
} as const;
