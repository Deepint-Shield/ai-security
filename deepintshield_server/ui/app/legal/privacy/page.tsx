import type { Metadata } from "next";
import Link from "next/link";

import { LEGAL_ENTITY, PRIVACY_POLICY_EFFECTIVE_DATE, PRIVACY_POLICY_VERSION } from "@/lib/legal/versions";

export const metadata: Metadata = {
	title: "Privacy Policy - DeepintShield",
	description: "How DeepintShield collects, uses and protects personal data.",
};

export default function PrivacyPage() {
	return (
		<article className="space-y-8 break-words text-[15px] [hyphens:auto]">
			<header className="space-y-2">
				<p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Legal · v{PRIVACY_POLICY_VERSION}</p>
				<h1 className="text-3xl font-semibold tracking-[-0.02em]">Privacy Policy</h1>
				<p className="text-sm text-muted-foreground">
					Last updated {PRIVACY_POLICY_EFFECTIVE_DATE}.
				</p>
			</header>

			<section className="space-y-3">
				<p>
					This Privacy Policy explains how <strong>{LEGAL_ENTITY.tradeName}</strong> (operating as{" "}
					<strong>{LEGAL_ENTITY.additionalTradeName}</strong>; &ldquo;we&rdquo;, &ldquo;us&rdquo;, &ldquo;our&rdquo;) collects,
					stores, uses and shares (together, &ldquo;processes&rdquo;) information when you use our services (the
					&ldquo;Services&rdquo;) - for example when you visit{" "}
					<a href={LEGAL_ENTITY.contact.website} className="underline">{LEGAL_ENTITY.contact.website}</a> or any other website
					of ours that links to this Policy, sign in to the {LEGAL_ENTITY.productName} dashboards, call our APIs, install
					our SDKs, or interact with us through sales, marketing or events.
				</p>
				<p>
					Reading this notice will help you understand your rights and choices. If you do not agree with our practices,
					please do not use the Services. For questions, write to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">Summary of key points</h2>
				<p>
					This summary captures the headline points; full detail follows the table of contents below.
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>What we process.</strong> When you use the Services, we may process personal information depending on how you interact with us, the choices you make and the features you use. See Section 1.</li>
					<li><strong>Sensitive categories.</strong> We do not routinely process sensitive personal data or information as defined under the SPDI Rules, 2011 or the DPDP Act, 2023.</li>
					<li><strong>Third-party data.</strong> We do not buy personal information about you from third parties.</li>
					<li><strong>How we use it.</strong> To provide, operate, secure, support and improve the Services, to comply with law, and (with your consent) for product communications.</li>
					<li><strong>Sharing.</strong> Only with sub-processors and categories of recipients described in Section 4, under appropriate confidentiality and data-protection obligations.</li>
					<li><strong>Security.</strong> We use organisational and technical safeguards described in Section 9.</li>
					<li><strong>Your rights.</strong> Under the DPDP Act, 2023 you have rights of access, correction, erasure, withdrawal of consent, nomination and grievance redressal. See Section 11.</li>
					<li><strong>How to exercise them.</strong> Write to{" "}
						<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>{" "}
						from the email associated with your account.
					</li>
				</ul>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">Table of contents</h2>
				<ol className="ml-5 list-decimal space-y-1 text-sm">
					<li>What information do we collect?</li>
					<li>How do we process your information?</li>
					<li>What legal bases do we rely on to process your personal information?</li>
					<li>When and with whom do we share your personal information?</li>
					<li>Do we use cookies and other tracking technologies?</li>
					<li>How do we handle your social logins?</li>
					<li>Is your information transferred internationally?</li>
					<li>How long do we keep your information?</li>
					<li>How do we keep your information safe?</li>
					<li>Do we collect information from minors?</li>
					<li>What are your privacy rights?</li>
					<li>Controls for Do-Not-Track features</li>
					<li>Do Indian residents have specific privacy rights?</li>
					<li>Do we make updates to this notice?</li>
					<li>How can you contact us about this notice?</li>
					<li>How can you review, update or delete the data we collect from you?</li>
				</ol>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">1. What information do we collect?</h2>
				<p>
					<strong>Personal information you provide.</strong> We collect personal information that you voluntarily provide
					when you register for the Services, request information about us, take part in features, or otherwise contact us.
					The information we collect depends on how you interact with the Services and may include your name, email
					address, organisation, role, password (stored as a one-way hash), and any other information you choose to share
					with us.
				</p>
				<p>
					<strong>Sensitive information.</strong> We do not request and do not knowingly process sensitive personal data or
					information (as defined under the Information Technology (Reasonable Security Practices and Procedures and
					Sensitive Personal Data or Information) Rules, 2011 - the &ldquo;SPDI Rules&rdquo;) for our own purposes. You
					should not submit sensitive personal data through the Services unless your use case strictly requires it; if you
					do, you remain the controller of that data and must have the lawful basis to do so.
				</p>
				<p>
					<strong>Payment data.</strong> If you make a purchase, we may collect data needed to process the payment, such as
					a payment-instrument identifier and tokens issued by our payment processor. We do not store full card numbers,
					CVVs or full bank-account details - these are handled by the processor under their own privacy notice. Indian
					customers may be asked for GSTIN and PAN to enable tax invoicing under the Central Goods and Services Tax Act,
					2017 and the Income-tax Act, 1961.
				</p>
				<p>
					<strong>Social login data.</strong> Where you choose to sign in via Google, Microsoft Entra or another single
					sign-on (SSO) provider, we receive identity-provider data as described in Section 6.
				</p>
				<p>
					All personal information you provide to us must be true, complete and accurate. Please notify us of any changes.
				</p>
				<p>
					<strong>Information we collect automatically.</strong> Some information is collected automatically when you visit
					or use the Services. It does not, by itself, identify you, but may include device and usage information, such as
					your Internet Protocol (IP) address, user agent, operating system, language preference, referring URLs, locale,
					approximate region, and information about how and when you use the Services. We collect this primarily to operate
					and secure the Services and for internal analytics. Categories include:
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Log and usage data.</strong> Service-related diagnostic, usage and performance information that our servers automatically collect when you access or use the Services and that we record in log files. Depending on how you interact with us, this may include your IP address, browser type and settings, the date and time of your activity, the pages or features used, error reports, and hardware settings.</li>
					<li><strong>Device data.</strong> Information about the computer, phone, tablet or other device used to access the Services, which may include device identifiers, browser type, hardware model, internet-service or mobile-network operator, operating system and configuration.</li>
					<li><strong>Approximate location.</strong> An approximate region derived from your IP address. We do not collect precise GPS location.</li>
				</ul>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">2. How do we process your information?</h2>
				<p>We process personal information for a variety of reasons, depending on how you interact with the Services, including:</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Account creation and authentication.</strong> So you can create and log in to your account and manage user provisioning.</li>
					<li><strong>Service delivery.</strong> To deliver the Services you have requested, including routing, governance, virtual-key management and audit logging.</li>
					<li><strong>Support.</strong> To respond to your enquiries and resolve issues you raise.</li>
					<li><strong>Service messages.</strong> To send security alerts, billing notices, password resets, changes to legal terms and other operational communications you cannot opt out of for as long as you have an account.</li>
					<li><strong>Order management.</strong> To process payments, manage subscriptions, raise tax invoices and respond to refund or chargeback claims.</li>
					<li><strong>Feedback.</strong> To request feedback from you and to contact you about your experience with the Services.</li>
					<li><strong>Marketing communications.</strong> To send product updates and event invitations where you have separately opted in. You can opt out at any time using the link in any marketing email.</li>
					<li><strong>Security and abuse prevention.</strong> To detect, investigate and respond to fraud, abuse and security incidents.</li>
					<li><strong>Product improvement.</strong> To compute aggregated, de-identified analytics that help us improve the Services. We do not use Customer Data to train our models or any third party&apos;s models.</li>
					<li><strong>Marketing effectiveness.</strong> To understand which campaigns are useful and to improve their relevance.</li>
					<li><strong>Vital interests.</strong> Where necessary to save or protect a person&apos;s vital interests, such as preventing imminent harm.</li>
					<li><strong>Legal obligations.</strong> To comply with our obligations under Indian law, including the Information Technology Act, 2000, the DPDP Act, 2023, GST law and applicable record-retention rules.</li>
				</ul>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">3. What legal bases do we rely on to process your personal information?</h2>
				<p>
					We process personal information only when we have a valid lawful basis under applicable data-protection law. As a
					Data Fiduciary under the DPDP Act, 2023, we rely on the following grounds:
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Consent.</strong> Where you have given us specific, informed, free and unambiguous consent for a defined purpose - for example, to create an account, to opt in to marketing emails, or to enable a non-essential feature. You may withdraw consent at any time; withdrawal does not affect the lawfulness of processing carried out before withdrawal.</li>
					<li><strong>Legitimate uses.</strong> The DPDP Act, 2023 (§7) recognises specified &ldquo;legitimate uses&rdquo; including providing services or benefits explicitly requested, complying with law, performing functions under law and responding to medical or other emergencies. We rely on these where applicable.</li>
					<li><strong>Contractual necessity.</strong> Where processing is required to deliver the features described in our <Link href="/legal/terms" className="underline">Terms and Conditions</Link>.</li>
					<li><strong>Compliance with legal obligations.</strong> Where we are required to process information to comply with Indian law (for example, tax-invoicing under §31 of the CGST Act, 2017, lawful interception under §69 of the Information Technology Act, 2000, or court orders).</li>
					<li><strong>Vital interests.</strong> Where processing is necessary to protect the vital interests of you or another natural person.</li>
				</ul>
				<p>
					If you are accessing the Services from the European Economic Area or the United Kingdom, we additionally rely on
					the lawful bases set out in the General Data Protection Regulation and the UK GDPR (consent, performance of a
					contract, legitimate interests, legal obligation and vital interests). Customers in Canada, Singapore or other
					regions may rely on equivalent local concepts including express and implied consent. Where we rely on legitimate
					interests, we have considered whether those interests are overridden by your fundamental rights and freedoms and
					can describe that assessment on request.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">4. When and with whom do we share your personal information?</h2>
				<p>We share personal information only as needed to operate the Services and only with parties bound by appropriate confidentiality and data-protection obligations:</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Cloud hosting and database providers</strong> who host the gateway, audit logs, billing systems and back-office tools.</li>
					<li><strong>Identity providers</strong> (Google, Microsoft Entra and other SSO sources you choose to use).</li>
					<li><strong>Model and tool providers</strong> you select to route traffic to. Your prompts and tool inputs flow to that provider; we are not responsible for their independent processing under their own privacy notices.</li>
					<li><strong>Payment and tax processors</strong> for billing, refunds and statutory compliance.</li>
					<li><strong>Email-delivery and customer-support tools</strong> we use to send transactional emails and respond to your tickets.</li>
					<li><strong>Observability and security tools</strong> used to monitor uptime, errors and abuse - typically receiving metadata only.</li>
					<li><strong>Professional advisors</strong> (auditors, legal counsel, tax advisors) under confidentiality obligations.</li>
					<li><strong>Acquirers and successors</strong> in the event of a merger, acquisition, reorganisation or sale of substantially all of our assets, with notice to you.</li>
					<li><strong>Public authorities and courts</strong> where compelled by lawful order under Indian law (including §69 and §69A of the Information Technology Act, 2000, the Code of Criminal Procedure, 1973 and successor statutes) or by comparable foreign law.</li>
					<li><strong>With your consent</strong> for any disclosure outside the cases described above.</li>
				</ul>
				<p>
					A current list of sub-processors is available on request from{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>.
					We do not sell personal information.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">5. Do we use cookies and other tracking technologies?</h2>
				<p>
					We use cookies and similar technologies (such as web-storage entries and pixels) only as needed to operate the
					Services. The categories we set are:
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Strictly necessary</strong> cookies for session management, CSRF protection and load-balancer affinity. These cannot be disabled if you want to remain signed in.</li>
					<li><strong>Preferences</strong> entries for theme, sidebar state and dismissal of UI prompts.</li>
					<li><strong>First-party analytics</strong> for product usage at the page-view level. We do not run third-party advertising trackers, retargeting pixels or device-fingerprinting.</li>
				</ul>
				<p>
					Most browsers allow you to refuse or clear cookies through their settings; doing so for strictly-necessary cookies
					will break login. We respect global privacy controls where applicable law requires it.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">6. How do we handle your social logins?</h2>
				<p>
					The Services may let you sign in or register using a social or enterprise identity provider, such as Google,
					Microsoft Entra or another SSO source. When you do, we receive certain profile information from that provider -
					typically your name, email address, profile picture (if available) and provider-issued user identifier.
				</p>
				<p>
					We use the information we receive only to enable sign-in, to display your account profile and (where you have
					granted us specific permissions) to populate your workspace. We do not control the privacy practices of the
					identity provider; please review the provider&apos;s own privacy notice to understand how they collect, use and
					share information.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">7. Is your information transferred internationally?</h2>
				<p>
					Our infrastructure is operated primarily from India. Some of our sub-processors (for example, certain
					email-delivery, payment-processor or model-provider sub-processors) may operate from outside India. Where
					personal information is transferred outside India, we rely on contractual safeguards consistent with the DPDP
					Act, 2023 and any restrictions notified by the Central Government regarding cross-border transfer. We will
					update this Policy if those rules change.
				</p>
				<p>
					If you are in the European Economic Area or the United Kingdom, transfers of your personal information outside
					that region are made under safeguards that meet the requirements of the GDPR and the UK GDPR.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">8. How long do we keep your information?</h2>
				<p>
					We retain personal information only as long as necessary for the purpose for which it was collected, plus any
					additional period required by law. Indicative retention periods:
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li>Account records: for the life of the account and up to ninety (90) days after closure, unless statutory retention applies.</li>
					<li>Authentication and security logs: typically twelve (12) months, longer where investigation or legal hold is required.</li>
					<li>Billing records and tax invoices: at least eight (8) years, in line with §36 of the Central Goods and Services Tax Act, 2017.</li>
					<li>Records of consent to legal terms: for the life of the account plus the limitation period under the Limitation Act, 1963.</li>
					<li>Customer Data: under your control and retained per your account configuration; deleted on your verified request, subject to legal exceptions.</li>
				</ul>
				<p>When we no longer need personal information, we will delete or anonymise it; if that is not feasible (for example, where data is held in backup) we will isolate it from further processing until deletion is possible.</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">9. How do we keep your information safe?</h2>
				<p>
					We use technical and organisational measures appropriate to the risk and consistent with industry practice to
					protect personal information, including encryption in transit, encryption at rest for primary data stores, hashed
					credential storage, role-based access control, audit logging, the principle of least privilege, network
					segmentation, vulnerability management and incident-response procedures.
				</p>
				<p>
					However, no electronic transmission over the internet or storage technology can be guaranteed to be secure; we
					cannot promise that unauthorised third parties will not be able to defeat our security and improperly collect,
					access, steal or modify your information. Where a personal-data breach is likely to result in risk to the rights
					of users, we will notify affected users and the Data Protection Board of India, and report to CERT-In, in line
					with applicable law and the timelines set by the Information Technology (The Indian Computer Emergency Response
					Team and Manner of Performing Functions and Duties) Rules, 2013 and the Digital Personal Data Protection Rules.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">10. Do we collect information from minors?</h2>
				<p>
					The Services are not directed to children under eighteen (18). We do not knowingly solicit personal information
					from children, and we do not knowingly market to them. If we learn that personal information of a child under 18
					has been collected without verifiable parental consent as required by §9 of the DPDP Act, 2023, we will take
					reasonable steps to delete that information. If you believe a child has provided us with personal information,
					please contact{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">11. What are your privacy rights?</h2>
				<p>Under the DPDP Act, 2023 and other applicable law, you have the following rights:</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Access.</strong> A summary of personal information we process about you and the categories of recipients with whom we have shared it.</li>
					<li><strong>Correction.</strong> Correction of personal information that is inaccurate, incomplete or misleading.</li>
					<li><strong>Updating and completion.</strong> Updating or completing personal information held about you.</li>
					<li><strong>Erasure.</strong> Erasure of personal information that is no longer needed for the purpose for which it was collected, subject to legal retention obligations.</li>
					<li><strong>Withdrawal of consent.</strong> Withdrawal of consent at any time, with effect from the time of withdrawal.</li>
					<li><strong>Nomination.</strong> Nomination of another individual to exercise your rights in the event of your death or incapacity, in line with §14 of the DPDP Act, 2023.</li>
					<li><strong>Grievance redressal.</strong> A right to lodge a grievance with our Grievance Officer (Section 12 of the website&apos;s contact details below) and, if not satisfied, to escalate to the Data Protection Board of India.</li>
				</ul>
				<p>
					If you are in the European Economic Area or the United Kingdom and believe we are unlawfully processing your
					personal information, you also have the right to lodge a complaint with your local data-protection authority. To
					exercise any right, write to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>{" "}
					from the email associated with your account or by another verified channel we may reasonably request. We will
					consider and act on your request within the timelines set by applicable law.
				</p>
				<p>
					<strong>Withdrawing consent.</strong> Where we rely on consent, you may withdraw it at any time. You can also opt
					out of marketing emails through the unsubscribe link in any marketing email. Operational messages cannot be
					opted out of for as long as your account is active.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">12. Controls for Do-Not-Track features</h2>
				<p>
					Most web browsers and some mobile operating systems include a Do-Not-Track (&ldquo;DNT&rdquo;) signal you can
					activate to express your preference not to have data about your online activities monitored and collected. There
					is currently no agreed technical standard for recognising and acting on DNT signals, and we do not currently
					respond to them. If a final standard is adopted in future, we will update this Policy to describe how we honour
					the relevant signal.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">13. Do Indian residents have specific privacy rights?</h2>
				<p>
					If you are a resident of India, you have specific privacy rights under the Digital Personal Data Protection Act,
					2023, the Information Technology Act, 2000 and the SPDI Rules, 2011, summarised below.
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li><strong>Notice.</strong> A right to receive a clear notice of the personal data being processed and the purpose for which it is processed (§5 of the DPDP Act, 2023).</li>
					<li><strong>Consent.</strong> A right to give and to withdraw free, informed, specific, unconditional and unambiguous consent (§6).</li>
					<li><strong>Access, correction and erasure.</strong> Rights of access (§11), correction and erasure (§12) of your personal data.</li>
					<li><strong>Grievance redressal.</strong> A right to grievance redressal (§13) and to escalate to the Data Protection Board of India.</li>
					<li><strong>Nomination.</strong> A right to nominate another person to exercise your rights in the event of your death or incapacity (§14).</li>
					<li><strong>Duties.</strong> The DPDP Act, 2023 also imposes duties on Data Principals (§15), including not registering false or frivolous grievances and providing authentic information when exercising rights of correction or erasure.</li>
				</ul>
				<p>
					We have published the contact details of our Grievance Officer in Section 15 below. If you are not satisfied with
					how a grievance is handled, you may approach the Data Protection Board of India once it is constituted.
				</p>
				<p>
					<strong>Other regions.</strong> Customers located in the European Economic Area, the United Kingdom, California
					or other jurisdictions may have additional rights under their local law. Please contact us using the details
					below to exercise those rights.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">14. Do we make updates to this notice?</h2>
				<p>
					We may update this Privacy Policy from time to time to reflect changes in our practices, in technology or in
					applicable law. The date at the top of this page tells you when it was last updated. Where the changes are
					material, we will notify you by email or through the Services and, where required, request fresh acceptance the
					next time you sign in. We encourage you to review this Policy from time to time to stay informed about how we
					protect your information.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">15. How can you contact us about this notice?</h2>
				<p>
					In line with rule 3(2) of the SPDI Rules, 2011, the Information Technology (Intermediary Guidelines and Digital
					Media Ethics Code) Rules, 2021 and §10 of the DPDP Act, 2023, the Grievance Officer is reachable at:
				</p>
				<address className="not-italic rounded-md border border-border/60 bg-card/40 p-4 text-sm">
					Office of the Grievance Officer<br />
					{LEGAL_ENTITY.tradeName}<br />
					{LEGAL_ENTITY.address.street}<br />
					{LEGAL_ENTITY.address.locality}<br />
					{LEGAL_ENTITY.address.city} {LEGAL_ENTITY.address.pin}, {LEGAL_ENTITY.address.state}, {LEGAL_ENTITY.address.country}<br />
					Email:{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>
				</address>
				<p>
					We will acknowledge a grievance within seventy-two (72) hours of receipt, redress it within fifteen (15) days for
					issues falling under the IT Rules 2021, and within thirty (30) days for other matters - or sooner where the law
					requires it. For general questions about this notice, write to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.email}`} className="underline">{LEGAL_ENTITY.contact.email}</a>; for
					operational support, write to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.supportEmail}`} className="underline">{LEGAL_ENTITY.contact.supportEmail}</a>.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">16. How can you review, update or delete the data we collect from you?</h2>
				<p>
					Based on applicable law, you have the right to request access to the personal information we hold about you,
					details of how we have processed it, correction of any inaccuracies, withdrawal of consent or erasure of your
					personal information, subject to legal retention obligations. To make any such request, please write to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.grievanceEmail}`} className="underline">{LEGAL_ENTITY.contact.grievanceEmail}</a>{" "}
					from the email associated with your account, or use the in-product controls where available. We may need to
					verify your identity before responding.
				</p>
			</section>
		</article>
	);
}
