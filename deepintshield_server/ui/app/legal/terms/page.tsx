import type { Metadata } from "next";
import Link from "next/link";

import { LEGAL_ENTITY, TERMS_OF_SERVICE_EFFECTIVE_DATE, TERMS_OF_SERVICE_VERSION } from "@/lib/legal/versions";

export const metadata: Metadata = {
	title: "Terms and Conditions - DeepintShield",
	description: "Terms governing your use of the DeepintShield platform.",
};

export default function TermsPage() {
	return (
		<article className="space-y-8 break-words text-[15px] [hyphens:auto]">
			<header className="space-y-2">
				<p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Legal · v{TERMS_OF_SERVICE_VERSION}</p>
				<h1 className="text-3xl font-semibold tracking-[-0.02em]">Terms and Conditions</h1>
				<p className="text-sm text-muted-foreground">
					Last updated {TERMS_OF_SERVICE_EFFECTIVE_DATE}.
				</p>
			</header>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">Agreement to our Legal Terms</h2>
				<p>
					We are <strong>{LEGAL_ENTITY.tradeName}</strong> (operating as <strong>{LEGAL_ENTITY.additionalTradeName}</strong>),
					with GSTIN {LEGAL_ENTITY.gstin} and a principal place of business at {LEGAL_ENTITY.address.street},{" "}
					{LEGAL_ENTITY.address.locality}, {LEGAL_ENTITY.address.city} {LEGAL_ENTITY.address.pin},{" "}
					{LEGAL_ENTITY.address.state}, {LEGAL_ENTITY.address.country}. In these Legal Terms, &ldquo;we&rdquo;, &ldquo;us&rdquo;,
					&ldquo;our&rdquo; and &ldquo;{LEGAL_ENTITY.productName}&rdquo; refer to that entity.
				</p>
				<p>
					We operate the website <a href={LEGAL_ENTITY.contact.website} className="underline">{LEGAL_ENTITY.contact.website}</a>
					{" "}(the &ldquo;Site&rdquo;), the {LEGAL_ENTITY.productName} platform and all related products, dashboards, APIs, SDKs
					and documentation that link to or reference these Legal Terms (collectively, the &ldquo;Services&rdquo;).
				</p>
				<p>
					You can contact us by email at{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.email}`} className="underline">{LEGAL_ENTITY.contact.email}</a>{" "}
					or by post at the address above.
				</p>
				<p>
					These Legal Terms form a legally binding agreement between you (whether personally or on behalf of an entity) and
					{" "}{LEGAL_ENTITY.productName}. By accessing or using the Services, you confirm that you have read, understood and
					agreed to be bound by these Legal Terms. If you do not agree, you must stop using the Services. Acceptance is
					recorded electronically and is enforceable under §10A of the Information Technology Act, 2000.
				</p>
				<p>
					We may update these Legal Terms from time to time. Where the change is material, we will give you reasonable advance
					notice through the Services or by email. Continued use after the effective date of an update constitutes acceptance
					of the updated Legal Terms.
				</p>
				<p>
					The Services are intended for users who are at least eighteen (18) years of age. If you are under 18, you may not
					use or register for the Services. We recommend that you save or print a copy of these Legal Terms for your records.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">Table of contents</h2>
				<ol className="ml-5 list-decimal space-y-1 text-sm">
					<li>Our Services</li>
					<li>Intellectual property rights</li>
					<li>User representations</li>
					<li>User registration</li>
					<li>Purchases and payment</li>
					<li>Subscriptions</li>
					<li>Software</li>
					<li>Prohibited activities</li>
					<li>User-generated contributions</li>
					<li>Contribution licence</li>
					<li>Third-party websites and content</li>
					<li>Services management</li>
					<li>Privacy policy</li>
					<li>Term and termination</li>
					<li>Modifications and interruptions</li>
					<li>Governing law</li>
					<li>Dispute resolution</li>
					<li>Corrections</li>
					<li>Disclaimer</li>
					<li>Limitations of liability</li>
					<li>Indemnification</li>
					<li>User data</li>
					<li>Electronic communications, transactions and signatures</li>
					<li>Indian users and residents</li>
					<li>Miscellaneous</li>
					<li>User content licence and attribution</li>
					<li>Contact us</li>
				</ol>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">1. Our Services</h2>
				<p>
					The information available through the Services is not directed to any person or entity in any jurisdiction where
					the provision of such information would be unlawful or would subject us to any registration requirement. If you
					choose to access the Services from outside India, you do so on your own initiative and are responsible for
					complying with applicable local law to the extent it applies.
				</p>
				<p>
					The Services are general-purpose AI gateway and governance tooling and have not been certified for industry-specific
					regimes such as the Health Insurance Portability and Accountability Act (HIPAA) of the United States, India&apos;s
					Pre-conception and Pre-natal Diagnostic Techniques Act, 1994, the Reserve Bank of India&apos;s outsourcing or
					IT-framework directions, the Insurance Regulatory and Development Authority of India&apos;s (IRDAI) cyber-security
					guidelines, or the Securities and Exchange Board of India&apos;s (SEBI) cybersecurity-and-cyber-resilience framework.
					If your use case is subject to any such regime, you remain solely responsible for confirming that the Services are
					appropriate and that your deployment complies, before relying on the Services.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">2. Intellectual property rights</h2>
				<p>
					<strong>Our intellectual property.</strong> We are the owner or licensee of all intellectual-property rights in the
					Services, including the source code, databases, application logic, software, dashboard designs, audio, video,
					text, images and graphics (collectively, the &ldquo;Content&rdquo;), and the trade marks, service marks and logos
					contained therein (the &ldquo;Marks&rdquo;). The Content and Marks are protected under the Copyright Act, 1957, the
					Trade Marks Act, 1999, the Patents Act, 1970 and analogous law worldwide. They are made available through the
					Services on an &ldquo;as is&rdquo; basis solely for your internal business use.
				</p>
				<p>
					<strong>Your right to use the Services.</strong> Subject to your continued compliance with these Legal Terms, we
					grant you a non-exclusive, non-transferable, revocable licence to access the Services and to download or print
					reasonable portions of the Content for your internal business use. Except as expressly permitted, no part of the
					Services and no Content or Marks may be copied, republished, scraped, redistributed, sold, licensed or otherwise
					commercialised without our prior written consent.
				</p>
				<p>
					Permissioned uses, including reuse of any Mark in marketing, must include proper attribution to us as licensor and
					must preserve any copyright or proprietary notice. We reserve all rights not expressly granted. A breach of this
					clause is a material breach of these Legal Terms and may result in immediate termination of your right to use the
					Services.
				</p>
				<p>
					<strong>Submissions.</strong> If you send us questions, comments, suggestions, ideas or feedback about the Services
					(&ldquo;Submissions&rdquo;), you grant us a worldwide, royalty-free, perpetual, irrevocable licence to use those
					Submissions for any lawful purpose without obligation or compensation to you. You confirm that any Submission is
					original to you (or that you have rights sufficient to grant the licence above), is not confidential, and does not
					violate the rights of any third party.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">3. User representations</h2>
				<p>By using the Services, you represent and warrant that:</p>
				<ul className="ml-5 list-disc space-y-2">
					<li>all registration information you submit is true, accurate, current and complete;</li>
					<li>you will keep that information accurate and update it promptly when it changes;</li>
					<li>you have legal capacity under §11 of the Indian Contract Act, 1872 and you agree to comply with these Legal Terms;</li>
					<li>you are not a minor in your jurisdiction;</li>
					<li>you will not access the Services through automated or non-human means except via the APIs and SDKs we publish;</li>
					<li>you will not use the Services for any unlawful or unauthorised purpose;</li>
					<li>your use will not violate any applicable law, including Indian law.</li>
				</ul>
				<p>
					If any information you provide is untrue, inaccurate, incomplete or outdated, we may suspend or terminate your
					account and refuse current or future use of the Services.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">4. User registration</h2>
				<p>
					You may be required to register to use the Services. You agree to keep your password confidential and you are
					responsible for all activity under your account, your API keys, virtual keys and OAuth tokens. We may, in our
					discretion, change a username we believe is inappropriate, misleading, infringing or objectionable.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">5. Purchases and payment</h2>
				<p>
					Where applicable, we accept the payment methods displayed at checkout, which may include UPI, Indian net-banking,
					credit and debit cards (Visa, Mastercard, RuPay, American Express, Discover) and other rails supported by our
					payment processor.
				</p>
				<p>
					You agree to provide current, complete and accurate purchase and account information for all purchases, and to
					promptly update payment information as needed. Goods and Services Tax (GST) and other applicable taxes will be
					added where required by Indian law. Prices may be denominated in INR or USD as stated at the point of sale, and
					may change at any time.
				</p>
				<p>
					You authorise us to charge your chosen payment method for the amounts you owe, including applicable taxes. We may
					correct pricing errors even after a payment has been requested or received. We may refuse, limit or cancel any
					order in our reasonable discretion, including where a transaction appears to come from a reseller, dealer or
					distributor we have not authorised. Where you are required under §194-O or other provisions of the Income-tax Act,
					1961 to deduct tax at source, you must furnish a valid TDS certificate within the prescribed timelines.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">6. Subscriptions</h2>
				<p>
					<strong>Billing and renewal.</strong> Paid subscriptions continue and renew automatically until cancelled. You consent
					to recurring charges on your chosen payment method until you cancel. The length of each billing cycle depends on
					the plan you have selected.
				</p>
				<p>
					<strong>Free trial.</strong> We may offer a time-limited free trial to new users. At the end of the trial, your
					account will be charged according to the subscription you selected unless you have cancelled before the end of
					the trial.
				</p>
				<p>
					<strong>Cancellation.</strong> You may cancel your subscription at any time using the in-product control or by
					writing to us. Cancellation takes effect at the end of the then-current paid term; we do not pro-rate Fees already
					charged for the current term except where required by law. If you have questions or are unhappy with the Services,
					please contact{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.supportEmail}`} className="underline">{LEGAL_ENTITY.contact.supportEmail}</a>.
				</p>
				<p>
					<strong>Fee changes.</strong> We may change subscription Fees from time to time. We will give you reasonable advance
					notice of any change in line with applicable law. Changed Fees apply only to renewals or new charges that occur
					after the notice period.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">7. Software</h2>
				<p>
					The Services may be delivered together with downloadable software, command-line tools, SDKs or sample code. Where
					a separate end-user licence agreement (&ldquo;EULA&rdquo;) accompanies that software, the EULA governs your use of
					it. Where no EULA is supplied, we grant you a non-exclusive, revocable, personal and non-transferable licence to
					use the software solely with the Services and in accordance with these Legal Terms.
				</p>
				<p>
					Any software is provided &ldquo;as is&rdquo; without warranty of any kind. To the extent permitted by law, we
					disclaim all implied warranties including merchantability, fitness for a particular purpose and non-infringement.
					You may not redistribute or reproduce the software except as the EULA or these Legal Terms allow.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">8. Prohibited activities</h2>
				<p>
					You may use the Services only for the purposes for which we make them available. You may not use the Services for
					any commercial endeavour we have not specifically authorised. As a user, you agree that you will not, and will not
					permit any third party to:
				</p>
				<ul className="ml-5 list-disc space-y-2">
					<li>systematically retrieve content or data from the Services to compile any database, directory or competing dataset;</li>
					<li>deceive, defraud or mislead us or other users, or attempt to obtain another user&apos;s credentials or sensitive information;</li>
					<li>circumvent, disable or interfere with security, governance, rate-limiting, virtual-key or guardrail features of the Services;</li>
					<li>tarnish or harm the Services or our reputation;</li>
					<li>use information obtained from the Services to harass, abuse or harm any person;</li>
					<li>misuse our support channels, file abusive tickets, or submit false claims;</li>
					<li>use the Services in a way that violates Indian law, including the Information Technology Act, 2000 and the rules thereunder, the Bharatiya Nyaya Sanhita 2023, the Digital Personal Data Protection Act, 2023, the Copyright Act 1957 or the Trade Marks Act 1999;</li>
					<li>frame or link to the Services without authorisation;</li>
					<li>upload or transmit malware, viruses, Trojan horses, ransomware or any code that interferes with the Services or other users;</li>
					<li>run automated tools, bots, scrapers, crawlers or scripts against the Services other than via the APIs and SDKs we publish;</li>
					<li>delete or obscure copyright or proprietary notices from any Content;</li>
					<li>impersonate another user or person or use another&apos;s username;</li>
					<li>upload material that acts as a passive or active collection mechanism (web bugs, tracking pixels, fingerprinting code) without authorisation;</li>
					<li>place an undue load on the Services or the networks supporting them;</li>
					<li>harass, intimidate or threaten our employees, contractors or agents;</li>
					<li>attempt to bypass any access control, paywall or rate limit;</li>
					<li>copy or adapt the software powering the Services beyond what applicable law expressly allows;</li>
					<li>decipher, decompile, disassemble or reverse engineer the Services, except to the extent applicable law expressly permits;</li>
					<li>scrape, mine or extract data using any automated system other than as standard search engines and browsers do;</li>
					<li>use buying or purchasing agents, or place orders through deceptive means;</li>
					<li>collect usernames or email addresses for unsolicited communications, or create accounts in bulk by automated means;</li>
					<li>use the Services to compete with us, including building, training or fine-tuning a competing AI gateway, governance, routing or guardrail product;</li>
					<li>sell or transfer your account or profile;</li>
					<li>use the Services to advertise or sell goods and services without our authorisation;</li>
					<li>generate child sexual-abuse material, non-consensual intimate imagery, deceptive deepfakes of real persons, content that incites violence or terrorism, or content prohibited by rule 3(1)(b) of the Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021.</li>
				</ul>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">9. User-generated contributions</h2>
				<p>
					The Services do not generally invite public posting of content. Where we provide a feature that lets you create,
					submit, post, transmit, publish or distribute content (including text, comments, images, suggestions, files,
					configurations or telemetry - together, &ldquo;Contributions&rdquo;), Contributions may be visible to other users
					of the Services or to third parties as the configuration permits. Any Contribution will be handled in line with our
					{" "}<Link href="/legal/privacy" className="underline">Privacy Policy</Link>.
				</p>
				<p>By creating or submitting Contributions, you represent and warrant that:</p>
				<ul className="ml-5 list-disc space-y-2">
					<li>their creation, transmission, display and copying do not infringe any third-party right (including copyright, patent, trade mark, trade-secret or moral rights);</li>
					<li>you are the creator and owner, or you have all licences, consents and authorisations needed, to grant us the rights described in these Legal Terms;</li>
					<li>you have the documented consent of every identifiable individual depicted in your Contribution, where required by law, for that depiction;</li>
					<li>your Contributions are not false, misleading or deceptive;</li>
					<li>your Contributions are not unsolicited advertising, pyramid schemes, spam or chain letters;</li>
					<li>your Contributions are not obscene, defamatory, harassing, libellous or otherwise unlawful in India;</li>
					<li>your Contributions do not ridicule, abuse or threaten any person or class of persons;</li>
					<li>your Contributions do not promote violence or harm against any specific person or class of persons;</li>
					<li>your Contributions comply with applicable law, including the Information Technology Act, 2000 and rules thereunder;</li>
					<li>your Contributions do not violate any third party&apos;s privacy or publicity rights;</li>
					<li>your Contributions do not include child sexual-abuse material or material that exploits minors;</li>
					<li>your Contributions do not contain unlawful discriminatory remarks against any individual or group;</li>
					<li>your Contributions do not link to material that violates these Legal Terms or applicable law.</li>
				</ul>
				<p>
					Use of the Services in breach of the foregoing is a breach of these Legal Terms and may result in suspension or
					termination of your right to use the Services.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">10. Contribution licence</h2>
				<p>
					You and we agree that we may access, store, process and use any information and personal data you provide,
					subject to our <Link href="/legal/privacy" className="underline">Privacy Policy</Link> and your account settings.
					Where you submit suggestions or other feedback regarding the Services, you agree that we may use and share such
					feedback for any purpose without compensation to you.
				</p>
				<p>
					We do not assert ownership over your Contributions. You retain all right, title and interest in your Contributions
					and any associated intellectual-property rights. We are not liable for statements or representations made in your
					Contributions. You are solely responsible for your Contributions and you agree to release us from any claim
					arising out of them.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">11. Third-party websites and content</h2>
				<p>
					The Services may link to or integrate with third-party websites, model providers, MCP servers, vector stores,
					identity providers, payment processors and other systems (&ldquo;Third-Party Websites&rdquo;), and may surface
					content, model outputs, articles, images and code originating from third parties (&ldquo;Third-Party Content&rdquo;).
					We do not investigate, monitor or verify Third-Party Websites or Third-Party Content for accuracy, lawfulness or
					appropriateness, and we are not responsible for them.
				</p>
				<p>
					Including or permitting use of any Third-Party Website or Third-Party Content does not imply our endorsement.
					When you leave the Services to access a Third-Party Website or to use Third-Party Content, you do so at your own
					risk and these Legal Terms no longer govern. You should review the privacy and other policies of the destination
					site. Purchases made through Third-Party Websites are between you and the third party, and we have no
					responsibility for those transactions. You agree to release us from any harm caused by Third-Party Content or any
					interaction with Third-Party Websites.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">12. Services management</h2>
				<p>
					We reserve the right (but not the obligation) to: (a) monitor the Services for breaches of these Legal Terms; (b)
					take appropriate action against anyone who, in our reasonable judgement, breaches the law or these Legal Terms,
					including reporting suspected illegality to law-enforcement authorities; (c) refuse, restrict, limit or disable
					(to the extent technically feasible) any of your Contributions or any portion of them; (d) remove or disable
					content or files that are excessive in size or otherwise burdensome to our infrastructure; and (e) otherwise
					manage the Services as we consider necessary to protect our rights and to keep the Services functioning correctly.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">13. Privacy policy</h2>
				<p>
					We care about data privacy and security. Please review our{" "}
					<Link href="/legal/privacy" className="underline">Privacy Policy</Link>. By using the Services, you agree to be
					bound by the Privacy Policy, which is incorporated into these Legal Terms. The Services are operated from India
					and primary data stores are located in India unless we have agreed otherwise with you in writing. If you access
					the Services from a region with data-protection laws different from those of India, you understand that your
					data may be transferred to and processed in India in accordance with the Privacy Policy and the Digital Personal
					Data Protection Act, 2023.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">14. Term and termination</h2>
				<p>
					These Legal Terms apply for as long as you use the Services. Without limiting any other provision, we reserve the
					right, in our reasonable discretion and without notice or liability, to deny access to the Services (including by
					blocking specified IP addresses) to any person, for any reason permitted by law, including for breach of any
					representation, warranty or covenant in these Legal Terms or of any applicable law or regulation. We may
					terminate your use of the Services or delete your account and any content you have posted at any time, in our
					reasonable discretion, where the law permits.
				</p>
				<p>
					If we terminate or suspend your account for cause, you are prohibited from registering a replacement account
					under your own name or under another person&apos;s name. In addition to suspension or termination, we may take
					appropriate legal action, including civil, criminal or injunctive remedies.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">15. Modifications and interruptions</h2>
				<p>
					We may change, modify or remove the contents of the Services at any time, in our discretion, without notice. We
					are not obliged to update any information or feature, and we are not liable to you or any third party for any
					modification, price change, suspension or discontinuance of the Services.
				</p>
				<p>
					We cannot guarantee that the Services will be available at all times. We may experience hardware, software or
					third-party-provider issues, or need to perform maintenance, that result in interruptions, delays or errors. We
					reserve the right to change, suspend, discontinue or otherwise modify the Services at any time without notice.
					You agree that we have no liability for any loss, damage or inconvenience caused by your inability to access or
					use the Services during any downtime, maintenance or discontinuance. Nothing in these Legal Terms obliges us to
					maintain the Services or to provide corrections, updates or releases.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">16. Governing law</h2>
				<p>
					These Legal Terms and your use of the Services are governed by and construed in accordance with{" "}
					{LEGAL_ENTITY.governingLaw}, applicable to agreements made and to be performed within India, without regard to
					its conflict-of-law principles. Application of the United Nations Convention on Contracts for the International
					Sale of Goods is excluded.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">17. Dispute resolution</h2>
				<p>
					Any legal action arising out of or in connection with these Legal Terms or your use of the Services shall be
					commenced or prosecuted exclusively in {LEGAL_ENTITY.jurisdiction}, and the parties consent to and waive defences
					of lack of personal jurisdiction or forum non conveniens with respect to that jurisdiction.
				</p>
				<p>
					The parties will first attempt in good faith to resolve any dispute through informal negotiation by writing to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.email}`} className="underline">{LEGAL_ENTITY.contact.email}</a>. If the
					dispute is not resolved within thirty (30) days, it will be referred to arbitration under the Arbitration and
					Conciliation Act, 1996, by a sole arbitrator mutually appointed by the parties (or, failing agreement, appointed
					in accordance with the Act). The seat and venue of arbitration will be Bengaluru, the language will be English,
					and the award will be final and binding. Either party may seek interim or injunctive relief from a competent
					court for the protection of its intellectual property or confidential information without prejudice to the
					arbitration agreement. No claim, action or proceeding arising out of these Legal Terms may be commenced more than
					one (1) year after the cause of action arose.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">18. Corrections</h2>
				<p>
					The Services may, from time to time, display information that contains typographical errors, inaccuracies or
					omissions, including descriptions, pricing, availability and other information. We reserve the right to correct
					any errors, inaccuracies or omissions and to change or update the information at any time, without prior notice.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">19. Disclaimer</h2>
				<p>
					The Services are provided on an &ldquo;as is&rdquo; and &ldquo;as available&rdquo; basis. You agree that your use
					of the Services is at your sole risk. To the maximum extent permitted by law, we disclaim all warranties, express,
					implied or statutory, in connection with the Services and your use of them, including the implied warranties of
					merchantability, fitness for a particular purpose, non-infringement and accuracy of any output.
				</p>
				<p>
					We make no warranties as to the accuracy or completeness of the Services&apos; Content, the content of any linked
					website, or the output of any model the Services route requests to. We assume no liability for: (a) errors,
					inaccuracies or omissions in any Content or model output; (b) personal injury or property damage of any nature
					resulting from your access to or use of the Services; (c) unauthorised access to or use of our systems or any
					personal or financial information stored on them; (d) interruption or cessation of transmission to or from the
					Services; (e) bugs, viruses or other harmful code transmitted to or through the Services by any third party; or
					(f) loss or damage resulting from use of any content posted, transmitted or otherwise made available via the
					Services. AI systems can produce incorrect, misleading, biased or fabricated output; you are responsible for
					human review and for any decisions taken on the basis of model output.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">20. Limitations of liability</h2>
				<p>
					To the maximum extent permitted by law, in no event will {LEGAL_ENTITY.productName}, its directors, employees or
					agents be liable to you or any third party for any indirect, consequential, exemplary, incidental, special or
					punitive damages, including lost profits, lost revenue, loss of data or other intangible losses, arising from
					your use of the Services, even if we have been advised of the possibility of such damages.
				</p>
				<p>
					Notwithstanding anything to the contrary, our aggregate liability to you, regardless of the form of action, is
					limited to the amount paid by you to us for the Services in the six (6) months immediately preceding the cause of
					action, or, where no payment has been made, INR 5,000 (Indian Rupees Five Thousand). Some jurisdictions and
					Indian consumer-protection law do not permit certain limitations on warranties or damages; if such law applies to
					you, some or all of the above limitations may not apply, and you may have additional rights.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">21. Indemnification</h2>
				<p>
					You agree to defend, indemnify and hold harmless {LEGAL_ENTITY.productName}, including our affiliates, officers,
					agents, partners and employees, from any loss, damage, liability, claim or demand (including reasonable
					advocate&apos;s fees and expenses) made by any third party arising out of or relating to: (a) your use of the
					Services; (b) breach of these Legal Terms; (c) breach of your representations and warranties in these Legal
					Terms; (d) your violation of any third party&apos;s rights, including intellectual-property rights; or (e) any
					harmful act towards another user of the Services with whom you connected through the Services. We reserve the
					right, at your expense, to assume the exclusive defence and control of any matter for which you are required to
					indemnify us, and you agree to cooperate at your expense with our defence. We will use reasonable efforts to
					notify you of any claim, action or proceeding subject to this indemnification.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">22. User data</h2>
				<p>
					We will retain certain data that you transmit to the Services for the purpose of operating the Services and
					evaluating performance, as well as data relating to your use of the Services. Although we perform regular routine
					backups, you are solely responsible for all data that you transmit through the Services or that relates to any
					activity you have undertaken using the Services. You agree that we have no liability to you for any loss or
					corruption of such data, and you waive any right of action against us arising from any such loss or corruption,
					save where loss arises directly from our gross negligence or wilful misconduct.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">23. Electronic communications, transactions and signatures</h2>
				<p>
					Visiting the Services, sending us emails and completing online forms constitute electronic communications. You
					consent to receive electronic communications and you agree that all agreements, notices, disclosures and other
					communications we provide to you electronically - by email or through the Services - satisfy any legal
					requirement that such communication be in writing under §10A of the Information Technology Act, 2000.
				</p>
				<p>
					You agree to the use of electronic signatures, contracts, orders and records, and to electronic delivery of
					notices, policies and records of transactions initiated or completed by us or via the Services. You waive any
					right or requirement under any statute, regulation, rule, ordinance or other law of any jurisdiction that
					requires an original signature or delivery or retention of non-electronic records, or that requires payment or
					credit by means other than electronic means, to the extent permitted by applicable law.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">24. Indian users and residents</h2>
				<p>
					If you are an Indian resident and you have a complaint about the Services that we have not satisfactorily
					resolved through our normal support channels, you may escalate the matter to our Grievance Officer, whose contact
					details are set out in our <Link href="/legal/privacy" className="underline">Privacy Policy</Link>. If your
					complaint relates to consumer protection, you may also approach the appropriate Consumer Forum constituted under
					the Consumer Protection Act, 2019. Where your complaint relates to processing of personal data and you are not
					satisfied with our response, you may approach the Data Protection Board of India under the Digital Personal Data
					Protection Act, 2023.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">25. Miscellaneous</h2>
				<p>
					These Legal Terms and any policies or operating rules posted by us in connection with the Services constitute the
					entire agreement and understanding between you and us. Our failure to exercise or enforce any right or provision
					of these Legal Terms is not a waiver. These Legal Terms operate to the fullest extent permissible by law. We may
					assign any or all of our rights and obligations to others at any time. We are not responsible for any loss,
					damage, delay or failure to act caused by anything outside our reasonable control. If any provision of these
					Legal Terms is held unlawful, void or unenforceable, that provision is severable and does not affect the validity
					or enforceability of the remaining provisions. There is no joint venture, partnership, employment or agency
					relationship between you and us as a result of these Legal Terms or your use of the Services. You agree that
					these Legal Terms will not be construed against us merely because we drafted them. You waive any defence based on
					the electronic form of these Legal Terms or the absence of physical signatures.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">26. User content licence and attribution</h2>
				<p>
					By (i) creating an account with us, (ii) using any open-source offering we publish, (iii) starring our public
					repositories, (iv) contributing to our open-source projects, or (v) publicly disclosing your use of our software
					or services, you grant us a non-exclusive, worldwide, royalty-free, transferable licence to use, display,
					reproduce and distribute your name, logo, trade marks and other identifying information for the purpose of
					identifying you as a customer, user, contributor or supporter on our website, marketing materials, presentations
					and documentation. You represent and warrant that you have all rights necessary to grant this licence. We will
					display your identifying information in a professional manner consistent with our treatment of other customers.
					You may revoke this licence at any time by writing to{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.email}`} className="underline">{LEGAL_ENTITY.contact.email}</a>, and we
					will remove your information from materials within our control within thirty (30) business days of receipt;
					existing printed material, cached content and previously distributed material may continue to display your
					information.
				</p>
			</section>

			<section className="space-y-3">
				<h2 className="text-xl font-semibold">27. Contact us</h2>
				<p>
					To resolve a complaint regarding the Services, or for further information about your use of them, please contact
					us at:
				</p>
				<address className="not-italic rounded-md border border-border/60 bg-card/40 p-4 text-sm">
					{LEGAL_ENTITY.tradeName}<br />
					{LEGAL_ENTITY.address.street}<br />
					{LEGAL_ENTITY.address.locality}<br />
					{LEGAL_ENTITY.address.city} {LEGAL_ENTITY.address.pin}, {LEGAL_ENTITY.address.state}, {LEGAL_ENTITY.address.country}<br />
					Email:{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.email}`} className="underline">{LEGAL_ENTITY.contact.email}</a><br />
					Support:{" "}
					<a href={`mailto:${LEGAL_ENTITY.contact.supportEmail}`} className="underline">{LEGAL_ENTITY.contact.supportEmail}</a>
				</address>
			</section>
		</article>
	);
}
