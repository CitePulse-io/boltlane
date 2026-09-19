# Legal & policy landscape for consented peer networks

Research ticket: [CitePulse-io/boltlane#9](https://github.com/CitePulse-io/boltlane/issues/9) · Date: 2026-09-18
Status: research memo only. **This is not legal advice.** Before launching payments, a hosted
Server, or a Requestor onboarding program, get counsel review in the operating jurisdiction.

## The question

Boltlane is a residential-IP proxy network whose peers are **consented device owners** paid in
Bitcoin Lightning, and whose Server software is open-source and self-hostable. What does the
legal/policy landscape of incumbent peer-bandwidth companies, US/EU regulators, open-source
distribution, and (later) app stores mean for the trust model and the peer agreement?

## Findings

### 1. ToS / legal-exposure patterns of incumbent peer-bandwidth companies

**Honeygain** (Lithuanian UAB, consumer payout via PayPal/JumpTask/crypto):
- Consent is layered: install-time "I agree with Terms of Use", plus a *per-session* re-confirmation
  ("Each time the Application is active you confirm that…") that sharing is not prohibited by the
  peer's ISP/mobile operator, that the peer is the account holder or has the holder's express
  permission, and that the connection is not a third-party shared network (employer, university,
  hotel, etc.) unless expressly permitted.
  Source: https://www.honeygain.com/terms-of-use/
- Age floor 18 (13 for personal data), device-ownership requirement ("only install and use the
  Application on devices you own… a material breach"), sanctions-country exclusions
  (Cuba, Iran, North Korea, Syria, Russia, Belarus, occupied Ukrainian regions), US-style
  arbitration + class waiver (EEA/CH/UK carved out), $20 minimum payout, forfeiture on breach.
  Same source.
- KYC is payout-gated, not signup-gated: "you may be required to validate your email … and provide
  us and/or our payment services providers with certain information (including personal information
  or identity verification), depending on your chosen payout method." Payouts run through third
  parties whose own verification procedures apply. Same source.
- Liability framing: peers bear all ISP-contract and blocklist risk (throttling, suspension,
  CAPTCHAs, IP blocklisting, complaints about their IP), enumerated a)–f) in the ToS. Same source.

**PacketStream** (US Inc., reseller model):
- Eligibility 18+, device/connection ownership or authorization, explicit "you are responsible for
  confirming that bandwidth sharing complies with your internet provider's terms, local law, and
  any network-owner rules."
  Source: https://packetstream.io/terms-of-service/
- Acceptable-use list is addressed to *both* sides of the market: no fraud, unauthorized access,
  malware, spam/harassment/unlawful data collection, IP infringement, "unlawful financial, payment,
  marketplace, government, or regulated activity", and a catch-all "violate applicable law or cause
  PacketStream, a Packeter, a reseller, or another person to violate applicable law."
  PacketStream reserves investigation, destination/traffic restriction, suspension, and cooperation
  with lawful government requests. Same source.
- Resellers ($500 minimum) own the end-customer relationship and must "ensure their end customers
  follow these Terms" — i.e., the operator pushes compliance obligations downstream contractually.
  Same source.
- Earnings can be withheld/reversed for "fraud, manipulation, prohibited activity" — the payout
  lever doubles as the enforcement lever. Same source.

**Grass** (BVI, token/USDC rewards):
- General Terms restrict sanctioned/legal-risk jurisdictions and minors, and add a separate
  **Network Use Policy** that gates the *demand* side: business-only access after risk-based due
  diligence (identity, stated use case, legal assessment, contractual compliance commitments);
  permitted-use whitelist (market research, price comparison, public-web-data collection for AI/ML,
  site performance testing, ad verification, SEO monitoring, web indexing, academic research);
  prohibited-use list (hacking, credential theft, malware, phishing, social engineering, DDoS,
  botnet activity, traffic flooding, circumvention of protection measures, fraud, impersonation,
  harassment, scalping, inventory hoarding); monitoring/enforcement incl. request logging, rate
  limiting, audits, blocking, and reporting to authorities.
  Sources: https://www.grass.io/terms-and-conditions/ , https://www.grass.io/network-use-policy/
- AppEsteem certification + AMTSO membership are used as third-party anti-malware credibility
  signals. Source: https://customer.appesteem.com/certified?vendor=GRASS (linked from both pages).

**Mysterium / MystNodes** (Panama NetSys Inc., dVPN-style exit nodes):
- Exit-node ToS explicitly tells node runners the operator "cannot guarantee that no illegal or
  criminal traffic passes in or through the Network and that you will never face any legal
  liability," while committing to help on legal inquiries; nodes may monitor traffic *only* for
  exit-destination whitelisting and "must not log and/or store any such data."
  Source: https://www.mystnodes.com/legal/terms-and-conditions
- Risk-mitigation model: **verified traffic only** by default (vetted B2B partners bound by
  contracts, responsible for abuse), public traffic opt-in with higher earnings, and
  country-specific warnings advising against public traffic in US/CA/UK/IT/AU/DE/IN.
  Source: https://help.mystnodes.com/en/articles/8005105-can-my-node-be-used-for-illegal-activities-how-do-we-protect-node-runners
- The industry's exit-node self-defense playbook is the dVPN Alliance guide: run in a favorable
  jurisdiction or separate entity, separate personal traffic from node traffic, inform the ISP,
  register the IP with the RIR, respond professionally to cease-and-desist letters, and **do not
  log transit traffic** (both a privacy pledge and evidence that the runner is a mere conduit).
  Sources it cites: DMCA 512 (US), TMG 8 (Germany), Art. 6:196c BW (NL), ECG 13 (AT), 2002:562 (SE).
  Source: https://dvpnalliance.org/exit-node/

**Pattern summary.** Every incumbent encodes: (a) explicit human consent, re-affirmed; (b) 18+ and
device/connection ownership; (c) "you checked your ISP's rules" responsibility-shifting; (d) a
prohibited-traffic list enforced via account suspension + payout withholding; (e) KYC pushed to the
payout rail rather than signup; (f) sanctions-country exclusions; (g) demand-side vetting (Grass's
business onboarding, Mysterium's verified-only default).

### 2. US/EU regulatory touchpoints

**US — the criminal ceiling (911 S5).** The controlling cautionary precedent is the DOJ/FBI
dismantling of the "911 S5" residential-proxy botnet (May 2024): YunHe Wang was arrested and OFAC
sanctioned for operating a proxy service built on ~19M **compromised** Windows machines, used for
fraud (including billions in fraudulent COVID-relief claims), bomb threats, child exploitation, and
export violations; Treasury designated the operators and their entities.
- FBI press release:
  https://www.fbi.gov/news/press-releases/911-s5-botnet-dismantled-and-its-administrator-arrested-in-coordinated-international-operation
- Treasury/OFAC action: https://home.treasury.gov/news/press-releases/jy2375
The distinguishing facts for Boltlane are **consent and malware**: 911 S5 harvested devices without
owners' knowledge. A network built on documented, revocable consent — and that can prove it — sits
on the lawful side of that line. But 911 S5 also shows regulators treat *who your requestors are and
what they did* as the operator's problem: the service's downstream users' crimes were attributed to
the network operator.

**US — FTC / consumer-protection & data-broker angle.** The FTC has no residential-proxy-specific
rule, but its 2024 data-broker sweep (X-Mode/Outlogic, InMarket, Mobilewalla, Gravy/Venntel) banned
the sale of sensitive location data and required supplier-consent programs — i.e., operators must
verify that the people upstream of the data actually consented.
- X-Mode/Outlogic order: https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-prohibits-data-broker-x-mode-social-outlogic-selling-sensitive-location-data
- InMarket order: https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-will-ban-inmarket-selling-precise-consumer-location-data
- FTC summary of the four cases: https://www.ftc.gov/business-guidance/blog/2024/12/protecting-consumers-location-data-key-takeaways-four-recent-cases
Implication: a hosted Boltlane Server that markets traffic to US customers is exposed under FTC Act
§5 unfairness/deception doctrines if it misrepresents what peers consented to, or if its demand-side
customers use the traffic for deceptive purposes. "Peers consented" must be true, documented, and
auditable, not marketing copy.

**EU — DSA relevance is indirect.** The Digital Services Act (Regulation (EU) 2022/2065) applies to
"intermediary services" (conduit, caching, hosting). A residential-proxy network is arguably a
conduit-like intermediary: DSA Arts. 4–6 preserve the conditional liability privilege (mere conduit
/liability exemption) *provided* the intermediary does not initiate the transmission, does not
modify content, and — for caching — acts expeditiously to remove/terminate on actual knowledge of
illegal activity. That is the legal architecture Mysterium leans on via the dVPN Alliance guidance.
A hosted EU-facing Server should: publish a notice-and-action channel, retain the safe-harbor
preconditions (no content modification beyond routing necessities), and be able to terminate
repeat-abuse requestors. Source: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022R2065
Note also GDPR applies to peers' personal data (IPs of peers are personal data; payout identity
data); self-hosting shifts "controller" responsibility to each Server operator.

### 3. How open-source/self-hostable changes the liability picture

- **Publisher vs operator split.** Open-source publication is generally protected (source-code
  publication ≠ provision of a service; US: DMCA 512-style conduit logic and First Amendment
  code-publication precedent; EU: DSA applies to services, not to code). The *operator of a Server*
  is the service provider that regulators and courts will look at. Boltlane's self-hosting design
  therefore naturally allocates risk to whoever actually operates.
- **But control draws liability.** If CitePulse runs the hosted SaaS Server, sells capacity, and
  pays peers, it is an operator for every practical purpose (and a money transmitter/payment
  intermediary question arises for Lightning payouts — a separate ticket). Self-hosters with
  payments off have a materially smaller footprint but are not zero: they still run a proxy their
  requestors abuse.
- **Fork risk is the real self-hosting exposure.** Anyone can fork the code, strip the policy
  enforcement, and run a non-consensual or abusive network. Mitigations used by comparables:
  Mysterium publishes client + server code while operating the trusted coordination/payments layer
  itself; Grass keeps network access business-gated. Boltlane should expect bad forks and keep the
  project's own name/brand/coordination layer clean, with an explicit "no warranty, operator is
  responsible for lawful operation" license posture (verify the chosen license wording with
  counsel) plus a trademark policy so abused forks can't masquerade.
- **Payments-off default is a feature.** Keeping payments off by default in self-hosted mode
  reduces money-transmission/sanctions surface for most deployments, consistent with the x402
  gating "default OFF for self-hosters" already recorded in CONTEXT.md.

### 4. App-store constraints for mobile peer apps (brief — mobile is later)

- **Google Play — Device and Network Abuse policy**: "Apps that facilitate proxy services to third
  parties may only do so in apps where that is the primary, user-facing core purpose of the app."
  Also: foreground-service declarations required for Android 14+ (user-initiated, perceptible,
  stoppable, only as long as needed), user-initiated data-transfer jobs must be started by user
  action, no bypassing Doze/power management, no self-updates or executable code downloads outside
  Play. Source: https://support.google.com/googleplay/android-developer/answer/9888379
  A Boltlane Android peer app is viable as long as proxying IS the app's core purpose, with clear
  consent and battery/transparency UX — but background persistence will be the fight.
- **Apple — App Review Guidelines**: no specific proxy prohibition, but 2.5.4 restricts background
  modes to their intended purposes (VoIP, audio, location, task completion…), 2.4.2 bans unrelated
  background processes / resource strain, 2.3.1(a) bans hidden/dormant features, and §1.2-style UGC
  moderation duties apply to anything user-facing. A NetworkExtension/VPN-profile approach (the
  route most bandwidth-sharing apps take on iOS) requires declaring purpose and passing review.
  Source: https://developer.apple.com/app-store/review/guidelines/
- Conclusion: desktop-first (already planned) is the right sequencing; when mobile comes, budget for
  store-policy friction on background traffic and consider whether the mobile peer experience ships
  as opt-in foreground/tethered mode first.

## Policy decisions the trust model and peer agreement must encode

These are the decisions Boltlane's trust model, peer agreement, and Server policy must make —
recorded here so the design tickets can reference them. (Recommendations, subject to counsel.)

1. **Prohibited traffic (peer agreement + Server policy).** Adopt a prohibited-use list modeled on
   PacketStream §7 / Grass Network Use Policy: no fraud, account/system compromise, malware
   distribution, phishing/spam/harassment, credential theft, DoS, scraping in breach of target
   systems' terms where unlawful, IP infringement, unlawful regulated activity, and anything that
   would cause a Peer to violate applicable law. The catch-all formulation "cause any Peer or
   operator to violate applicable law" is worth copying verbatim — it is the clause that maps
   everyday abuse onto operator liability.
2. **Demand-side gating (trust model).** Requestors are not anonymous by default: per-requestor
   identity + stated use case + contractual prohibited-use commitment (Grass's onboarding controls
   are the template). Default posture for a hosted Server: **verified-requestor-only traffic**;
   open traffic is an opt-in the Peer must explicitly enable (Mysterium's verified/public switch),
   with country warnings for peers in US/CA/UK/DE/IT/AU/IN at minimum.
3. **Consent language (peer agreement + client UX).** Consent must be: (a) explicit at enrollment
   with an affirmative act; (b) device/connection-scoped — peer affirms they own the device and are
   the account holder for the connection (or have the holder's permission) and that their ISP's
   terms permit sharing; (c) re-affirmed periodically / revocable instantly (kill switch that stops
   accepting traffic and halts earning); (d) age 18+; (e) no enrollment on shared/third-party
   networks (employer/school/hotel) without express permission; (f) sanctions/jurisdiction
   exclusions list, updatable by Server policy.
4. **KYC thresholds (payouts, when on).** Follow the incumbents: no KYC at enrollment; KYC
   triggered by the payout rail (Lightning wallets are mostly anonymous — but the *hosted* payout
   aggregator/processor, if any, will impose its own thresholds) and by risk signals (velocity,
   multiple devices per IP, fraud flags). Self-hosted Servers with payments off: no KYC by design.
   Counsel review required on Lightning payout thresholds and any money-transmission analysis.
5. **Takedown / abuse posture (hosted Server; optional modules for self-hosters).** Publish an
   abuse-report channel; act on actual knowledge (suspend requestor account, block destination,
   preserve eligibility for intermediary safe harbor under DSA Arts. 4–6 and DMCA 512 logic);
   cooperate with lawful process; keep **no content logging on peers** (mere-conduit evidence per
   dVPN Alliance guidance), with the minimum operator-side metadata needed to meter and enforce.
   Cease-and-desist handling guidance for peers should be linked in docs (Lumen database).
6. **Enforcement lever.** Payout withholding/reversal on breach (PacketStream/Honeygain pattern) is
   the pragmatic enforcement mechanism a Lightning-native design can support natively (invoices are
   pre-funded; disputed earnings simply never settle).
7. **Open-source posture.** License should disclaim any warranty of lawful operation and place
   compliance duty on the operator; separate trademark policy to keep abused forks off the
   Boltlane name; keep the hosted coordination/policy layer as the trustworthy reference
   deployment. Verify final license wording with counsel.
8. **Mobile (later).** Design the protocol so a mobile peer can ship under Google Play's
   "proxy facilitation as primary core purpose" rule and Apple's background-mode limits:
   user-initiated start/stop, honest notifications, no hidden features. Flag now so the tunnel
   design doesn't assume always-on background execution on phones.

## Source index

| Claim cluster | Source |
|---|---|
| Honeygain consent flow, eligibility, KYC-at-payout, ISP risk | https://www.honeygain.com/terms-of-use/ |
| PacketStream AUP, reseller terms, payout clawback | https://packetstream.io/terms-of-service/ |
| Grass demand-side onboarding, permitted/prohibited uses | https://www.grass.io/network-use-policy/ , https://www.grass.io/terms-and-conditions/ |
| Mysterium exit-node terms, no-logs, verified-traffic default, country warnings | https://www.mystnodes.com/legal/terms-and-conditions , https://help.mystnodes.com/en/articles/8005105-can-my-node-be-used-for-illegal-activities-how-do-we-protect-node-runners |
| Exit-node liability playbook, safe-harbor statutes | https://dvpnalliance.org/exit-node/ |
| 911 S5 takedown (criminal exposure for non-consensual proxy networks) | https://www.fbi.gov/news/press-releases/911-s5-botnet-dismantled-and-its-administrator-arrested-in-coordinated-international-operation , https://home.treasury.gov/news/press-releases/jy2375 |
| FTC data-broker/sensitive-location enforcement | https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-prohibits-data-broker-x-mode-social-outlogic-selling-sensitive-location-data , https://www.ftc.gov/news-events/news/press-releases/2024/01/ftc-order-will-ban-inmarket-selling-precise-consumer-location-data , https://www.ftc.gov/business-guidance/blog/2024/12/protecting-consumers-location-data-key-takeaways-four-recent-cases |
| DSA intermediary/safe-harbor framework | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022R2065 |
| Google Play proxy/background policies | https://support.google.com/googleplay/android-developer/answer/9888379 |
| Apple App Review Guidelines | https://developer.apple.com/app-store/review/guidelines/ |