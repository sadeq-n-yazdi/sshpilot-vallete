package blocklist

// This file is the default policy data for ADR-0017. Editing it changes what
// the system refuses and MUST bump ListVersion (see match.go). It must NOT bump
// TableVersion: nothing here affects which identifiers compare equal.
//
// # How to read a term
//
// Terms are written the way a human writes the word. They are skeletonized once
// at load, so every entry automatically covers its own case, accent, fullwidth,
// mathematical, circled, homoglyph, leetspeak and separator-padded spellings.
// "admin" already blocks "Admin", "4dm1n", "a-d-m-i-n", "аdmin" with a Cyrillic
// a, "𝐚𝐝𝐦𝐢𝐧" and "admiη". Adding any of those spellings by hand would be
// redundant at best and, if the folding tables later changed, misleading.
//
// A corollary worth stating because it is easy to get wrong: a term is only
// useful if it survives skeletonisation. Writing "well-known" and "wellknown"
// as two entries is a duplicate, not two rules, and NewMatcher rejects it.
//
// # The two failure directions are not symmetric
//
// Under-blocking is a missed impersonation, which a later entry fixes. Over-
// blocking refuses a real person the name they wanted, which they experience as
// the product being broken and which no later entry undoes. The lists below are
// therefore deliberately finite and lean toward omission, matching the
// convention already set for the folding tables in tables.go.

// DefaultLists returns the curated lists this service ships with.
//
// A fresh slice is returned on each call, and the Lists it contains are plain
// data. Callers may append their own lists or drop one of these -- a deployment
// with no public sign-up has little use for the offensive list -- without
// mutating anything shared. Fb3's runtime editing and allowlist are expected to
// build on this by composing Lists, not by rewriting the engine.
//
// The order matters only within a match mode; NewMatcher puts every
// whole-skeleton list ahead of every substring list regardless. Routing is
// listed before impersonation so that a term reserved for both reasons is
// reported as the route collision it primarily is.
func DefaultLists() []List {
	return []List{
		{Name: "routing", Mode: MatchWholeSkeleton, Terms: routingTerms()},
		{Name: "impersonation", Mode: MatchWholeSkeleton, Terms: impersonationTerms()},
		{Name: "offensive", Mode: MatchSubstring, Terms: offensiveTerms()},
	}
}

// DefaultMatcher builds a Matcher over DefaultLists.
//
// It returns an error rather than panicking even though the input is a
// compile-time constant, because Fb3 will need the same construction path for
// administrator-supplied lists and a function that panics on bad data is not a
// path an admin API can use.
func DefaultMatcher() (*Matcher, error) {
	return NewMatcher(DefaultLists()...)
}

// routingTerms are names that would collide with the application's own URL
// space, or that users would reasonably read as part of it.
//
// Whole-skeleton mode, so each blocks the name itself and its evasive
// spellings, and nothing longer: "api" blocks "api" and "@p1" but not "apiary".
//
// Reserving a name here costs a user a name they might have wanted, so the list
// covers paths the service plausibly serves or will serve -- ADR-0017 names
// api, admin, healthz, readyz, .well-known, static, assets and login as the
// pattern -- plus the service's own identity, which is the one impersonation a
// routing table cannot protect against. Generic English words are not reserved
// speculatively: "home", "user" and "profile" were considered and left out, as
// plausible handles that this service does not in fact route.
func routingTerms() []string {
	return []string{
		// The service's own names. Anyone registering these is claiming to be
		// the operator, and no route check would catch it.
		"sshpilot", "vallet", "vallete", "sshpilot-vallet",

		// Reserved by convention or by protocol, and expected at the apex by
		// tooling rather than chosen by a user.
		".well-known", "robots.txt", "favicon.ico", "sitemap.xml",

		// Health, readiness and operational endpoints.
		"healthz", "readyz", "livez", "health", "status", "metrics", "ping",

		// Static asset roots.
		"static", "assets", "public", "cdn", "media", "img", "images", "css",
		"js", "fonts",

		// The API surface. Version prefixes such as "v1" are deliberately NOT
		// reserved: the leetspeak stage folds 1 to i, so the term "v1" would in
		// fact reserve "vi" -- an ordinary short handle -- while "v2" folds to
		// itself, making the pair silently inconsistent. This is the general
		// rule for curation here, and TestDefaultTermsAreSkeletonStable
		// enforces it: a term containing a digit does not mean what it looks
		// like. API versions live under the reserved "api" prefix anyway.
		"api", "apis", "graphql", "rpc", "webhook", "webhooks",

		// Authentication and session routes.
		"login", "logout", "signin", "signout", "signup", "register",
		"auth", "oauth", "sso", "saml", "session", "sessions", "token",
		"tokens", "password", "passwords", "reset", "verify", "confirm",
		"enroll", "enrollment",

		// Account and administration surfaces.
		"admin", "account", "accounts", "settings", "preferences", "dashboard",
		"console", "portal", "manage", "management",

		// Documentation and marketing surfaces the service is likely to own.
		"docs", "documentation", "help", "support", "faq",
		"about", "contact", "blog", "news", "pricing", "terms",
		"privacy", "legal", "security", "changelog",

		// Hostname-shaped names that read as infrastructure.
		"www", "ftp", "mail", "smtp", "imap", "pop", "ns", "mx", "dns",
		"localhost", "server", "host", "node", "proxy", "gateway",

		// Placeholder and sentinel values. These matter because they are what a
		// serialization bug or a null-coalescing mistake writes into a URL, and
		// a real owner holding one turns that bug into a takeover.
		"null", "nil", "none", "undefined", "nan", "true", "false",
		"test", "testing", "example", "sample", "demo", "default", "unknown",
		"anonymous", "guest",
	}
}

// impersonationTerms are names that assert authority the holder does not have.
//
// Whole-skeleton mode, and ADR-0017 states the required behavior directly:
// "root blocks root/r00t but not roots". Every term here is a name a user could
// read as speaking for the service, so the harm is the whole identifier being
// that word; a longer name that merely contains it is a different name.
//
// Terms are single words wherever the two-word form skeletonizes to the same
// thing anyway: "no-reply" and "noreply" are one entry, not two, because the
// separator does not survive.
func impersonationTerms() []string {
	return []string{
		// Privileged accounts, including the Unix names an SSH-adjacent product
		// makes especially credible.
		"root", "toor", "superuser", "sudo", "wheel", "daemon", "operator",
		"sysadmin", "sysop",

		// Administrative roles. "admin" itself is in routing; these are the
		// spellings that are not route names.
		"administrator", "administration", "admins", "moderator", "moderators",
		"owner", "staff", "team", "employee", "official", "officials",

		// Service and support identities, the classic phishing handles.
		"helpdesk", "customer-service", "customer-support", "servicedesk",
		"noreply", "donotreply", "postmaster", "webmaster",
		"hostmaster", "abuse", "info", "contact-us",

		// Trust and safety signals. These are the words a user scans for when
		// deciding whether a page is genuine.
		"verified", "verify-account", "trust", "safety", "trustandsafety",
		"authentic", "genuine", "certified",

		// Money. A handle in this space plus a plausible page is a complete
		// payment-redirection attack.
		"billing", "payment", "payments", "invoice", "invoices", "refund",
		"refunds", "checkout", "wallet", "payout", "payouts",

		// Security-response identities, distinct from the "security" route.
		"security-team", "secops", "soc", "cert", "incident", "csirt",

		// The service speaking in the first person.
		"system", "service", "notifications", "alerts", "announcement",
		"announcements",
	}
}

// offensiveTerms are matched as substrings, because a slur embedded in a public
// URL is on display no matter what surrounds it.
//
// # Curation is the only defense against the Scunthorpe problem here
//
// Substring matching has no way to tell a word from a fragment, so a term that
// is a substring of an ordinary word blocks that ordinary word forever. The
// blast radius is much wider than it looks, because the skeleton has already
// had separators removed: a term that is harmless mid-word can still be formed
// across the join of two innocent components.
//
// Every term below was checked against that. The ones deliberately EXCLUDED are
// as much a part of this policy as the ones included, and they are recorded so
// that a future editor does not "helpfully" add them back:
//
//   - "ass" appears in class, assist, assets, password, assign, embassy,
//     brass, compass -- and "assets" is itself a reserved routing term.
//   - "anal" appears in analysis, analytics, canal, analog.
//   - "cum" appears in document, circumstance, accumulate, cucumber.
//   - "tit" appears in title, constitution, competitor, institute.
//   - "hell" appears in shell, hello, michelle, shelling -- and "shell" is
//     unavoidable vocabulary for an SSH product.
//   - "rape" appears in grape, drape, scrape, therapy.
//   - "pedo" appears in torpedo, pedometer, pedestrian.
//   - "coon" appears in raccoon, cocoon, tycoon.
//   - "spic" appears in spice, suspicious, conspicuous.
//   - "chink" is an ordinary English noun.
//   - The three-letter prefix of the racial slur below appears in night,
//     nightly, insignia; only the full forms are listed.
//
// Those omissions are under-blocking, which is the correctable direction: an
// administrator can add any of them at runtime in Fb3 once the allowlist exists
// to absorb the false positives, and that is the right order to do it in.
//
// The list is intentionally short and restricted to terms that are
// unambiguously slurs or profanity in general use, with no common innocent
// superstring. It is not an attempt at a complete profanity filter; ADR-0017
// puts curation over time in the administrator's hands.
//
// Leetspeak and homoglyph spellings need no entries: folding handles "sh1t",
// "f*ck" once the symbol folds, "$hit" and the Unicode variants.
//
// Plural and inflected forms are likewise omitted wherever the base form is
// already a substring of them: "nigger" covers "niggers" and "retard" covers
// "retarded", so listing both would add a term that can never be the one
// reported. TestNoOffensiveTermIsRedundant enforces this, because a redundant
// entry reads to a reviewer as extra coverage that does not exist.
func offensiveTerms() []string {
	return []string{
		// General profanity with no common innocent superstring.
		"fuck", "shit", "bitch", "bastard", "wanker", "bollocks",
		"asshole", "arsehole", "dickhead", "dumbass", "jackass",

		// Sexual profanity.
		"cunt", "whore", "slut", "blowjob", "handjob", "porn",
		"hentai", "nudes",

		// Racial, ethnic and religious slurs. Listed in full forms only, for
		// the prefix reason given above.
		"nigger", "nigga", "kike", "wetback", "beaner",
		"gook", "raghead", "towelhead", "paki",

		// Slurs targeting sexuality and gender identity.
		"faggot", "tranny", "trannies", "dyke",

		// Ableist slurs.
		"retard", "spastic", "mongoloid",

		// Extremist identity claims. These are impersonation-adjacent but the
		// harm is the same as a slur -- the word being in the URL -- so they
		// match as substrings rather than whole names.
		"nazi", "hitler", "kkk", "whitepower",
	}
}
