# 0034. RFC 2136 (dynamic DNS UPDATE + TSIG) DNS-01 provider

- **Status:** Proposed
- **Date:** 2026-07-24

## Context

ADR-0015 §2 defined a pluggable DNS-provider seam for the ACME DNS-01 solver and
listed RFC 2136 in its phase-1 provider set. Every provider landed before it —
Cloudflare, Route 53, DigitalOcean, DNSimple, Gandi, GoDaddy, ArvanCloud,
Namecheap, OVH — is a vendor **HTTPS API**, so they all fit the seam's
`NewAPIProvider(name, creds Credentials, client *http.Client)` shape: a self
contained file in `internal/dns01` plus one `case` in the registry switch, with
nothing else in the solver, the ACME flow or the config schema changing.

RFC 2136 (RFC 2136 UPDATE, authenticated with TSIG per RFC 8945) does not fit
that shape, and this is the ADR for the three places it forces a change.

1. **It is not HTTP.** It sends a signed DNS UPDATE message straight to an
   authoritative nameserver, so it ignores the shared `*http.Client` entirely and
   needs a DNS message/UPDATE/TSIG implementation the standard library does not
   provide.
2. **It needs non-secret settings the seam signature cannot carry** — the
   nameserver address, the TSIG key name, and the TSIG algorithm.
3. **TSIG is an authentication primitive**, so the MAC must not be hand-rolled and
   the algorithm set must be an allowlist, not a passthrough.

## Decision

### New dependency: `github.com/miekg/dns`

RFC 2136 requires constructing, signing and exchanging DNS messages. Reimplementing
DNS wire format and the TSIG MAC by hand would be exactly the kind of security
sensitive code this project avoids writing itself, so we take a deliberate,
user-approved dependency on `github.com/miekg/dns` — the de-facto standard Go DNS
library — pinned like every other module and kept under the `make vuln`
(govulncheck) hard gate and the reproducible-build check. It is used only inside
`internal/dns01/rfc2136.go`: message construction, the UPDATE, TSIG signing, and
the unsigned SOA query used for zone discovery. The library's built-in TSIG
support computes the MAC over the canonical wire form; this code never touches
the MAC itself.

### Wiring: constructed in the transport layer, not through `NewAPIProvider`

The seam's `NewAPIProvider` signature carries only `(name, creds, client)`. The
RFC 2136 provider additionally needs `server`, `tsig_key_name` and
`tsig_algorithm`, which are **not secret**. Two options were considered:

- **(a)** widen `NewAPIProvider` to carry RFC 2136 settings — rejected: it
  pollutes the signature every other provider shares and every test that calls it,
  for one provider's benefit.
- **(b)** carry the settings through the `Credentials` set — rejected: `Credentials`
  is the secret-custody type; putting non-secret values in it abuses the model and
  would add `Reveal` sites.

We chose the remaining option: construct the provider in the **wiring layer**
(`internal/transport/http/tls.go`, `newDNSProvider`) via an exported
`dns01.NewRFC2136(server, keyName, algorithm string, creds Credentials)`. The TSIG
**secret** still arrives through the same resolved `credentials_ref` /
`credentials_refs` path as every other provider, so credential custody is
unchanged; only the three non-secret settings are read from config. `NewAPIProvider`
keeps its narrow signature and refuses `"rfc2136"` like any name it does not list —
its doc comment names RFC 2136 as the documented exception so the invariant "one
file plus one case" stays honest.

### Config schema extension (fail-closed)

`config.ACMEDNSConfig` gains three fields, all plain config with clear doc comments
explaining why they are **not** secret references:

- `server` (`host:port`) — the address travels in cleartext in every DNS packet.
  Required for rfc2136; no discovery fallback, because a settable-then-guessed
  nameserver is a way to steer a zone-editing key at another host.
- `tsig_key_name` — the key **name** is sent in the clear inside every TSIG record.
- `tsig_algorithm` — names a public hash. Validated against a fixed allowlist of
  strong HMACs (`hmac-sha224`/`256`/`384`/`512`); the historical `hmac-md5` and
  `hmac-sha1` defaults are refused, because a weak signing primitive lets a forged
  UPDATE rewrite the zone.

`config.Validate`, when `provider == "rfc2136"`, requires all three and checks the
algorithm against an allowlist. `config` keeps its **own** copy of that four-name
allowlist rather than importing `internal/dns01`: `config` is a foundational package
and must not pull the DNS wire stack (`miekg/dns`) into the dependency closure of
everything that reads configuration (the client binary `vallet-helper`, for example,
imports neither). A parity test (`TestTSIGAlgorithmParity`) — which, being a test,
may freely import `dns01` — pins config's list to `dns01.TSIGAlgorithmNames()`, so
the duplicate cannot drift: a value config accepts is one the provider can sign with,
and the reverse. Unknown-YAML-key strictness is unchanged, and all three carry the
standard `VALLET_*` env bindings.

Only the TSIG **secret** is a credential; it rides `credentials_ref` and is checked
by the existing shared credential validation.

### Security properties

- The TSIG secret enters as a `secrets.Redacted` and is unwrapped in exactly one
  place — where the DNS library computes the message MAC — pinned by the package's
  `Reveal()`-call-site test.
- Errors name the record and the DNS rcode (from the library's fixed table), never
  the credential; a signed request is never rendered into an error, and the SOA
  discovery query is unsigned.
- A domain name read out of a server's SOA response is bounded with
  `safetext.Bound` before it is used or logged.
- Zone discovery walks up the labels most-specific-first, so a delegated subdomain
  wins over its parent. Cleanup removes exactly the one TXT record it published (a
  specific-RR delete, not a record-set wipe) and is idempotent because RFC 2136
  makes deleting an absent RR a NOERROR no-op.
- The solver's authoritative-nameserver propagation gate (ADR-0015) is unchanged
  and still applies; the provider does not wait for propagation itself.

## Consequences

- One new third-party dependency, confined to one file and kept green under the
  supply-chain gates of ADR-0027.
- The DNS-01 seam now has one documented exception to "one file plus one case":
  RFC 2136 also touches the config schema and is built in the wiring layer. This is
  called out in `NewAPIProvider`'s doc and here.
- Real DNS I/O is exercised in tests through an in-process `miekg/dns` server bound
  to a random localhost UDP port, which drives TSIG signing (valid key signs and
  applies; wrong secret is rejected), zone discovery, publish/cleanup scoping and
  every fail-closed refusal — with no live nameserver.

## Related

- ADR-0015 — HTTPS-only transport and certificate provisioning (the DNS-01 seam).
- ADR-0022 — configuration and secrets (the `secrets.Ref` / `Redacted` model the
  TSIG secret rides).
- ADR-0027 — supply-chain and build security (the gates the new dependency passes).
