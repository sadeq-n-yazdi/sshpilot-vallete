# DNS-01 provider credentials

For operators configuring the ACME **DNS-01** solver in `api` mode.

A DNS-01 credential can rewrite your zone. It is the highest-privilege secret
this program holds, so two rules apply to every provider below:

- **It comes from the secret provider**, never from the config file. Set
  `tls.acme.dns.credentials_ref` to a reference such as
  `env:VALLET_DNS_CREDENTIALS` or `file:/run/secrets/vallet-dns`
  (ADR-0022). The value is never written to logs, telemetry, the database, or
  an error message.
- **Scope it as narrowly as the provider allows.** The program cannot make a
  credential less powerful than you issued it. Everything below is the
  narrowest grant that still works.

### One credential or several

Providers that authenticate with a **single value** (Cloudflare, DigitalOcean,
DNSimple, Gandi, ArvanCloud) use `credentials_ref`.

Providers that need **several named values** — Route 53 and OVH — use
`credentials_refs`, a map from a credential name to its own reference:

```yaml
tls:
  acme:
    dns:
      mode: api
      provider: route53
      credentials_refs:
        access_key_id: env:VALLET_DNS_AWS_KEY_ID
        secret_access_key: env:VALLET_DNS_AWS_SECRET
```

Each value is resolved independently through the secret provider, so no
credential is ever written in the config file. Set **either** `credentials_ref`
**or** `credentials_refs` for a provider, never both — startup is refused if
both are present, so the source of a credential is never ambiguous. A
single-value provider may also use `credentials_refs` with one entry.

---

## AWS Route 53

### Credential format

Route 53 needs two values. The preferred form is the named
`credentials_refs` map shown above, with `access_key_id` and
`secret_access_key` as separate references.

For back-compatibility the two values may still be supplied as a single
`credentials_ref` with the halves packed by a colon:

```
AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Either form works. With the named map, supply both `access_key_id` and
`secret_access_key`; supplying only one is refused (it is a configuration
mistake, not a packed value to split). With the packed single reference, both
halves must be present and non-empty. In both forms a malformed value is
refused at startup rather than at the first renewal, and surrounding whitespace
and a trailing newline are tolerated, so a file-backed secret works without
special handling.

There is no region to configure. Route 53 is a global service with a single
control plane, always signed for `us-east-1`.

### Minimal IAM policy

Replace `Z1EXAMPLEZONEID` with the hosted zone ID of the domain you are getting
a certificate for. Use a dedicated IAM user or role for this program and attach
nothing else to it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FindTheHostedZone",
      "Effect": "Allow",
      "Action": "route53:ListHostedZonesByName",
      "Resource": "*"
    },
    {
      "Sid": "ReadTheChallengeRecordSet",
      "Effect": "Allow",
      "Action": "route53:ListResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/Z1EXAMPLEZONEID"
    },
    {
      "Sid": "WriteOnlyAcmeChallengeTxtRecords",
      "Effect": "Allow",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/Z1EXAMPLEZONEID",
      "Condition": {
        "ForAllValues:StringEquals": {
          "route53:ChangeResourceRecordSetsRecordTypes": ["TXT"],
          "route53:ChangeResourceRecordSetsActions": ["UPSERT", "DELETE"]
        },
        "ForAllValues:StringLike": {
          "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
            "_acme-challenge.*"
          ]
        }
      }
    }
  ]
}
```

Why each piece is there, and why nothing else is:

- **`ListHostedZonesByName`** finds the zone. AWS does not support resource
  scoping on this action, so `"Resource": "*"` is forced. It is a read of zone
  names and IDs only.
- **`ListResourceRecordSets`** is needed because Route 53 has no per-record
  identifiers. A record set is keyed by name and type and holds a *set* of
  values, so publishing a challenge means reading the current values and writing
  back the union, and removing one means writing back the difference. Without
  this read the program would have to overwrite the whole record set, which
  would destroy any other TXT value at the same name — including the second
  challenge of a wildcard certificate.
- **`ChangeResourceRecordSets`** is constrained three ways: to one hosted zone,
  to `TXT` records only, and to names beginning `_acme-challenge.`. With these
  conditions the credential cannot alter your `A`, `MX`, `NS` or any other
  record, and cannot touch a TXT record outside the challenge prefix. The
  normalized-record-names condition key compares against the lowercased name
  with the trailing dot removed, which is why the pattern has no trailing dot.
- **`route53:GetChange` is deliberately absent.** It is conventional to poll a
  change until its status becomes `INSYNC`, and this program does not. The
  solver already waits until every authoritative nameserver for the zone serves
  the value, which is a strictly stronger condition: those nameservers *are* the
  Route 53 fleet, so "all of them are serving it" entails "the change is in
  sync". The reverse is not true, and fails in the case that matters most — a
  change written to a private hosted zone, or to a public zone your registrar
  does not delegate to, reaches `INSYNC` promptly and is never visible to the
  CA. Granting `GetChange` would add permission for a check that is weaker than
  the one already being made.

`UPSERT` and `DELETE` are the only actions used; `CREATE` is not, because it
fails when a record set already exists at the name.

### Hosted zones: what will be refused

The program picks the zone rather than trusting configuration, and it fails
loudly instead of guessing:

- **Private hosted zones are ignored.** They are visible only inside their
  associated VPCs, and the CA queries the public internet.
- **Two public hosted zones with the same name is an error, not a coin flip.**
  AWS permits duplicates, but only the one your registrar delegates to is real.
  Writing into the other one succeeds, reaches `INSYNC`, and is never seen — so
  issuance would fail ten minutes later with a message about DNS rather than
  about your account. Delete the unused duplicate.
- **The most specific zone wins.** If you hold both `example.com` and a
  delegated `eu.example.com`, a name under the latter is written there.

---

## Cloudflare

Set `credentials_ref` to an **API token** (not the legacy global API key).

Issue it from *My Profile → API Tokens* with the **Edit zone DNS** template,
and restrict *Zone Resources* to the single zone you are getting a certificate
for. That is the narrowest grant Cloudflare offers: the API has no per-record
scoping, so a token that can edit DNS in a zone can edit any record in it. The
program only ever deletes by the record ID its own create returned, so it cannot
remove a record it did not create — but that is a property of this program, not
a limit the token enforces.

---

## DigitalOcean

Set `credentials_ref` to a DigitalOcean **personal access token** with the
`write` scope, issued from *API → Tokens*.

### The scope is coarse, and this is the honest version

Unlike Route 53 and Cloudflare, DigitalOcean offers **no way to narrow this
credential to one domain, one record type, or one record name**. A legacy
personal access token with `write` is **account-wide**: the same token that
edits your DNS can create and destroy Droplets, Kubernetes clusters, volumes,
snapshots and load balancers, and can read your account. Newer DigitalOcean
tokens support per-resource-type scopes, and if your account offers them, grant
only the DNS/domain write scope — but even that is every domain in the account,
not the one being validated.

There is no policy this program can hand you that makes the token narrower,
and none of the safety below comes from the token:

- The program only ever deletes a record whose **value it published itself**,
  matched exactly, so it cannot remove a record it did not create — including
  your own TXT record at the same name, and including the second challenge of a
  wildcard certificate. That is a property of *this program*, not a limit the
  token enforces.
- Anything else holding the same token is unconstrained by any of that.

So treat a DigitalOcean DNS-01 token as an account credential: give it its own
token rather than reusing one, store it in the secret provider, and rotate it if
it is ever exposed. If your threat model cannot accept an account-wide
credential on this host, use a provider whose API supports scoping, or run
DNS-01 in `manual` mode.

### Domains: what will be refused

The program picks the domain rather than trusting configuration, and it fails
loudly instead of guessing:

- **The most specific domain wins.** If you hold both `example.com` and a
  delegated `eu.example.com`, a name under the latter is written there. Writing
  to the parent would put the record in a zone that is not authoritative for the
  name.
- **No matching domain is an error.** The name being validated must sit under a
  domain in this account. Guessing would write the challenge somewhere the CA
  never queries, and issuance would fail ten minutes later with a message about
  DNS rather than about your account.
- **There is no ambiguity to resolve.** A domain name is the API's own path key,
  so an account cannot hold two domains with the same name — unlike Route 53,
  where duplicate hosted zones are possible and are refused.

Record names are stored **relative** to the domain, and the program computes
that split itself; a name that does not sit inside the resolved domain is
refused rather than written. Sending the fully qualified name would create the
record at `_acme-challenge.example.com.example.com`, which the API accepts and
no CA ever queries.

The program does not poll DigitalOcean for the change to be applied. The solver
already waits until every authoritative nameserver for the zone serves the
value, which is a strictly stronger condition.

---

## DNSimple

Set `credentials_ref` to a DNSimple **account API token**, issued from
*Account → Automation → API tokens*.

### Use an account token, not a user token

DNSimple issues two kinds of token, and this matters:

- An **account token** is tied to one account. This is what to use.
- A **user token** grants access to *every* account the user can reach.

The program refuses a user token at the first issuance rather than working
around it. Every DNSimple API path is account-scoped
(`/v2/{account}/zones/...`), so an account id is required to write anything, and
the program reads it from `/v2/whoami` — the account the **presented token**
belongs to. A user token has no single account behind it: `whoami` returns a
null account, because the user may belong to several. Picking one would mean the
program decides, on its own initiative, which of your accounts gets written to.

Taking the id from the token rather than from configuration is also what makes a
cross-account misroute impossible. There is no number you can set that points
this credential at somebody else's account; the credential can only ever address
its own.

### The scope is coarse

DNSimple's API tokens are **account-wide**. There is no way to narrow one to a
single domain, record type, or record name, so a token that can edit DNS can
edit every zone in the account. That is a limit of the API, not something this
code can close, and none of the safety below comes from the token:

- The program only ever deletes a record whose **value it published itself**,
  matched exactly, so it cannot remove a record it did not create — including
  your own TXT record at the same name, and including the second challenge of a
  wildcard certificate. That is a property of *this program*, not a limit the
  token enforces.
- Anything else holding the same token is unconstrained by any of that.

Give DNS-01 its own token rather than reusing one, store it in the secret
provider, and rotate it if it is ever exposed. If your threat model cannot accept
an account-wide credential on this host, use a provider whose API supports
scoping, or run DNS-01 in `manual` mode.

### Zones: what will be refused

The program picks the zone rather than trusting configuration, and it fails
loudly instead of guessing:

- **The most specific zone wins.** If you hold both `example.com` and a delegated
  `eu.example.com`, a name under the latter is written there. Writing to the
  parent would put the record in a zone that is not authoritative for the name.
- **No matching zone is an error.** The name being validated must sit under a
  zone in this account. Guessing would write the challenge somewhere the CA never
  queries, and issuance would fail ten minutes later with a message about DNS
  rather than about your account.
- **There is no ambiguity to resolve.** Within one account a zone name is the
  API's own path key, so an account cannot hold two zones with the same name —
  unlike Route 53, where duplicate hosted zones are possible and are refused. The
  same name *can* exist in a different account, which is exactly why the account
  is pinned from the token.

Record names are stored **relative** to the zone — on both the write and the read
path, unlike DigitalOcean, whose list filter wants the fully qualified name. The
program computes that split itself; a name that does not sit inside the resolved
zone is refused rather than written. Sending the fully qualified name would
create the record at `_acme-challenge.example.com.example.com`, which the API
accepts and no CA ever queries.

The program does not poll DNSimple for the change to be applied. The solver
already waits until every authoritative nameserver for the zone serves the value,
which is a strictly stronger condition.

---

## Gandi

Set `credentials_ref` to a Gandi **Personal Access Token (PAT)**, created from
*Organizations → (your organization) → Manage → Personal Access Tokens*.

The token is presented as `Authorization: Bearer <PAT>`. Gandi's older
`Authorization: Apikey <key>` scheme is **deprecated** and this program does not
send it, so an API key issued under the legacy scheme will not work — mint a PAT
instead.

### Scope it as narrowly as Gandi allows

A PAT is created against **one organization**, and its permissions are
selectable. Grant only what DNS-01 needs:

- Restrict the token to the single organization that holds the domain you are
  getting a certificate for.
- Enable only the permission that covers LiveDNS record management (**"Manage
  domain name technical configurations"** / *See and renew domain names* is not
  required). Do **not** grant billing, transfer, or organization-management
  permissions.

That is the narrowest grant Gandi offers. Within an organization the API has no
per-record scoping, so a token that can edit LiveDNS records can edit any record
in that organization's domains. None of the safety below comes from the token:

- The program only ever removes a TXT **value it published itself**, matched
  exactly. Gandi addresses records by record set — a *set* of values keyed by
  name and type — so on cleanup the program reads the current set, writes back
  every other value unchanged, and deletes the set outright **only** when its own
  value was the last one in it. It therefore cannot remove a record it did not
  create, including your own TXT record at the same name, and including the
  second challenge of a wildcard certificate, which sits at the same name with a
  different digest. That is a property of *this program*, not a limit the token
  enforces.
- Anything else holding the same token is unconstrained by any of that.

Give DNS-01 its own token rather than reusing one, store it in the secret
provider, and rotate it if it is ever exposed. If your threat model cannot accept
an organization-wide credential on this host, use a provider whose API supports
finer scoping, or run DNS-01 in `manual` mode.
## ArvanCloud

Set `credentials_ref` to an ArvanCloud **API key**, issued from *Machine User →
API keys* (or *Profile → API keys*). Supply the **bare key**: valletd sends it in
the documented `Authorization: Apikey <key>` header and adds the `Apikey ` prefix
itself, so do not include that prefix in the stored value.

The API base is fixed at `https://napi.arvancloud.ir/cdn/4.0` and is never
configurable — a settable endpoint would be a way to point this
zone-editing key at another host. See the ArvanCloud CDN 4.0 DNS API reference:
<https://docs.arvancloud.ir/en/developer-tools/api/api-usage> and
<https://docs.arvancloud.ir/en/cdn/dns-records/adding-records>.

### The scope is coarse

ArvanCloud's API keys are **account-wide**. There is no way to narrow one to a
single domain, record type, or record name, so a key that can edit DNS can edit
every domain in the account — and the same key reaches the rest of the CDN, DNS,
and object-storage APIs it is entitled to. That is a limit of the API, not
something this code can close, and none of the safety below comes from the key:

- The program only ever deletes a record whose **value it published itself**,
  matched exactly, so it cannot remove a record it did not create — including
  your own TXT record at the same name, and including the second challenge of a
  wildcard certificate. That is a property of *this program*, not a limit the
  key enforces.
- Anything else holding the same key is unconstrained by any of that.

Give DNS-01 its own key rather than reusing one, store it in the secret provider,
and rotate it if it is ever exposed. If your threat model cannot accept an
account-wide credential on this host, use a provider whose API supports scoping,
or run DNS-01 in `manual` mode.

### Domains: what will be refused

The program picks the domain rather than trusting configuration, and it fails
loudly instead of guessing:

- **The most specific domain wins.** If you hold both `example.com` and a
  delegated `eu.example.com`, a name under the latter is written there. Writing
  to the parent would put the record in a zone that is not authoritative for the
  name.
- **No matching domain is an error.** The name being validated must sit under a
  domain the token can manage. `GET /v5/livedns/domains/{fqdn}` answers `404`
  ("Unknown domain") for a domain the token does not hold, which is the only
  status treated as "try the parent"; a rejected token or a server error is
  surfaced rather than swallowed. Guessing would write the challenge somewhere
  the CA never queries, and issuance would fail ten minutes later with a message
  about DNS rather than about your account.
- **There is no ambiguity to resolve.** A domain name is the API's own path key,
  so one organization cannot hold two domains with the same name — unlike Route
  53, where duplicate hosted zones are possible and are refused.

Record names are stored **relative** to the domain (the apex is `@`), and the
program computes that split itself; a name that does not sit inside the resolved
domain is refused rather than written. The challenge TTL is set to Gandi's floor
of **300 seconds** — Gandi rejects a lower value — and an existing record set's
own TTL is preserved when the program merges a challenge into it.

The program does not poll Gandi for the change to be applied. The solver already
waits until every authoritative nameserver for the zone serves the value, which
is a strictly stronger condition.
  domain in this account. A domain absent from the account answers `404`, which
  is what advances the search to the parent; guessing would write the challenge
  somewhere the CA never queries.
- **There is no ambiguity to resolve.** A domain name is the API's own path key,
  so an account cannot hold two domains with the same name — unlike Route 53,
  where duplicate hosted zones are possible and are refused.

Record names are stored **relative** to the domain, and the program computes that
split itself; a name that does not sit inside the resolved domain is refused
rather than written. Sending the fully qualified name would create the record at
`_acme-challenge.example.com.example.com`, which the API accepts and no CA ever
queries. The TXT value is carried in the nested `{"value":{"text":"..."}}` object
the API requires, and the cleanup listing is matched on name, type and exact
value in code rather than trusting the API's `search` filter.

The program does not poll ArvanCloud for the change to be applied. The solver
already waits until every authoritative nameserver for the zone serves the value,
which is a strictly stronger condition.

---

## OVH

OVH does not authenticate with a single token. Every request is **signed** with
three distinct values, so OVH is configured only through `credentials_refs`,
never `credentials_ref`:

```yaml
tls:
  acme:
    dns:
      mode: api
      provider: ovh
      credentials_refs:
        application_key: env:VALLET_DNS_OVH_APP_KEY
        application_secret: env:VALLET_DNS_OVH_APP_SECRET
        consumer_key: env:VALLET_DNS_OVH_CONSUMER_KEY
        endpoint: env:VALLET_DNS_OVH_ENDPOINT   # optional; default ovh-eu
```

- `application_key` and `application_secret` identify the application. Create
  them at <https://api.ovh.com/createApp/> (EU) or the regional console.
- `consumer_key` is the per-user token authorizing that application. Create it
  with a validation request scoped to the DNS operations below, then have the
  account owner validate it once.
- `endpoint` selects the region and is **optional**, defaulting to `ovh-eu`. It
  is chosen from a fixed allowlist — `ovh-eu`, `ovh-ca`, `ovh-us` — and any
  other value is refused at startup. It is **not** a free-form URL: a settable
  base would be a way to point a zone-editing credential at another host, so the
  region name maps to a fixed OVH base URL and nothing else is accepted.

Supplying only some of the three required fields, or a blank one, is refused at
startup rather than at the first renewal. The `application_secret` is the only
field OVH never transmits — it is the SHA-1 signing key — and it never appears in
a log or an error.

### Scope the consumer key as narrowly as OVH allows

OVH scopes a consumer key by **method and path pattern**. Grant only what DNS-01
needs against your zone, for example:

```
GET    /domain/zone/*
POST   /domain/zone/*/record
GET    /domain/zone/*/record
GET    /domain/zone/*/record/*
DELETE /domain/zone/*/record/*
POST   /domain/zone/*/refresh
```

That is far narrower than an all-`/*` grant. The program only ever deletes a
record whose **value it published itself**, matched exactly, so it cannot remove
a record it did not create — including your own TXT record at the same name, and
including the second challenge of a wildcard certificate. That is a property of
*this program*, not a limit the key enforces, so still give DNS-01 its own
consumer key, store every field in the secret provider, and rotate them if
exposed.

### The refresh step

OVH stages zone edits and does **not** serve them until the zone is refreshed.
The program issues `POST /domain/zone/{zone}/refresh` after creating the
challenge record and again after deleting it on cleanup, so the change the CA
needs is actually served. A create that was not refreshed reports success and is
never visible, which would fail issuance ten minutes later with a message about
DNS rather than about the record.

### Signed requests and the timestamp

Each request carries `X-Ovh-Application`, `X-Ovh-Consumer`, `X-Ovh-Timestamp`
and `X-Ovh-Signature`, where the signature is
`"$1$" + SHA1(application_secret + "+" + consumer_key + "+" + METHOD + "+" +
fullURL + "+" + body + "+" + timestamp)`. The timestamp is adjusted by the
delta between OVH's clock and this host's, fetched once from the unauthenticated
`/auth/time` endpoint, so a skewed local clock does not make OVH reject every
call.

### Zones: what will be refused

The program picks the zone rather than trusting configuration, and it fails
loudly instead of guessing:

- **The most specific zone wins.** If you hold both `example.com` and a delegated
  `eu.example.com`, a name under the latter is written there.
- **No matching zone is an error.** The name being validated must sit under a
  zone the consumer key can manage; `GET /domain/zone/{zone}` answers `404` for a
  zone it does not, which is the only status treated as "try the parent". A
  rejected credential or a server error is surfaced rather than swallowed.
- **There is no ambiguity to resolve.** A zone name is the API's own path key, so
  an account cannot hold two zones with the same name — unlike Route 53, where
  duplicate hosted zones are possible and are refused.

Record names are stored **relative** to the zone (the apex is the empty
subdomain), and the program computes that split itself; a name that does not sit
inside the resolved zone is refused rather than written.

The program does not poll OVH for the change to be applied. The solver already
waits until every authoritative nameserver for the zone serves the value, which
is a strictly stronger condition.
