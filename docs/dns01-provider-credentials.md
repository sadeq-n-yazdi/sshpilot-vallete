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

---

## AWS Route 53

### Credential format

Route 53 needs two values, and `credentials_ref` resolves to one string, so
they are packed with a colon:

```
AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Both halves must be present and non-empty; a malformed value is refused at
startup rather than at the first renewal. Surrounding whitespace and a trailing
newline are tolerated, so a file-backed secret works without special handling.

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
