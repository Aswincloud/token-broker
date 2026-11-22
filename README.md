# token-broker

Gives GitHub Actions workflows short-lived, narrowly scoped **aswincloud-bot**
GitHub App tokens, so the App's private key never lives in GitHub.

```
workflow ──(GitHub OIDC token, aud=https://token-broker.aswincloud.com)──▶ POST /token
                                                                             │ verify OIDC (signature, issuer, audience, expiry)
                                                                             │ match policy (repo + job_workflow_ref + event)
                                                                             │ sign App JWT with the private key (Worker secret)
                                                                             ▼
workflow ◀────────── 1-hour installation token, scoped to the requested repos + permissions
```

## Why

Before this, `APP_PRIVATE_KEY` was an org secret readable by every public
repo's workflows. Any step that ran in such a job (e.g. a malicious npm
`postinstall`) could copy the key and mint org-wide tokens forever. Here the key
is a Cloudflare Worker secret; a compromised job can get at most the one token
its rule allows, valid for an hour.

## The policy is the security boundary

`src/policy.ts` lists exactly which workflow may get what. A request is honoured
only if:

- the caller's org name **and numeric id** match;
- `repository` **and** `job_workflow_ref` (the signed workflow file + ref) match a rule exactly,
  so the same file on another branch, another file, or a fork never matches;
- `event_name` is one the rule allows (no `pull_request*` on write rules);
- every requested repository and permission is within the rule's maximum.

Add a rule only for a workflow on `main`, with the smallest permissions it needs.

## Using it from a workflow

```yaml
permissions:
  id-token: write   # to request the OIDC token
  contents: read
steps:
  - name: Get App token from token-broker
    id: app
    run: |
      oidc=$(curl -sS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://token-broker.aswincloud.com" | jq -r .value)
      tok=$(curl -sSf -X POST https://token-broker.aswincloud.com/token \
        -H "Authorization: Bearer $oidc" -H 'Content-Type: application/json' \
        -d '{"repositories":[".github"],"permissions":{"contents":"write"}}' | jq -r .token)
      echo "::add-mask::$tok"
      echo "token=$tok" >> "$GITHUB_OUTPUT"
```

## Deploy

```bash
npm ci --ignore-scripts && npm test && npm run typecheck
# GitHub hands out PKCS#1; the broker needs PKCS#8:
openssl pkcs8 -topk8 -nocrypt -in app.pem -out app-pkcs8.pem
npx wrangler secret put APP_PRIVATE_KEY < app-pkcs8.pem && shred -u app.pem app-pkcs8.pem
npx wrangler deploy
```

Every issue / denial is logged as JSON (Workers observability): repository,
workflow, event, rule, granted repos/permissions — never the token or key.

## Limits

- The key still exists as a Worker secret: Cloudflare account security
  (2FA, scoped API tokens) now protects it.
- If the Worker is down, broker-based workflows can't get tokens.
