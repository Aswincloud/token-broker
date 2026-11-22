// token-broker: hands GitHub Actions workflows short-lived, narrowly scoped
// aswincloud-bot App tokens, so the App's private key never lives in GitHub.
//
//   POST /token   Authorization: Bearer <GitHub Actions OIDC token, aud=AUDIENCE>
//                 body: {"repositories": ["<repo>"], "permissions": {"contents": "write"}}
//   -> 200 {"token", "expires_at", "repositories", "permissions"}
//   GET  /health  -> 200 {"ok": true}
//
// Refusals return a short generic reason; details go to the Worker log only.

import { decide, type Request as TokenRequest } from "./policy.ts";
import { cachedJwks, verifyGithubOidc } from "./oidc.ts";
import { appJwt, importPkcs8, mintInstallationToken } from "./github.ts";

export interface Env {
  APP_ID: string;
  APP_INSTALLATION_ID: string;
  /** PKCS#8 PEM. Worker secret only — never in wrangler config or a build. */
  APP_PRIVATE_KEY: string;
  /** OIDC audience the workflows request, e.g. "https://token-broker.aswincloud.com". */
  AUDIENCE: string;
}

const jwks = cachedJwks();
const MAX_BODY_BYTES = 4096;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });

export async function handle(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/health" && req.method === "GET") return json(200, { ok: true });
  if (url.pathname !== "/token") return json(404, { error: "not found" });
  if (req.method !== "POST") return json(405, { error: "method not allowed" });

  const auth = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)$/.exec(auth);
  if (!m) return json(401, { error: "missing or malformed bearer token" });

  let claims;
  try {
    claims = await verifyGithubOidc(m[1]!, env.AUDIENCE, jwks);
  } catch (e) {
    console.log(JSON.stringify({ event: "oidc_rejected", reason: (e as Error).message }));
    return json(401, { error: "invalid OIDC token" });
  }

  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) return json(413, { error: "body too large" });
  let body: TokenRequest;
  try {
    body = JSON.parse(raw) as TokenRequest;
  } catch {
    return json(400, { error: "body must be JSON" });
  }

  const d = decide(claims, body);
  const who = { repository: claims.repository, workflow: claims.job_workflow_ref, github_event: claims.event_name };
  if (!d.ok) {
    console.log(JSON.stringify({ event: "denied", ...who, reason: d.reason }));
    return json(403, { error: "not allowed", reason: d.reason });
  }

  try {
    const key = await importPkcs8(env.APP_PRIVATE_KEY);
    const jwt = await appJwt(env.APP_ID, key);
    const t = await mintInstallationToken(jwt, env.APP_INSTALLATION_ID, d.repositories, d.permissions);
    console.log(JSON.stringify({ event: "issued", ...who, rule: d.rule.name, repositories: t.repositories, permissions: t.permissions, expires_at: t.expires_at }));
    return json(200, t);
  } catch (e) {
    console.log(JSON.stringify({ event: "mint_failed", ...who, reason: (e as Error).message }));
    return json(502, { error: "could not mint token" });
  }
}

export default { fetch: handle } satisfies ExportedHandler<Env>;
