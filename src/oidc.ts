// Verifies GitHub Actions OIDC tokens (RS256 JWTs) with Web Crypto.
//
// Checks, in order: header alg/kid, signature against GitHub's published JWKS,
// issuer, audience, expiry / not-before / issued-at (with a small clock skew),
// and the presence of the claims the policy relies on. Every failure throws;
// callers must treat any exception as "not authenticated".

import type { Claims } from "./policy.ts";

export const ISSUER = "https://token.actions.githubusercontent.com";
export const JWKS_URL = `${ISSUER}/.well-known/jwks`;
const SKEW_SECONDS = 60;
/** GitHub's Actions OIDC tokens live ~5–10 minutes; reject anything claiming longer. */
const MAX_LIFETIME_SECONDS = 15 * 60;

export interface Jwk extends JsonWebKey {
  kid?: string;
}

export type JwksFetcher = () => Promise<{ keys: Jwk[] }>;

const b64urlToBytes = (s: string): Uint8Array => {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const decodeJson = (part: string): Record<string, unknown> => {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("malformed JWT part");
  return parsed as Record<string, unknown>;
};

const REQUIRED = ["repository", "repository_owner", "repository_owner_id", "job_workflow_ref", "event_name", "ref"] as const;

export async function verifyGithubOidc(
  token: string,
  audience: string,
  fetchJwks: JwksFetcher,
  now: number = Math.floor(Date.now() / 1000),
): Promise<Claims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("not a JWT");
  const [h, p, s] = parts as [string, string, string];

  const header = decodeJson(h);
  if (header.alg !== "RS256") throw new Error("unexpected alg");
  if (typeof header.kid !== "string" || !header.kid) throw new Error("missing kid");

  const { keys } = await fetchJwks();
  const jwk = keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error("unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    b64urlToBytes(s),
    new TextEncoder().encode(`${h}.${p}`),
  );
  if (!valid) throw new Error("bad signature");

  const c = decodeJson(p);
  if (c.iss !== ISSUER) throw new Error("wrong issuer");
  const aud = c.aud;
  const audOk = Array.isArray(aud) ? aud.length === 1 && aud[0] === audience : aud === audience;
  if (!audOk) throw new Error("wrong audience");

  const exp = c.exp, nbf = c.nbf, iat = c.iat;
  if (typeof exp !== "number" || typeof iat !== "number") throw new Error("missing exp/iat");
  if (now > exp + SKEW_SECONDS) throw new Error("token expired");
  if (typeof nbf === "number" && now + SKEW_SECONDS < nbf) throw new Error("token not yet valid");
  if (iat > now + SKEW_SECONDS) throw new Error("token issued in the future");
  if (exp - iat > MAX_LIFETIME_SECONDS) throw new Error("token lifetime too long");

  for (const k of REQUIRED) {
    if (typeof c[k] !== "string" || !c[k]) throw new Error(`missing claim ${k}`);
  }
  return {
    repository: c.repository as string,
    repository_owner: c.repository_owner as string,
    repository_owner_id: c.repository_owner_id as string,
    job_workflow_ref: c.job_workflow_ref as string,
    event_name: c.event_name as string,
    ref: c.ref as string,
  };
}

/** JWKS fetcher with a short in-isolate cache; refetches when a kid is unknown upstream. */
export function cachedJwks(ttlMs = 10 * 60 * 1000, fetchImpl: typeof fetch = fetch): JwksFetcher {
  let cache: { at: number; keys: Jwk[] } | null = null;
  return async () => {
    if (cache && Date.now() - cache.at < ttlMs) return { keys: cache.keys };
    const res = await fetchImpl(JWKS_URL, { headers: { "User-Agent": "aswincloud-token-broker" } });
    if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
    const body = (await res.json()) as { keys?: Jwk[] };
    if (!Array.isArray(body.keys)) throw new Error("JWKS malformed");
    cache = { at: Date.now(), keys: body.keys };
    return { keys: body.keys };
  };
}
