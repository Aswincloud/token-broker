// Signs a GitHub App JWT with the private key and exchanges it for a
// repository- and permission-scoped installation token (valid 1 hour).
//
// The private key arrives as PKCS#8 PEM ("BEGIN PRIVATE KEY"). GitHub hands
// out PKCS#1 ("BEGIN RSA PRIVATE KEY"); convert once before storing it:
//   openssl pkcs8 -topk8 -nocrypt -in app.pem -out app-pkcs8.pem

import type { Access } from "./policy.ts";

const API = "https://api.github.com";
const UA = "aswincloud-token-broker";

const b64url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlJson = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));

export async function importPkcs8(pem: string): Promise<CryptoKey> {
  if (pem.includes("BEGIN RSA PRIVATE KEY")) {
    throw new Error("APP_PRIVATE_KEY must be PKCS#8 (BEGIN PRIVATE KEY); convert with openssl pkcs8 -topk8 -nocrypt");
  }
  const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
}

export async function appJwt(appId: string, key: CryptoKey, now = Math.floor(Date.now() / 1000)): Promise<string> {
  // iat backdated 60 s for clock drift; GitHub caps exp at 10 minutes.
  const unsigned = `${b64urlJson({ alg: "RS256", typ: "JWT" })}.${b64urlJson({ iat: now - 60, exp: now + 540, iss: appId })}`;
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned)));
  return `${unsigned}.${b64url(sig)}`;
}

export interface MintedToken {
  token: string;
  expires_at: string;
  permissions: Record<string, string>;
  repositories: string[];
}

export async function mintInstallationToken(
  jwt: string,
  installationId: string,
  repositories: string[],
  permissions: Record<string, Access>,
  fetchImpl: typeof fetch = fetch,
): Promise<MintedToken> {
  const res = await fetchImpl(`${API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": UA,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ repositories, permissions }),
  });
  if (!res.ok) {
    // Never echo GitHub's body to the caller verbatim; log a short form.
    throw new Error(`GitHub token mint failed: ${res.status}`);
  }
  const b = (await res.json()) as {
    token: string;
    expires_at: string;
    permissions: Record<string, string>;
    repositories?: { name: string }[];
  };
  return {
    token: b.token,
    expires_at: b.expires_at,
    permissions: b.permissions,
    repositories: (b.repositories ?? []).map((r) => r.name),
  };
}
