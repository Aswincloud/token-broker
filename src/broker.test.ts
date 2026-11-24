import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, ORG, ORG_ID, type Claims, type Rule } from "./policy.ts";
import { ISSUER, verifyGithubOidc, type Jwk } from "./oidc.ts";
import { appJwt, importPkcs8 } from "./github.ts";

const AUD = "https://token-broker.aswincloud.com";
const now = Math.floor(Date.now() / 1000);

const b64url = (b: Uint8Array) =>
  Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));

// A local RSA key stands in for GitHub's OIDC signing key.
const kp = (await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
)) as CryptoKeyPair;
const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as Jwk;
const jwks = async () => ({ keys: [{ ...pub, kid: "k1" }] });

async function sign(payload: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "k1" }, key = kp.privateKey) {
  const unsigned = `${enc(header)}.${enc(payload)}`;
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned)));
  return `${unsigned}.${b64url(sig)}`;
}

const goodClaims = (over: Record<string, unknown> = {}) => ({
  iss: ISSUER,
  aud: AUD,
  iat: now - 10,
  nbf: now - 10,
  exp: now + 300,
  repository: `${ORG}/.github`,
  repository_owner: ORG,
  repository_owner_id: ORG_ID,
  job_workflow_ref: `${ORG}/.github/.github/workflows/update-readme.yml@refs/heads/main`,
  event_name: "schedule",
  ref: "refs/heads/main",
  ...over,
});

// ---------------- OIDC verification ----------------

test("accepts a correctly signed token", async () => {
  const c = await verifyGithubOidc(await sign(goodClaims()), AUD, jwks, now);
  assert.equal(c.repository, `${ORG}/.github`);
});

test("rejects a token signed by a different key (forged)", async () => {
  const other = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"],
  )) as CryptoKeyPair;
  await assert.rejects(verifyGithubOidc(await sign(goodClaims(), undefined, other.privateKey), AUD, jwks, now), /bad signature/);
});

test("rejects tampered payload", async () => {
  const t = await sign(goodClaims());
  const [h, , s] = t.split(".");
  const tampered = `${h}.${enc(goodClaims({ repository: `${ORG}/other` }))}.${s}`;
  await assert.rejects(verifyGithubOidc(tampered, AUD, jwks, now), /bad signature/);
});

test("rejects alg=none and HS256", async () => {
  await assert.rejects(verifyGithubOidc(await sign(goodClaims(), { alg: "none", kid: "k1" }), AUD, jwks, now), /unexpected alg/);
  await assert.rejects(verifyGithubOidc(await sign(goodClaims(), { alg: "HS256", kid: "k1" }), AUD, jwks, now), /unexpected alg/);
});

test("rejects unknown kid", async () => {
  await assert.rejects(verifyGithubOidc(await sign(goodClaims(), { alg: "RS256", kid: "nope" }), AUD, jwks, now), /unknown signing key/);
});

test("rejects wrong issuer / audience", async () => {
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ iss: "https://evil.example" })), AUD, jwks, now), /wrong issuer/);
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ aud: "sts.amazonaws.com" })), AUD, jwks, now), /wrong audience/);
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ aud: [AUD, "x"] })), AUD, jwks, now), /wrong audience/);
});

test("rejects expired, not-yet-valid, future-issued and over-long tokens", async () => {
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ exp: now - 120 })), AUD, jwks, now), /expired/);
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ nbf: now + 600 })), AUD, jwks, now), /not yet valid/);
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ iat: now + 600 })), AUD, jwks, now), /future/);
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ iat: now - 10, exp: now + 7200 })), AUD, jwks, now), /lifetime too long/);
});

test("rejects tokens missing policy claims", async () => {
  await assert.rejects(verifyGithubOidc(await sign(goodClaims({ job_workflow_ref: undefined })), AUD, jwks, now), /missing claim job_workflow_ref/);
});

// ---------------- Policy ----------------

const claims = (over: Partial<Claims> = {}): Claims => ({
  repository: `${ORG}/.github`,
  repository_owner: ORG,
  repository_owner_id: ORG_ID,
  job_workflow_ref: `${ORG}/.github/.github/workflows/update-readme.yml@refs/heads/main`,
  event_name: "schedule",
  ref: "refs/heads/main",
  ...over,
});
const ask = { repositories: [".github"], permissions: { contents: "write" as const } };

test("allows the update-readme workflow exactly what its rule grants", () => {
  const d = decide(claims(), ask);
  assert.equal(d.ok, true);
});

test("allows asking for less (read instead of write)", () => {
  assert.equal(decide(claims(), { repositories: [".github"], permissions: { contents: "read" } }).ok, true);
});

test("refuses other orgs and a same-named org with a different id", () => {
  assert.equal(decide(claims({ repository_owner: "Evil", repository: "Evil/.github" }), ask).ok, false);
  assert.equal(decide(claims({ repository_owner_id: "1" }), ask).ok, false);
});

test("refuses the same workflow file on another branch (job_workflow_ref differs)", () => {
  const d = decide(claims({ job_workflow_ref: `${ORG}/.github/.github/workflows/update-readme.yml@refs/heads/evil` }), ask);
  assert.deepEqual(d, { ok: false, reason: "no rule for this workflow" });
});

test("refuses a different workflow file in the same repo", () => {
  assert.equal(decide(claims({ job_workflow_ref: `${ORG}/.github/.github/workflows/steal.yml@refs/heads/main` }), ask).ok, false);
});

test("refuses pull_request events even for a listed workflow", () => {
  const d = decide(claims({ event_name: "pull_request_target" }), ask);
  assert.equal(d.ok, false);
});

test("refuses extra repositories, extra permissions and escalation", () => {
  assert.equal(decide(claims(), { repositories: [".github", "3d_printing"], permissions: { contents: "write" } }).ok, false);
  assert.equal(decide(claims(), { repositories: [".github"], permissions: { contents: "write", administration: "write" } }).ok, false);
  assert.equal(decide(claims(), { repositories: [".github"], permissions: { metadata: "write" } }).ok, false);
});

test("refuses inherited property names as permissions", () => {
  for (const name of ["constructor", "toString", "hasOwnProperty", "__proto__"]) {
    const req = JSON.parse(`{"repositories":[".github"],"permissions":{"${name}":"write"}}`);
    assert.equal(decide(claims(), req).ok, false, name);
  }
});

test("refuses empty or malformed requests", () => {
  assert.equal(decide(claims(), { repositories: [], permissions: { contents: "read" } }).ok, false);
  assert.equal(decide(claims(), { repositories: [".github"], permissions: {} }).ok, false);
  assert.equal(decide(claims(), { repositories: [".github"], permissions: { contents: "admin" as never } }).ok, false);
  assert.equal(decide(claims(), {} as never).ok, false);
});

test("custom rules are matched exactly", () => {
  const rules: Rule[] = [{ name: "x", repository: `${ORG}/a`, jobWorkflowRef: `${ORG}/a/.github/workflows/w.yml@refs/heads/main`, events: ["push"], repositories: ["a"], permissions: { issues: "write" } }];
  const c = claims({ repository: `${ORG}/a`, job_workflow_ref: `${ORG}/a/.github/workflows/w.yml@refs/heads/main`, event_name: "push" });
  assert.equal(decide(c, { repositories: ["a"], permissions: { issues: "write" } }, rules).ok, true);
  assert.equal(decide(c, ask, rules).ok, false);
});

// ---------------- App JWT ----------------

test("signs a verifiable GitHub App JWT from a PKCS#8 key", async () => {
  const app = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", app.privateKey)) as ArrayBuffer);
  const pem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  const jwt = await appJwt("1597322", await importPkcs8(pem), now);
  const [h, p, s] = jwt.split(".");
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", app.publicKey, Buffer.from(s!, "base64url"), new TextEncoder().encode(`${h}.${p}`));
  assert.equal(ok, true);
  const payload = JSON.parse(Buffer.from(p!, "base64url").toString());
  assert.equal(payload.iss, "1597322");
  assert.ok(payload.exp - payload.iat <= 600);
});

test("rejects a PKCS#1 key with a clear message", async () => {
  await assert.rejects(importPkcs8("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"), /PKCS#8/);
});
