// The allowlist: which GitHub Actions workflow may get which App token.
//
// This is the security boundary. A request is honoured only when the caller's
// verified OIDC claims match a rule exactly AND the requested repositories and
// permissions are a subset of what that rule grants. Anything else is refused.
//
// Match on `job_workflow_ref`, not `workflow` or `ref`: it names the workflow
// FILE and the ref it ran from, and GitHub signs it. A workflow file added on a
// branch, or a fork, cannot produce a matching value.

export type Access = "read" | "write";

export interface Rule {
  /** Human label for logs. */
  name: string;
  /** Exact `repository` claim, e.g. "Aswincloud/.github". */
  repository: string;
  /**
   * Exact `job_workflow_ref` claim:
   * "<owner>/<repo>/.github/workflows/<file>@refs/heads/main".
   */
  jobWorkflowRef: string;
  /** Allowed `event_name` claims. Keep `pull_request*` out of write rules. */
  events: string[];
  /** Repositories (names inside the org) the token may be scoped to. */
  repositories: string[];
  /** Maximum permissions. A request may ask for less, never more. */
  permissions: Record<string, Access>;
}

export const ORG = "Aswincloud";
/** Numeric org id: pinned so a renamed/recreated org of the same name can't match. */
export const ORG_ID = "219316445";

const wf = (repo: string, file: string) =>
  `${ORG}/${repo}/.github/workflows/${file}@refs/heads/main`;

export const RULES: Rule[] = [
  {
    name: "update-readme",
    repository: `${ORG}/.github`,
    jobWorkflowRef: wf(".github", "update-readme.yml"),
    events: ["schedule", "workflow_dispatch"],
    repositories: [".github"],
    permissions: { contents: "write", metadata: "read" },
  },
];

const RANK: Record<Access, number> = { read: 1, write: 2 };

export interface Claims {
  repository: string;
  repository_owner: string;
  repository_owner_id: string;
  job_workflow_ref: string;
  event_name: string;
  ref: string;
}

export interface Request {
  repositories: string[];
  permissions: Record<string, Access>;
}

export type Decision =
  | { ok: true; rule: Rule; repositories: string[]; permissions: Record<string, Access> }
  | { ok: false; reason: string };

export function decide(claims: Claims, req: Request, rules: Rule[] = RULES): Decision {
  if (claims.repository_owner !== ORG || claims.repository_owner_id !== ORG_ID) {
    return { ok: false, reason: "caller is not in the organization" };
  }
  const rule = rules.find(
    (r) => r.repository === claims.repository && r.jobWorkflowRef === claims.job_workflow_ref,
  );
  if (!rule) return { ok: false, reason: "no rule for this workflow" };
  if (!rule.events.includes(claims.event_name)) {
    return { ok: false, reason: `event ${claims.event_name} is not allowed for ${rule.name}` };
  }

  if (!Array.isArray(req.repositories) || req.repositories.length === 0) {
    return { ok: false, reason: "request must name at least one repository" };
  }
  for (const repo of req.repositories) {
    if (typeof repo !== "string" || !rule.repositories.includes(repo)) {
      return { ok: false, reason: `repository ${String(repo)} is not allowed for ${rule.name}` };
    }
  }

  const perms = req.permissions;
  if (!perms || typeof perms !== "object" || Array.isArray(perms) || Object.keys(perms).length === 0) {
    return { ok: false, reason: "request must name at least one permission" };
  }
  for (const [perm, level] of Object.entries(perms)) {
    const max = rule.permissions[perm];
    if (!max) return { ok: false, reason: `permission ${perm} is not allowed for ${rule.name}` };
    if (level !== "read" && level !== "write") {
      return { ok: false, reason: `permission ${perm} has invalid level ${String(level)}` };
    }
    if (RANK[level] > RANK[max]) {
      return { ok: false, reason: `permission ${perm}:${level} exceeds ${max} for ${rule.name}` };
    }
  }

  return { ok: true, rule, repositories: [...req.repositories], permissions: { ...perms } };
}
