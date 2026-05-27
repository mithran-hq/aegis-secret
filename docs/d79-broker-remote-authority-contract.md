# D79 Broker Remote Authority Contract

This contract defines how Aegis Broker reintroduces remote authenticated
authority for protected D79 workers without placing reusable write credentials
in the worker lane.

Protected workers must not receive raw GitHub, cloud, deploy, package, or
source-control write credentials. Broker is the authority lane. Aegis Secret is
the credential storage and materialization boundary. In MAP 1.0 they may be
packaged together, but the evidence and control boundary remains separate.

## Contract Shape

Every brokered remote mutation is one of:

- a typed semantic action with an explicit action id and input schema;
- an approved CLI profile that constrains an existing third-party tool launch.

Arbitrary shell passthrough with raw credentials is forbidden. Unsupported
remote mutations in protected mode fail closed until a typed action or approved
CLI profile exists.

Policy changes are data or config reloads. New mutation kinds require new
typed-action or CLI-profile support; Broker must not generate dynamic source
code or synthesize arbitrary privileged shells from policy data.

## Typed Actions

Typed actions are for product-critical, method-sensitive operations where the
API shape is stable.

Required fields:

| Field | Requirement |
| --- | --- |
| `schema_version` | `aegis.broker.remote_authority_action.v1` |
| `action_id` | Stable id such as `github.issue.close` or `github.pr.comment`. |
| `input_schema_ref` | Versioned schema for the typed action payload. |
| `grant_class` | D79 grant class from Mithran Auth, such as `github_issue_pr_mutation`. |
| `credential_class` | Matching credential class, such as `github_app_installation_token`. |
| `policy_ref` | Policy id and hash used to authorize the action. |
| `bruno_gate_ref` | Bruno guard schema or `none` when not required. |
| `approval_requirement` | `none`, `biometric`, `human_confirm`, or `biometric_and_human_confirm`. |
| `auth_lease_ref` | Short-lived Auth lease ref used for credential materialization. |
| `execution_mode` | `broker_api_call` or `broker_job`. |
| `cleanup` | Credential drop/revoke and temp-file cleanup requirements. |

Example action ids:

- `github.issue.close`
- `github.issue.comment`
- `github.pr.comment`
- `github.pr.merge`
- `git.branch.push`
- `release.publish`

Typed actions execute in Broker or a Broker-launched approved job identity, not
in the protected worker process tree.

## CLI Profiles

CLI profiles are for existing tools where native reimplementation would create
an unsafe compatibility burden.

Required fields:

| Field | Requirement |
| --- | --- |
| `schema_version` | `aegis.broker.cli_profile.v1` |
| `profile_id` | Stable id such as `terraform.apply.gcp` or `npm.publish`. |
| `tool` | Resolved command name, for example `terraform`, `gcloud`, `aws`, `kubectl`, `npm`. |
| `argv_template` | Fixed argv shape with named parameters; no arbitrary shell fragments. |
| `argv_template_digest` | Hash of the reviewed argv template. |
| `allowed_cwd` | Project or job workspace constraints. |
| `grant_class` | Auth grant class required by the profile. |
| `credential_class` | Auth credential class materialized for the profile. |
| `credential_mount` | Env vars or temp files allowed for the child process. |
| `network_policy_ref` | Egress constraints for the launched tool. |
| `approval_requirement` | Approval required before execution. |
| `timeout_seconds` | Maximum run time. |
| `output_redaction` | Redaction policy for stdout, stderr, logs, and artifacts. |
| `cleanup` | Credential/temp-file cleanup and process reap requirements. |

Initial profile families:

- `terraform` for `apply`, `destroy`, `import`, `state`, and `force-unlock`;
- `gcloud`, `aws`, and `az` mutating resource commands;
- `kubectl` mutating cluster commands;
- package managers for npm, PyPI, RubyGems, crates.io, and container publish
  paths;
- deployment CLIs that change routes, releases, or production resources.

Read-only commands such as `terraform plan`, `gh issue list`, `git status`, and
inspection commands do not require Broker unless policy explicitly protects
them.

## Execution Flow

1. Protected worker requests a typed action or approved CLI profile.
2. Broker resolves the action/profile by id and validates the payload against
   the versioned schema.
3. Broker loads policy by id and policy hash.
4. Broker invokes Bruno when the action/profile requires a method gate.
5. Broker obtains required local approval.
6. Broker redeems a short-lived Mithran Auth lease for the exact grant class,
   credential class, project, repo, or resource scope.
7. Broker materializes credential values only inside Broker memory or an
   approved Broker job.
8. Broker performs the API call or constrained CLI launch.
9. Broker redacts output, writes evidence, drops credentials, deletes temporary
   files, and reaps child processes.

## Deny And Error Behavior

Protected mode must deny direct worker remote writes with stable reason
categories:

| Reason | Meaning |
| --- | --- |
| `broker_action_unsupported` | No typed action exists for the mutation. |
| `broker_cli_profile_unsupported` | No approved CLI profile exists for the tool/argv. |
| `broker_policy_missing` | Required policy id or hash is unavailable. |
| `broker_policy_denied` | Policy blocks the request. |
| `broker_bruno_denied` | Bruno denied a method-sensitive action. |
| `broker_approval_required` | Required local approval was not granted. |
| `broker_auth_lease_denied` | Auth refused or could not mint the lease. |
| `broker_credential_materialization_failed` | Aegis Secret could not materialize scoped credentials. |
| `broker_cleanup_failed` | Cleanup or reap evidence is incomplete. |

Errors returned to the worker must be redaction-safe and must not include raw
credential values, bearer strings, private key material, provider config files,
or unredacted host paths.

## Evidence

Every brokered attempt emits `aegis.broker.remote_authority_evidence.v1`.

Required fields:

- `evidence_id`
- `action_id` or `profile_id`
- `caller` with agent, session ref, and requester ref
- `project_ref`
- `repo_ref` when repository scoped
- `resource_scope_ref`
- `grant_class`
- `credential_class`
- `auth_lease_ref`
- `policy_ref` and `policy_hash`
- `bruno_decision_ref` or `none`
- `approval_ref` or `none`
- `execution_mode`
- `command_digest` for CLI profiles
- `argv_template` for CLI profiles with parameter values redacted
- `started_at` and `completed_at`
- `result`: `allowed`, `denied`, `failed`, or `cleanup_failed`
- `cleanup_status`
- `redaction_state`
- `raw_credential_material_printed=false`

Evidence may include output digests and artifact refs. It must not include raw
credential values, private key material, access tokens, cookies, refresh
tokens, package tokens, cloud credential files, or full unredacted host paths.

## Boundary With Aegis Secret

Aegis Secret stores and unlocks credential material. Broker decides whether a
remote-authority action or profile may run, redeems the Auth lease, scopes the
credential materialization, launches the trusted action/profile, and records
evidence.

The compatibility package may expose both `aegis-secret` and `aegis-broker`
names from the same binary, but public contracts should call the authority lane
Broker and the storage lane Aegis Secret.
