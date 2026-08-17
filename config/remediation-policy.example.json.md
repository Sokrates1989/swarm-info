# Vulnerability remediation policy

`swarm-info` no longer requires a pre-existing policy to enter automatic
remediation. Without one, it runs conservative built-in rules and creates a
host-owned policy automatically:

- If the current directory is a Git deployment repository with an existing
  `configs/` directory, it uses `configs/remediation-policy.json` there.
- Otherwise it uses
  `${XDG_CONFIG_HOME:-$HOME/.config}/swarm-info/remediation-policy.json`.
- `--remediation-policy <PATH>` or `SWARM_INFO_REMEDIATION_POLICY` selects an
  explicit installation-owned path, including a not-yet-created file.

The built-in executor can change a service only when all of these facts are
proven: the deployed image has an exact rollback digest, the verified source
already follows mutable `latest`, the registry's `latest` digest moved, the
candidate scan improves critical/high findings without adding a new finding,
and image metadata proves the same visible major version. It then shows the
exact service update and rollback and asks default-No questions for both
backup/compatibility readiness and execution. It never edits source files or
refreshes unrelated images in the stack.

You may still copy `remediation-policy.example.json` into the Git repository
that owns the installation's Swarm stack files and pass that tracked file to
`swarm-info --remediation-policy <PATH>`. Never add registry credentials,
Docker secrets, passwords, or tokens to this policy.

## Read-only image successor evidence

Schema 3 adds an optional `image_update_discovery.successors` list for images
whose maintained replacement lives in a different repository. This list is
used only by `swarm-info --discover-image-updates`; it cannot authorize an
edit, deployment, backup exemption, or automatic remediation. Each mapping
needs an HTTPS evidence URL and an operator-written reason:

```json
{
  "schema_version": 3,
  "image_update_discovery": {
    "successors": [
      {
        "id": "reviewed-browser-successor",
        "repository": "docker.io/browserless/chrome",
        "successor_repository": "ghcr.io/browserless/chromium",
        "reason": "The vendor documents this repository as the maintained replacement.",
        "evidence_url": "https://github.com/browserless/browserless"
      }
    ]
  },
  "targets": []
}
```

Keep this evidence installation-owned. The discovery command remains
network-silent for both repositories until their registry hosts are explicitly
allowed on that invocation.

## Generated review queue

Schemas 2 and 3 permit a machine-owned `generated_review` section. Every safe-run
assessment replaces that section while preserving `targets`. It records:

- every vulnerable service not covered by an active target;
- validated `latest` candidates and candidates that were rejected or could
  not be discovered;
- deployment mapping evidence and stable blocked-reason codes;
- the latest declined, failed, rolled-back, or successful attempt outcome;
- an inert `suggested_target` template; and
- localized `_guidance` explaining every authority-bearing field.

`generated_review` is evidence only. The parser never treats it as authority.
To override built-in behavior, copy a reviewed `suggested_target` into the
top-level `targets` array, replace every missing value, document backup
handling, and explicitly enable the entry. The generated section is overwritten
on the next assessment, so do not keep operator decisions there.

Common generated reason codes:

- `policy-target-missing`: no persisted override grants authority for the
  service; this alone does not mean the service can be updated safely.
- `backup-classification-required`: persistent-data impact has not been
  reviewed. A force attempt cannot bypass this gate.
- `current-image-mutable`: the live report lacks a full digest, so exact
  rollback content is not proven.
- `candidate-not-discovered`: the deployed image uses a fixed tag and the tool
  refuses to guess a newer application version.
- `latest-current` / `latest-unresolved`: `latest` has not
  moved or its current registry digest cannot be proven.
- A candidate validation code such as `candidate-new-findings`,
  `candidate-not-improved`, or `candidate-scan-failed`: a discovered candidate
  failed the shared risk/no-new-findings validator.
- `same-major-version-not-proven`: image metadata cannot prove that the
  candidate stays within the visible major release.
- `deployment-source-unresolved` / `deployment-source-unverified`: the mapper
  cannot authorize a declarative relationship.
- `source-does-not-follow-latest`: the built-in no-edit refresh is not
  applicable; a reviewed source adapter is needed.
- `one-run-backup-confirmation-required` and
  `one-run-update-confirmation-required`: all built-in technical gates passed,
  but both human confirmations are still required before execution.

An execution failure updates `last_attempt` with a stable engine reason and a
bounded, single-line diagnostic detail. The latest attempt survives later
review refreshes. Reasons include `candidate-scan-failed`, `live-image-changed`,
`service-convergence-timeout`, or a rollback-aware verification failure. Use
that evidence to improve a
generally safe built-in rule only when the condition is portable. Keep
installation-specific assumptions as disabled policy overrides until they are
reviewed locally.

Auto-remediation is denied unless an enabled target names one exact live
service, its current repository, an immutable candidate image, and a documented
backup exemption. The current service image must also contain an immutable
digest so rollback can restore the exact artifact. A declaratively mapped
service additionally needs a source adapter.

```json
{
  "schema_version": 3,
  "image_update_discovery": {
    "successors": []
  },
  "targets": [
    {
      "id": "example-web-0-2-2",
      "enabled": true,
      "match": {
        "service": "example_web",
        "repository": "sokrates1989/example-web"
      },
      "candidate_image": "sokrates1989/example-web:0.2.2@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "backup": {
        "status": "not_required",
        "reason": "Stateless web frontend; persistent data is not changed."
      },
      "auto_eligible": false,
      "source": {
        "type": "dotenv",
        "file": ".env",
        "name_key": "WEB_IMAGE_NAME",
        "version_key": "WEB_IMAGE_VERSION"
      },
      "verification": {
        "timeout_seconds": 300
      }
    }
  ]
}
```

Set `auto_eligible` to `true` only after reviewing the mapping, candidate, edit
adapter, backup classification, and dry-run plan. `--force-auto-remedy-attempt`
can bypass only `auto_eligible`; it cannot bypass any other safeguard.

For a digest-pinned candidate whose tag is `latest`, a mapped and verified
source that already declares unpinned `latest` becomes a `latest-refresh`
action and does not need a source adapter. All other mapped source changes
still require an exact adapter.

Create one target per distinct deployment source and image update. When several
services use the same image variable in one stack, select one representative
service; that stack deployment updates the shared source once, and the final
all-image scan verifies every consumer. Use separate targets when consumers are
owned by different stacks or source keys.

Supported source adapters:

- `dotenv` with `image_key`: replaces one exact key with the full immutable
  image reference.
- `dotenv` with `name_key` and `version_key`: replaces the repository and tag;
  the candidate digest is still enforced during validation and deployment.
- `yaml_image`: replaces one simple scalar `image:` value under the exact
  mapped Compose service. YAML anchors, expressions, and ambiguous layouts are
  rejected.

For an unresolved deployment path, the plan can only offer a guarded runtime
override. Such an override is configuration drift, is disabled by default, and
requires both `--allow-runtime-override` and a separate interactive approval.
