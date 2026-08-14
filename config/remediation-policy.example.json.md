# Vulnerability remediation policy

Copy `remediation-policy.example.json` into the Git repository that owns the
installation's Swarm stack files. Pass that tracked installation-specific file
to `swarm-info --remediation-policy <PATH>`. Never add registry credentials,
Docker secrets, passwords, or tokens to this policy.

Auto-remediation is denied unless an enabled target names one exact live
service, its current repository, an immutable candidate image, and a documented
backup exemption. The current service image must also contain an immutable
digest so rollback can restore the exact artifact. A declaratively mapped
service additionally needs a source adapter.

```json
{
  "schema_version": 1,
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
