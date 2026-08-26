"""Verify bounded, read-only image update candidate discovery."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from scripts.image_update_cli import _anonymous_docker_environment
from scripts.image_update_discovery import discover_image_updates
from scripts.image_update_registry import (
    DigestResolution,
    HttpResponse,
    RegistryRepository,
    RegistryTag,
    RegistryTagClient,
    TagListing,
)
from scripts.remediation_policy import load_policy
from scripts.vulnerability_scan import CommandResult


OLD_DIGEST = "sha256:" + "1" * 64
PATCH_DIGEST = "sha256:" + "2" * 64
MINOR_DIGEST = "sha256:" + "3" * 64
MAJOR_DIGEST = "sha256:" + "4" * 64
LATEST_DIGEST = "sha256:" + "5" * 64
SUCCESSOR_DIGEST = "sha256:" + "6" * 64


def source_report(reference: str = "docker.io/example/app:1.2.3") -> dict[str, object]:
    """Return minimal complete schema-v2 vulnerability evidence."""

    return {
        "schema_version": 2,
        "completed_at": "2026-08-17T10:00:00Z",
        "summary": {"complete": True},
        "scope": {"image_fingerprint": "scope-1"},
        "images": [
            {
                "reference": reference,
                "digest": OLD_DIGEST,
                "status": "vulnerable",
                "services": [
                    {"name": "demo_worker"},
                    {"name": "demo_api"},
                ],
            }
        ],
    }


class FakeTransport:
    """Return queued registry responses and retain outbound request evidence."""

    def __init__(self, responses: list[HttpResponse]) -> None:
        """Store deterministic responses in expected call order."""

        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, headers: dict[str, str]) -> HttpResponse:
        """Record one bounded request and return its queued response."""

        self.calls.append((url, dict(headers)))
        if not self.responses:
            raise AssertionError(f"unexpected registry request: {url}")
        return self.responses.pop(0)


class FakeListingClient:
    """Supply predetermined tag listings without performing network I/O."""

    def __init__(
        self,
        listings: dict[str, TagListing],
        resolutions: dict[tuple[str, str, str], DigestResolution] | None = None,
    ) -> None:
        """Store listings keyed by canonical repository."""

        self.listings = listings
        self.resolutions = resolutions or {}
        self.calls: list[tuple[str, int]] = []
        self.resolution_calls: list[tuple[str, str, str]] = []

    def list_tags(self, reference: str, max_tags: int) -> TagListing:
        """Return one exact listing and retain the requested bound."""

        self.calls.append((reference, max_tags))
        return self.listings[reference]

    def resolve_platform_digest(
        self,
        reference: str,
        tag: str,
        platform: str,
    ) -> DigestResolution:
        """Return one optional Registry V2 resolution fixture."""

        key = (reference, tag, platform)
        self.resolution_calls.append(key)
        return self.resolutions.get(key, DigestResolution("digest-unresolved"))


class MetadataClient:
    """Resolve selected registry tags to deterministic immutable digests."""

    def __init__(self, digests: dict[str, str]) -> None:
        """Store reference-to-digest mappings and command evidence."""

        self.digests = digests
        self.commands: list[list[str]] = []

    def run(self, arguments: list[str]) -> CommandResult:
        """Model Buildx metadata and reject unexpected fallback commands."""

        command = list(arguments)
        self.commands.append(command)
        if command[:3] != ["buildx", "imagetools", "inspect"]:
            return CommandResult(1, "", "unexpected command")
        reference = command[-1]
        digest = self.digests.get(reference)
        if digest is None:
            return CommandResult(1, "", "missing fixture")
        return CommandResult(
            0,
            json.dumps(
                {
                    "manifest": {"digest": digest},
                    "image": {
                        "created": "2026-07-01T00:00:00Z",
                        "config": {},
                    },
                }
            ),
            "",
        )


def listing(
    repository: str,
    *tags: RegistryTag,
    status: str = "ok",
    complete: bool = True,
    error: str = "",
) -> TagListing:
    """Build one concise registry listing fixture."""

    host, _, name = repository.partition("/")
    return TagListing(
        RegistryRepository(host, name),
        status,
        tags,
        complete,
        error,
    )


class RegistryTagClientTests(unittest.TestCase):
    """Keep registry discovery bounded and silent until explicitly approved."""

    def test_unapproved_registry_performs_no_network_request(self) -> None:
        """Treat repository names as metadata that needs an explicit egress gate."""

        transport = FakeTransport([])
        result = RegistryTagClient(set(), transport).list_tags("nginx:1.27", 100)

        self.assertEqual(result.status, "registry-approval-required")
        self.assertEqual(result.repository.canonical, "docker.io/library/nginx")
        self.assertEqual(transport.calls, [])

    def test_docker_metadata_environment_removes_registry_credentials(self) -> None:
        """Resolve public digests without consulting the operator's Docker auth."""

        original = {
            "PATH": "/usr/bin",
            "DOCKER_CONFIG": "/home/operator/.docker",
            "DOCKER_AUTH_CONFIG": '{"auths":{"registry.example":{}}}',
            "REGISTRY_AUTH_FILE": "/home/operator/auth.json",
        }

        isolated = _anonymous_docker_environment(Path("/tmp/empty-docker"), original)

        self.assertEqual(Path(isolated["DOCKER_CONFIG"]), Path("/tmp/empty-docker"))
        self.assertEqual(isolated["PATH"], "/usr/bin")
        self.assertNotIn("DOCKER_AUTH_CONFIG", isolated)
        self.assertNotIn("REGISTRY_AUTH_FILE", isolated)
        self.assertEqual(original["DOCKER_CONFIG"], "/home/operator/.docker")

    def test_docker_hub_tags_retain_publication_timestamp(self) -> None:
        """Use provider timestamp and digest evidence without downloading layers."""

        transport = FakeTransport(
            [
                HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "results": [
                                {
                                    "name": "1.27.4",
                                    "last_updated": "2026-08-01T12:00:00Z",
                                    "images": [
                                        {
                                            "os": "linux",
                                            "architecture": "amd64",
                                            "digest": PATCH_DIGEST,
                                        }
                                    ],
                                }
                            ],
                            "next": None,
                        }
                    ).encode(),
                )
            ]
        )

        result = RegistryTagClient({"docker.io"}, transport).list_tags(
            "nginx:1.27", 100
        )

        self.assertTrue(result.complete)
        self.assertEqual(result.tags[0].updated_at, "2026-08-01T12:00:00Z")
        self.assertEqual(
            result.tags[0].updated_at_source,
            "docker-hub-tag-last-updated",
        )
        self.assertEqual(
            result.tags[0].digest_for_platform("linux/amd64"),
            PATCH_DIGEST,
        )
        self.assertEqual(len(transport.calls), 1)

    def test_docker_hub_auth_failure_uses_public_registry_fallback(self) -> None:
        """Keep public official images discoverable without stored credentials."""

        transport = FakeTransport(
            [
                HttpResponse(401, {}, b""),
                HttpResponse(
                    401,
                    {
                        "www-authenticate": (
                            'Bearer realm="https://auth.docker.io/token",'
                            'service="registry.docker.io",'
                            'scope="repository:library/postgres:pull"'
                        )
                    },
                    b"",
                ),
                HttpResponse(200, {}, b'{"token":"public-token"}'),
                HttpResponse(
                    200,
                    {},
                    b'{"name":"library/postgres","tags":["16.4.0"]}',
                ),
            ]
        )

        result = RegistryTagClient({"docker.io"}, transport).list_tags(
            "postgres:16.3.0", 100
        )

        self.assertTrue(result.complete)
        self.assertEqual([tag.name for tag in result.tags], ["16.4.0"])
        self.assertTrue(
            transport.calls[1][0].startswith(
                "https://registry-1.docker.io/v2/library/postgres/tags/list"
            )
        )
        self.assertEqual(
            transport.calls[3][1]["Authorization"],
            "Bearer public-token",
        )

    def test_registry_manifest_resolves_exact_platform_digest(self) -> None:
        """Resolve a selected public tag directly without pulling image layers."""

        transport = FakeTransport(
            [
                HttpResponse(404, {}, b""),
                HttpResponse(
                    401,
                    {
                        "www-authenticate": (
                            'Bearer realm="https://auth.docker.io/token",'
                            'service="registry.docker.io",'
                            'scope="repository:library/postgres:pull"'
                        )
                    },
                    b"",
                ),
                HttpResponse(200, {}, b'{"token":"public-token"}'),
                HttpResponse(
                    200,
                    {"content-type": "application/vnd.oci.image.index.v1+json"},
                    json.dumps(
                        {
                            "manifests": [
                                {
                                    "digest": MAJOR_DIGEST,
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "arm64",
                                    },
                                },
                                {
                                    "digest": PATCH_DIGEST,
                                    "platform": {
                                        "os": "linux",
                                        "architecture": "amd64",
                                    },
                                },
                            ]
                        }
                    ).encode(),
                ),
            ]
        )

        result = RegistryTagClient({"docker.io"}, transport).resolve_platform_digest(
            "postgres:16.4.0",
            "16.4.0",
            "linux/amd64",
        )

        self.assertEqual(result, DigestResolution("ok", PATCH_DIGEST))
        self.assertIn(
            "application/vnd.oci.image.index.v1+json",
            transport.calls[1][1]["Accept"],
        )
        self.assertEqual(
            transport.calls[3][1]["Authorization"],
            "Bearer public-token",
        )

    def test_docker_hub_tag_detail_is_cached_by_platform(self) -> None:
        """Resolve repeated candidates through one public provider metadata call."""

        transport = FakeTransport(
            [
                HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "images": [
                                {
                                    "os": "linux",
                                    "architecture": "amd64",
                                    "digest": PATCH_DIGEST,
                                }
                            ]
                        }
                    ).encode(),
                )
            ]
        )
        client = RegistryTagClient({"docker.io"}, transport)

        first = client.resolve_platform_digest(
            "postgres:16.4.0",
            "16.4.0",
            "linux/amd64",
        )
        second = client.resolve_platform_digest(
            "docker.io/library/postgres",
            "16.4.0",
            "linux/amd64",
        )

        self.assertEqual(first, DigestResolution("ok", PATCH_DIGEST))
        self.assertEqual(second, first)
        self.assertEqual(len(transport.calls), 1)
        self.assertIn(
            "/v2/namespaces/library/repositories/postgres/tags/16.4.0",
            transport.calls[0][0],
        )

    def test_external_auth_realm_requires_explicit_host_approval(self) -> None:
        """Keep a registry token host network-silent until separately approved."""

        challenge = {
            "www-authenticate": (
                'Bearer realm="https://auth.linuxserver.io/token",'
                'service="lscr.io",scope="repository:linuxserver/duplicati:pull"'
            )
        }
        blocked_transport = FakeTransport([HttpResponse(401, challenge, b"")])

        blocked = RegistryTagClient({"lscr.io"}, blocked_transport).list_tags(
            "lscr.io/linuxserver/duplicati:latest",
            100,
        )

        self.assertEqual(blocked.status, "auth-host-approval-required")
        self.assertEqual(blocked.error, "auth.linuxserver.io")
        self.assertEqual(len(blocked_transport.calls), 1)

        approved_transport = FakeTransport(
            [
                HttpResponse(401, challenge, b""),
                HttpResponse(200, {}, b'{"token":"public-token"}'),
                HttpResponse(
                    200,
                    {},
                    b'{"name":"linuxserver/duplicati","tags":["latest"]}',
                ),
            ]
        )
        approved = RegistryTagClient(
            {"lscr.io", "auth.linuxserver.io"},
            approved_transport,
        ).list_tags("lscr.io/linuxserver/duplicati:latest", 100)

        self.assertTrue(approved.complete)
        self.assertEqual([tag.name for tag in approved.tags], ["latest"])

    def test_provider_overrun_is_incomplete_at_configured_tag_limit(self) -> None:
        """Fail closed if a provider returns more tags than the requested page."""

        transport = FakeTransport(
            [
                HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "results": [
                                {"name": "1.0.0"},
                                {"name": "1.1.0"},
                            ],
                            "next": None,
                        }
                    ).encode(),
                )
            ]
        )

        result = RegistryTagClient({"docker.io"}, transport).list_tags(
            "nginx:1.0.0", 1
        )

        self.assertEqual(result.status, "tag-limit-exceeded")
        self.assertFalse(result.complete)

    def test_distribution_registry_uses_anonymous_bearer_challenge(self) -> None:
        """Obtain a public pull token without reading local Docker credentials."""

        transport = FakeTransport(
            [
                HttpResponse(
                    401,
                    {
                        "www-authenticate": (
                            'Bearer realm="https://ghcr.io/token",'
                            'service="ghcr.io",scope="repository:team/app:pull"'
                        )
                    },
                    b"",
                ),
                HttpResponse(200, {}, b'{"token":"public-token"}'),
                HttpResponse(
                    200,
                    {},
                    b'{"name":"team/app","tags":["1.0.0","1.1.0"]}',
                ),
            ]
        )

        result = RegistryTagClient({"ghcr.io"}, transport).list_tags(
            "ghcr.io/team/app:1.0.0", 100
        )

        self.assertTrue(result.complete)
        self.assertEqual([tag.name for tag in result.tags], ["1.0.0", "1.1.0"])
        self.assertNotIn("Authorization", transport.calls[0][1])
        self.assertNotIn("Authorization", transport.calls[1][1])
        self.assertEqual(
            transport.calls[2][1]["Authorization"],
            "Bearer public-token",
        )


class ImageUpdateDiscoveryTests(unittest.TestCase):
    """Select immutable update tracks without making security claims."""

    def test_container_source_retains_exact_compose_ownership_and_selectors(
        self,
    ) -> None:
        """Project only bounded standalone ownership fields into discovery."""

        report = source_report()
        report["scope"]["resource_type"] = "container"
        report["images"][0]["local_image_id"] = OLD_DIGEST
        report["images"][0]["services"] = [
            {
                "name": "demo_api_1",
                "stack": "demo",
                "compose_service": "api",
                "compose_working_dir": "/srv/demo",
                "compose_config_files": [
                    "/srv/demo/compose.yml",
                    "/srv/demo/compose.override.yml",
                ],
                "environment": {"TOKEN": "must-not-copy"},
            }
        ]
        repository = "docker.io/example/app"

        outcome = discover_image_updates(
            report,
            Path("security_scan-running.json"),
            MetadataClient({}),
            FakeListingClient(
                {
                    repository: listing(
                        repository,
                        status="registry-approval-required",
                        complete=False,
                    )
                }
            ),
            "linux/amd64",
            2000,
        )

        current = outcome.report["images"][0]["current"]
        self.assertEqual(current["resource_type"], "container")
        self.assertEqual(current["local_image_id"], OLD_DIGEST)
        self.assertEqual(
            current["resources"],
            [
                {
                    "type": "container",
                    "name": "demo_api_1",
                    "selectors": {
                        "container": "demo_api_1",
                        "image_id": OLD_DIGEST,
                        "compose_project": "demo",
                        "compose_service": "demo/api",
                    },
                    "ownership": {
                        "compose_project": "demo",
                        "compose_service": "api",
                        "working_directory": "/srv/demo",
                        "config_files": [
                            "/srv/demo/compose.yml",
                            "/srv/demo/compose.override.yml",
                        ],
                        "complete": True,
                    },
                }
            ],
        )
        self.assertNotIn("environment", json.dumps(current))

    def test_no_registry_approval_returns_actionable_incomplete_report(self) -> None:
        """List required hosts without invoking Docker metadata resolution."""

        repository = "docker.io/example/app"
        listings = FakeListingClient(
            {
                repository: listing(
                    repository,
                    status="registry-approval-required",
                    complete=False,
                )
            }
        )
        docker = MetadataClient({})

        outcome = discover_image_updates(
            source_report(),
            Path("vulnerability_scan.json"),
            docker,
            listings,
            "linux/amd64",
            2000,
        )

        self.assertEqual(outcome.exit_code, 3)
        self.assertEqual(outcome.report["required_registry_hosts"], ["docker.io"])
        self.assertFalse(outcome.report["complete"])
        self.assertEqual(
            outcome.report["policy"]["docker_metadata_config"],
            "caller-provided",
        )
        self.assertIsNone(outcome.report["policy"]["registry_credentials_used"])
        self.assertEqual(docker.commands, [])

    def test_external_auth_host_is_reported_as_required_approval(self) -> None:
        """Turn a safe token-realm refusal into a copyable approval host."""

        repository = "lscr.io/linuxserver/duplicati"
        outcome = discover_image_updates(
            source_report("lscr.io/linuxserver/duplicati:latest"),
            Path("vulnerability_scan.json"),
            MetadataClient({}),
            FakeListingClient(
                {
                    repository: listing(
                        repository,
                        status="auth-host-approval-required",
                        complete=False,
                        error="auth.linuxserver.io",
                    )
                }
            ),
            "linux/amd64",
            10000,
        )
        self.assertEqual(outcome.exit_code, 3)
        self.assertEqual(
            outcome.report["required_registry_hosts"],
            ["auth.linuxserver.io"],
        )

    def test_short_display_digest_is_not_claimed_as_immutable_identity(self) -> None:
        """Discard legacy digest prefixes while retaining the source reference."""

        report = source_report("docker.io/example/app:latest@sha256:1234")
        report["images"][0]["digest"] = "sha256:1234"
        repository = "docker.io/example/app"

        outcome = discover_image_updates(
            report,
            Path("vulnerability_scan.json"),
            MetadataClient({}),
            FakeListingClient(
                {
                    repository: listing(
                        repository,
                        status="registry-approval-required",
                        complete=False,
                    )
                }
            ),
            "linux/amd64",
            2000,
        )

        self.assertIsNone(outcome.report["images"][0]["current"]["digest"])

    def test_semver_tracks_ignore_prereleases_and_resolve_exact_digests(self) -> None:
        """Offer patch, minor, and major tracks with honest compatibility labels."""

        repository = "docker.io/example/app"
        tags = (
            RegistryTag("1.2.3", "2026-01-01T00:00:00Z", "registry"),
            RegistryTag("1.2.4", "2026-02-01T00:00:00Z", "registry"),
            RegistryTag("1.3.0"),
            RegistryTag("2.0.0"),
            RegistryTag("2.1.0-rc.1"),
        )
        docker = MetadataClient(
            {
                f"{repository}:1.2.3@{OLD_DIGEST}": OLD_DIGEST,
                f"{repository}:1.2.4": PATCH_DIGEST,
                f"{repository}:1.3.0": MINOR_DIGEST,
                f"{repository}:2.0.0": MAJOR_DIGEST,
            }
        )

        outcome = discover_image_updates(
            source_report(),
            Path("vulnerability_scan.json"),
            docker,
            FakeListingClient({repository: listing(repository, *tags)}),
            "linux/amd64",
            2000,
            now=dt.datetime(2026, 8, 17, tzinfo=dt.timezone.utc),
        )

        candidates = outcome.report["images"][0]["candidates"]
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(len(candidates), 3)
        self.assertEqual(
            {candidate["compatibility"] for candidate in candidates},
            {"same-minor", "same-major", "major-change"},
        )
        self.assertFalse(any("rc" in candidate["tag"] for candidate in candidates))
        self.assertTrue(
            all(candidate["security_comparison"] == "not-scanned" for candidate in candidates)
        )
        self.assertTrue(
            all(candidate["deployment_authorized"] is False for candidate in candidates)
        )
        self.assertEqual(candidates[0]["lifecycle"]["source"], "registry")

    def test_alias_tracks_are_deduplicated_by_artifact_digest(self) -> None:
        """Represent several tags for one artifact as one deployable identity."""

        repository = "docker.io/example/app"
        tags = (RegistryTag("1.2.4"), RegistryTag("1.3.0"), RegistryTag("2.0.0"))
        docker = MetadataClient(
            {
                f"{repository}:1.2.3@{OLD_DIGEST}": OLD_DIGEST,
                f"{repository}:1.2.4": MAJOR_DIGEST,
                f"{repository}:1.3.0": MAJOR_DIGEST,
                f"{repository}:2.0.0": MAJOR_DIGEST,
            }
        )

        outcome = discover_image_updates(
            source_report(),
            Path("vulnerability_scan.json"),
            docker,
            FakeListingClient({repository: listing(repository, *tags)}),
            "linux/amd64",
            2000,
        )

        candidates = outcome.report["images"][0]["candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["digest"], MAJOR_DIGEST)
        self.assertEqual(candidates[0]["tags"], ["1.2.4", "1.3.0", "2.0.0"])
        self.assertEqual(
            candidates[0]["tracks"],
            ["newest-stable", "same-major", "same-minor"],
        )

    def test_provider_platform_digest_avoids_docker_resolution_failure(self) -> None:
        """Retain a candidate when Docker Hub already supplied exact identity."""

        repository = "docker.io/example/app"
        tags = (
            RegistryTag("1.2.3", "2026-01-01T00:00:00Z", "registry"),
            RegistryTag(
                "1.2.4",
                "2026-02-01T00:00:00Z",
                "registry",
                platform_digests=(("linux/amd64", PATCH_DIGEST),),
            ),
        )
        docker = MetadataClient(
            {f"{repository}:1.2.3@{OLD_DIGEST}": OLD_DIGEST}
        )

        outcome = discover_image_updates(
            source_report(),
            Path("vulnerability_scan.json"),
            docker,
            FakeListingClient({repository: listing(repository, *tags)}),
            "linux/amd64",
            2000,
        )

        candidates = outcome.report["images"][0]["candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["digest"], PATCH_DIGEST)
        self.assertFalse(outcome.report["errors"])
        self.assertFalse(docker.commands)

    def test_repeated_rate_limit_is_resolved_and_reported_once(self) -> None:
        """Avoid multiplying one candidate failure across current image records."""

        repository = "docker.io/example/app"
        report = source_report()
        repeated = dict(report["images"][0])
        repeated["digest"] = "sha256:" + "7" * 64
        repeated["services"] = [{"name": "demo_scheduler"}]
        report["images"].append(repeated)
        resolver = FakeListingClient(
            {
                repository: listing(
                    repository,
                    RegistryTag("1.2.3", "2026-01-01T00:00:00Z", "registry"),
                    RegistryTag("1.2.4", "2026-02-01T00:00:00Z", "registry"),
                )
            },
            {
                (repository, "1.2.4", "linux/amd64"): DigestResolution(
                    "rate-limited"
                )
            },
        )

        outcome = discover_image_updates(
            report,
            Path("vulnerability_scan.json"),
            MetadataClient({}),
            resolver,
            "linux/amd64",
            10000,
        )

        self.assertEqual(outcome.exit_code, 3)
        self.assertEqual(outcome.report["summary"]["error_count"], 1)
        self.assertEqual(
            outcome.report["errors"][0]["status"],
            "digest-rate-limited",
        )
        self.assertEqual(
            resolver.resolution_calls,
            [(repository, "1.2.4", "linux/amd64")],
        )

    def test_registry_manifest_fallback_avoids_docker_resolution_failure(self) -> None:
        """Use direct public manifest evidence when Docker metadata is unavailable."""

        repository = "docker.io/example/app"
        resolver = FakeListingClient(
            {
                repository: listing(
                    repository,
                    RegistryTag("1.2.3"),
                    RegistryTag("1.2.4"),
                )
            },
            {
                (repository, "1.2.4", "linux/amd64"): DigestResolution(
                    "ok",
                    PATCH_DIGEST,
                )
            },
        )

        outcome = discover_image_updates(
            source_report(),
            Path("vulnerability_scan.json"),
            MetadataClient({f"{repository}:1.2.3@{OLD_DIGEST}": OLD_DIGEST}),
            resolver,
            "linux/amd64",
            10000,
        )

        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.report["images"][0]["candidates"][0]["digest"], PATCH_DIGEST)
        self.assertEqual(
            resolver.resolution_calls,
            [(repository, "1.2.4", "linux/amd64")],
        )

    def test_reviewed_successor_is_informational_and_never_authorizing(self) -> None:
        """Discover a replacement repository while preserving the trust boundary."""

        repository = "docker.io/example/app"
        successor = "ghcr.io/example/app-next"
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": 3,
                        "image_update_discovery": {
                            "successors": [
                                {
                                    "id": "example-successor",
                                    "repository": repository,
                                    "successor_repository": successor,
                                    "reason": "Maintainer replacement reviewed by operator.",
                                    "evidence_url": "https://example.com/migration",
                                }
                            ]
                        },
                        "targets": [],
                    }
                ),
                encoding="utf-8",
            )
            policy = load_policy(policy_path)
            docker = MetadataClient(
                {
                    f"{repository}:1.2.3@{OLD_DIGEST}": OLD_DIGEST,
                    f"{successor}:2.55.1": SUCCESSOR_DIGEST,
                    f"{successor}:latest": LATEST_DIGEST,
                }
            )
            outcome = discover_image_updates(
                source_report(),
                Path("vulnerability_scan.json"),
                docker,
                FakeListingClient(
                    {
                        repository: listing(repository, RegistryTag("1.2.3")),
                        successor: listing(
                            successor,
                            RegistryTag("2.55.1"),
                            RegistryTag("latest"),
                        ),
                    }
                ),
                "linux/amd64",
                2000,
                policy=policy,
            )

        candidates = outcome.report["images"][0]["candidates"]
        self.assertEqual(len(candidates), 2)
        self.assertTrue(
            all(candidate["source"] == "policy-successor" for candidate in candidates)
        )
        self.assertTrue(
            all(candidate["deployment_authorized"] is False for candidate in candidates)
        )
        self.assertTrue(all(candidate["successor_evidence"] for candidate in candidates))


if __name__ == "__main__":
    unittest.main()
