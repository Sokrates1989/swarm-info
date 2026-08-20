"""Read bounded public image-tag metadata from explicitly approved registries.

Repository names can themselves be sensitive. The adapter is therefore
network-silent unless the operator explicitly approves the canonical registry
host. It performs anonymous metadata requests only and never reads Docker
credential files or invokes credential helpers.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import socket
from typing import Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from scripts.remediation_policy import image_repository


MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_PAGE_SIZE = 100
AUTH_PARAMETER_PATTERN = re.compile(
    r"([A-Za-z][A-Za-z0-9_-]*)=(?:\"([^\"]*)\"|([^,\s]+))"
)
NEXT_LINK_PATTERN = re.compile(r"<([^>]+)>\s*;\s*rel=\"?next\"?", re.IGNORECASE)
FULL_SHA256_PATTERN = re.compile(r"sha256:[0-9a-fA-F]{64}")
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    """One bounded HTTP response returned by the injectable transport."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    """Minimal transport contract used by deterministic registry tests."""

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        """Fetch one URL without accepting request-body data."""


class UrllibTransport:
    """Perform bounded HTTPS GET requests through Python's standard library."""

    def __init__(self, timeout_seconds: float = 15.0) -> None:
        """Store the per-request timeout used for registry metadata calls."""

        self.timeout_seconds = timeout_seconds

    def get(self, url: str, headers: Mapping[str, str]) -> HttpResponse:
        """Return success and HTTP-error responses while translating I/O errors."""

        request = Request(url, headers=dict(headers), method="GET")
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return HttpResponse(
                    int(response.status),
                    {key.lower(): value for key, value in response.headers.items()},
                    _bounded_read(response),
                )
        except HTTPError as error:
            return HttpResponse(
                int(error.code),
                {key.lower(): value for key, value in error.headers.items()},
                _bounded_read(error),
            )
        except (OSError, TimeoutError, URLError, socket.timeout) as error:
            raise RegistryRequestError("network-error", str(error)) from error


class RegistryRequestError(RuntimeError):
    """Describe one sanitized registry discovery failure with a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a bounded diagnostic that never contains response bodies."""

        super().__init__(code)
        self.code = code
        self.detail = " ".join(str(detail).split())[:300]


@dataclasses.dataclass(frozen=True)
class RegistryRepository:
    """Canonical registry host and repository path without tag or digest."""

    registry: str
    name: str

    @property
    def canonical(self) -> str:
        """Return the normalized repository identity used in reports."""

        return f"{self.registry}/{self.name}"


@dataclasses.dataclass(frozen=True)
class RegistryTag:
    """One tag and optional provider-supplied publication timestamp."""

    name: str
    updated_at: str | None = None
    updated_at_source: str = "unknown"
    platform_digests: tuple[tuple[str, str], ...] = ()

    def digest_for_platform(self, platform: str) -> str | None:
        """Return the provider-supplied immutable digest for one platform."""

        return next(
            (digest for candidate, digest in self.platform_digests if candidate == platform),
            None,
        )


@dataclasses.dataclass(frozen=True)
class TagListing:
    """Bounded tag enumeration result for one image repository."""

    repository: RegistryRepository
    status: str
    tags: tuple[RegistryTag, ...] = ()
    complete: bool = False
    error: str = ""


@dataclasses.dataclass(frozen=True)
class DigestResolution:
    """One platform-specific immutable manifest resolution result."""

    status: str
    digest: str | None = None
    error: str = ""


def _bounded_read(response: object) -> bytes:
    """Read at most the configured response limit and reject oversized data."""

    body = response.read(MAX_RESPONSE_BYTES + 1)  # type: ignore[attr-defined]
    if len(body) > MAX_RESPONSE_BYTES:
        raise RegistryRequestError("response-too-large")
    return body


def parse_repository(reference: str) -> RegistryRepository:
    """Normalize one Docker image reference into registry and repository parts."""

    canonical = image_repository(reference)
    registry, separator, name = canonical.partition("/")
    if not separator or not registry or not name:
        raise RegistryRequestError("invalid-repository", reference)
    return RegistryRepository(registry, name)


def _json_object(response: HttpResponse) -> Mapping[str, object]:
    """Decode one response body as a JSON object without echoing invalid data."""

    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RegistryRequestError("invalid-response") from error
    if not isinstance(payload, Mapping):
        raise RegistryRequestError("invalid-response")
    return payload


def _docker_hub_platform_digests(
    item: Mapping[str, object],
) -> tuple[tuple[str, str], ...]:
    """Extract validated platform-to-digest evidence from one Docker Hub tag."""

    images = item.get("images")
    if not isinstance(images, list):
        return ()
    digests: dict[str, str] = {}
    for image in images:
        if not isinstance(image, Mapping):
            continue
        operating_system = image.get("os")
        architecture = image.get("architecture")
        variant = image.get("variant")
        digest = image.get("digest")
        if (
            not isinstance(operating_system, str)
            or not isinstance(architecture, str)
            or not isinstance(digest, str)
            or not FULL_SHA256_PATTERN.fullmatch(digest)
        ):
            continue
        platform = f"{operating_system}/{architecture}"
        if isinstance(variant, str) and variant:
            platform = f"{platform}/{variant}"
        digests.setdefault(platform, digest.lower())
    return tuple(sorted(digests.items()))


def _platform_matches(candidate: Mapping[str, object], platform: str) -> bool:
    """Return whether registry platform evidence matches the requested target."""

    requested = platform.split("/")
    if len(requested) not in {2, 3}:
        return False
    if candidate.get("os") != requested[0]:
        return False
    if candidate.get("architecture") != requested[1]:
        return False
    return len(requested) == 2 or candidate.get("variant") == requested[2]


def _platform_descriptor_digest(
    manifest: Mapping[str, object],
    platform: str,
) -> str | None:
    """Select a validated child-manifest digest from a multi-platform index."""

    descriptors = manifest.get("manifests")
    if not isinstance(descriptors, list):
        return None
    for descriptor in descriptors:
        if not isinstance(descriptor, Mapping):
            continue
        candidate_platform = descriptor.get("platform")
        digest = descriptor.get("digest")
        if (
            isinstance(candidate_platform, Mapping)
            and _platform_matches(candidate_platform, platform)
            and isinstance(digest, str)
            and FULL_SHA256_PATTERN.fullmatch(digest)
        ):
            return digest.lower()
    return None


def _response_error(response: HttpResponse) -> RegistryRequestError:
    """Translate HTTP status codes into stable operator-facing reason codes."""

    if response.status in {401, 403}:
        return RegistryRequestError("authentication-required")
    if response.status == 404:
        return RegistryRequestError("repository-not-found")
    if response.status == 429:
        return RegistryRequestError("rate-limited")
    return RegistryRequestError("http-error", str(response.status))


def _auth_parameters(challenge: str) -> dict[str, str]:
    """Parse a Bearer challenge without accepting arbitrary authentication data."""

    scheme, separator, values = challenge.partition(" ")
    if not separator or scheme.lower() != "bearer":
        raise RegistryRequestError("authentication-required")
    return {
        match.group(1).lower(): match.group(2) or match.group(3) or ""
        for match in AUTH_PARAMETER_PATTERN.finditer(values)
    }


def _token_realm_host(realm: str) -> str:
    """Return one safe HTTPS token host or an empty invalid marker."""

    parsed = urlparse(realm)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        return ""
    return parsed.netloc.lower()


def _token_url(
    repository: RegistryRepository,
    challenge: str,
    allowed_hosts: set[str],
) -> str:
    """Build the anonymous pull-token request from a validated challenge."""

    parameters = _auth_parameters(challenge)
    realm = parameters.pop("realm", "")
    realm_host = _token_realm_host(realm)
    built_in_hosts = {repository.registry}
    if repository.registry == "docker.io":
        built_in_hosts.update({"registry-1.docker.io", "auth.docker.io"})
    if not realm_host:
        raise RegistryRequestError("unsupported-auth-realm")
    if realm_host not in built_in_hosts and realm_host not in allowed_hosts:
        raise RegistryRequestError("auth-host-approval-required", realm_host)
    parsed = urlparse(realm)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update(parameters)
    query.setdefault("scope", f"repository:{repository.name}:pull")
    return urlunparse(parsed._replace(query=urlencode(query)))


class RegistryTagClient:
    """List public tags with bounded pagination and explicit host approval."""

    def __init__(
        self,
        allowed_registries: set[str],
        transport: HttpTransport | None = None,
    ) -> None:
        """Store canonical approved hosts and an optional deterministic transport."""

        self.allowed_registries = {value.lower() for value in allowed_registries}
        self.transport = transport or UrllibTransport()
        self._tokens: dict[str, str] = {}
        self._digest_resolutions: dict[
            tuple[str, str, str], DigestResolution
        ] = {}

    def list_tags(self, reference: str, max_tags: int) -> TagListing:
        """Enumerate one approved repository or return a network-silent state."""

        repository = parse_repository(reference)
        if not 1 <= max_tags <= 10000:
            raise ValueError("max_tags must be between 1 and 10000")
        if repository.registry not in self.allowed_registries:
            return TagListing(repository, "registry-approval-required")
        try:
            if repository.registry == "docker.io":
                return self._list_docker_hub(repository, max_tags)
            return self._list_distribution(repository, max_tags)
        except RegistryRequestError as error:
            return TagListing(repository, error.code, error=error.detail)

    def _request_registry(
        self,
        repository: RegistryRepository,
        url: str,
        accept: str = "application/json",
    ) -> HttpResponse:
        """Fetch one Registry API page, obtaining only an anonymous token."""

        headers = {"Accept": accept, "User-Agent": "swarm-info"}
        token = self._tokens.get(repository.canonical)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = self.transport.get(url, headers)
        if response.status != 401 or token:
            return response
        challenge = response.headers.get("www-authenticate", "")
        token_response = self.transport.get(
            _token_url(repository, challenge, self.allowed_registries),
            {"Accept": "application/json", "User-Agent": "swarm-info"},
        )
        if token_response.status != 200:
            raise _response_error(token_response)
        token_payload = _json_object(token_response)
        candidate = token_payload.get("token") or token_payload.get("access_token")
        if not isinstance(candidate, str) or not candidate or len(candidate) > 16384:
            raise RegistryRequestError("invalid-token-response")
        self._tokens[repository.canonical] = candidate
        headers["Authorization"] = f"Bearer {candidate}"
        return self.transport.get(url, headers)

    def resolve_platform_digest(
        self,
        reference: str,
        tag: str,
        platform: str,
    ) -> DigestResolution:
        """Resolve one selected tag once without pulling image layers."""

        repository = parse_repository(reference)
        cache_key = (repository.canonical, tag, platform)
        cached = self._digest_resolutions.get(cache_key)
        if cached is not None:
            return cached
        resolution = self._resolve_platform_digest_uncached(
            repository,
            tag,
            platform,
        )
        self._digest_resolutions[cache_key] = resolution
        return resolution

    def _resolve_platform_digest_uncached(
        self,
        repository: RegistryRepository,
        tag: str,
        platform: str,
    ) -> DigestResolution:
        """Resolve provider metadata first, then use the OCI registry fallback."""

        if repository.registry not in self.allowed_registries:
            return DigestResolution(
                "registry-approval-required",
                error=repository.registry,
            )
        if repository.registry == "docker.io":
            try:
                provider_resolution = self._resolve_docker_hub_tag_detail(
                    repository,
                    tag,
                    platform,
                )
            except RegistryRequestError as error:
                return DigestResolution(error.code, error=error.detail)
            if provider_resolution is not None:
                return provider_resolution
        api_host = (
            "registry-1.docker.io"
            if repository.registry == "docker.io"
            else repository.registry
        )
        manifest_url = (
            f"https://{api_host}/v2/{quote(repository.name, safe='/')}/"
            f"manifests/{quote(tag, safe='')}"
        )
        try:
            response = self._request_registry(
                repository,
                manifest_url,
                MANIFEST_ACCEPT,
            )
            if response.status != 200:
                raise _response_error(response)
            payload = _json_object(response)
            descriptor_digest = _platform_descriptor_digest(payload, platform)
            if descriptor_digest is not None:
                return DigestResolution("ok", descriptor_digest)
            if isinstance(payload.get("manifests"), list):
                return DigestResolution("platform-not-found")
            return self._single_manifest_digest(
                repository,
                api_host,
                payload,
                response,
                platform,
            )
        except RegistryRequestError as error:
            return DigestResolution(error.code, error=error.detail)

    def _resolve_docker_hub_tag_detail(
        self,
        repository: RegistryRepository,
        tag: str,
        platform: str,
    ) -> DigestResolution | None:
        """Use Docker Hub tag details when they contain exact platform identity."""

        namespace, separator, name = repository.name.partition("/")
        if not separator or not namespace or not name:
            return None
        url = (
            "https://hub.docker.com/v2/namespaces/"
            f"{quote(namespace, safe='')}/repositories/"
            f"{quote(name, safe='')}/tags/{quote(tag, safe='')}"
        )
        response = self.transport.get(
            url,
            {"Accept": "application/json", "User-Agent": "swarm-info"},
        )
        if response.status in {401, 403, 404}:
            return None
        if response.status != 200:
            raise _response_error(response)
        payload = _json_object(response)
        platform_digests = _docker_hub_platform_digests(payload)
        if not platform_digests:
            return None
        digest = next(
            (
                candidate_digest
                for candidate_platform, candidate_digest in platform_digests
                if candidate_platform == platform
            ),
            None,
        )
        return (
            DigestResolution("ok", digest)
            if digest is not None
            else DigestResolution("platform-not-found")
        )

    def _single_manifest_digest(
        self,
        repository: RegistryRepository,
        api_host: str,
        manifest: Mapping[str, object],
        response: HttpResponse,
        platform: str,
    ) -> DigestResolution:
        """Verify a single-image manifest platform through its small config blob."""

        config = manifest.get("config")
        config_digest = config.get("digest") if isinstance(config, Mapping) else None
        if not isinstance(config_digest, str) or not FULL_SHA256_PATTERN.fullmatch(
            config_digest
        ):
            return DigestResolution("manifest-config-missing")
        config_url = (
            f"https://{api_host}/v2/{quote(repository.name, safe='/')}/"
            f"blobs/{config_digest.lower()}"
        )
        config_response = self._request_registry(repository, config_url)
        if config_response.status != 200:
            raise _response_error(config_response)
        config_payload = _json_object(config_response)
        if not _platform_matches(config_payload, platform):
            return DigestResolution("platform-not-found")
        calculated = "sha256:" + hashlib.sha256(response.body).hexdigest()
        header_digest = response.headers.get("docker-content-digest", "").lower()
        if header_digest and (
            not FULL_SHA256_PATTERN.fullmatch(header_digest)
            or header_digest != calculated
        ):
            return DigestResolution("manifest-digest-mismatch")
        return DigestResolution("ok", calculated)

    def _list_distribution(
        self,
        repository: RegistryRepository,
        max_tags: int,
        api_host: str | None = None,
    ) -> TagListing:
        """Follow standard Registry V2 tag pagination on one HTTPS origin."""

        host = api_host or repository.registry
        page_size = min(DEFAULT_PAGE_SIZE, max_tags)
        url = (
            f"https://{host}/v2/{quote(repository.name, safe='/')}/tags/list?"
            f"{urlencode({'n': page_size})}"
        )
        tags: dict[str, RegistryTag] = {}
        while url:
            response = self._request_registry(repository, url)
            if response.status != 200:
                raise _response_error(response)
            payload = _json_object(response)
            raw_tags = payload.get("tags") or []
            if not isinstance(raw_tags, list):
                raise RegistryRequestError("invalid-response")
            page_truncated = False
            for index, value in enumerate(raw_tags):
                if isinstance(value, str) and value and len(value) <= 128:
                    tags.setdefault(value, RegistryTag(value))
                    if len(tags) >= max_tags:
                        page_truncated = index < len(raw_tags) - 1
                        break
            next_url = self._next_url(url, response.headers.get("link", ""), host)
            if len(tags) >= max_tags and (next_url or page_truncated):
                return TagListing(
                    repository,
                    "tag-limit-exceeded",
                    tuple(sorted(tags.values(), key=lambda item: item.name)),
                    False,
                )
            url = next_url
        return TagListing(
            repository,
            "ok",
            tuple(sorted(tags.values(), key=lambda item: item.name)),
            True,
        )

    def _list_docker_hub(
        self, repository: RegistryRepository, max_tags: int
    ) -> TagListing:
        """Read Docker Hub's public tag pages including last-updated evidence."""

        page_size = min(DEFAULT_PAGE_SIZE, max_tags)
        url = (
            "https://hub.docker.com/v2/repositories/"
            f"{quote(repository.name, safe='/')}/tags?"
            f"{urlencode({'page_size': page_size})}"
        )
        tags: dict[str, RegistryTag] = {}
        while url:
            response = self.transport.get(
                url,
                {"Accept": "application/json", "User-Agent": "swarm-info"},
            )
            if response.status != 200:
                if response.status in {401, 403}:
                    return self._list_distribution(
                        repository,
                        max_tags,
                        api_host="registry-1.docker.io",
                    )
                raise _response_error(response)
            payload = _json_object(response)
            results = payload.get("results")
            if not isinstance(results, list):
                raise RegistryRequestError("invalid-response")
            page_truncated = False
            for index, item in enumerate(results):
                if not isinstance(item, Mapping):
                    continue
                name = item.get("name")
                if not isinstance(name, str) or not name or len(name) > 128:
                    continue
                updated_at = item.get("last_updated")
                tags.setdefault(
                    name,
                    RegistryTag(
                        name,
                        updated_at if isinstance(updated_at, str) else None,
                        (
                            "docker-hub-tag-last-updated"
                            if isinstance(updated_at, str)
                            else "unknown"
                        ),
                        _docker_hub_platform_digests(item),
                    ),
                )
                if len(tags) >= max_tags:
                    page_truncated = index < len(results) - 1
                    break
            next_value = payload.get("next")
            next_url = next_value if isinstance(next_value, str) else ""
            if next_url and not self._same_https_host(next_url, "hub.docker.com"):
                raise RegistryRequestError("unsafe-pagination-url")
            if len(tags) >= max_tags and (next_url or page_truncated):
                return TagListing(
                    repository,
                    "tag-limit-exceeded",
                    tuple(sorted(tags.values(), key=lambda item: item.name)),
                    False,
                )
            url = next_url
        return TagListing(
            repository,
            "ok",
            tuple(sorted(tags.values(), key=lambda item: item.name)),
            True,
        )

    @staticmethod
    def _same_https_host(url: str, host: str) -> bool:
        """Return whether a pagination URL stays on its expected HTTPS host."""

        parsed = urlparse(url)
        return (
            parsed.scheme == "https"
            and parsed.username is None
            and parsed.password is None
            and parsed.netloc.lower() == host.lower()
        )

    def _next_url(self, current: str, link: str, host: str) -> str:
        """Resolve a standard next-page link without permitting origin changes."""

        if not link:
            return ""
        match = NEXT_LINK_PATTERN.search(link)
        if not match:
            raise RegistryRequestError("invalid-pagination-link")
        candidate = urljoin(current, match.group(1))
        if not self._same_https_host(candidate, host):
            raise RegistryRequestError("unsafe-pagination-url")
        return candidate
