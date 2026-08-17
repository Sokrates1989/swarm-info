"""Read bounded public image-tag metadata from explicitly approved registries.

Repository names can themselves be sensitive. The adapter is therefore
network-silent unless the operator explicitly approves the canonical registry
host. It performs anonymous metadata requests only and never reads Docker
credential files or invokes credential helpers.
"""

from __future__ import annotations

import dataclasses
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


def _allowed_token_realm(registry: str, realm: str) -> bool:
    """Permit anonymous tokens only from the registry or Docker Hub auth host."""

    parsed = urlparse(realm)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return False
    registry_hosts = {registry}
    if registry == "docker.io":
        registry_hosts.update({"registry-1.docker.io", "auth.docker.io"})
    return parsed.netloc.lower() in registry_hosts


def _token_url(repository: RegistryRepository, challenge: str) -> str:
    """Build the anonymous pull-token request from a validated challenge."""

    parameters = _auth_parameters(challenge)
    realm = parameters.pop("realm", "")
    if not realm or not _allowed_token_realm(repository.registry, realm):
        raise RegistryRequestError("unsupported-auth-realm")
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
        self, repository: RegistryRepository, url: str
    ) -> HttpResponse:
        """Fetch one Registry API page, obtaining only an anonymous token."""

        headers = {"Accept": "application/json", "User-Agent": "swarm-info"}
        token = self._tokens.get(repository.canonical)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = self.transport.get(url, headers)
        if response.status != 401 or token:
            return response
        challenge = response.headers.get("www-authenticate", "")
        token_response = self.transport.get(
            _token_url(repository, challenge),
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
