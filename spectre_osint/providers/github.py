"""GitHub REST API. Token optional (higher rate limit). Never prints secrets."""

from __future__ import annotations

import re

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Entity, Finding, Relationship
from spectre_osint.core.evidence import make_evidence
from spectre_osint.core.exceptions import ProviderUnavailable
from spectre_osint.core.redaction import mask_secret
from spectre_osint.core.types import (
    Confidence,
    EntityType,
    FindingStatus,
    ProviderKeyType,
    RelationType,
)
from spectre_osint.providers.base import Provider, ProviderResult

_SECRET_HINTS = re.compile(
    r"(api[_-]?key|secret|token|password|BEGIN (RSA |OPENSSH )?PRIVATE KEY)",
    re.IGNORECASE,
)


class GitHubProvider(Provider):
    name = "github"
    supported_entities = frozenset(
        {
            EntityType.USERNAME,
            EntityType.EMAIL,
            EntityType.DOMAIN,
            EntityType.COMPANY,
            EntityType.ORGANIZATION,
            EntityType.PERSON,
        }
    )
    requires_api_key = False
    key_type = ProviderKeyType.OPTIONAL_API_KEY
    optional_secret = "github_token"
    health_url = "https://api.github.com/zen"
    rate_limit = "0.5s / GitHub quota"

    def is_configured(self, settings: Settings) -> bool:
        return True

    def _headers(self, settings: Settings) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if settings.secret_present("github_token") and settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token.get_secret_value()}"
        return headers

    async def search(self, entity: Entity, settings: Settings) -> ProviderResult:
        if entity.type in {EntityType.USERNAME, EntityType.PERSON}:
            return await self._user(entity, settings)
        if entity.type in {EntityType.COMPANY, EntityType.ORGANIZATION}:
            return await self._org(entity, settings)
        if entity.type == EntityType.EMAIL:
            return await self._email(entity, settings)
        return await self._domain(entity, settings)

    async def _user(self, entity: Entity, settings: Settings) -> ProviderResult:
        login = entity.normalized_value
        response = await self.http.get(
            f"https://api.github.com/users/{login}",
            provider=self.name,
            headers=self._headers(settings),
            follow_redirects=True,
            cache_ttl=settings.cache_default_ttl,
            accept_statuses={200, 404},
        )
        if response.status_code == 404:
            return _not_found(entity, f"GitHub user {login}")
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"GitHub HTTP {response.status_code}")
        data = response.json_data
        evidence = make_evidence(
            source="GitHub API",
            provider=self.name,
            confidence=Confidence.HIGH,
            url=data.get("html_url"),
            raw={
                "login": data.get("login"),
                "name": data.get("name"),
                "company": data.get("company"),
                "blog": data.get("blog"),
                "public_repos": data.get("public_repos"),
            },
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="GitHub user",
            status=FindingStatus.FOUND,
            summary=f"public profile {data.get('login')} repos={data.get('public_repos')}",
            data={
                "login": data.get("login"),
                "name": data.get("name"),
                "company": data.get("company"),
                "blog": data.get("blog"),
                "bio": data.get("bio"),
                "location": data.get("location"),
                "public_repos": data.get("public_repos"),
                "html_url": data.get("html_url"),
                "type": data.get("type"),
                "created_at": data.get("created_at"),
            },
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        extras: list[Entity] = []
        rels: list[Relationship] = []
        from spectre_osint.modules.username.correlate import link_public_website

        linked = link_public_website(
            entity,
            data.get("blog"),
            source="GitHub",
            evidence_id=evidence.id,
            confidence=Confidence.HIGH,
        )
        extras.extend(linked["entities"])
        rels.extend(linked["relationships"])
        if data.get("html_url"):
            profile = Entity.create(
                EntityType.SOCIAL_PROFILE,
                data["html_url"],
                source="GitHub",
                confidence=Confidence.HIGH,
                tags=["github"],
            )
            extras.append(profile)
            rels.append(
                Relationship(
                    from_entity_id=entity.id,
                    to_entity_id=profile.id,
                    relation=RelationType.HAS_PROFILE,
                    source="GitHub",
                    confidence=Confidence.HIGH,
                    evidence_id=evidence.id,
                )
            )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            entities=extras,
            relationships=rels,
            evidence=[evidence],
            payload=finding.data,
        )

    async def _org(self, entity: Entity, settings: Settings) -> ProviderResult:
        slug = entity.normalized_value.replace(" ", "-")
        response = await self.http.get(
            f"https://api.github.com/orgs/{slug}",
            provider=self.name,
            headers=self._headers(settings),
            follow_redirects=True,
            accept_statuses={200, 404},
        )
        if response.status_code == 404:
            return _not_found(entity, f"GitHub org {slug}")
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"GitHub HTTP {response.status_code}")
        data = response.json_data
        evidence = make_evidence(
            source="GitHub API",
            provider=self.name,
            confidence=Confidence.HIGH,
            url=data.get("html_url"),
            raw={"login": data.get("login"), "blog": data.get("blog")},
            entity_id=entity.id,
        )
        finding = Finding(
            module=self.name,
            title="GitHub organization",
            status=FindingStatus.FOUND,
            summary=f"org {data.get('login')} repos={data.get('public_repos')}",
            data={
                "login": data.get("login"),
                "name": data.get("name"),
                "blog": data.get("blog"),
                "html_url": data.get("html_url"),
                "public_repos": data.get("public_repos"),
                "created_at": data.get("created_at"),
            },
            confidence=Confidence.HIGH,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.FOUND,
            findings=[finding],
            evidence=[evidence],
            payload=finding.data,
        )

    async def _email(self, entity: Entity, settings: Settings) -> ProviderResult:
        # Public commit search is allowed by the API; never scrape private mail.
        q = entity.normalized_value
        response = await self.http.get(
            "https://api.github.com/search/users",
            provider=self.name,
            headers=self._headers(settings),
            params={"q": f"{q} in:email"},
            follow_redirects=True,
            accept_statuses={200, 401, 403, 422},
        )
        if response.status_code in {401, 403, 422}:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.PROVIDER_UNAVAILABLE,
                findings=[
                    Finding(
                        module=self.name,
                        title="GitHub email search",
                        status=FindingStatus.PROVIDER_UNAVAILABLE,
                        summary="PROVIDER UNAVAILABLE: GitHub search requires a token or was rejected",
                        entity_id=entity.id,
                    )
                ],
            )
        if response.status_code >= 400 or not response.json_data:
            raise ProviderUnavailable(f"GitHub HTTP {response.status_code}")
        items = response.json_data.get("items") or []
        if not items:
            return _not_found(entity, "GitHub email search")
        evidence = make_evidence(
            source="GitHub Search API",
            provider=self.name,
            confidence=Confidence.MEDIUM,
            url="https://api.github.com/search/users",
            raw={"total": response.json_data.get("total_count"), "logins": [i.get("login") for i in items[:10]]},
            entity_id=entity.id,
            notes="possible_match only — public search hits are not identity confirmation",
        )
        finding = Finding(
            module=self.name,
            title="GitHub email search",
            status=FindingStatus.INFERENCE,
            summary=f"INFERENCE: {len(items)} possible public user hits (not identity confirmation)",
            data={
                "possible_matches": [
                    {"login": i.get("login"), "html_url": i.get("html_url"), "confidence": "MEDIUM"}
                    for i in items[:10]
                ]
            },
            confidence=Confidence.MEDIUM,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=FindingStatus.INFERENCE,
            findings=[finding],
            evidence=[evidence],
        )

    async def _domain(self, entity: Entity, settings: Settings) -> ProviderResult:
        response = await self.http.get(
            "https://api.github.com/search/code",
            provider=self.name,
            headers=self._headers(settings),
            params={"q": entity.normalized_value},
            follow_redirects=True,
            accept_statuses={200, 401, 403, 422},
        )
        if response.status_code in {401, 403, 422}:
            return ProviderResult(
                provider=self.name,
                status=FindingStatus.NOT_CONFIGURED
                if not settings.secret_present("github_token")
                else FindingStatus.PROVIDER_UNAVAILABLE,
                findings=[
                    Finding(
                        module=self.name,
                        title="GitHub code search",
                        status=FindingStatus.NOT_CONFIGURED
                        if not settings.secret_present("github_token")
                        else FindingStatus.PROVIDER_UNAVAILABLE,
                        summary="Provider not configured"
                        if not settings.secret_present("github_token")
                        else "PROVIDER UNAVAILABLE",
                        entity_id=entity.id,
                    )
                ],
            )
        items = (response.json_data or {}).get("items") or []
        secret_hits = []
        public_refs = []
        for item in items[:20]:
            path = item.get("path") or ""
            repo = (item.get("repository") or {}).get("full_name")
            public_refs.append({"repo": repo, "path": path, "html_url": item.get("html_url")})
            if _SECRET_HINTS.search(path):
                secret_hits.append(
                    {
                        "file": path,
                        "type": "path_hint",
                        "redacted_preview": mask_secret(path, keep=6),
                        "note": "Potential secret detected — token/value not retrieved",
                    }
                )
        finding = Finding(
            module=self.name,
            title="GitHub public references",
            status=FindingStatus.FOUND if items else FindingStatus.NOT_FOUND,
            summary=f"{len(items)} public code references" if items else "NOT FOUND",
            data={"references": public_refs, "potential_secrets": secret_hits},
            confidence=Confidence.MEDIUM if items else None,
            entity_id=entity.id,
        )
        return ProviderResult(
            provider=self.name,
            status=finding.status,
            findings=[finding],
        )


def _not_found(entity: Entity, title: str) -> ProviderResult:
    return ProviderResult(
        provider="github",
        status=FindingStatus.NOT_FOUND,
        findings=[
            Finding(
                module="github",
                title=title,
                status=FindingStatus.NOT_FOUND,
                summary="NOT FOUND",
                entity_id=entity.id,
            )
        ],
    )
