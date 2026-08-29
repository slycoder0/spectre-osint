"""Optional LLM helper. Output is always tagged AI_ANALYSIS and never CONFIRMED.

This module is not part of the default investigation pipeline. It only runs when
`LLM_ENABLED=true` and a backend is configured. Failures never mutate collected facts.
"""

from __future__ import annotations

from spectre_osint.core.config import Settings
from spectre_osint.core.entities import Finding, InvestigationResult
from spectre_osint.core.http_client import HttpClient
from spectre_osint.core.redaction import redact_text
from spectre_osint.core.types import Confidence, FindingStatus


async def summarize_optional(
    result: InvestigationResult,
    settings: Settings,
    http: HttpClient | None = None,
) -> Finding:
    if not settings.llm_enabled:
        return Finding(
            module="llm",
            title="AI analysis",
            status=FindingStatus.NOT_CONFIGURED,
            summary="Provider not configured (LLM disabled). SPECTRE never requires an LLM.",
            data={"tag": "AI_ANALYSIS"},
            confidence=Confidence.LOW,
        )

    facts = [
        f"{f.module}: {f.status} {f.summary}" for f in result.findings[:40]
    ]
    prompt = (
        "Summarize the following OSINT evidence. Do not invent facts. "
        "If something is missing, say NOT FOUND.\n\n" + "\n".join(facts)
    )
    owns = http is None
    client = http or HttpClient(settings)
    try:
        text = await _complete(client, settings, prompt)
    except Exception as exc:  # noqa: BLE001
        return Finding(
            module="llm",
            title="AI_ANALYSIS",
            status=FindingStatus.PROVIDER_UNAVAILABLE,
            summary=f"PROVIDER UNAVAILABLE: {redact_text(str(exc))}",
            data={"tag": "AI_ANALYSIS", "confidence_cap": "LOW"},
            confidence=Confidence.LOW,
        )
    finally:
        if owns:
            await client.close()

    if not text:
        return Finding(
            module="llm",
            title="AI_ANALYSIS",
            status=FindingStatus.NOT_FOUND,
            summary="NOT FOUND — LLM returned an empty summary",
            data={"tag": "AI_ANALYSIS"},
            confidence=Confidence.LOW,
        )
    return Finding(
        module="llm",
        title="AI_ANALYSIS",
        status=FindingStatus.INFERENCE,
        summary=f"AI_ANALYSIS: {text[:500]}",
        data={"tag": "AI_ANALYSIS", "confidence_cap": "LOW", "full": text[:4000]},
        confidence=Confidence.LOW,
    )


async def _complete(http: HttpClient, settings: Settings, prompt: str) -> str:
    if settings.secret_present("openai_api_key") and settings.openai_api_key:
        url = settings.openai_base_url.rstrip("/") + "/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.openai_api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        body = {
            "model": settings.openai_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
        response = await http.post(
            url,
            provider="llm-openai",
            headers=headers,
            json_body=body,
            ssrf=False,
        )
        choices = (response.json_data or {}).get("choices") or []
        if not choices:
            return ""
        return str((choices[0].get("message") or {}).get("content") or "")
    # Local Ollama only when explicitly enabled — loopback is intentional.
    url = settings.ollama_base_url.rstrip("/") + "/api/generate"
    response = await http.post(
        url,
        provider="llm-ollama",
        json_body={"model": settings.ollama_model, "prompt": prompt, "stream": False},
        ssrf=False,
    )
    if not response.json_data:
        raise RuntimeError(f"Ollama HTTP {response.status_code}")
    return str(response.json_data.get("response") or "")
