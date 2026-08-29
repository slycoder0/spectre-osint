from __future__ import annotations

from spectre_osint.core.redaction import mask_secret, redact_mapping, redact_text


def test_mask_secret() -> None:
    masked = mask_secret("sk-123456789")
    assert "123456789" not in masked
    assert masked.startswith("sk")


def test_redact_text_strips_bearer() -> None:
    text = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    redacted = redact_text(text)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in redacted


def test_redact_mapping_keys() -> None:
    payload = {"api_key": "supersecretvalue", "nested": {"token": "abcd1234"}}
    redacted = redact_mapping(payload)
    assert "supersecretvalue" not in str(redacted)
    assert "abcd1234" not in str(redacted)


def test_cookie_and_session_redaction() -> None:
    from spectre_osint.core.redaction import strip_auth_material

    text = "Cookie: sessionid=abcSECRET99; Authorization: Bearer tok_secret"
    redacted = redact_text(text)
    assert "abcSECRET99" not in redacted
    payload = strip_auth_material(
        {"cookie": "abcSECRET99", "sessionid": "abcSECRET99", "platform": "Instagram", "session_status": "ACTIVE"}
    )
    assert "abcSECRET99" not in str(payload)
    assert payload["session_status"] == "ACTIVE"
    assert payload["platform"] == "Instagram"
