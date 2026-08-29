"""Public username presence checks loaded from data/sites.yaml.

HTTP 200 alone is never CONFIRMED. Implementation lives in engine.py.
"""

from spectre_osint.modules.username.engine import analyze_username, classify_html, load_sites

__all__ = ["analyze_username", "classify_html", "load_sites"]
