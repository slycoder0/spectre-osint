"""Public username presence checks loaded from data/sites.yaml.

HTTP 200 alone is never CONFIRMED. Implementation lives in engine.py and catalog.py.
"""

from spectre_osint.modules.username.catalog import (
    CatalogError,
    CatalogValidationError,
    CheckMethod,
    ConfidenceStrategy,
    SiteCatalog,
    SiteDefinition,
    load_catalog,
)
from spectre_osint.modules.username.engine import analyze_username, classify_html, load_sites

__all__ = [
    "CatalogError",
    "CatalogValidationError",
    "CheckMethod",
    "ConfidenceStrategy",
    "SiteCatalog",
    "SiteDefinition",
    "analyze_username",
    "classify_html",
    "load_catalog",
    "load_sites",
]
