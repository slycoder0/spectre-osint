"""Service layer shared by the CLI commands and (Phase 3) the interactive menu.

Services run investigations and turn results into language-neutral view models. They
never print, never import Rich and never translate: renderers in `spectre_osint/cli/`
decide how a view looks, in which language.
"""
