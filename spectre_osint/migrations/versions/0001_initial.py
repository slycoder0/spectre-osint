"""initial schema including investigation_runs

Revision ID: 0001
Revises:
Create Date: 2026-08-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("description", sa.Text(), default=""),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.Column("targets", sa.JSON(), default=list),
        sa.Column("notes", sa.Text(), default=""),
        sa.Column("active", sa.Boolean(), default=False),
    )
    op.create_table(
        "investigation_runs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id"), nullable=False),
        sa.Column("target", sa.String(1024), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("parent_run_id", sa.String(64), nullable=True),
        sa.Column("depth", sa.Integer(), default=0),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("report_path", sa.Text(), nullable=True),
        sa.Column("extra", sa.JSON(), default=dict),
    )
    op.create_table(
        "entities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id")),
        sa.Column("type", sa.String(32)),
        sa.Column("value", sa.String(1024)),
        sa.Column("normalized_value", sa.String(1024)),
        sa.Column("source", sa.String(128)),
        sa.Column("confidence", sa.String(16)),
        sa.Column("first_seen", sa.DateTime(timezone=True)),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("tags", sa.JSON()),
        sa.Column("metadata", sa.JSON()),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id")),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("investigation_runs.id"), nullable=True),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("module", sa.String(64)),
        sa.Column("title", sa.String(255)),
        sa.Column("status", sa.String(32)),
        sa.Column("summary", sa.Text()),
        sa.Column("data", sa.JSON()),
        sa.Column("confidence", sa.String(16), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id")),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("investigation_runs.id"), nullable=True),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("finding_id", sa.String(64), nullable=True),
        sa.Column("source", sa.String(128)),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True)),
        sa.Column("raw_reference", sa.Text(), nullable=True),
        sa.Column("provider", sa.String(64)),
        sa.Column("confidence", sa.String(16)),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_table(
        "relationships",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id")),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("investigation_runs.id"), nullable=True),
        sa.Column("from_entity_id", sa.String(64)),
        sa.Column("to_entity_id", sa.String(64)),
        sa.Column("relation", sa.String(64)),
        sa.Column("source", sa.String(128)),
        sa.Column("confidence", sa.String(16)),
        sa.Column("timestamp", sa.DateTime(timezone=True)),
        sa.Column("evidence_id", sa.String(64), nullable=True),
        sa.Column("metadata", sa.JSON()),
    )
    op.create_table(
        "provider_results",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id")),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("investigation_runs.id"), nullable=True),
        sa.Column("provider", sa.String(64)),
        sa.Column("entity_id", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32)),
        sa.Column("queried_at", sa.DateTime(timezone=True)),
        sa.Column("payload", sa.JSON()),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.id")),
        sa.Column("run_id", sa.String(64), sa.ForeignKey("investigation_runs.id"), nullable=True),
        sa.Column("path", sa.Text()),
        sa.Column("format", sa.String(16)),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(128)),
        sa.Column("status", sa.String(32)),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("message", sa.Text()),
    )


def downgrade() -> None:
    for table in (
        "tasks",
        "reports",
        "provider_results",
        "relationships",
        "evidence",
        "findings",
        "entities",
        "investigation_runs",
        "cases",
    ):
        op.drop_table(table)
