"""Exclusion gate audit log (Stage 6).

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the append-only exclusion audit log."""
    op.create_table(
        "exclusion_audit_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("input_reference", sa.String(length=255), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("brand_id", sa.Integer(), nullable=True),
        sa.Column("brand_asset_id", sa.Integer(), nullable=True),
        sa.Column("analyzer_input_id", sa.String(length=255), nullable=True),
        sa.Column("alert_eligible", sa.Boolean(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Drop the exclusion audit log."""
    op.drop_table("exclusion_audit_log")
