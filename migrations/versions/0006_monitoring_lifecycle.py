"""Persisted monitoring targets, checks, observations and alerts.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "monitoring_targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("brand_id", sa.Integer(), nullable=True),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("removed", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("check_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(24), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "interval_seconds >= 60 AND interval_seconds <= 2592000",
            name="ck_monitoring_interval",
        ),
        sa.ForeignKeyConstraint(["brand_id"], ["brands.id"]),
        sa.UniqueConstraint("target_type", "target", name="uq_monitoring_target_identity"),
    )
    op.create_index("ix_monitoring_targets_brand_id", "monitoring_targets", ["brand_id"])
    op.create_index("ix_monitoring_targets_next_check_at", "monitoring_targets", ["next_check_at"])
    op.create_index(
        "ix_monitoring_targets_check_started_at", "monitoring_targets", ["check_started_at"]
    )

    op.create_table(
        "monitoring_checks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("providers_json", sa.Text(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["monitoring_targets.id"]),
    )
    op.create_index("ix_monitoring_checks_target_id", "monitoring_checks", ["target_id"])

    op.create_table(
        "monitoring_observations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("observation_key", sa.String(64), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_check_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["monitoring_targets.id"]),
        sa.ForeignKeyConstraint(["last_check_id"], ["monitoring_checks.id"]),
        sa.UniqueConstraint("target_id", "observation_key", name="uq_monitor_observation_key"),
    )
    op.create_index(
        "ix_monitoring_observations_target_id", "monitoring_observations", ["target_id"]
    )

    op.create_table(
        "monitoring_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("check_id", sa.Integer(), nullable=False),
        sa.Column("observation_id", sa.Integer(), nullable=False),
        sa.Column("change_type", sa.String(24), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["monitoring_targets.id"]),
        sa.ForeignKeyConstraint(["check_id"], ["monitoring_checks.id"]),
        sa.ForeignKeyConstraint(["observation_id"], ["monitoring_observations.id"]),
    )
    op.create_index("ix_monitoring_alerts_target_id", "monitoring_alerts", ["target_id"])
    op.create_index("ix_monitoring_alerts_check_id", "monitoring_alerts", ["check_id"])
    op.create_index("ix_monitoring_alerts_observation_id", "monitoring_alerts", ["observation_id"])


def downgrade() -> None:
    op.drop_table("monitoring_alerts")
    op.drop_table("monitoring_observations")
    op.drop_table("monitoring_checks")
    op.drop_table("monitoring_targets")
