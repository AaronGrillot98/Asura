"""initial schema — captures the indexed-column + JSON-payload tables.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-05-17

This revision creates every persisted table that `app.db.models` declares.
Each table follows the same pattern: a small set of indexed columns for the
filters the app actually runs, plus a JSON `payload` column that round-trips
the full Pydantic dump on read.

Subsequent revisions evolve these schemas by adding indexed columns; the
JSON payload column absorbs everything else without a migration.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_workspaces_name", "workspaces", ["name"])

    op.create_table(
        "projects",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("workspace_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_projects_workspace_id", "projects", ["workspace_id"])
    op.create_index("ix_projects_name", "projects", ["name"])
    op.create_index("ix_projects_is_demo_data", "projects", ["is_demo_data"])
    op.create_index("ix_projects_created_at", "projects", ["created_at"])

    op.create_table(
        "assets",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_assets_project_id", "assets", ["project_id"])
    op.create_index("ix_assets_kind", "assets", ["kind"])

    op.create_table(
        "targets",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_targets_project_id", "targets", ["project_id"])
    op.create_index("ix_targets_kind", "targets", ["kind"])
    op.create_index("ix_targets_is_demo_data", "targets", ["is_demo_data"])

    op.create_table(
        "authorized_scopes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_authorized_scopes_project_id", "authorized_scopes", ["project_id"])
    op.create_index("ix_authorized_scopes_is_demo_data", "authorized_scopes", ["is_demo_data"])

    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("scanner", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_scanner_runs_project_id", "scanner_runs", ["project_id"])
    op.create_index("ix_scanner_runs_scan_id", "scanner_runs", ["scan_id"])
    op.create_index("ix_scanner_runs_scanner", "scanner_runs", ["scanner"])
    op.create_index("ix_scanner_runs_mode", "scanner_runs", ["mode"])
    op.create_index("ix_scanner_runs_status", "scanner_runs", ["status"])
    op.create_index("ix_scanner_runs_is_demo_data", "scanner_runs", ["is_demo_data"])
    op.create_index("ix_scanner_runs_started_at", "scanner_runs", ["started_at"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("scanner", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("fingerprint_hash", sa.String(), nullable=True),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_findings_project_id", "findings", ["project_id"])
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_scanner", "findings", ["scanner"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_fingerprint_hash", "findings", ["fingerprint_hash"])
    op.create_index("ix_findings_is_demo_data", "findings", ["is_demo_data"])
    op.create_index("ix_findings_created_at", "findings", ["created_at"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("scanner", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("captured_at", sa.DateTime(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])
    op.create_index("ix_evidence_scanner", "evidence", ["scanner"])
    op.create_index("ix_evidence_is_demo_data", "evidence", ["is_demo_data"])
    op.create_index("ix_evidence_captured_at", "evidence", ["captured_at"])

    op.create_table(
        "attack_paths",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_attack_paths_project_id", "attack_paths", ["project_id"])
    op.create_index("ix_attack_paths_is_demo_data", "attack_paths", ["is_demo_data"])

    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("priority", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_remediation_tasks_project_id", "remediation_tasks", ["project_id"])
    op.create_index("ix_remediation_tasks_priority", "remediation_tasks", ["priority"])
    op.create_index("ix_remediation_tasks_status", "remediation_tasks", ["status"])
    op.create_index("ix_remediation_tasks_is_demo_data", "remediation_tasks", ["is_demo_data"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("workspace_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("decision", sa.String(), nullable=True),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_audit_logs_workspace_id", "audit_logs", ["workspace_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_decision", "audit_logs", ["decision"])
    op.create_index("ix_audit_logs_target", "audit_logs", ["target"])
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])

    op.create_table(
        "reports",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=True),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_reports_project_id", "reports", ["project_id"])
    op.create_index("ix_reports_kind", "reports", ["kind"])
    op.create_index("ix_reports_is_demo_data", "reports", ["is_demo_data"])
    op.create_index("ix_reports_generated_at", "reports", ["generated_at"])

    op.create_table(
        "scan_schedules",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_scan_schedules_project_id", "scan_schedules", ["project_id"])
    op.create_index("ix_scan_schedules_enabled", "scan_schedules", ["enabled"])
    op.create_index("ix_scan_schedules_is_demo_data", "scan_schedules", ["is_demo_data"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("is_demo_data", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_scan_jobs_project_id", "scan_jobs", ["project_id"])
    op.create_index("ix_scan_jobs_kind", "scan_jobs", ["kind"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_is_demo_data", "scan_jobs", ["is_demo_data"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])


def downgrade() -> None:
    op.drop_table("scan_jobs")
    op.drop_table("scan_schedules")
    op.drop_table("reports")
    op.drop_table("audit_logs")
    op.drop_table("remediation_tasks")
    op.drop_table("attack_paths")
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("scanner_runs")
    op.drop_table("authorized_scopes")
    op.drop_table("targets")
    op.drop_table("assets")
    op.drop_table("projects")
    op.drop_table("workspaces")
