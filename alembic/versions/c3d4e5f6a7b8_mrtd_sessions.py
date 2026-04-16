"""MRTD sessions — şifreli MRZ / NFC oturum tablosu + FK'ler

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-04-17 00:00:00.000000

Eklenenler:
  - mrtd_sessions tablosu (approve_id = id, AES-GCM şifreli DG blobları,
    doc_no/tckn HMAC indeksleri, 15 dk TTL)
  - corporate_payments.mrtd_session_id (FK, nullable) — audit zinciri
  - corporate_receive_requests.mrtd_session_id (FK, nullable)

Güvenlik:
  - PCI DSS 3.4 — tüm PAN-eşdeğeri kimlik verisi (DG1/DG2/DG11/SOD) şifreli
  - OWASP A01 — mrtd_sessions.user_id ON DELETE CASCADE
  - OWASP A09 — doc_no_hash ile auditable ama reversible olmayan arama
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── mrtd_sessions tablosu ──────────────────────────────────────────────
    op.create_table(
        "mrtd_sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            comment="approve_id — Flutter'a döndürülür",
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column(
            "status",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        # Şifreli DG blobları
        sa.Column("mrz_blob", sa.LargeBinary, nullable=True),
        sa.Column("dg1_blob", sa.LargeBinary, nullable=True),
        sa.Column("dg2_blob", sa.LargeBinary, nullable=True),
        sa.Column("dg11_blob", sa.LargeBinary, nullable=True),
        sa.Column("sod_blob", sa.LargeBinary, nullable=True),
        # HMAC indeksleri
        sa.Column("doc_no_hash", sa.String(64), nullable=True),
        sa.Column("tckn_hash", sa.String(64), nullable=True),
        # Metadata
        sa.Column("doc_type", sa.String(8), nullable=True),
        sa.Column("issuing_state", sa.String(3), nullable=True),
        sa.Column("nationality", sa.String(3), nullable=True),
        sa.Column("date_of_expiry", sa.String(6), nullable=True),
        sa.Column(
            "passive_auth_ok",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("client_ip_hash", sa.String(64), nullable=True),
        sa.Column("user_agent_hash", sa.String(64), nullable=True),
        # Lifecycle
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("mrz_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nfc_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # İlişkiler
        sa.Column(
            "linked_payment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("corporate_payments.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "linked_receive_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("corporate_receive_requests.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "attempts", sa.Integer, nullable=False, server_default=sa.text("0")
        ),
        sa.Column("last_error", sa.String(200), nullable=True),
    )

    op.create_index(
        "ix_mrtd_sessions_user_id", "mrtd_sessions", ["user_id"]
    )
    op.create_index(
        "ix_mrtd_sessions_status", "mrtd_sessions", ["status"]
    )
    op.create_index(
        "ix_mrtd_sessions_doc_no_hash", "mrtd_sessions", ["doc_no_hash"]
    )
    op.create_index(
        "ix_mrtd_sessions_tckn_hash", "mrtd_sessions", ["tckn_hash"]
    )
    op.create_index(
        "ix_mrtd_sessions_linked_payment_id",
        "mrtd_sessions",
        ["linked_payment_id"],
    )
    op.create_index(
        "ix_mrtd_sessions_linked_receive_id",
        "mrtd_sessions",
        ["linked_receive_id"],
    )
    op.create_index(
        "ix_mrtd_session_user_status",
        "mrtd_sessions",
        ["user_id", "status"],
    )
    op.create_index(
        "ix_mrtd_session_expires", "mrtd_sessions", ["expires_at"]
    )

    # ── corporate_payments.mrtd_session_id ─────────────────────────────────
    op.add_column(
        "corporate_payments",
        sa.Column(
            "mrtd_session_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_corporate_payments_mrtd_session_id",
        "corporate_payments",
        ["mrtd_session_id"],
    )

    # ── corporate_receive_requests.mrtd_session_id ─────────────────────────
    op.add_column(
        "corporate_receive_requests",
        sa.Column(
            "mrtd_session_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_corporate_receive_requests_mrtd_session_id",
        "corporate_receive_requests",
        ["mrtd_session_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_corporate_receive_requests_mrtd_session_id",
        table_name="corporate_receive_requests",
    )
    op.drop_column("corporate_receive_requests", "mrtd_session_id")

    op.drop_index(
        "ix_corporate_payments_mrtd_session_id", table_name="corporate_payments"
    )
    op.drop_column("corporate_payments", "mrtd_session_id")

    op.drop_index("ix_mrtd_session_expires", table_name="mrtd_sessions")
    op.drop_index("ix_mrtd_session_user_status", table_name="mrtd_sessions")
    op.drop_index(
        "ix_mrtd_sessions_linked_receive_id", table_name="mrtd_sessions"
    )
    op.drop_index(
        "ix_mrtd_sessions_linked_payment_id", table_name="mrtd_sessions"
    )
    op.drop_index("ix_mrtd_sessions_tckn_hash", table_name="mrtd_sessions")
    op.drop_index("ix_mrtd_sessions_doc_no_hash", table_name="mrtd_sessions")
    op.drop_index("ix_mrtd_sessions_status", table_name="mrtd_sessions")
    op.drop_index("ix_mrtd_sessions_user_id", table_name="mrtd_sessions")
    op.drop_table("mrtd_sessions")
