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


def _has_table(bind, name: str) -> bool:
    insp = sa.inspect(bind)
    return insp.has_table(name)


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    if not insp.has_table(table):
        return False
    return any(c["name"] == column for c in insp.get_columns(table))


def _has_index(bind, table: str, index: str) -> bool:
    insp = sa.inspect(bind)
    if not insp.has_table(table):
        return False
    return any(i["name"] == index for i in insp.get_indexes(table))


def upgrade() -> None:
    # Bu migration idempotent: tablo / kolon / index zaten varsa atlanır.
    # (Base.metadata.create_all() ile mrtd_sessions erken oluşmuş olabilir.)
    bind = op.get_bind()

    # ── mrtd_sessions tablosu ──────────────────────────────────────────────
    if not _has_table(bind, "mrtd_sessions"):
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
                "attempts",
                sa.Integer,
                nullable=False,
                server_default=sa.text("0"),
            ),
            sa.Column("last_error", sa.String(200), nullable=True),
        )

    # İndeksler — tabloyu yeniden tarayalım (create_all ile eksik kalmış olabilir)
    _indexes = [
        ("ix_mrtd_sessions_user_id", ["user_id"]),
        ("ix_mrtd_sessions_status", ["status"]),
        ("ix_mrtd_sessions_doc_no_hash", ["doc_no_hash"]),
        ("ix_mrtd_sessions_tckn_hash", ["tckn_hash"]),
        ("ix_mrtd_sessions_linked_payment_id", ["linked_payment_id"]),
        ("ix_mrtd_sessions_linked_receive_id", ["linked_receive_id"]),
        ("ix_mrtd_session_user_status", ["user_id", "status"]),
        ("ix_mrtd_session_expires", ["expires_at"]),
    ]
    for name, cols in _indexes:
        if not _has_index(bind, "mrtd_sessions", name):
            op.create_index(name, "mrtd_sessions", cols)

    # ── corporate_payments.mrtd_session_id ─────────────────────────────────
    if not _has_column(bind, "corporate_payments", "mrtd_session_id"):
        op.add_column(
            "corporate_payments",
            sa.Column(
                "mrtd_session_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
        )
    if not _has_index(
        bind, "corporate_payments", "ix_corporate_payments_mrtd_session_id"
    ):
        op.create_index(
            "ix_corporate_payments_mrtd_session_id",
            "corporate_payments",
            ["mrtd_session_id"],
        )

    # ── corporate_receive_requests.mrtd_session_id ─────────────────────────
    if not _has_column(
        bind, "corporate_receive_requests", "mrtd_session_id"
    ):
        op.add_column(
            "corporate_receive_requests",
            sa.Column(
                "mrtd_session_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
        )
    if not _has_index(
        bind,
        "corporate_receive_requests",
        "ix_corporate_receive_requests_mrtd_session_id",
    ):
        op.create_index(
            "ix_corporate_receive_requests_mrtd_session_id",
            "corporate_receive_requests",
            ["mrtd_session_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_index(
        bind,
        "corporate_receive_requests",
        "ix_corporate_receive_requests_mrtd_session_id",
    ):
        op.drop_index(
            "ix_corporate_receive_requests_mrtd_session_id",
            table_name="corporate_receive_requests",
        )
    if _has_column(bind, "corporate_receive_requests", "mrtd_session_id"):
        op.drop_column("corporate_receive_requests", "mrtd_session_id")

    if _has_index(
        bind, "corporate_payments", "ix_corporate_payments_mrtd_session_id"
    ):
        op.drop_index(
            "ix_corporate_payments_mrtd_session_id",
            table_name="corporate_payments",
        )
    if _has_column(bind, "corporate_payments", "mrtd_session_id"):
        op.drop_column("corporate_payments", "mrtd_session_id")

    for name in (
        "ix_mrtd_session_expires",
        "ix_mrtd_session_user_status",
        "ix_mrtd_sessions_linked_receive_id",
        "ix_mrtd_sessions_linked_payment_id",
        "ix_mrtd_sessions_tckn_hash",
        "ix_mrtd_sessions_doc_no_hash",
        "ix_mrtd_sessions_status",
        "ix_mrtd_sessions_user_id",
    ):
        if _has_index(bind, "mrtd_sessions", name):
            op.drop_index(name, table_name="mrtd_sessions")

    if _has_table(bind, "mrtd_sessions"):
        op.drop_table("mrtd_sessions")
