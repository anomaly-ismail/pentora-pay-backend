"""Performance indexes — composite indexes for hot query paths

Revision ID: a1b2c3d4e5f6
Revises: 50fa01fee0fd
Create Date: 2026-04-09 00:00:00.000000

Eklenen index'ler:
  - ix_journal_entries_account_created : işlem geçmişi sorgularında ORDER BY hızlandırır
  - ix_journal_entries_tx_account      : transaction join sorgularını hızlandırır
  - ix_sessions_token_hash             : her auth isteğinde token hash lookup
"""
from typing import Sequence, Union
from alembic import op


revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "50fa01fee0fd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # journal_entries: account_id + created_at (DESC sıralama için BRIN veya BTREE)
    op.create_index(
        "ix_journal_entries_account_created",
        "journal_entries",
        ["account_id", "created_at"],
        unique=False,
    )
    # journal_entries: transaction_id + account_id join
    op.create_index(
        "ix_journal_entries_tx_account",
        "journal_entries",
        ["transaction_id", "account_id"],
        unique=False,
    )
    # user_sessions: grauth_token_hash — her auth isteğinde kullanılır
    op.create_index(
        "ix_sessions_token_hash",
        "user_sessions",
        ["grauth_token_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_sessions_token_hash", table_name="user_sessions")
    op.drop_index("ix_journal_entries_tx_account", table_name="journal_entries")
    op.drop_index("ix_journal_entries_account_created", table_name="journal_entries")
