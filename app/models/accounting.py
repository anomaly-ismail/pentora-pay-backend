import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Numeric,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AccountType(str, enum.Enum):
    ASSET = "ASSET"         # System assets
    LIABILITY = "LIABILITY" # User balances (what we owe to users)
    EQUITY = "EQUITY"
    REVENUE = "REVENUE"
    EXPENSE = "EXPENSE"


class JournalDirection(str, enum.Enum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
        comment="Null if this is a system account, else fk to user.",
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    type: Mapped[AccountType] = mapped_column(
        Enum(AccountType, name="account_type_enum"),
        nullable=False,
    )

    currency: Mapped[str] = mapped_column(
        String(3),
        default="TRY",
        nullable=False,
    )

    # Fast-read balance. Updates occur inside the journal entry transaction.
    balance: Mapped[float] = mapped_column(
        Numeric(18, 4),
        default=0.0,
        nullable=False,
        server_default=text("0.0000"),
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        server_default=text("true"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    entries: Mapped[list["JournalEntry"]] = relationship("JournalEntry", back_populates="account")

    __table_args__ = (
        Index("ix_accounts_user_id_currency_name", "user_id", "currency", "name", unique=True, postgresql_where=text("user_id IS NOT NULL")),
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    reference_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
        index=True,
        comment="Idempotency key or external ref",
    )

    description: Mapped[str] = mapped_column(String(512), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    
    entries: Mapped[list["JournalEntry"]] = relationship("JournalEntry", back_populates="transaction")


class JournalEntry(Base):
    """
    Immutable ledger line.
    """
    __tablename__ = "journal_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    transaction_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("transactions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("accounts.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    direction: Mapped[JournalDirection] = mapped_column(
        Enum(JournalDirection, name="journal_direction_enum"),
        nullable=False,
    )

    # Monetary value must be strictly positive mapped to Numeric.
    amount: Mapped[float] = mapped_column(
        Numeric(18, 4),
        nullable=False,
    )

    currency: Mapped[str] = mapped_column(String(3), default="TRY", nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    transaction: Mapped["Transaction"] = relationship("Transaction", back_populates="entries")
    account: Mapped["Account"] = relationship("Account", back_populates="entries")
