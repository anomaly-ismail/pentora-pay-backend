import uuid
from decimal import Decimal, ROUND_HALF_EVEN
from datetime import datetime, timezone
from typing import TypedDict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from app.models.accounting import (
    Account,
    AccountType,
    Transaction,
    JournalEntry,
    JournalDirection,
)

# Para birimleri için standart hassasiyet: 4 ondalık basamak (Banker's rounding)
CURRENCY_QUANTUM = Decimal("0.0001")


def normalize(amount: Decimal) -> Decimal:
    """Tutarı 4 ondalık basamağa yuvarlar (ROUND_HALF_EVEN = Banker's rounding)."""
    return amount.quantize(CURRENCY_QUANTUM, rounding=ROUND_HALF_EVEN)

class EntryRequest(TypedDict):
    account_id: uuid.UUID
    direction: JournalDirection
    amount: Decimal


class AccountingRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_account(
        self,
        name: str,
        type: AccountType,
        user_id: uuid.UUID | None = None,
        currency: str = "TRY",
        initial_balance: Decimal = Decimal('0.0000'),
    ) -> Account:
        """Kullanıcıya veya sisteme ait yeni bir hesap oluşturur."""
        account = Account(
            user_id=user_id,
            name=name,
            type=type,
            currency=currency,
            balance=initial_balance
        )
        self.db.add(account)
        await self.db.flush()
        return account

    async def get_user_primary_wallet(self, user_id: uuid.UUID) -> Account | None:
        stmt = select(Account).where(
            Account.user_id == user_id,
            Account.type == AccountType.LIABILITY,
            Account.currency == "TRY",
            Account.name == "Ana Cüzdan"
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_user_primary_wallet_for_update(self, user_id: uuid.UUID) -> Account | None:
        """Aynı hesabı SELECT FOR UPDATE (row-level lock) ile çeker — race condition önlemi."""
        stmt = (
            select(Account)
            .where(
                Account.user_id == user_id,
                Account.type == AccountType.LIABILITY,
                Account.currency == "TRY",
                Account.name == "Ana Cüzdan",
            )
            .with_for_update()
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_user_escrow_for_update(self, user_id: uuid.UUID) -> Account | None:
        """Kullanıcının escrow hesabını row-level lock ile çeker."""
        stmt = (
            select(Account)
            .where(
                Account.user_id == user_id,
                Account.type == AccountType.LIABILITY,
                Account.currency == "TRY",
                Account.name == "escrow",
            )
            .with_for_update()
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_or_create_system_account(
        self,
        name: str,
        account_type: AccountType = AccountType.ASSET,
        currency: str = "TRY",
    ) -> Account:
        """
        Verilen adla sistem hesabını getirir; yoksa oluşturur.
        Sistem hesapları user_id=None ve ASSET tipindedir.
        """
        stmt = select(Account).where(
            Account.user_id.is_(None),
            Account.name == name,
            Account.currency == currency,
        )
        result = await self.db.execute(stmt)
        account = result.scalars().first()
        if account:
            return account
        return await self.create_account(
            name=name,
            type=account_type,
            user_id=None,
            currency=currency,
            initial_balance=Decimal("0.0000"),
        )

    async def record_transaction(
        self,
        reference_id: str | None,
        description: str,
        entries: List[EntryRequest]
    ) -> Transaction:
        """
        Çift Taraflı Kayıt (Double-Entry Bookkeeping) kuralını işler.
        ACID garantilidir, Row-Level locking kullanır.
        """
        # 1. Bakiye kontrolü (Debits = Credits)
        total_debit = sum(e["amount"] for e in entries if e["direction"] == JournalDirection.DEBIT)
        total_credit = sum(e["amount"] for e in entries if e["direction"] == JournalDirection.CREDIT)

        if total_debit != total_credit:
            raise ValueError(f"Journal unbalanced: Debits ({total_debit}) != Credits ({total_credit})")

        if total_debit <= 0:
            raise ValueError("Transaction must have strict positive amounts.")

        # 2. Transaction Oluştur
        transaction = Transaction(
            reference_id=reference_id,
            description=description
        )
        self.db.add(transaction)
        await self.db.flush()

        # 3. Yevmiye kayıtları ve Account Bakiye güncellemeleri
        for req in entries:
            amount = normalize(req["amount"])   # Banker's rounding — küsürat kayması yok
            if amount <= 0:
                raise ValueError("Journal entry amount must be strictly positive.")

            # SELECT ... FOR UPDATE (Kilit al - Race condition önlemi)
            stmt = select(Account).where(Account.id == req["account_id"]).with_for_update()
            result = await self.db.execute(stmt)
            account = result.scalars().first()

            if not account:
                raise ValueError(f"Account {req['account_id']} not found.")

            # JournalEntry kaydı
            journal_entry = JournalEntry(
                transaction_id=transaction.id,
                account_id=account.id,
                direction=req["direction"],
                amount=amount,
                currency=account.currency
            )
            self.db.add(journal_entry)

            # Bakiye Hesaplama
            # Hesap tiplerine göre Artış (Debit/Credit) mantığı:
            if account.type in (AccountType.ASSET, AccountType.EXPENSE):
                # Varlık ve Giderler: Debit (+) / Credit (-)
                if req["direction"] == JournalDirection.DEBIT:
                    account.balance += amount
                else:
                    account.balance -= amount
            elif account.type in (AccountType.LIABILITY, AccountType.EQUITY, AccountType.REVENUE):
                # Yükümlülük (Kullanıcı cüzdanları), Özkaynak, Gelir: Credit (+) / Debit (-)
                if req["direction"] == JournalDirection.CREDIT:
                    account.balance += amount
                else:
                    account.balance -= amount

            # Negatif bakiye kabul edilemez durumları (örn kullanıcı cüzdanı eksiye düşemez)
            # Eğer overdraft desteklenmiyorsa (kredi kartı hariç):
            if account.type == AccountType.LIABILITY and account.balance < 0:
                 raise ValueError("Yetersiz Bakiye.")

        await self.db.flush()
        return transaction
