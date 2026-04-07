from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload

from app.db.dependencies import get_db
from app.api.dependencies import get_current_user
from app.models.user import User
from app.models.accounting import Account, AccountType, JournalEntry, JournalDirection, Transaction
from app.schemas.account import AccountSummaryResponse, TransactionsListResponse, TransactionItem

router = APIRouter(prefix="/accounts", tags=["Accounts"])

@router.get(
    "/summary",
    response_model=AccountSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Kullanıcı Hesap Özeti",
    description="OWASP Standartlarında cüzdan bakiyesini, escrow miktarını ve işlem özetlerini getirir."
)
async def get_account_summary(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> AccountSummaryResponse:
    # Ana Cüzdanı Al
    stmt_account = select(Account).where(
        Account.user_id == current_user.id,
        Account.name == "Ana Cüzdan",
        Account.type == AccountType.LIABILITY,
        Account.currency == "TRY"
    )
    account = (await db.execute(stmt_account)).scalars().first()

    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Uygun hesap bulunamadı."
        )

    # Escrow (Bekleyen) Cüzdanı Al
    stmt_escrow = select(Account).where(
        Account.user_id == current_user.id,
        Account.name == "escrow",
        Account.type == AccountType.LIABILITY,
        Account.currency == "TRY"
    )
    escrow_account = (await db.execute(stmt_escrow)).scalars().first()
    pending_bal = float(escrow_account.balance) if escrow_account else 0.0

    # CREDITS (Gelen)
    stmt_credits = select(func.sum(JournalEntry.amount)).where(
        JournalEntry.account_id == account.id,
        JournalEntry.direction == JournalDirection.CREDIT
    )
    incoming = (await db.execute(stmt_credits)).scalar() or 0.0

    # DEBITS (Giden)
    stmt_debits = select(func.sum(JournalEntry.amount)).where(
        JournalEntry.account_id == account.id,
        JournalEntry.direction == JournalDirection.DEBIT
    )
    outgoing = (await db.execute(stmt_debits)).scalar() or 0.0

    return AccountSummaryResponse(
        total_balance=float(account.balance),
        pending_balance=pending_bal,
        incoming=float(incoming),
        outgoing=float(outgoing)
    )

@router.get(
    "/transactions",
    response_model=TransactionsListResponse,
    status_code=status.HTTP_200_OK,
    summary="İşlem Geçmişi (Transactions)",
    description="Kullanıcıya ait (Ana Cüzdan + Escrow) yevmiye kayıtlarını döndürür."
)
async def get_transactions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> TransactionsListResponse:
    # Kullanıcının IDOR korumalı şekilde cüzdanlarını bul
    stmt_accounts = select(Account.id, Account.name).where(
        Account.user_id == current_user.id,
        Account.type == AccountType.LIABILITY,
        Account.currency == "TRY"
    )
    user_accounts = (await db.execute(stmt_accounts)).all()
    account_ids = [acc.id for acc in user_accounts]
    escrow_id = next((acc.id for acc in user_accounts if acc.name == "escrow"), None)
    
    if not account_ids:
        return TransactionsListResponse(transactions=[])

    # İlgili JournalEntry kayıtlarını bul
    stmt_entries = (
        select(JournalEntry)
        .options(selectinload(JournalEntry.transaction))
        .where(JournalEntry.account_id.in_(account_ids))
        .order_by(JournalEntry.created_at.desc())
        .limit(100)
    )
    entries = (await db.execute(stmt_entries)).scalars().all()

    items = []
    for entry in entries:
        tx = entry.transaction
        
        # Bekleyen hesap işlemi mi?
        is_pending = entry.account_id == escrow_id
        
        # Yön
        is_incoming = None
        if not is_pending:
            is_incoming = entry.direction == JournalDirection.CREDIT
        
        # Miktar: frontend tarafında + ve - eklenmesi için düz alıyoruz, dart tarafında isIncoming değerlendirilir
        amt_str = f"₺{float(entry.amount):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        
        # Status Mapping
        status_code = 1 if is_incoming else 2
        if is_pending:
            status_code = 3
        
        items.append(TransactionItem(
            id=str(tx.id),
            name="Sistem İşlemi" if is_incoming else "Ödeme Transferi",
            tckn="Ağ İşlemi",
            amount=("+ " if is_incoming else "- ") + amt_str,
            date=entry.created_at.strftime("%d.%m.%Y %H:%M"),
            status="Tamamlandı" if not is_pending else "Bekliyor",
            status_code=status_code,
            description=tx.description,
            ref=tx.reference_id or str(tx.id)[:8].upper(),
            is_incoming=is_incoming,
            is_pending=is_pending
        ))

    return TransactionsListResponse(transactions=items)
