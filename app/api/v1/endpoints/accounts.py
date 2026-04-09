from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.db.dependencies import get_db
from app.api.dependencies import get_current_user, UserDTO
from app.models.accounting import Account, AccountType, JournalEntry, JournalDirection, Transaction
from app.schemas.account import AccountSummaryResponse, TransactionsListResponse, TransactionItem

router = APIRouter(prefix="/accounts", tags=["Accounts"])


@router.get(
    "/summary",
    response_model=AccountSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Kullanıcı Hesap Özeti",
    description="OWASP Standartlarında cüzdan bakiyesini, escrow miktarını ve işlem özetlerini getirir.",
)
async def get_account_summary(
    request: Request,
    current_user: UserDTO = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> AccountSummaryResponse:
    # Tek sorguda tüm kullanıcı hesaplarını çek (Ana Cüzdan + escrow)
    stmt_accounts = select(Account).where(
        Account.user_id == current_user.id,
        Account.type == AccountType.LIABILITY,
        Account.currency == "TRY",
        Account.is_active.is_(True),
    )
    accounts = (await db.execute(stmt_accounts)).scalars().all()

    main_account = next((a for a in accounts if a.name == "Ana Cüzdan"), None)
    if not main_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Uygun hesap bulunamadı.",
        )

    escrow_account = next((a for a in accounts if a.name == "escrow"), None)
    pending_bal = float(escrow_account.balance) if escrow_account else 0.0

    # CREDIT ve DEBIT toplamlarını tek sorguda al
    stmt_agg = select(
        JournalEntry.direction,
        func.sum(JournalEntry.amount).label("total"),
    ).where(
        JournalEntry.account_id == main_account.id,
    ).group_by(JournalEntry.direction)

    agg_rows = (await db.execute(stmt_agg)).all()
    incoming = 0.0
    outgoing = 0.0
    for row in agg_rows:
        if row.direction == JournalDirection.CREDIT:
            incoming = float(row.total)
        else:
            outgoing = float(row.total)

    return AccountSummaryResponse(
        total_balance=float(main_account.balance),
        pending_balance=pending_bal,
        incoming=incoming,
        outgoing=outgoing,
    )


@router.get(
    "/transactions",
    response_model=TransactionsListResponse,
    status_code=status.HTTP_200_OK,
    summary="İşlem Geçmişi (Transactions)",
    description="Kullanıcıya ait (Ana Cüzdan + Escrow) yevmiye kayıtlarını döndürür.",
)
async def get_transactions(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100, description="Sayfa başına kayıt"),
    offset: int = Query(default=0, ge=0, description="Atlanan kayıt sayısı"),
    current_user: UserDTO = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TransactionsListResponse:
    # Kullanıcının IDOR korumalı şekilde cüzdanlarını bul (tek sorgu)
    stmt_accounts = select(Account.id, Account.name).where(
        Account.user_id == current_user.id,
        Account.type == AccountType.LIABILITY,
        Account.currency == "TRY",
    )
    user_accounts = (await db.execute(stmt_accounts)).all()
    account_ids = [acc.id for acc in user_accounts]
    escrow_id = next((acc.id for acc in user_accounts if acc.name == "escrow"), None)

    if not account_ids:
        return TransactionsListResponse(transactions=[])

    # JournalEntry + Transaction tek sorguda — JOIN ile N+1 önlenir
    stmt_entries = (
        select(JournalEntry)
        .options(selectinload(JournalEntry.transaction))
        .where(JournalEntry.account_id.in_(account_ids))
        .order_by(JournalEntry.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    entries = (await db.execute(stmt_entries)).scalars().all()

    items = []
    for entry in entries:
        tx: Transaction = entry.transaction
        is_pending = entry.account_id == escrow_id
        is_incoming = None if is_pending else (entry.direction == JournalDirection.CREDIT)

        amt_str = f"₺{float(entry.amount):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

        if is_pending:
            status_code = 3
        elif is_incoming:
            status_code = 1
        else:
            status_code = 2

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
            is_pending=is_pending,
        ))

    return TransactionsListResponse(transactions=items)
