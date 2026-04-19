import uuid

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

    # 0) Escrow FIFO Netleştirme:
    #    "Pending" (bekleyen) bir işlem, escrow'da hâlâ tutulan parayı temsil
    #    eder. Sistem genelde iki ayrı `Transaction` üretir:
    #      • Tahsilat (CREDIT escrow)
    #      • Müşteri onayı (DEBIT escrow + CREDIT ana cüzdan)
    #    Onay sonrası tahsilat işlemi de hâlâ defterde durur ama netleşmiştir.
    #    Bu yüzden escrow geçmişini zaman sırasına göre tarayıp her DEBIT'i en
    #    eski açık CREDIT'le eşleştiriyoruz. Geriye kalan açık CREDIT'lerin
    #    transaction_id'leri, gerçekten henüz netleşmemiş "bekleyen" işlemlerdir.
    unsettled_pending_tx_ids: set = set()
    if escrow_id is not None:
        stmt_escrow = (
            select(JournalEntry)
            .where(JournalEntry.account_id == escrow_id)
            .order_by(JournalEntry.created_at.asc(), JournalEntry.id.asc())
        )
        escrow_history = (await db.execute(stmt_escrow)).scalars().all()

        open_credits: list = []  # FIFO kuyruğu — açık CREDIT'ler
        for e in escrow_history:
            if e.direction == JournalDirection.CREDIT:
                open_credits.append(e)
            else:  # DEBIT — en eski açık CREDIT'i kapat
                if open_credits:
                    open_credits.pop(0)

        unsettled_pending_tx_ids = {e.transaction_id for e in open_credits}

    # 1) Benzersiz transaction_id'leri zaman sırasına göre sayfala.
    #    Çift-kayıt muhasebesinde her işlem 2 JournalEntry üretir (ana cüzdan
    #    + escrow). Sayfa başına transaction göstermek için entry bazında değil
    #    transaction bazında `LIMIT/OFFSET` uygulanmalı. Aksi hâlde her işlem
    #    hem "Gelen/Giden" hem "Bekleyen" sekmesinde iki kere görünür.
    stmt_tx_ids = (
        select(
            JournalEntry.transaction_id,
            func.max(JournalEntry.created_at).label("last_at"),
        )
        .where(JournalEntry.account_id.in_(account_ids))
        .group_by(JournalEntry.transaction_id)
        .order_by(func.max(JournalEntry.created_at).desc())
        .limit(limit)
        .offset(offset)
    )
    tx_id_rows = (await db.execute(stmt_tx_ids)).all()
    if not tx_id_rows:
        return TransactionsListResponse(transactions=[])
    tx_ids = [r.transaction_id for r in tx_id_rows]
    tx_order = {tx_id: idx for idx, tx_id in enumerate(tx_ids)}

    # 2) Bu transaction'ların kullanıcıya ait TÜM entries'lerini tek seferde çek.
    #    Escrow + ana cüzdan leg'leri birlikte gelir; pending/settled kararı
    #    bu leg'lerin birleşimine bakarak verilir.
    stmt_entries = (
        select(JournalEntry)
        .options(selectinload(JournalEntry.transaction))
        .where(
            JournalEntry.transaction_id.in_(tx_ids),
            JournalEntry.account_id.in_(account_ids),
        )
    )
    entries = (await db.execute(stmt_entries)).scalars().all()

    # 3) Transaction bazında grupla.
    from collections import defaultdict
    tx_entries: dict = defaultdict(list)
    for e in entries:
        tx_entries[e.transaction_id].append(e)

    items: list[TransactionItem] = []
    for tx_id, entry_list in tx_entries.items():
        tx: Transaction = entry_list[0].transaction

        main_entry = next(
            (e for e in entry_list if e.account_id != escrow_id), None
        )
        escrow_entries = [e for e in entry_list if e.account_id == escrow_id]

        is_truly_pending = tx_id in unsettled_pending_tx_ids

        if main_entry is not None and not is_truly_pending:
            # Ana cüzdanda hareket var ve escrow'da açık CREDIT yok →
            # işlem netleşmiş (tamamlanmış).
            is_pending = False
            is_incoming = main_entry.direction == JournalDirection.CREDIT
            primary_entry = main_entry
        elif is_truly_pending:
            # Escrow'da hâlâ açık CREDIT var → gerçekten "bekleyen" işlem.
            is_pending = True
            is_incoming = None
            # Tutarı escrow CREDIT entry'sinden al (kullanıcıya bekleyen miktarı
            # bu yansıtır).
            primary_entry = next(
                (e for e in escrow_entries if e.direction == JournalDirection.CREDIT),
                escrow_entries[0] if escrow_entries else (main_entry or entry_list[0]),
            )
        elif main_entry is not None:
            # Sadece ana cüzdan hareketi var, escrow yok / netleşmiş → tamamlanmış.
            is_pending = False
            is_incoming = main_entry.direction == JournalDirection.CREDIT
            primary_entry = main_entry
        else:
            # Sadece escrow leg'i var ve FIFO ile netleşmiş — kullanıcıya
            # gösterilecek anlamlı bir görünüm yok, atla.
            continue

        amt_value = float(primary_entry.amount)
        amt_str = (
            f"₺{amt_value:,.2f}"
            .replace(",", "X").replace(".", ",").replace("X", ".")
        )

        if is_pending:
            status_code = 3
            status_text = "Bekliyor"
        elif is_incoming:
            status_code = 1
            status_text = "Tamamlandı"
        else:
            status_code = 2
            status_text = "Tamamlandı"

        items.append(
            TransactionItem(
                id=str(tx.id),
                name=(
                    "Sistem İşlemi" if is_incoming
                    else ("Bekleyen İşlem" if is_pending else "Ödeme Transferi")
                ),
                tckn="Ağ İşlemi",
                amount=(
                    ("+ " if is_incoming else ("" if is_pending else "- "))
                    + amt_str
                ),
                date=primary_entry.created_at.strftime("%d.%m.%Y %H:%M"),
                status=status_text,
                status_code=status_code,
                description=tx.description,
                ref=tx.reference_id or str(tx.id)[:8].upper(),
                is_incoming=is_incoming,
                is_pending=is_pending,
            )
        )

    # 4) İlk sorgudaki sıralamayı koru (zaman sırası).
    items.sort(key=lambda it: tx_order.get(uuid.UUID(it.id), 0))

    return TransactionsListResponse(transactions=items)
