import uuid
from decimal import Decimal
from sqlalchemy.ext.asyncio import AsyncSession
from app.repositories.accounting_repo import AccountingRepository
from app.models.accounting import AccountType

class AccountingService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AccountingRepository(db)

    async def setup_user_wallet(self, user_id: uuid.UUID) -> None:
        """
        Kullanıcı kayıt olduğunda otomatik olarak Liability hesabını (Cüzdan) oluşturur.
        Bankanın bakış açısıyla müşterinin parası Liability'dir.
        """
        # Kullanıcının zaten bir cüzdanı var mı?
        existing = await self.repo.get_user_primary_wallet(user_id)
        if existing:
            return

        await self.repo.create_account(
            name="Ana Cüzdan",
            type=AccountType.LIABILITY,
            user_id=user_id,
            currency="TRY",
            initial_balance=Decimal('0.0000')
        )

        await self.repo.create_account(
            name="escrow",
            type=AccountType.LIABILITY,
            user_id=user_id,
            currency="TRY",
            initial_balance=Decimal('0.0000')
        )
