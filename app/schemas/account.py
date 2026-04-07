from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class AccountSummaryResponse(BaseModel):
    total_balance: float = Field(..., description="Cüzdandaki mevcut kullanılabilir Miktar")
    pending_balance: float = Field(..., description="Escrow cüzdanındaki bekleyen bakiye")
    incoming: float = Field(..., description="Hesaba gelen değerlerin (Credit) toplamı")
    outgoing: float = Field(..., description="Hesaptan çıkan değerlerin (Debit) toplamı")

class TransactionItem(BaseModel):
    id: str
    name: str
    tckn: str
    amount: str
    date: str
    status: str
    status_code: int
    description: str
    ref: str
    is_incoming: Optional[bool]
    is_pending: bool = False

class TransactionsListResponse(BaseModel):
    transactions: List[TransactionItem]
