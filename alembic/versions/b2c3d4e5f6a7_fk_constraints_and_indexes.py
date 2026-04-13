"""FK constraints ve eksik index'ler

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-04-13 00:00:00.000000

SEC-1: FK eksikliği — 4 tabloda user_id / seller_user_id sütunları users.id'ye
referans vermeden oluşturulmuştu. Referansal bütünlük olmadan:
  - Silinmiş kullanıcılara ait "yetim" kayıtlar kalabilir.
  - Uygulama katmanında fark edilemeyen veri tutarsızlıkları oluşabilir.
  - CASCADE/RESTRICT politikaları uygulanamaz.

PERF-3: web_corporate_applications.submitted_at sütununa index eksikti.
  - list_all() sorgusu ORDER BY submitted_at DESC ile tam tablo taraması yapıyordu.
  - Index eklenerek admin paneli listeleme sorgusu hızlandırıldı.

Eklenen FK'lar:
  - corporate_payments.seller_user_id        → users.id  ON DELETE RESTRICT
  - corporate_receive_requests.seller_user_id → users.id  ON DELETE RESTRICT
  - user_notifications.user_id               → users.id  ON DELETE CASCADE
  - corporate_applications.user_id           → users.id  ON DELETE SET NULL (nullable)

Eklenen index'ler:
  - ix_web_corp_app_submitted_at : web_corporate_applications.submitted_at DESC
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── SEC-1: FK Kısıtlamaları ───────────────────────────────────────────────

    # corporate_payments.seller_user_id → users.id
    # ON DELETE RESTRICT: ödeme geçmişi olan kullanıcı silinemez (veri bütünlüğü)
    op.create_foreign_key(
        "fk_corp_payments_seller_user",
        "corporate_payments",
        "users",
        ["seller_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # corporate_receive_requests.seller_user_id → users.id
    # ON DELETE RESTRICT: alım talebi olan kullanıcı silinemez
    op.create_foreign_key(
        "fk_corp_receive_seller_user",
        "corporate_receive_requests",
        "users",
        ["seller_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # user_notifications.user_id → users.id
    # ON DELETE CASCADE: kullanıcı silinince bildirimleri de silinir (GDPR/KVKK uyumu)
    op.create_foreign_key(
        "fk_notifications_user",
        "user_notifications",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # corporate_applications.user_id → users.id
    # ON DELETE SET NULL: user_id nullable — kullanıcı silinince başvuru kayıt olarak kalır
    op.create_foreign_key(
        "fk_corp_app_user",
        "corporate_applications",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # ── PERF-3: web_corporate_applications submitted_at index ─────────────────
    # Admin panel list_all() → ORDER BY submitted_at DESC tam tablo taramasından kurtarır
    op.create_index(
        "ix_web_corp_app_submitted_at",
        "web_corporate_applications",
        [sa.text("submitted_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_web_corp_app_submitted_at", table_name="web_corporate_applications")
    op.drop_constraint("fk_corp_app_user", "corporate_applications", type_="foreignkey")
    op.drop_constraint("fk_notifications_user", "user_notifications", type_="foreignkey")
    op.drop_constraint("fk_corp_receive_seller_user", "corporate_receive_requests", type_="foreignkey")
    op.drop_constraint("fk_corp_payments_seller_user", "corporate_payments", type_="foreignkey")
