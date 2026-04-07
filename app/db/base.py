"""SQLAlchemy DeclarativeBase — tüm modeller buradan miras alır."""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
