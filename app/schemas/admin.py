from pydantic import BaseModel, EmailStr


class AdminLoginRequest(BaseModel):
    email: EmailStr
    password: str


class AdminLoginResponse(BaseModel):
    """
    H-12: Admin JWT artık YALNIZCA HttpOnly cookie ile döner.
    Body'de access_token YOK — XSS ile token çalınamaz.
    """
    expires_in: int
    success: bool = True


class AdminLogoutResponse(BaseModel):
    message: str = "Admin oturumu sonlandırıldı."
