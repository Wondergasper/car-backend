from typing import Optional, List
from pydantic_settings import BaseSettings
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    SUPABASE_DB_URL: Optional[str] = None
    SUPABASE_DB_URL_SYNC: Optional[str] = None
    DATABASE_URL: str = "postgresql+asyncpg://carbot:carbot_password@localhost:5432/carbot"
    DATABASE_URL_SYNC: str = "postgresql://carbot:carbot_password@localhost:5432/carbot"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    GOOGLE_API_KEY: str = ""
    OBJECT_STORAGE_BUCKET: str = "carbot-reports"
    RESEND_API_KEY: str = ""
    RESEND_FROM_EMAIL: str = "noreply@car-bot.ai"
    # Intelligence layer
    HUGGINGFACE_TOKEN: str = ""
    OFFLINE_MODE: bool = False
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
    ]

    @property
    def db_url(self) -> str:
        return self.SUPABASE_DB_URL or self.DATABASE_URL

    @property
    def db_url_sync(self) -> str:
        return self.SUPABASE_DB_URL_SYNC or self.DATABASE_URL_SYNC

    def validate_secret_key(self):
        if self.SECRET_KEY == "your-secret-key-change-in-production":
            logger.warning("SECRET_KEY is set to the insecure default!")

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    s = Settings()
    s.validate_secret_key()
    return s
