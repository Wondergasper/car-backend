from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://carbot:carbot_password@localhost:5432/carbot"
    DATABASE_URL_SYNC: str = "postgresql://carbot:carbot_password@localhost:5432/carbot"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    GOOGLE_API_KEY: str = ""
    OBJECT_STORAGE_BUCKET: str = "carbot-reports"

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
