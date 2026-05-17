from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Asura"
    database_url: str = "sqlite:///./asura.db"
    redis_url: str = "redis://localhost:6379/0"
    asura_mode: str = "passive"
    asura_evidence_dir: str = "./evidence"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

