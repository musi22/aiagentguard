from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def create_database_engine(url: str | None = None) -> Engine:
    settings = get_settings()
    resolved = url or settings.database_url
    creator = None
    if url is None and settings.database_host:
        import psycopg
        from urllib.parse import quote_plus

        if not settings.database_user:
            raise RuntimeError("DATABASE_USER is required when DATABASE_HOST is configured")
        resolved = (
            f"postgresql+psycopg://{quote_plus(settings.database_user)}@{settings.database_host}/"
            f"{quote_plus(settings.database_name)}?sslmode=require"
        )
        if settings.database_auth == "entra":
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential(managed_identity_client_id=settings.azure_client_id)

            def creator():  # type: ignore[no-redef]
                token = credential.get_token("https://ossrdbms-aad.database.windows.net/.default").token
                return psycopg.connect(
                    host=settings.database_host, dbname=settings.database_name, user=settings.database_user,
                    password=token, sslmode="require",
                )
        else:
            from .security import get_secret_store

            def creator():  # type: ignore[no-redef]
                password = get_secret_store().get(settings.database_secret_name)
                return psycopg.connect(
                    host=settings.database_host, dbname=settings.database_name, user=settings.database_user,
                    password=password, sslmode="require",
                )
    connect_args = {"check_same_thread": False} if resolved.startswith("sqlite") else {}
    engine_options = {"creator": creator} if creator is not None else {}
    engine = create_engine(resolved, pool_pre_ping=True, connect_args=connect_args, **engine_options)
    if resolved.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def sqlite_constraints(connection, _: object) -> None:  # type: ignore[no-untyped-def]
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


engine = create_database_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise


def set_tenant_context(session: Session, organization_id: str) -> None:
    session.info["organization_id"] = organization_id
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT set_config('app.current_organization', :org, true)"), {"org": organization_id})


@event.listens_for(Session, "after_begin")
def reapply_tenant_context(session: Session, transaction: object, connection: object) -> None:
    organization_id = session.info.get("organization_id")
    if organization_id and connection.dialect.name == "postgresql":
        connection.execute(
            text("SELECT set_config('app.current_organization', :org, true)"), {"org": organization_id}
        )
