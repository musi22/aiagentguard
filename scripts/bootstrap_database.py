"""Run migrations as the Azure PostgreSQL Entra administrator, then grant runtime principals."""
from __future__ import annotations

import os
import subprocess
import sys

from psycopg import sql

from agentguard_api.database import engine


def main() -> None:
    if os.getenv("DATABASE_AUTH") != "entra":
        raise SystemExit("Database bootstrap requires DATABASE_AUTH=entra")
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True)  # noqa: S603
    names = [os.environ["DATABASE_API_PRINCIPAL"], os.environ["DATABASE_WORKER_PRINCIPAL"]]
    with engine.begin() as connection:
        raw = connection.connection.driver_connection
        with raw.cursor() as cursor:
            for name in names:
                cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,))
                if not cursor.fetchone():
                    cursor.execute("SELECT * FROM pgaadauth_create_principal(%s, false, false)", (name,))
            api, worker = map(sql.Identifier, names)
            for principal in (api, worker):
                cursor.execute(sql.SQL("GRANT CONNECT ON DATABASE agentguard TO {} ").format(principal))
                cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {} ").format(principal))
                cursor.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {} ").format(principal))
                cursor.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {} ").format(principal))
                cursor.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {} ").format(principal))
                cursor.execute(sql.SQL("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {} ").format(principal))
            cursor.execute(sql.SQL("ALTER ROLE {} BYPASSRLS").format(worker))


if __name__ == "__main__":
    main()
