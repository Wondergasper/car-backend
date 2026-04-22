"""Backwards-compatible schema updates for older deployed databases."""

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncConnection


async def ensure_connector_webhook_secret_column(conn: AsyncConnection) -> None:
    """Add connectors.webhook_secret when the table predates that column.

    Render and similar deploys can boot against an existing database that was
    created before the Connector model gained webhook_secret. Base.metadata.create_all()
    does not alter existing tables, so we patch the column in place.
    """

    def _missing_webhook_secret(sync_conn) -> bool:
        inspector = inspect(sync_conn)
        if "connectors" not in inspector.get_table_names():
            return False

        existing_columns = {column["name"] for column in inspector.get_columns("connectors")}
        return "webhook_secret" not in existing_columns

    if await conn.run_sync(_missing_webhook_secret):
        await conn.execute(
            text("ALTER TABLE connectors ADD COLUMN webhook_secret VARCHAR(255)")
        )


async def ensure_connector_events_connector_id_nullable(conn: AsyncConnection) -> None:
    """Relax connector_events.connector_id for org-level manual uploads.

    Older deployed databases may still have a NOT NULL constraint on
    connector_events.connector_id even though the application now stores
    org-scoped `manual_file_upload` events without a connector.
    """

    def _connector_id_is_not_nullable(sync_conn) -> bool:
        inspector = inspect(sync_conn)
        if "connector_events" not in inspector.get_table_names():
            return False

        for column in inspector.get_columns("connector_events"):
            if column["name"] == "connector_id":
                return not column.get("nullable", True)

        return False

    if await conn.run_sync(_connector_id_is_not_nullable):
        await conn.execute(
            text("ALTER TABLE connector_events ALTER COLUMN connector_id DROP NOT NULL")
        )
