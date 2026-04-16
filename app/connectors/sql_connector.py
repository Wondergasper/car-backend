"""
SQL Connector — Generic database connector for PostgreSQL, MySQL, MSSQL.
Actually queries databases, extracts schema metadata, samples data for PII scanning,
and sends structured payloads to the CAR-Bot event pipeline.
"""
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from app.core.pii_scanner import PIIScanner

logger = logging.getLogger(__name__)


class SQLConnector:
    """
    Connects to SQL databases, extracts metadata and data samples,
    and produces structured audit payloads for the rules engine.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 5432)
        self.database = config.get("database", "")
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.ssl_mode = config.get("ssl_mode", "require")
        self.driver = config.get("driver", "postgresql")  # postgresql, mysql, mssql
        self.scanner = PIIScanner()
        self.connection = None

    def _build_connection_string(self) -> str:
        """Build database connection string based on driver."""
        if self.driver == "postgresql":
            return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}?sslmode={self.ssl_mode}"
        elif self.driver == "mysql":
            return f"mysql+pymysql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        elif self.driver == "mssql":
            return f"mssql+pyodbc://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}?driver=ODBC+Driver+17+for+SQL+Server"
        else:
            raise ValueError(f"Unsupported driver: {self.driver}")

    def connect(self) -> bool:
        """Test connection to the database."""
        try:
            import urllib.parse
            from sqlalchemy import create_engine, text

            conn_string = self._build_connection_string()
            engine = create_engine(conn_string, pool_timeout=10)

            with engine.connect() as conn:
                # Test query
                result = conn.execute(text("SELECT 1"))
                result.fetchone()

            logger.info(f"Successfully connected to {self.database} on {self.host}:{self.port}")
            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def get_schema_metadata(self) -> Dict[str, Any]:
        """
        Extract database schema: tables, columns, row counts, data types.
        This is the primary metadata for the audit rules engine.
        """
        try:
            from sqlalchemy import create_engine, text

            conn_string = self._build_connection_string()
            engine = create_engine(conn_string, pool_timeout=10)

            tables = {}

            with engine.connect() as conn:
                if self.driver == "postgresql":
                    tables = self._get_postgresql_schema(conn)
                elif self.driver == "mysql":
                    tables = self._get_mysql_schema(conn)
                elif self.driver == "mssql":
                    tables = self._get_mssql_schema(conn)

            logger.info(f"Extracted schema metadata: {len(tables)} tables")
            return tables

        except Exception as e:
            logger.error(f"Schema extraction failed: {e}")
            return {}

    def _get_postgresql_schema(self, conn) -> Dict[str, Any]:
        """Extract PostgreSQL schema metadata."""
        from sqlalchemy import text
        tables = {}

        # Get tables with row counts
        result = conn.execute(text("""
            SELECT
                schemaname,
                relname as tablename,
                n_live_tup as row_count,
                pg_size_pretty(pg_total_relation_size(relid)) as total_size
            FROM pg_stat_user_tables
            ORDER BY n_live_tup DESC
        """))

        for row in result:
            tables[row.tablename] = {
                "schema": row.schemaname,
                "row_count": row.row_count,
                "total_size": row.total_size,
                "columns": [],
                "contains_pii": False,
            }

        # Get columns for each table
        for table_name in tables:
            col_result = conn.execute(text("""
                SELECT column_name, data_type, is_nullable, character_maximum_length
                FROM information_schema.columns
                WHERE table_name = :table_name
                ORDER BY ordinal_position
            """), {"table_name": table_name})

            for col in col_result:
                tables[table_name]["columns"].append({
                    "name": col.column_name,
                    "type": col.data_type,
                    "nullable": col.is_nullable,
                    "max_length": col.character_maximum_length,
                })

        return tables

    def _get_mysql_schema(self, conn) -> Dict[str, Any]:
        """Extract MySQL schema metadata."""
        from sqlalchemy import text
        tables = {}

        result = conn.execute(text("""
            SELECT
                TABLE_SCHEMA,
                TABLE_NAME,
                TABLE_ROWS,
                DATA_LENGTH + INDEX_LENGTH as total_size
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = :database
            AND TABLE_TYPE = 'BASE TABLE'
        """), {"database": self.database})

        for row in result:
            tables[row.TABLE_NAME] = {
                "schema": row.TABLE_SCHEMA,
                "row_count": row.TABLE_ROWS,
                "total_size": str(row.total_size),
                "columns": [],
                "contains_pii": False,
            }

        for table_name in tables:
            col_result = conn.execute(text("""
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH
                FROM information_schema.COLUMNS
                WHERE TABLE_NAME = :table_name
                AND TABLE_SCHEMA = :database
                ORDER BY ORDINAL_POSITION
            """), {"table_name": table_name, "database": self.database})

            for col in col_result:
                tables[table_name]["columns"].append({
                    "name": col.COLUMN_NAME,
                    "type": col.DATA_TYPE,
                    "nullable": col.IS_NULLABLE,
                    "max_length": col.CHARACTER_MAXIMUM_LENGTH,
                })

        return tables

    def _get_mssql_schema(self, conn) -> Dict[str, Any]:
        """Extract MSSQL schema metadata."""
        from sqlalchemy import text
        tables = {}

        result = conn.execute(text("""
            SELECT
                s.name as schema_name,
                t.name as table_name,
                p.rows as row_count,
                SUM(a.total_pages) * 8 / 1024 as total_size_mb
            FROM sys.tables t
            JOIN sys.schemas s ON t.schema_id = s.schema_id
            JOIN sys.indexes i ON t.object_id = i.object_id
            JOIN sys.partitions p ON i.object_id = p.object_id AND i.index_id = p.index_id
            JOIN sys.allocation_units a ON p.partition_id = a.container_id
            WHERE t.is_ms_shipped = 0
            GROUP BY s.name, t.name, p.rows
            ORDER BY p.rows DESC
        """))

        for row in result:
            tables[row.table_name] = {
                "schema": row.schema_name,
                "row_count": row.row_count,
                "total_size": f"{row.total_size_mb}MB",
                "columns": [],
                "contains_pii": False,
            }

        for table_name in tables:
            col_result = conn.execute(text("""
                SELECT
                    c.name as column_name,
                    ty.name as data_type,
                    c.is_nullable,
                    c.max_length
                FROM sys.columns c
                JOIN sys.types ty ON c.user_type_id = ty.user_type_id
                JOIN sys.tables t ON c.object_id = t.object_id
                WHERE t.name = :table_name
                ORDER BY c.column_id
            """), {"table_name": table_name})

            for col in col_result:
                tables[table_name]["columns"].append({
                    "name": col.column_name,
                    "type": col.data_type,
                    "nullable": "YES" if col.is_nullable else "NO",
                    "max_length": col.max_length,
                })

        return tables

    def identify_pii_columns(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan column names for potential PII indicators.
        This is a fast pre-check before sampling actual data.
        """
        pii_keywords = [
            "email", "phone", "mobile", "fax",
            "bvn", "bank_verification",
            "nin", "national_id", "identity_number",
            "drivers_license", "drivers_lic",
            "voters_id", "voter_card",
            "passport", "ssn", "social_security",
            "address", "city", "state", "zip", "postal",
            "dob", "birth_date", "date_of_birth",
            "gender", "ethnicity", "race",
            "salary", "income", "credit_score",
            "medical", "diagnosis", "treatment",
            "biometric", "fingerprint", "face",
            "password", "hash", "secret",
        ]

        for table_name, table_info in schema.items():
            pii_columns = []
            for col in table_info.get("columns", []):
                col_name_lower = col["name"].lower()
                if any(kw in col_name_lower for kw in pii_keywords):
                    pii_columns.append(col["name"])

            table_info["pii_columns"] = pii_columns
            table_info["contains_pii"] = len(pii_columns) > 0

        return schema

    def sample_data(self, schema: Dict[str, Any], sample_size: int = 100) -> List[Dict[str, Any]]:
        """
        Sample actual data from tables containing PII columns.
        Returns structured payloads for PII scanning.
        """
        try:
            from sqlalchemy import create_engine, text

            conn_string = self._build_connection_string()
            engine = create_engine(conn_string, pool_timeout=10)

            payloads = []

            with engine.connect() as conn:
                for table_name, table_info in schema.items():
                    if not table_info.get("contains_pii", False):
                        continue

                    pii_cols = table_info.get("pii_columns", [])
                    if not pii_cols:
                        continue

                    # Sample data from this table
                    cols_str = ", ".join([f'"{c}"' for c in pii_cols[:5]])  # Limit to 5 columns
                    query = f"SELECT {cols_str} FROM {table_name} LIMIT {sample_size}"

                    try:
                        result = conn.execute(text(query))
                        columns = result.keys()

                        for row in result:
                            record = dict(zip(columns, row))
                            # Convert non-serializable values
                            record = {k: str(v) if v is not None else "" for k, v in record.items()}
                            payloads.append({
                                "source": f"{self.database}/{table_name}",
                                "record": record,
                            })
                    except Exception as e:
                        logger.warning(f"Failed to sample from {table_name}: {e}")

            logger.info(f"Sampled {len(payloads)} records from {self.database}")
            return payloads

        except Exception as e:
            logger.error(f"Data sampling failed: {e}")
            return []

    def build_audit_payload(self, schema: Dict[str, Any], samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build a structured payload for the CAR-Bot audit pipeline.
        Combines schema metadata with sampled data for rules engine evaluation.
        """
        # Aggregate PII from samples
        pii_findings = []
        for sample in samples:
            record = sample.get("record", {})
            findings = self.scanner.scan_dict(record, location=sample.get("source", "unknown"))
            pii_findings.extend([f.__dict__ if hasattr(f, '__dict__') else f for f in findings])

        # Identify personal data fields
        personal_data_fields = set()
        for table_name, table_info in schema.items():
            for col in table_info.get("pii_columns", []):
                personal_data_fields.add(f"{table_name}.{col}")

        # Count total rows and PII-containing tables
        total_rows = sum(t.get("row_count", 0) for t in schema.values())
        pii_tables = [t for t, info in schema.items() if info.get("contains_pii", False)]

        return {
            "connector_type": "sql",
            "database": self.database,
            "driver": self.driver,
            "host": self.host,
            "encryption": {
                "at_rest": self.ssl_mode != "disable",  # SSL implieses encryption in transit
                "in_transit": self.ssl_mode in ("require", "verify-ca", "verify-full"),
            },
            "authentication_methods": ["password"],  # Default, could be extended
            "schema": {
                "total_tables": len(schema),
                "total_rows": total_rows,
                "pii_tables": pii_tables,
                "pii_tables_count": len(pii_tables),
            },
            "personal_data_fields": list(personal_data_fields),
            "pii_findings": pii_findings,
            "pii_finding_count": len(pii_findings),
            "sample_record_count": len(samples),
            "scanned_at": datetime.utcnow().isoformat(),
        }

    def run_full_audit(self) -> Dict[str, Any]:
        """
        Run the complete audit pipeline for this SQL connector:
        1. Connect to database
        2. Extract schema metadata
        3. Identify PII columns
        4. Sample data from PII-containing tables
        5. Scan samples for PII
        6. Build structured audit payload
        """
        logger.info(f"Starting SQL connector audit for {self.database}")

        # Step 1: Test connection
        if not self.connect():
            return {
                "status": "failed",
                "error": "Could not connect to database",
                "connector_type": "sql",
                "database": self.database,
            }

        # Step 2: Extract schema
        schema = self.get_schema_metadata()

        # Step 3: Identify PII columns
        schema = self.identify_pii_columns(schema)

        # Step 4: Sample data
        samples = self.sample_data(schema, sample_size=100)

        # Step 5-6: Build payload
        payload = self.build_audit_payload(schema, samples)
        payload["status"] = "completed"

        logger.info(f"SQL connector audit completed: {payload['pii_finding_count']} PII findings")
        return payload
