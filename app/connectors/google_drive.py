"""
Google Drive Connector — Scans Google Drive files for PII.
Connects via Google Drive API, reads supported file types,
extracts text content, and scans for Nigerian personal identifiers.
"""
import json
import logging
import io
from typing import Dict, Any, List, Optional
from datetime import datetime

from app.core.pii_scanner import PIIScanner

logger = logging.getLogger(__name__)


class GoogleDriveConnector:
    """
    Connects to Google Drive, scans files for PII,
    and produces structured audit payloads.
    """

    SUPPORTED_TYPES = {
        "csv": "text/csv",
        "json": "application/json",
        "txt": "text/plain",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pdf": "application/pdf",
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.service_account_key = config.get("service_account_key", "")
        self.folder_id = config.get("folder_id", "")
        self.file_types = config.get("file_types", ["csv", "json", "xlsx", "txt"])
        self.scanner = PIIScanner()
        self.credentials = None

    def _load_credentials(self) -> Dict[str, Any]:
        """Load and validate service account credentials."""
        try:
            if isinstance(self.service_account_key, str):
                creds = json.loads(self.service_account_key)
            else:
                creds = self.service_account_key

            if "type" not in creds or creds.get("type") != "service_account":
                raise ValueError("Invalid service account key: missing 'type' field")

            return creds

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in service account key: {e}")

    def connect(self) -> bool:
        """Test connection to Google Drive API."""
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            creds_dict = self._load_credentials()
            credentials = service_account.Credentials.from_service_account_info(
                creds_dict,
                scopes=["https://www.googleapis.com/auth/drive.readonly"]
            )

            self.credentials = credentials
            drive_service = build("drive", "v3", credentials=credentials)

            # Test: try to list files in the specified folder
            drive_service.files().list(
                q=f"'{self.folder_id}' in parents",
                pageSize=1,
                fields="files(id)"
            ).execute()

            logger.info(f"Successfully connected to Google Drive folder: {self.folder_id}")
            return True

        except ImportError:
            logger.error("Google API libraries not installed. Run: pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib")
            return False
        except Exception as e:
            logger.error(f"Google Drive connection failed: {e}")
            return False

    def list_files(self) -> List[Dict[str, Any]]:
        """List all supported files in the target folder."""
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        if not self.credentials:
            creds_dict = self._load_credentials()
            self.credentials = service_account.Credentials.from_service_account_info(
                creds_dict,
                scopes=["https://www.googleapis.com/auth/drive.readonly"]
            )

        drive_service = build("drive", "v3", credentials=self.credentials)

        # Build MIME type filter
        mime_types = [self.SUPPORTED_TYPES.get(ft) for ft in self.file_types if ft in self.SUPPORTED_TYPES]
        mime_query = " or ".join([f"mimeType='{mt}'" for mt in mime_types if mt])

        if not mime_query:
            mime_query = "mimeType contains 'text' or mimeType contains 'spreadsheet'"

        # Query: files in folder, matching types, not trashed
        query = f"'{self.folder_id}' in parents and trashed=false and ({mime_query})"

        files = []
        page_token = None

        while True:
            response = drive_service.files().list(
                q=query,
                pageSize=100,
                pageToken=page_token,
                fields="files(id, name, mimeType, size, modifiedTime), nextPageToken"
            ).execute()

            files.extend(response.get("files", []))
            page_token = response.get("nextPageToken")

            if not page_token:
                break

        logger.info(f"Found {len(files)} files in Google Drive folder")
        return files

    def read_file_content(self, file_id: str, file_name: str, mime_type: str) -> Optional[str]:
        """Read file content based on file type."""
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload

        drive_service = build("drive", "v3", credentials=self.credentials)

        try:
            ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""

            if ext in ("csv", "txt", "json"):
                # Text-based files: download directly
                request = drive_service.files().get_media(fileId=file_id)
                fh = io.BytesIO()
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while not done:
                    status, done = downloader.next_chunk()

                content = fh.getvalue().decode("utf-8", errors="replace")
                return content

            elif ext in ("xlsx", "docx", "pdf"):
                # Binary files: export or extract text
                # For Google Sheets/Docs, export as text
                if "spreadsheet" in mime_type:
                    # Export as CSV
                    request = drive_service.files().export_media(
                        fileId=file_id,
                        mimeType="text/csv"
                    )
                    fh = io.BytesIO()
                    downloader = MediaIoBaseDownload(fh, request)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()
                    return fh.getvalue().decode("utf-8", errors="replace")

                elif "document" in mime_type:
                    # Export as plain text
                    request = drive_service.files().export_media(
                        fileId=file_id,
                        mimeType="text/plain"
                    )
                    fh = io.BytesIO()
                    downloader = MediaIoBaseDownload(fh, request)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()
                    return fh.getvalue().decode("utf-8", errors="replace")

                else:
                    # PDF or other binary: skip for now
                    logger.info(f"Skipping unsupported binary file: {file_name}")
                    return None

        except Exception as e:
            logger.error(f"Failed to read file {file_name}: {e}")
            return None

        return None

    def scan_file(self, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single Google Drive file for PII."""
        file_id = file_info["id"]
        file_name = file_info["name"]
        mime_type = file_info.get("mimeType", "")

        result = {
            "file_id": file_id,
            "file_name": file_name,
            "mime_type": mime_type,
            "size": file_info.get("size", "unknown"),
            "modified_time": file_info.get("modifiedTime", ""),
            "pii_found": 0,
            "findings": [],
            "status": "skipped",
        }

        content = self.read_file_content(file_id, file_name, mime_type)
        if not content:
            result["status"] = "failed"
            return result

        # Scan content for PII
        findings = self.scanner.scan_text(content, location=f"drive/{file_name}")

        if findings:
            result["pii_found"] = len(findings)
            result["findings"] = [
                {
                    "category": f.category.value if hasattr(f.category, 'value') else str(f.category),
                    "value": f.value,
                    "confidence": f.confidence,
                    "risk_level": f.risk_level,
                }
                for f in findings
            ]
            result["status"] = "flagged"
        else:
            result["status"] = "clean"

        return result

    def run_full_audit(self) -> Dict[str, Any]:
        """
        Run the complete audit pipeline for Google Drive:
        1. Connect to Drive
        2. List files
        3. Read and scan each file
        4. Build structured audit payload
        """
        logger.info(f"Starting Google Drive audit for folder: {self.folder_id}")

        # Step 1: Test connection
        if not self.connect():
            return {
                "status": "failed",
                "error": "Could not connect to Google Drive",
                "connector_type": "google_drive",
                "folder_id": self.folder_id,
            }

        # Step 2: List files
        files = self.list_files()

        # Step 3: Scan each file
        scan_results = []
        total_pii = 0
        flagged_files = []

        for file_info in files:
            result = self.scan_file(file_info)
            scan_results.append(result)
            total_pii += result.get("pii_found", 0)

            if result["status"] == "flagged":
                flagged_files.append({
                    "file_name": result["file_name"],
                    "pii_count": result["pii_found"],
                    "findings": result["findings"],
                })

        # Step 4: Build payload
        # Extract PII findings for rules engine
        all_pii_findings = []
        for r in scan_results:
            for f in r.get("findings", []):
                all_pii_findings.append(f)

        payload = {
            "connector_type": "google_drive",
            "folder_id": self.folder_id,
            "total_files_scanned": len(scan_results),
            "flagged_files_count": len(flagged_files),
            "total_pii_instances": total_pii,
            "flagged_files": flagged_files,
            "pii_findings": all_pii_findings,
            "pii_finding_count": len(all_pii_findings),
            "encryption": {
                "at_rest": True,  # Google Drive encrypts at rest
                "in_transit": True,  # HTTPS
            },
            "access_control_policy": "detected",  # Google Drive has built-in access controls
            "scanned_at": datetime.utcnow().isoformat(),
            "status": "completed",
        }

        logger.info(
            f"Google Drive audit completed: "
            f"{len(scan_results)} files scanned, "
            f"{len(flagged_files)} flagged, "
            f"{total_pii} PII instances"
        )
        return payload
