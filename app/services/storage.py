import os
import shutil
from typing import Optional
from app.core.config import get_settings

settings = get_settings()


class ObjectStorageService:
    """
    Simplified storage service using the local filesystem.
    Replaced AWS S3 implementation.
    """

    def __init__(self):
        self.base_dir = "media"
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)

    async def upload_file(self, file_path: str, object_name: str) -> Optional[str]:
        """Upload a file to local storage."""
        try:
            dest_path = os.path.join(self.base_dir, object_name)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy2(file_path, dest_path)
            # In a real local setup, this would be a relative URL served by FastAPI
            return f"/media/{object_name}"
        except Exception as e:
            print(f"Local storage error (upload): {e}")
            return None

    async def download_file(self, object_name: str, file_path: str) -> bool:
        """Download a file from local storage."""
        try:
            src_path = os.path.join(self.base_dir, object_name)
            shutil.copy2(src_path, file_path)
            return True
        except Exception as e:
            print(f"Local storage error (download): {e}")
            return False

    async def get_presigned_url(self, object_name: str, expiration: int = 3600) -> Optional[str]:
        """
        Generate a URL for downloading a file.
        For local storage, returns a direct link.
        """
        return f"http://localhost:8000/media/{object_name}"

    async def delete_file(self, object_name: str) -> bool:
        """Delete a file from local storage."""
        try:
            path = os.path.join(self.base_dir, object_name)
            if os.path.exists(path):
                os.remove(path)
            return True
        except Exception as e:
            print(f"Local storage error (delete): {e}")
            return False


# Singleton instance
object_storage = ObjectStorageService()
