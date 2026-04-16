import boto3
from botocore.exceptions import ClientError
from typing import Optional
from app.core.config import get_settings

settings = get_settings()


class ObjectStorageService:
    """Service for managing object storage (S3-compatible)."""

    def __init__(self):
        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION,
        )
        self.bucket = settings.OBJECT_STORAGE_BUCKET

    async def upload_file(self, file_path: str, object_name: str) -> Optional[str]:
        """Upload a file to object storage."""
        try:
            self.s3_client.upload_file(file_path, self.bucket, object_name)
            return f"https://{self.bucket}.s3.{settings.AWS_REGION}.amazonaws.com/{object_name}"
        except ClientError as e:
            print(f"Error uploading file: {e}")
            return None

    async def download_file(self, object_name: str, file_path: str) -> bool:
        """Download a file from object storage."""
        try:
            self.s3_client.download_file(self.bucket, object_name, file_path)
            return True
        except ClientError as e:
            print(f"Error downloading file: {e}")
            return False

    async def get_presigned_url(self, object_name: str, expiration: int = 3600) -> Optional[str]:
        """Generate a presigned URL for downloading a file."""
        try:
            response = self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": object_name},
                ExpiresIn=expiration,
            )
            return response
        except ClientError as e:
            print(f"Error generating presigned URL: {e}")
            return None

    async def delete_file(self, object_name: str) -> bool:
        """Delete a file from object storage."""
        try:
            self.s3_client.delete_object(Bucket=self.bucket, Key=object_name)
            return True
        except ClientError as e:
            print(f"Error deleting file: {e}")
            return False


# Singleton instance
object_storage = ObjectStorageService()
