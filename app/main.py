"""
FastAPI application entry point.
This module is imported by the ASGI server (uvicorn) to start the application.
"""
from main import app, create_app

__all__ = ["app", "create_app"]
