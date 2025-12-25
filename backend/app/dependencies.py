"""Dependency injection for FastAPI."""

from typing import Optional
from app.services.elasticsearch import ElasticsearchService

# Global Elasticsearch service instance
_es_service: Optional[ElasticsearchService] = None


def set_es_service(service: ElasticsearchService):
    """Set the Elasticsearch service instance."""
    global _es_service
    _es_service = service


def get_es_service() -> ElasticsearchService:
    """Get Elasticsearch service instance."""
    if _es_service is None:
        raise RuntimeError("Elasticsearch service not initialized")
    return _es_service


