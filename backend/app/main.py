"""Main FastAPI application entry point."""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import structlog

from app.config import get_settings
from app.dependencies import set_es_service
from app.services.elasticsearch import ElasticsearchService

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    settings = get_settings()
    
    # Initialize Elasticsearch connection
    es_service = ElasticsearchService(settings.elasticsearch_url)
    await es_service.connect()
    set_es_service(es_service)
    logger.info("Elasticsearch connection established")
    
    yield
    
    # Cleanup
    await es_service.close()
    logger.info("Elasticsearch connection closed")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="Honeypot Monitoring API",
        description="Backend API for honeypot monitoring dashboard",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    
    # Add rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
    
    # Request logging middleware
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        logger.info(
            "request_processed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            process_time=f"{process_time:.3f}s",
            client_ip=request.client.host if request.client else "unknown"
        )
        
        return response
    
    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "service": "honeypot-monitoring-api"}
    
    # Import routers after app creation to avoid circular imports
    from app.auth.routes import router as auth_router
    from app.routers.dashboard import router as dashboard_router
    from app.routers.cowrie import router as cowrie_router
    from app.routers.dionaea import router as dionaea_router
    from app.routers.galah import router as galah_router
    from app.routers.rdpy import router as rdpy_router
    from app.routers.heralding import router as heralding_router
    from app.routers.firewall import router as firewall_router
    from app.routers.attackmap import router as attackmap_router
    from app.routers.attacker import router as attacker_router
    
    # Include routers
    app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
    app.include_router(dashboard_router, prefix="/api/dashboard", tags=["Dashboard"])
    app.include_router(cowrie_router, prefix="/api/cowrie", tags=["Cowrie"])
    app.include_router(dionaea_router, prefix="/api/dionaea", tags=["Dionaea"])
    app.include_router(galah_router, prefix="/api/galah", tags=["Galah"])
    app.include_router(rdpy_router, prefix="/api/rdpy", tags=["RDPY"])
    app.include_router(heralding_router, prefix="/api/heralding", tags=["Heralding"])
    app.include_router(firewall_router, prefix="/api/firewall", tags=["Firewall"])
    app.include_router(attackmap_router, prefix="/api/attackmap", tags=["Attack Map"])
    app.include_router(attacker_router, prefix="/api/attacker", tags=["Attacker"])
    
    return app


app = create_app()
