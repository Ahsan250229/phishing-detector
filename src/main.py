import os
import uuid
import time
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from auth.routes import router as auth_router
app.include_router(auth_router)


from src.api.routes import router as api_router

APP_ENV = os.getenv("APP_ENV", "development")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(level=LOG_LEVEL, format="%(message)s")
logger = logging.getLogger("phishing-detector")

app = FastAPI(
    title="Phishing Email Detector",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

@app.middleware("http")
async def add_request_id_and_logging(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start = time.time()

    try:
        response = await call_next(request)
    except Exception:
        # Do not leak stack traces to clients
        logger.exception(
            '{"event":"unhandled_exception","request_id":"%s","path":"%s"}',
            request_id, str(request.url.path)
        )
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "request_id": request_id},
        )

    latency_ms = int((time.time() - start) * 1000)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"

    logger.info(
        '{"event":"http_request","request_id":"%s","method":"%s","path":"%s","status_code":%d,"latency_ms":%d}',
        request_id, request.method, str(request.url.path), response.status_code, latency_ms
    )
    return response

app.include_router(api_router, prefix="/api")
