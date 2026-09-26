import os
import sys
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Kessel Flow Gateway",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "kessel-gateway",
        "pid": os.getpid()
    }

@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    return {"message": "Kessel Flow API Online"}
