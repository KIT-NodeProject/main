from fastapi import FastAPI
from app.api.routes.health import router as health_router
from app.api.routes.targets import router as target_router

app = FastAPI()
app.include_router(health_router)
app.include_router(target_router)
