from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.email_routes import router as email_router
from app.api.dashboard_routes import router as dashboard_router

app = FastAPI(title="Phishing Email Analyzer")

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static"
)

app.include_router(email_router)
app.include_router(dashboard_router)
