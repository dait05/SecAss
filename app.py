"""安全情报分析助手 —— FastAPI 服务入口"""

from __future__ import annotations
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from agent import SecurityAgent

app = FastAPI(title="Security Intelligence Agent")
templates = Jinja2Templates(directory="templates")
agent = SecurityAgent()


class ChatRequest(BaseModel):
    message: str


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/chat")
async def chat(req: ChatRequest):
    async def stream():
        async for chunk in agent.chat(req.message):
            yield chunk

    return StreamingResponse(stream(), media_type="text/plain; charset=utf-8")


@app.post("/api/reset")
async def reset():
    agent.reset()
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=7860, reload=True)
