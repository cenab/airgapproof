import json
import os
import urllib.request

import psycopg
import redis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI()
database = os.environ.get("DATABASE_URL", "postgresql://demo:demo@postgres:5432/demo")
cache = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379"), socket_timeout=2)
inference = os.environ.get("INFERENCE_URL", "http://inference:8080")


class Input(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


@app.get("/health")
def health():
    try:
        with psycopg.connect(database, connect_timeout=2) as connection:
            connection.execute("SELECT 1")
        cache.ping()
        with urllib.request.urlopen(inference + "/health", timeout=2) as response:
            assert response.status == 200
    except Exception as error:
        raise HTTPException(503, "An offline dependency is unavailable") from error
    return {"status": "ok"}


@app.post("/workflow")
def workflow(body: Input):
    try:
        request = urllib.request.Request(
            inference + "/infer", data=body.model_dump_json().encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.load(response)
        with psycopg.connect(database, connect_timeout=2) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS inference_results (id BIGSERIAL PRIMARY KEY, result JSONB NOT NULL)")
            row = connection.execute(
                "INSERT INTO inference_results(result) VALUES (%s::jsonb) RETURNING id",
                (json.dumps(result),),
            ).fetchone()
            stored = connection.execute("SELECT result FROM inference_results WHERE id=%s", row).fetchone()[0]
        cache.set(f"result:{row[0]}", json.dumps(stored))
        cached = json.loads(cache.get(f"result:{row[0]}"))
        assert cached["dimensions"] == stored["dimensions"] == 384
        return {"status": "ok", "dimensions": 384, "persisted": True, "cached": True}
    except Exception as error:
        raise HTTPException(503, "Inference, persistence, or caching failed offline") from error
