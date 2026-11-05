import os
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
import onnxruntime as ort
from fastapi import FastAPI
from pydantic import BaseModel, Field
from tokenizers import Tokenizer

MODEL = "Xenova/all-MiniLM-L6-v2"
REVISION = "751bff37182d3f1213fa05d7196b954e230abad9"


@asynccontextmanager
async def lifespan(app):
    path = Path("/models")
    if os.environ.get("MODEL_SOURCE") == "remote":
        from huggingface_hub import snapshot_download

        path = Path(snapshot_download(
            MODEL, revision=REVISION,
            allow_patterns=["onnx/model_quantized.onnx", "tokenizer.json"],
        ))
    tokenizer = Tokenizer.from_file(str(path / "tokenizer.json"))
    tokenizer.enable_truncation(max_length=128)
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    app.state.tokenizer = tokenizer
    app.state.model = ort.InferenceSession(
        str(path / "onnx/model_quantized.onnx"), options,
        providers=["CPUExecutionProvider"],
    )
    yield


app = FastAPI(lifespan=lifespan)


class Input(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": True}


@app.post("/infer")
def infer(body: Input):
    tokens = app.state.tokenizer.encode(body.text)
    values = {
        "input_ids": np.array([tokens.ids], dtype=np.int64),
        "attention_mask": np.array([tokens.attention_mask], dtype=np.int64),
        "token_type_ids": np.array([tokens.type_ids], dtype=np.int64),
    }
    inputs = {field.name: values[field.name] for field in app.state.model.get_inputs()}
    hidden = app.state.model.run(None, inputs)[0]
    mask = values["attention_mask"][..., None]
    embedding = (hidden * mask).sum(axis=1) / np.maximum(mask.sum(axis=1), 1)
    embedding /= np.maximum(np.linalg.norm(embedding, axis=1, keepdims=True), 1e-12)
    assert embedding.shape == (1, 384) and np.isfinite(embedding).all()
    return {"dimensions": 384, "embedding": embedding[0].tolist()}
