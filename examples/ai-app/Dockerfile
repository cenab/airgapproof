FROM python:3.13-slim-bookworm AS base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py inference.py ./
ENV PYTHONUNBUFFERED=1 HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_ETAG_TIMEOUT=2 HF_HUB_DOWNLOAD_TIMEOUT=2
EXPOSE 8080
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8080"]

FROM base AS remote
ENV MODEL_SOURCE=remote

FROM base AS bundled
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('Xenova/all-MiniLM-L6-v2', revision='751bff37182d3f1213fa05d7196b954e230abad9', allow_patterns=['onnx/model_quantized.onnx', 'tokenizer.json'], local_dir='/models')"
ENV MODEL_SOURCE=local HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
