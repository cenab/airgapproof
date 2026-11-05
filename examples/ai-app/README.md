# Offline AI application

This example runs four services: a FastAPI API, an ONNX inference server,
PostgreSQL, and Redis. The API embeds text, saves the result in PostgreSQL,
reads it back, and verifies the cached Redis copy. Recovery tests restart the
API and repeat its dependency-aware health check.

The model is
[Xenova/all-MiniLM-L6-v2](https://huggingface.co/Xenova/all-MiniLM-L6-v2/tree/751bff37182d3f1213fa05d7196b954e230abad9),
pinned to revision `751bff37182d3f1213fa05d7196b954e230abad9`. It produces
384-dimensional sentence embeddings using CPU inference. The example uses
`tokenizer.json` and `onnx/model_quantized.onnx`; it doesn't need PyTorch or a GPU.
Consult the upstream model card and its Apache-2.0 license before redistribution.

The `remote` Docker stage contains application dependencies but no model files.
Its inference service attempts to fetch the model at startup. The `bundled`
stage downloads the pinned artifact while building and enables offline mode for
execution. Both stages use the same application code and functional profile.

Run `make demo` from the repository root. Preparation deliberately uses the
internet. Each subsequent test uses a new isolated project and fresh database
volume. The sample database credentials are for these disposable services only.
