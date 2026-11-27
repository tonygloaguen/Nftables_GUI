from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import AsyncIterator, Literal, Self
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import Field, JsonValue, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from nft_gui.api.homepage import ASSETS, homepage
from nft_gui.config import Settings
from nft_gui.errors import NftError, UnsupportedError
from nft_gui.executor import NftExecutor
from nft_gui.executor.policy import MAX_SOURCE_BYTES
from nft_gui.executor.policy import prepare_source
from nft_gui.generator import generate_nft
from nft_gui.models import Ruleset
from nft_gui.models.ruleset import Model
from nft_gui.parser import from_nft_json, from_nft_text, to_nft_json
from nft_gui.storage import atomic_write, digest, read_private
from nft_gui.transactions import TransactionManager
from nft_gui.templates import catalog, preview_template
from nft_gui.templates.schema import PreviewRequest


class SourceRequest(Model):
    source: str | None = Field(default=None, min_length=1, max_length=MAX_SOURCE_BYTES)
    ruleset: Ruleset | None = None

    @model_validator(mode="after")
    def exclusive_input(self) -> Self:
        if (self.source is None) == (self.ruleset is None):
            raise ValueError("Provide exactly one of source or ruleset")
        return self

    def render(self) -> str:
        if self.source is not None:
            return self.source
        assert self.ruleset is not None
        return generate_nft(self.ruleset)


class ApplyRequest(SourceRequest):
    confirm_seconds: int | None = Field(default=None, ge=15, le=300)


class TextRequest(Model):
    source: str = Field(max_length=MAX_SOURCE_BYTES)


class ExportRequest(SourceRequest):
    format: Literal["nft", "json", "ir"] = "nft"


class RestoreRequest(Model):
    confirm_seconds: int | None = Field(default=None, ge=15, le=300)


class RequestGuard:
    """Token, same-origin and bounded bodies before FastAPI consumes JSON."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        token = self.settings.api_token
        public_shell = scope["method"] in {"GET", "HEAD"} and (
            scope["path"] in {"/", "/session"} or scope["path"].startswith("/assets/"))
        if token and not public_shell:
            supplied = request.headers.get("authorization", "")
            expected = "Bearer " + token
            if not secrets.compare_digest(supplied.encode(), expected.encode()):
                await JSONResponse({"detail": "Authentication required"}, 401,
                                   headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
                return
        origin = request.headers.get("origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or parsed.netloc != request.headers.get("host"):
                await JSONResponse({"detail": "Cross-origin request rejected"}, 403)(scope, receive, send)
                return
        if request.headers.get("sec-fetch-site") == "cross-site":
            await JSONResponse({"detail": "Cross-site request rejected"}, 403)(scope, receive, send)
            return
        if scope["method"] in {"POST", "PUT", "PATCH"}:
            content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                await JSONResponse({"detail": "application/json required"}, 415)(scope, receive, send)
                return
        # JSON escaping may expand source length. Bound the complete request as well.
        limit = MAX_SOURCE_BYTES * 3
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > limit:
                await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        consumed = False

        async def bounded_receive() -> Message:
            nonlocal consumed
            if consumed:
                return await receive()
            consumed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, bounded_receive, send)


def create_app(settings: Settings | None = None, *, executor: NftExecutor | None = None,
               manager: TransactionManager | None = None) -> FastAPI:
    config = settings or Settings.from_env()
    executor = executor or NftExecutor(config)
    manager = manager or TransactionManager(executor)
    service, transactions = executor, manager

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await run_in_threadpool(transactions.recover)
        yield
        # A pending transaction remains armed after the API shuts down.

    app = FastAPI(title="Nftables GUI", version="0.1.0", lifespan=lifespan)
    app.state.executor = service
    app.state.transactions = transactions
    app.mount("/assets", StaticFiles(directory=ASSETS), name="assets")
    app.add_middleware(RequestGuard, settings=config)
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=list({"127.0.0.1", "localhost", "[::1]", config.host}))

    @app.exception_handler(NftError)
    async def nft_error(request: Request, exc: NftError) -> JSONResponse:
        code = 409 if exc.code == "conflict" else 422
        if exc.code == "not_found":
            code = 404
        elif exc.code == "timeout":
            code = 504
        elif exc.code in {"execution_unavailable", "execution_failed", "watchdog_unavailable"}:
            code = 503
        elif exc.code in {"corrupt_state", "corrupt_snapshot", "backend_mismatch", "unsafe_path"}:
            code = 500
        return JSONResponse({"detail": exc.detail()}, status_code=code)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> HTMLResponse:
        return HTMLResponse(homepage(), headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; "
                                       "connect-src 'self'; img-src 'self' data:; "
                                       "base-uri 'none'; frame-ancestors 'none'",
        })

    @app.get("/session")
    def session() -> dict[str, bool]:
        return {"authentication_required": bool(config.api_token)}

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "backend": config.backend, "live": service.live,
                "confirmation_seconds": config.default_confirm_seconds}

    @app.get("/ruleset")
    def read_ruleset() -> dict[str, object]:
        if service.live:
            ruleset = from_nft_json(service.read_json())
            try:
                source: str | None = generate_nft(ruleset)
                warning: str | None = None
            except UnsupportedError as exc:
                source, warning = None, str(exc)
        else:
            source = service.read_source()
            ruleset = from_nft_text(source)
            warning = None
            try:
                cached = Ruleset.model_validate_json(read_private(
                    service.directory / "views" / f"{digest(source)}.json"))
                if prepare_source(generate_nft(cached)) == source:
                    ruleset = cached
            except (OSError, ValueError, NftError):
                pass
        return {"ruleset": ruleset.model_dump(mode="json"), "source": source, "warning": warning}

    @app.get("/templates")
    def templates() -> dict[str, object]:
        return catalog()

    @app.post("/templates/{template_id}/preview")
    def template_preview(template_id: str, document: PreviewRequest) -> dict[str, object]:
        # Pure construction: no executor, filesystem write or active ruleset mutation.
        return preview_template(template_id, document.values)

    @app.post("/parse/json", response_model=Ruleset)
    def parse_json(document: dict[str, JsonValue]) -> Ruleset:
        return from_nft_json(document)

    @app.post("/parse/text", response_model=Ruleset)
    def parse_text(document: TextRequest) -> Ruleset:
        return from_nft_text(document.source)

    @app.post("/parse/ir", response_model=Ruleset)
    def parse_ir(document: Ruleset) -> Ruleset:
        return document

    @app.post("/generate")
    def generate(ruleset: Ruleset) -> dict[str, object]:
        return {"source": generate_nft(ruleset), "nft_validated": False}

    @app.post("/validate")
    def validate(document: SourceRequest) -> dict[str, object]:
        source = service.check(document.render())
        return {"valid": True, "source": source, "ruleset_hash": digest(source)}

    @app.post("/transactions", status_code=201)
    def apply(document: ApplyRequest) -> dict[str, object]:
        result = transactions.apply(document.render(), confirm_seconds=document.confirm_seconds)
        response = asdict(result)
        if document.ruleset is not None and not service.live:
            try:
                atomic_write(service.directory / "views" / f"{result.ruleset_hash}.json",
                             document.ruleset.model_dump_json())
            except (OSError, NftError):
                response["editor_warning"] = "La vue visuelle n'a pas pu être sauvegardée ; la source reste disponible."
        return response

    @app.get("/transactions/pending")
    def pending() -> dict[str, object]:
        current = transactions.current()
        return {"transaction": asdict(current) if current else None}

    @app.get("/audit")
    def audit(limit: int = Query(default=100, ge=1, le=200)) -> dict[str, object]:
        return {"entries": service.audit.tail(limit)}

    @app.get("/snapshots")
    def snapshots() -> dict[str, object]:
        entries: list[dict[str, object]] = []
        for path in sorted(transactions.snapshots.glob("*.nft"), reverse=True)[:100]:
            if path.is_symlink():
                continue
            try:
                created = datetime.strptime(path.stem.split("-")[0], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
                entries.append({"id": path.stem, "created_at": created.isoformat(),
                                "size": path.stat().st_size})
            except ValueError:
                continue
        return {"snapshots": entries}

    @app.get("/snapshots/{snapshot_id}")
    def snapshot(snapshot_id: str) -> dict[str, str]:
        return {"source": transactions.snapshot_source(snapshot_id)}

    @app.post("/snapshots/{snapshot_id}/restore", status_code=201)
    def restore(snapshot_id: str, document: RestoreRequest) -> dict[str, object]:
        return asdict(transactions.apply(transactions.snapshot_source(snapshot_id),
                                         confirm_seconds=document.confirm_seconds))

    @app.get("/transactions/{transaction_id}")
    def transaction(transaction_id: str) -> dict[str, object]:
        return asdict(transactions.get(transaction_id))

    @app.post("/transactions/{transaction_id}/confirm")
    def confirm(transaction_id: str) -> dict[str, object]:
        return asdict(transactions.confirm(transaction_id))

    @app.post("/transactions/{transaction_id}/rollback")
    def rollback(transaction_id: str) -> dict[str, object]:
        return asdict(transactions.rollback(transaction_id))

    @app.post("/export")
    def export(document: ExportRequest) -> Response:
        if document.format == "nft":
            source = service.check(document.render())
            response: Response = PlainTextResponse(source, headers={
                "Content-Disposition": 'attachment; filename="ruleset.nft"'})
        else:
            ruleset = document.ruleset or from_nft_text(document.source or "")
            data = to_nft_json(ruleset) if document.format == "json" else ruleset.model_dump(mode="json")
            source = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
            response = Response(source, media_type="application/json", headers={
                "Content-Disposition": f'attachment; filename="ruleset.{document.format}.json"'})
        service.audit.record("export", "ok", digest(source))
        return response

    return app
