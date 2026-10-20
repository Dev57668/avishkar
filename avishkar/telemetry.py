"""Structured logs + optional OpenTelemetry traces. Never records source, secrets or prompts.

Tracing is off unless AVISHKAR_OTEL=1; with OTEL_EXPORTER_OTLP_ENDPOINT set it exports over OTLP/HTTP.
If the opentelemetry packages are missing everything degrades to no-ops. Span attributes are restricted to an
allowlist of safe, low-sensitivity keys.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import time

SAFE_ATTRS = {"correlation_id", "stage", "job_id", "run_id", "kind", "status", "outcome", "detector", "org_id",
              "attempt", "duration_ms", "event"}
_tracer = None
log = logging.getLogger("avishkar")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        d = {"ts": round(record.created, 3), "level": record.levelname, "msg": record.getMessage()}
        d.update({k: v for k, v in getattr(record, "ctx", {}).items() if k in SAFE_ATTRS})
        return json.dumps(d)


def configure_logging(level=None):
    if not any(isinstance(h.formatter, JsonFormatter) for h in log.handlers):
        h = logging.StreamHandler()
        h.setFormatter(JsonFormatter())
        log.addHandler(h)
    log.setLevel(level or os.environ.get("AVISHKAR_LOG_LEVEL", "INFO"))
    log.propagate = False


def configure_tracing(exporter=None) -> bool:
    """Enable tracing. `exporter` is injectable for tests; otherwise OTLP/HTTP from env. Returns True if active."""
    global _tracer
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
    except ImportError:
        return False
    if exporter is None:
        if os.environ.get("AVISHKAR_OTEL") != "1":
            return False
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError:
            return False
        exporter, proc = OTLPSpanExporter(), BatchSpanProcessor
    else:
        proc = SimpleSpanProcessor
    provider = TracerProvider(resource=Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "avishkar")}))
    provider.add_span_processor(proc(exporter))
    _tracer = provider.get_tracer("avishkar")  # private provider: never mutates global OTel state
    return True


def disable_tracing():
    global _tracer
    _tracer = None


@contextlib.contextmanager
def span(name: str, **attrs):
    """Trace + log one stage with duration. Unknown attribute keys are dropped (allowlist)."""
    safe = {k: v for k, v in attrs.items() if k in SAFE_ATTRS and v is not None}
    t0 = time.time()
    cm = _tracer.start_as_current_span(name, attributes={k: str(v) for k, v in safe.items()}) if _tracer \
        else contextlib.nullcontext()
    err = None
    with cm as sp:
        try:
            yield sp
        except Exception as e:
            err = type(e).__name__
            if sp is not None:
                sp.set_attribute("error.type", err)
            raise
        finally:
            ms = int((time.time() - t0) * 1000)
            log.info(name, extra={"ctx": {**safe, "duration_ms": ms, **({"outcome": f"error:{err}"} if err else {})}})
