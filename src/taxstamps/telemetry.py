"""OpenTelemetry wiring for tax-stamps (Phase-7 OTel wave).

Contract (OTEL_DESIGN.md §1/§2):

- ``OTEL_EXPORTER_OTLP_ENDPOINT`` unset => telemetry is DISABLED; every
  entry point is a no-op that never breaks boot, settlement or any request.
  This is the platform's one sanctioned fail-open.
- When set: OTLP gRPC span and metric exporters behind batch/async
  processors (non-blocking). A down collector means spans are dropped and
  counted on ``telemetry_dropped_total`` — never a settlement failure.
- Graceful shutdown flushes with a hard 5s bound.
- Propagation is W3C tracecontext + baggage; ``tenant.id`` and ``agency``
  baggage entries are copied onto every server span as attributes. Metrics
  stay low-cardinality (no tenant labels, no account/assessment ids).
"""

from __future__ import annotations

import logging
import os
from collections.abc import MutableMapping
from typing import Any

from opentelemetry import baggage, context, propagate, trace
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.propagators.textmap import Setter
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

log = logging.getLogger(__name__)

ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"
TENANT_ATTRIBUTES = ("tenant.id", "agency")
SHUTDOWN_FLUSH_TIMEOUT_MILLIS = 5_000
DROPPED_METRIC = "telemetry_dropped_total"

_propagator = CompositePropagator(
    [TraceContextTextMapPropagator(), W3CBaggagePropagator()]
)


class _DictSetter(Setter[MutableMapping[str, str]]):
    def set(self, carrier: MutableMapping[str, str], key: str, value: str) -> None:
        carrier[key] = value


def telemetry_enabled(environ: dict[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return bool(env.get(ENDPOINT_ENV, "").strip())


def get_tracer(name: str = "taxstamps") -> trace.Tracer:
    """A tracer from the global provider (no-op when telemetry is disabled)."""
    return trace.get_tracer(name)


def inject_context(carrier: MutableMapping[str, str]) -> MutableMapping[str, str]:
    """Inject the current W3C tracecontext+baggage into a message carrier."""
    _propagator.inject(carrier, setter=_DictSetter())
    return carrier


def extract_context(carrier: MutableMapping[str, str] | dict[str, str]) -> context.Context:
    """Extract a W3C tracecontext+baggage context from a message carrier."""
    return _propagator.extract(carrier)


class _DropCountingSpanExporter:
    """SpanExporter wrapper: collector-down = drop + count, never raise."""

    def __init__(self, inner: Any, dropped_counter: Any = None) -> None:
        self._inner = inner
        self._dropped = dropped_counter

    def export(self, spans: Any) -> Any:
        from opentelemetry.sdk.trace.export import SpanExportResult

        try:
            return self._inner.export(spans)
        except Exception as exc:  # collector down: drop-with-metric
            if self._dropped is not None:
                self._dropped.add(len(spans))
            log.warning("otel span export dropped %d span(s): %s", len(spans), exc)
            return SpanExportResult.FAILURE

    def shutdown(self) -> None:
        self._inner.shutdown()

    def force_flush(self, timeout_millis: int = SHUTDOWN_FLUSH_TIMEOUT_MILLIS) -> bool:
        return self._inner.force_flush(timeout_millis)


def _resource(service_name: str, version: str) -> Resource:
    return Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", service_name),
            "service.namespace": "blueeconomy",
            "service.version": version,
            "deployment.environment": os.environ.get("OTEL_ENVIRONMENT", "production"),
        }
    )


def tenant_server_request_hook(span: trace.Span, scope: dict[str, Any]) -> None:
    """FastAPI server-request hook: baggage tenant.id/agency -> span attrs."""
    if span is None or not span.is_recording():
        return
    headers = {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in scope.get("headers", [])
    }
    ctx = _propagator.extract(headers)
    for key in TENANT_ATTRIBUTES:
        value = baggage.get_baggage(key, context=ctx)
        if value:
            span.set_attribute(key, value)


def _instrument_clients() -> None:
    """Best-effort auto-instrumentation of the client libs actually in use."""
    for label, install in (
        ("sqlalchemy", lambda: __import__(
            "opentelemetry.instrumentation.sqlalchemy", fromlist=["SQLAlchemyInstrumentor"]
        ).SQLAlchemyInstrumentor().instrument()),
        ("redis", lambda: __import__(
            "opentelemetry.instrumentation.redis", fromlist=["RedisInstrumentor"]
        ).RedisInstrumentor().instrument()),
        ("httpx", lambda: __import__(
            "opentelemetry.instrumentation.httpx", fromlist=["HTTPXClientInstrumentor"]
        ).HTTPXClientInstrumentor().instrument()),
        ("aiokafka", lambda: __import__(
            "opentelemetry.instrumentation.aiokafka", fromlist=["AIOKafkaInstrumentor"]
        ).AIOKafkaInstrumentor().instrument()),
    ):
        try:
            install()
        except Exception as exc:
            log.warning("otel %s instrumentation unavailable: %s", label, exc)


def init_telemetry(app: Any = None, *, service_name: str, version: str) -> bool:
    """Configure providers + auto-instrumentation. No-op when disabled.

    Returns True when telemetry was enabled. Never raises — a misconfigured
    collector endpoint must not break the business path.
    """
    if not telemetry_enabled():
        log.info("otel disabled (%s unset)", ENDPOINT_ENV)
        return False
    try:
        from opentelemetry import metrics
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = _resource(service_name, version)

        meter_provider = MeterProvider(
            resource=resource,
            metric_readers=[
                PeriodicExportingMetricReader(
                    OTLPMetricExporter(), export_interval_millis=30_000
                )
            ],
        )
        metrics.set_meter_provider(meter_provider)
        dropped = meter_provider.get_meter(service_name).create_counter(
            DROPPED_METRIC,
            description="telemetry items dropped because the collector was unavailable",
        )

        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(
                _DropCountingSpanExporter(OTLPSpanExporter(), dropped),
                export_timeout_millis=SHUTDOWN_FLUSH_TIMEOUT_MILLIS,
            )
        )
        trace.set_tracer_provider(tracer_provider)
        propagate.set_global_textmap(_propagator)

        if app is not None:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(
                app, server_request_hook=tenant_server_request_hook
            )
        _instrument_clients()

        import atexit

        atexit.register(shutdown_telemetry)
        log.info("otel enabled -> %s", os.environ[ENDPOINT_ENV])
        return True
    except Exception as exc:  # fail-open: telemetry must never break boot
        log.warning("otel init failed; telemetry disabled: %s", exc)
        return False


def shutdown_telemetry() -> None:
    """Flush + shutdown providers, bounded at <=5s (graceful shutdown)."""
    tracer_provider = trace.get_tracer_provider()
    shutdown = getattr(tracer_provider, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown()
        except Exception:
            log.warning("otel tracer shutdown failed", exc_info=True)
    from opentelemetry import metrics

    meter_provider = metrics.get_meter_provider()
    shutdown = getattr(meter_provider, "shutdown", None)
    if callable(shutdown):
        try:
            shutdown()
        except Exception:
            log.warning("otel meter shutdown failed", exc_info=True)
