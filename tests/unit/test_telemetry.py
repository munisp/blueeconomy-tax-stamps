"""Phase-7 OTel tests: disabled-mode boot, propagation round-trip, tenant baggage."""

from __future__ import annotations

import pytest
from opentelemetry import baggage, context, trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from taxstamps import telemetry


@pytest.fixture()
def memory_exporter():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter, provider


def test_disabled_by_default_without_endpoint(monkeypatch):
    monkeypatch.delenv(telemetry.ENDPOINT_ENV, raising=False)
    assert telemetry.telemetry_enabled() is False
    assert telemetry.init_telemetry(None, service_name="t", version="0") is False
    with telemetry.get_tracer().start_as_current_span("noop") as span:
        assert span.is_recording() is False


def test_disabled_mode_app_constructs(monkeypatch):
    """Telemetry-off: the FastAPI app object imports and builds unchanged."""
    monkeypatch.delenv(telemetry.ENDPOINT_ENV, raising=False)
    from taxstamps.main import app

    assert app is not None
    # Settlement tracer stays a no-op when disabled.
    from taxstamps.services import payments

    with payments._tracer.start_as_current_span("taxstamps.settlement.receipt") as span:
        assert span.is_recording() is False


def test_propagation_round_trip(memory_exporter):
    exporter, provider = memory_exporter
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("producer") as span:
        ctx = baggage.set_baggage("tenant.id", "tenant-9")
        ctx = baggage.set_baggage("agency", "FMMBE", context=ctx)
        token = context.attach(ctx)
        try:
            carrier: dict[str, str] = {}
            telemetry.inject_context(carrier)
        finally:
            context.detach(token)
        expected_trace_id = span.get_span_context().trace_id

    assert "traceparent" in carrier and "baggage" in carrier
    # Simulate a Kafka record carrier (headers arrive as bytes tuples).
    extracted = telemetry.extract_context(carrier)
    assert (
        trace.get_current_span(extracted).get_span_context().trace_id
        == expected_trace_id
    )
    assert baggage.get_baggage("tenant.id", context=extracted) == "tenant-9"
    assert baggage.get_baggage("agency", context=extracted) == "FMMBE"
    with tracer.start_as_current_span("consumer", context=extracted) as child:
        assert child.get_span_context().trace_id == expected_trace_id


def test_tenant_baggage_becomes_span_attributes(memory_exporter):
    exporter, provider = memory_exporter
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    app = FastAPI()

    @app.get("/ping")
    def ping():
        return {"ok": True}

    FastAPIInstrumentor().instrument_app(
        app, server_request_hook=telemetry.tenant_server_request_hook
    )
    previous = trace.get_tracer_provider()
    trace.set_tracer_provider(provider)
    try:
        client = TestClient(app)
        response = client.get(
            "/ping", headers={"baggage": "tenant.id=tenant-9,agency=FMMBE"}
        )
        assert response.status_code == 200
    finally:
        FastAPIInstrumentor().uninstrument_app(app)
        trace.set_tracer_provider(previous)

    server_spans = [
        s for s in exporter.get_finished_spans() if s.kind == trace.SpanKind.SERVER
    ]
    assert server_spans, "server span expected"
    assert server_spans[0].attributes["tenant.id"] == "tenant-9"
    assert server_spans[0].attributes["agency"] == "FMMBE"


def test_settlement_spans_recorded(memory_exporter):
    """Manual settlement spans emit with low-cardinality attributes."""
    exporter, provider = memory_exporter
    tracer = provider.get_tracer("taxstamps.settlement")
    with tracer.start_as_current_span("taxstamps.settlement.receipt") as span:
        span.set_attribute("settlement.rail", "tigerbeetle")
        span.set_attribute("settlement.receipt_status", "APPLIED")
    spans = exporter.get_finished_spans()
    assert spans[0].name == "taxstamps.settlement.receipt"
    assert spans[0].attributes["settlement.receipt_status"] == "APPLIED"
    assert "external_reference" not in spans[0].attributes


def test_drop_counting_exporter_never_raises():
    class FailingExporter:
        def export(self, spans):
            raise ConnectionError("collector down")

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=5000):
            return False

    counts = []

    class Counter:
        def add(self, n):
            counts.append(n)

    wrapped = telemetry._DropCountingSpanExporter(FailingExporter(), Counter())
    from opentelemetry.sdk.trace.export import SpanExportResult

    assert wrapped.export([object(), object(), object()]) is SpanExportResult.FAILURE
    assert counts == [3]
