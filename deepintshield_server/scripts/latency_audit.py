#!/usr/bin/env python3
import argparse
import json
import math
import os
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone


DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_PROMPT = "Explain transformers in two short sentences."


def percentile(values, pct):
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    rank = (len(values) - 1) * pct
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return values[low]
    weight = rank - low
    return values[low] + ((values[high] - values[low]) * weight)


def summarize_samples(samples):
    ordered = sorted(samples)
    return {
        "count": len(ordered),
        "p50_ms": round(percentile(ordered, 0.50), 2),
        "p95_ms": round(percentile(ordered, 0.95), 2),
        "p99_ms": round(percentile(ordered, 0.99), 2),
        "mean_ms": round(statistics.fmean(ordered), 2),
        "min_ms": round(ordered[0], 2),
        "max_ms": round(ordered[-1], 2),
    }


class SessionClient:
    def __init__(self, base_url, timeout):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cookie_jar = urllib.request.HTTPCookieProcessor()
        self.opener = urllib.request.build_opener(self.cookie_jar)

    def request(self, method, path, *, json_body=None, headers=None):
        url = f"{self.base_url}{path}"
        payload = None
        merged_headers = {"Accept": "application/json"}
        if headers:
            merged_headers.update(headers)
        if json_body is not None:
            payload = json.dumps(json_body).encode("utf-8")
            merged_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=payload, headers=merged_headers, method=method)
        start = time.perf_counter()
        with self.opener.open(req, timeout=self.timeout) as response:
            body = response.read()
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            content_type = response.headers.get("Content-Type", "")
            parsed = None
            if "application/json" in content_type and body:
                parsed = json.loads(body.decode("utf-8"))
            return {
                "status": response.status,
                "elapsed_ms": elapsed_ms,
                "body": parsed,
                "raw_body": body,
                "headers": dict(response.headers.items()),
            }


def benchmark_endpoint(client, path, runs):
    samples = []
    for _ in range(runs):
        result = client.request("GET", path)
        samples.append(result["elapsed_ms"])
    return summarize_samples(samples)


def benchmark_chat(client, *, virtual_key, model, prompt, runs, headers=None):
    samples = []
    cache_observations = []
    for _ in range(runs):
        result = client.request(
            "POST",
            "/langchain/chat/completions",
            json_body={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
            },
            headers={
                "Authorization": f"Bearer {virtual_key}",
                "x-bf-vk": virtual_key,
                **(headers or {}),
            },
        )
        samples.append(result["elapsed_ms"])
        cache_debug = None
        body = result["body"] or {}
        if isinstance(body, dict):
            cache_debug = (((body.get("choices") or [{}])[0].get("message") or {}).get("cache_debug"))
            if cache_debug is None:
                cache_debug = (((body.get("extra_fields") or {})).get("cache_debug"))
        cache_observations.append(cache_debug)
    return summarize_samples(samples), cache_observations


def login_if_needed(client, email, password):
    auth_info = client.request("GET", "/api/session/is-auth-enabled")
    enabled = bool((auth_info["body"] or {}).get("is_enabled"))
    if not enabled:
        return {"enabled": False, "logged_in": False}
    if not email or not password:
        return {"enabled": True, "logged_in": False}
    client.request("POST", "/api/session/login", json_body={"email": email, "password": password})
    return {"enabled": True, "logged_in": True}


def build_time_window():
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    return start.isoformat(timespec="seconds").replace("+00:00", "Z"), end.isoformat(timespec="seconds").replace("+00:00", "Z")


def main():
    parser = argparse.ArgumentParser(description="Run a local DeepIntShield latency audit.")
    parser.add_argument("--base-url", default=os.getenv("DEEPINTSHIELD_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--virtual-key", default=os.getenv("DEEPINTSHIELD_VIRTUAL_KEY"))
    parser.add_argument("--model", default=os.getenv("DEEPINTSHIELD_MODEL", DEFAULT_MODEL))
    parser.add_argument("--prompt", default=os.getenv("DEEPINTSHIELD_PROMPT", DEFAULT_PROMPT))
    parser.add_argument("--timeout-seconds", type=float, default=float(os.getenv("DEEPINTSHIELD_TIMEOUT_SECONDS", "30")))
    parser.add_argument("--runs", type=int, default=int(os.getenv("DEEPINTSHIELD_AUDIT_RUNS", "5")))
    parser.add_argument("--admin-email", default=os.getenv("DEEPINTSHIELD_ADMIN_EMAIL"))
    parser.add_argument("--admin-password", default=os.getenv("DEEPINTSHIELD_ADMIN_PASSWORD"))
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    client = SessionClient(args.base_url, args.timeout_seconds)
    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url,
        "model": args.model,
        "runs": args.runs,
        "scenarios": {},
        "notes": [
            "Provider miss latency includes unavoidable upstream model time.",
            "Semantic and external/model-backed guardrail scenarios are marked skipped unless the local stack is explicitly configured for them.",
            "Per-request phase timings are persisted in AI Logs metadata under latency_breakdown_ms after this audit instrumentation change.",
        ],
    }

    login_result = login_if_needed(client, args.admin_email, args.admin_password)
    results["session"] = login_result

    if args.virtual_key:
        uncached_prompt = f"{args.prompt} request_id={uuid.uuid4()}"
        miss_stats, _ = benchmark_chat(
            client,
            virtual_key=args.virtual_key,
            model=args.model,
            prompt=uncached_prompt,
            runs=args.runs,
        )
        results["scenarios"]["uncached_miss"] = miss_stats

        direct_cache_key = f"latency-audit-direct-{uuid.uuid4()}"
        benchmark_chat(
            client,
            virtual_key=args.virtual_key,
            model=args.model,
            prompt=args.prompt,
            runs=1,
            headers={
                "x-bf-cache-key": direct_cache_key,
                "x-bf-cache-type": "direct",
            },
        )
        direct_hit_stats, direct_cache_debug = benchmark_chat(
            client,
            virtual_key=args.virtual_key,
            model=args.model,
            prompt=args.prompt,
            runs=args.runs,
            headers={
                "x-bf-cache-key": direct_cache_key,
                "x-bf-cache-type": "direct",
            },
        )
        direct_hit_stats["last_cache_debug"] = direct_cache_debug[-1]
        results["scenarios"]["direct_cache_hit"] = direct_hit_stats

        semantic_cache_key = f"latency-audit-semantic-{uuid.uuid4()}"
        benchmark_chat(
            client,
            virtual_key=args.virtual_key,
            model=args.model,
            prompt="What are transformers in machine learning?",
            runs=1,
            headers={
                "x-bf-cache-key": semantic_cache_key,
                "x-bf-cache-type": "semantic",
            },
        )
        semantic_hit_stats, semantic_cache_debug = benchmark_chat(
            client,
            virtual_key=args.virtual_key,
            model=args.model,
            prompt="Explain transformer models used in NLP.",
            runs=args.runs,
            headers={
                "x-bf-cache-key": semantic_cache_key,
                "x-bf-cache-type": "semantic",
            },
        )
        semantic_hit_stats["last_cache_debug"] = semantic_cache_debug[-1]
        results["scenarios"]["semantic_cache_hit"] = semantic_hit_stats
        results["scenarios"]["direct_cache_hit_with_guardrail_reuse"] = direct_hit_stats
    else:
        results["scenarios"]["uncached_miss"] = {"skipped": "DEEPINTSHIELD_VIRTUAL_KEY not provided"}
        results["scenarios"]["direct_cache_hit"] = {"skipped": "DEEPINTSHIELD_VIRTUAL_KEY not provided"}
        results["scenarios"]["semantic_cache_hit"] = {"skipped": "DEEPINTSHIELD_VIRTUAL_KEY not provided"}
        results["scenarios"]["direct_cache_hit_with_guardrail_reuse"] = {"skipped": "DEEPINTSHIELD_VIRTUAL_KEY not provided"}

    if login_result.get("logged_in"):
        start_time, end_time = build_time_window()
        results["scenarios"]["dashboard_logs_histogram"] = benchmark_endpoint(
            client,
            f"/api/logs/histogram?start_time={urllib.parse.quote(start_time)}&end_time={urllib.parse.quote(end_time)}",
            args.runs,
        )
        results["scenarios"]["dashboard_logs_stats"] = benchmark_endpoint(
            client,
            f"/api/logs/stats?start_time={urllib.parse.quote(start_time)}&end_time={urllib.parse.quote(end_time)}",
            args.runs,
        )
        results["scenarios"]["dashboard_logs_filterdata"] = benchmark_endpoint(
            client,
            "/api/logs/filterdata",
            args.runs,
        )
        results["scenarios"]["ai_logs_table"] = benchmark_endpoint(
            client,
            f"/api/logs?limit=25&offset=0&sort_by=timestamp&order=desc&start_time={urllib.parse.quote(start_time)}&end_time={urllib.parse.quote(end_time)}",
            args.runs,
        )
        results["scenarios"]["guardrail_latency_histogram"] = benchmark_endpoint(
            client,
            f"/api/guardrails/latency?start_time={urllib.parse.quote(start_time)}&end_time={urllib.parse.quote(end_time)}",
            args.runs,
        )
    else:
        results["scenarios"]["dashboard_logs_histogram"] = {"skipped": "dashboard session credentials not provided"}
        results["scenarios"]["dashboard_logs_stats"] = {"skipped": "dashboard session credentials not provided"}
        results["scenarios"]["dashboard_logs_filterdata"] = {"skipped": "dashboard session credentials not provided"}
        results["scenarios"]["ai_logs_table"] = {"skipped": "dashboard session credentials not provided"}
        results["scenarios"]["guardrail_latency_histogram"] = {"skipped": "dashboard session credentials not provided"}

    results["scenarios"]["guarded_miss_deterministic_only"] = {
        "skipped": "requires a dedicated deterministic guardrail policy/profile in the target workspace"
    }
    results["scenarios"]["guarded_miss_model_backed_or_external"] = {
        "skipped": "requires explicit model-backed or external guardrail provider bindings"
    }

    rendered = json.dumps(results, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            handle.write("\n")
    print(rendered)


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {payload}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Request failed: {exc}")
