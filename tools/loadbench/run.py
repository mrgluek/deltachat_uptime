"""Run the uptime bot's synthetic load scenarios and print a Markdown report."""

import argparse
import asyncio
from contextlib import closing, ExitStack
import cProfile
import json
import logging
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc

import database

from .gen_db import MARKER, describe, populate
from .measure import Clock, Meter
from .scenarios import Bench, SCENARIOS, VARIANT, WORKLOADS, import_bot_offline, prepare


def source_connection(path):
    return sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)


def read_fixture(path, *, include_counts=False):
    if not path.is_file() or any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("use a closed fixture created by tools.loadbench.gen_db")
    try:
        with closing(source_connection(path)) as conn:
            row = conn.execute("SELECT value FROM config WHERE key = ?", (MARKER,)).fetchone()
            if row is None:
                raise ValueError("database has no synthetic loadbench fixture marker")
            fixture = {"settings": json.loads(row[0])}
            if include_counts:
                min_size, max_size = conn.execute(
                    "SELECT MIN(n), MAX(n) FROM (SELECT COUNT(*) n FROM resources GROUP BY dc_chat_id)").fetchone()
                fixture.update(rows=describe(conn), bytes=path.stat().st_size, chat_size_range=[min_size, max_size])
            return fixture
    except sqlite3.Error as exc:
        raise ValueError("use a database created by tools.loadbench.gen_db") from exc


class WorkloadLog(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.warnings = []

    def emit(self, record):
        self.warnings.append({"level": record.levelname, "message": record.getMessage()})


async def measure_workload(args, bench):
    meter = bench.meter
    workload = WORKLOADS[bench.name]
    if args.memory:
        meter.trace_memory = True
        tracemalloc.start()
        memory_start = tracemalloc.get_traced_memory()[0]
    if args.profile:
        meter.profile = cProfile.Profile()
        meter.profile.enable()
    wall_start, cpu_start = time.perf_counter(), time.process_time()
    try:
        with meter.span(bench.name):
            await workload(bench)
    finally:
        meter.total["wall_s"] = time.perf_counter() - wall_start
        meter.total["cpu_s"] = time.process_time() - cpu_start
        meter.total["calls"] = 1
        if args.profile:
            meter.profile.disable()
        if args.memory:
            meter.total["peak_memory_growth_bytes"] = tracemalloc.get_traced_memory()[1] - memory_start
            tracemalloc.stop()
    result = {"scenario": bench.name, "status": "ok", "total": meter.total,
              "functions": {key: value for key, value in meter.functions.items() if key != bench.name},
              "details": bench.details, "notes": bench.notes, **bench.communications()}
    if args.profile:
        result["profile_top_15_cumulative"] = meter.profile_top()
    return result


def run_worker(args):
    path = args.db.resolve()
    settings = read_fixture(path)["settings"]
    bot, violations = import_bot_offline()
    meter = Meter()
    clock = Clock(settings["epoch"])
    log = WorkloadLog()
    logging.getLogger().addHandler(log)
    logging.getLogger().setLevel(logging.WARNING)
    with ExitStack() as stack:
        directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="loadbench-db-"))
        scratch = Path(directory) / "fixture.db"
        database.DB_PATH = str(scratch)
        if args.copy:
            shutil.copyfile(path, scratch)
        else:
            database.init_db()
            database.close_db()
            with closing(sqlite3.connect(scratch)) as conn:
                populate(conn, argparse.Namespace(**settings))
        meter.install_database(stack, clock)
        if args.worker in ("cleanup", "startup"):
            meter.measure_lock(stack)
        stack.callback(database.close_db)
        bench = Bench(args.worker, bot, meter, clock, stack)
        prepare(bench)
        result = asyncio.run(measure_workload(args, bench))
        # The normal executors handled only local SQLite and mock RPC work.
        bot.db_executor.shutdown()
        bot.rpc_executor.shutdown()
        if violations:
            raise RuntimeError(f"blocked unexpected network or subprocess activity: {', '.join(sorted(set(violations)))}")
        if bench.rpc.unexpected:
            raise RuntimeError(f"incomplete RPC stub: {', '.join(sorted(bench.rpc.unexpected))}")
        errors = [entry["message"] for entry in log.warnings if entry["level"] in ("ERROR", "CRITICAL")]
        if errors:
            raise RuntimeError(f"bot logged errors: {'; '.join(errors[:5])}")
        if log.warnings:
            result["log_warnings"] = log.warnings
        print(json.dumps(result))


def format_row(label, values):
    lock = f"{values['max_write_lock_s'] * 1_000:.3f}" if values["max_write_lock_s"] else "—"
    memory = values.get("peak_memory_growth_bytes", values.get("peak_memory_growth_lower_bound_bytes"))
    memory = f"{memory / 2**20:.2f}" if memory is not None else "—"
    return (f"| {label} | {values['calls']:,} | {values['wall_s'] * 1_000:.3f} | "
            f"{values['cpu_s'] * 1_000:.3f} | {values['connects']:,} | "
            f"{values['writer_transactions']:,} | {values['rows']:,} | {values['rpc_calls']:,} | "
            f"{values['rpc_bytes']:,} | {values['mails_queued']:,} | {lock} | {memory} |")


TABLE = [
    "| Scenario or function | Calls | Wall ms | CPU ms | _connect | Writes | SQL rows | RPC calls | RPC bytes | Mails queued | Longest lock ms | Peak MiB |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]


def markdown(report, include_functions=False):
    fixture = report["fixture"]
    rows = fixture["rows"]
    lines = [f"## Load benchmark ({rows['resources']:,} monitors)", "",
             f"{rows['chats']:,} chats, {rows['peers']:,} peers, {rows['probe_targets']:,} mirrored targets, "
             f"{fixture['settings']['history_days']} days of history, {fixture['bytes']:,} database bytes.", "",
             *TABLE]
    for result in report["scenarios"]:
        name = result["scenario"]
        if result["status"] == "ok":
            lines.append(format_row(name, result["total"]))
        else:
            lines.append(f"| {name} ({result['status']}) | — | — | — | — | — | — | — | — | — | — | — |")
    if report["settings"]["memory"] and include_functions:
        lines.extend(("", "Per-function peaks are observed lower bounds for process-wide traced Python allocations."))
    for result in report["scenarios"]:
        name = result["scenario"]
        if result["status"] != "ok":
            lines.extend(("", f"- **{name}** failed. {result['reason']}"))
            continue
        lines.extend(("", f"### {name}", ""))
        lines.extend(f"- {note}" for note in result["notes"])
        details = result["details"]
        if name in ("startup", "scheduler_tick"):
            dispatch = details["first_dispatch_s"]
            dispatch = f"{dispatch * 1_000:.3f} ms" if dispatch is not None else "none due"
            lines.append(f"- First dispatch after {dispatch}. "
                         f"Created {details['tasks_created']:,} tasks in {details['ticks']} scheduler "
                         f"{'tick' if details['ticks'] == 1 else 'ticks'}.")
        priorities = result["mails_queued_by_priority"]
        if priorities:
            lines.append("- Queued mails by priority. " + ", ".join(f"{k} {v:,}" for k, v in sorted(priorities.items())) + ".")
        if include_functions:
            lines.extend(("", *TABLE))
            for function, values in sorted(result["functions"].items(), key=lambda item: -item[1]["wall_s"]):
                lines.append(format_row(function, values))
        if result.get("profile_top_15_cumulative"):
            lines.extend(("", "| cProfile function | Calls | Self ms | Cumulative ms |",
                          "|---|---:|---:|---:|"))
            for entry in result["profile_top_15_cumulative"]:
                function = entry["function"].replace("|", r"\|")
                lines.append(f"| `{function}` | {entry['calls']:,} | {entry['self_s'] * 1_000:.3f} | "
                             f"{entry['cumulative_s'] * 1_000:.3f} |")
    return "\n".join(lines) + "\n"


def write_artifact(path, content):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def git_revision():
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
                                cwd=Path(database.__file__).resolve().parent)
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_suite(args, fixture):
    start = time.perf_counter()
    names = list(SCENARIOS) if args.only is None else [args.only]
    if "record_checks" in names:
        names.insert(names.index("record_checks") + 1, VARIANT)
    results = []
    for name in names:
        flags = [flag for flag, enabled in (("--profile", args.profile), ("--memory", args.memory),
                                           ("--no-copy", not args.copy)) if enabled]
        print(f"Running {name} ...", file=sys.stderr, flush=True)
        try:
            run = subprocess.run([sys.executable, "-B", "-m", __spec__.name, "--db", str(args.db),
                                  "--worker", name, *flags], capture_output=True, text=True, timeout=args.timeout)
            if run.returncode:
                reason = (run.stderr.strip() or run.stdout.strip()).splitlines()
                results.append({"scenario": name, "status": "failed",
                                "reason": reason[-1] if reason else f"worker exited {run.returncode}"})
            else:
                results.append(json.loads(run.stdout))
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            results.append({"scenario": name, "status": "failed", "reason": str(exc)})
    return {"format_version": 1, "fixture": fixture, "revision": git_revision(),
            "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                            "machine": platform.machine(), "system": platform.system()},
            "settings": {"copy": args.copy, "profile": args.profile, "memory": args.memory},
            "suite_wall_s": time.perf_counter() - start, "scenarios": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--only", choices=(*SCENARIOS, VARIANT))
    parser.add_argument("--copy", action=argparse.BooleanOptionalAction, default=True,
                        help="copy the fixture per scenario (default); --no-copy regenerates it from its seed")
    parser.add_argument("--profile", action="store_true", help="include a cumulative cProfile top 15")
    parser.add_argument("--memory", action="store_true", help="measure scenario peak Python allocation growth")
    parser.add_argument("--functions", action="store_true", help="include per-function metrics in Markdown")
    parser.add_argument("--json", type=Path, help="write full metrics as JSON")
    parser.add_argument("--markdown", type=Path, help="save the printed Markdown")
    parser.add_argument("--timeout", type=int, default=540, help="seconds allowed per isolated scenario")
    parser.add_argument("--worker", choices=(*SCENARIOS, VARIANT), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        run_worker(args)
        return
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        fixture = read_fixture(args.db.resolve(), include_counts=True)
        outputs = [path.resolve() for path in (args.json, args.markdown) if path is not None]
        source = args.db.resolve()
        protected = {source, *(Path(f"{source}{suffix}") for suffix in ("-wal", "-shm", "-journal"))}
        if any(path in protected or (path.exists() and path.samefile(source)) for path in outputs):
            raise ValueError("output paths must be separate from the input database")
        if len(set(outputs)) != len(outputs):
            raise ValueError("JSON and Markdown need separate output paths")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    report = run_suite(args, fixture)
    summary = markdown(report, include_functions=args.functions)
    print(summary, end="")
    if args.json:
        write_artifact(args.json, json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.markdown:
        write_artifact(args.markdown, summary)
    return any(item["status"] != "ok" for item in report["scenarios"])


if __name__ == "__main__":
    raise SystemExit(main())
