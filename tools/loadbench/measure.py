"""Measurement hooks installed only in the isolated benchmark process."""

import asyncio
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
import cProfile
from functools import partial, wraps
import inspect
import pstats
import sqlite3
import threading
import time
import tracemalloc

import database


class Proxy:
    def __init__(self, original, **overrides):
        self.original = original
        self.__dict__.update(overrides)

    def __getattr__(self, name):
        return getattr(self.original, name)


class Clock:
    def __init__(self, epoch):
        self.epoch = epoch
        self.offset = 0

    def time(self):
        return self.epoch + self.offset

    def monotonic(self):
        return time.monotonic() + self.offset

    def __getattr__(self, name):
        return getattr(time, name)


# SQL rows consumed by these reads, including multiple queries per call and cache misses.
LARGE_READS = (
    "get_all_resources", "get_active_probe_targets", "get_partial_journal_rows",
    "get_pending_partial_notices", "get_configs", "get_resources",
    "get_resources_uptime_30d", "get_resource_uptime_window", "get_recent_chat_events",
    "get_recent_incidents", "get_incident_downtime_events", "get_incident_downtime_events_batch",
    "get_chat_partial_outages", "get_incident_sync_candidates",
    "get_all_peers", "get_all_active_incidents", "get_active_incidents_for_chat",
    "get_unlinked_open_downtime_events", "get_monitored_chats", "get_retained_message_ids",
)


def metrics():
    return dict(calls=0, wall_s=0.0, cpu_s=0.0, connects=0, sqlite_opens=0, writer_transactions=0,
                rows=0, rpc_calls=0, rpc_bytes=0, mails_queued=0, max_write_lock_s=0.0)


class Meter:
    def __init__(self):
        self.scopes = ContextVar("loadbench_scopes", default=())
        self.read = ContextVar("loadbench_sql_read", default=None)
        self.functions = defaultdict(metrics)
        self.total = metrics()
        self.lock = threading.Lock()
        self.profile = None
        self.thread_stats = None
        self.trace_memory = False

    def add(self, name, count=1):
        scopes = self.scopes.get()
        if scopes:
            with self.lock:
                self.total[name] += count
                for scope in scopes:
                    self.functions[scope][name] += count

    def write_hold(self, elapsed):
        scopes = self.scopes.get()
        if scopes:
            with self.lock:
                for values in (self.total, *(self.functions[scope] for scope in scopes)):
                    values["max_write_lock_s"] = max(values["max_write_lock_s"], elapsed)

    @contextmanager
    def span(self, name):
        token = self.scopes.set((*self.scopes.get(), name))
        if self.trace_memory:
            memory_start, peak_start = tracemalloc.get_traced_memory()
        wall, cpu = time.perf_counter(), time.process_time()
        try:
            yield
        finally:
            elapsed, consumed = time.perf_counter() - wall, time.process_time() - cpu
            self.scopes.reset(token)
            if self.trace_memory:
                memory_end, peak_end = tracemalloc.get_traced_memory()
                observed = (peak_end if peak_end > peak_start else memory_end) - memory_start
            with self.lock:
                data = self.functions[name]
                data["calls"] += 1
                data["wall_s"] += elapsed
                data["cpu_s"] += consumed
                if self.trace_memory:
                    key = "peak_memory_growth_lower_bound_bytes"
                    data[key] = max(data.get(key, 0), observed)

    def wrap(self, function, *, read=False):
        name = function.__name__
        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def measured(*args, **kwargs):
                with self.span(name):
                    return await function(*args, **kwargs)
        else:
            @wraps(function)
            def measured(*args, **kwargs):
                if not self.scopes.get():
                    return function(*args, **kwargs)
                with self.span(name):
                    token = self.read.set(name) if read else None
                    try:
                        return function(*args, **kwargs)
                    finally:
                        if token is not None:
                            self.read.reset(token)
        return measured

    def install_database(self, stack, clock):
        meter = self

        class Cursor(sqlite3.Cursor):
            def fetchone(self):
                row = super().fetchone()
                if row is not None and self.description and meter.read.get():
                    meter.add("rows")
                return row

            def fetchmany(self, *args):
                rows = super().fetchmany(*args)
                if rows and self.description and meter.read.get():
                    meter.add("rows", len(rows))
                return rows

            def fetchall(self):
                rows = super().fetchall()
                if rows and self.description and meter.read.get():
                    meter.add("rows", len(rows))
                return rows

            def __iter__(self):
                if not self.description or not meter.read.get():
                    return super().__iter__()
                return self.count_rows()

            def count_rows(self):
                count = 0
                try:
                    for row in iter(super().__next__, None):
                        count += 1
                        yield row
                finally:
                    if count:
                        meter.add("rows", count)

        class Connection(sqlite3.Connection):
            def cursor(self, factory=Cursor):
                return super().cursor(factory)

            def execute(self, sql, parameters=()):
                if meter.read.get():
                    return self.cursor().execute(sql, parameters)
                return super().execute(sql, parameters)

        def connect(*args, **kwargs):
            meter.add("sqlite_opens")
            return sqlite3.connect(*args, **kwargs, factory=Connection)

        db_connect = database._connect
        db_transaction = database._writer_transaction

        @wraps(db_connect)
        def count_connect(*args, **kwargs):
            self.add("connects")
            return db_connect(*args, **kwargs)

        @contextmanager
        def count_transaction():
            self.add("writer_transactions")
            with db_transaction() as conn:
                yield conn

        stack.enter_context(patch(database, "time", clock))
        stack.enter_context(patch(database, "sqlite3", Proxy(sqlite3, connect=connect)))
        stack.enter_context(patch(database, "_connect", count_connect))
        stack.enter_context(patch(database, "_writer_transaction", count_transaction))
        for name in LARGE_READS:
            stack.enter_context(patch(database, name, self.wrap(getattr(database, name), read=True)))

    def measure_lock(self, stack):
        meter = self
        lock = database._write_lock

        class TimedLock:
            def __enter__(self):
                lock.acquire()
                self.start = time.perf_counter()

            def __exit__(self, *exc):
                elapsed = time.perf_counter() - self.start
                lock.release()
                meter.write_hold(elapsed)

        stack.enter_context(patch(database, "_write_lock", TimedLock()))

    def executor_call(self, function):
        context = copy_context()
        if self.profile is None:
            return partial(context.run, function)

        def profiled():
            profile = cProfile.Profile()
            try:
                return profile.runcall(context.run, function)
            finally:
                with self.lock:
                    if self.thread_stats is None:
                        self.thread_stats = pstats.Stats(profile)
                    else:
                        self.thread_stats.add(profile)

        return profiled

    def install_executors(self, stack, bot):
        async def run_db(function, *args, **kwargs):
            return await asyncio.get_running_loop().run_in_executor(
                bot.db_executor, self.executor_call(partial(function, *args, **kwargs)))

        async def run_rpc(function, *args, **kwargs):
            return await asyncio.get_running_loop().run_in_executor(
                bot.rpc_executor, self.executor_call(partial(function, *args, **kwargs)))

        async def to_thread(function, /, *args, **kwargs):
            if self.profile is None:
                return await asyncio.to_thread(function, *args, **kwargs)
            return await asyncio.get_running_loop().run_in_executor(
                None, self.executor_call(partial(function, *args, **kwargs)))

        stack.enter_context(patch(bot, "run_db", run_db))
        stack.enter_context(patch(bot, "run_rpc", run_rpc))
        stack.enter_context(patch(bot, "asyncio", Proxy(asyncio, to_thread=to_thread)))

    def profile_top(self):
        stats = pstats.Stats(self.profile)
        if self.thread_stats is not None:
            stats.add(self.thread_stats)
        top = sorted(stats.stats.items(), key=lambda pair: pair[1][3], reverse=True)[:15]
        return [{"function": pstats.func_std_string(function), "calls": data[1],
                 "self_s": data[2], "cumulative_s": data[3]} for function, data in top]


@contextmanager
def patch(obj, name, value):
    previous = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, previous)
