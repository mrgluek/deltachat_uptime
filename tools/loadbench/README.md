# Uptime bot load benchmark

Run from the repository root with the project environment active.

```sh
source venv/bin/activate
python -m tools.loadbench.gen_db --db /tmp/lb.db
python -m tools.loadbench.run --db /tmp/lb.db --json /tmp/lb.json --markdown /tmp/lb.md
```

The generator requires a new path. Seed 1 creates 10,000 monitors, 300
skewed-size chats, 20 peers and 200 mirrored targets per peer. The default
is 30 days of history with a small expired tail for cleanup. Use
`--history-days 90` for the longer history. At 10,000 monitors, the
90-day fixture's cleanup on main at 50c26fc exceeded the time budget
because of the correlated journal-key pruning queries. Use
`--scale` to adjust history row counts independently.

For a smaller comparison, generate a second fixture.

```sh
python -m tools.loadbench.gen_db --db /tmp/lb-small.db \
  --monitors 1000 --chats 60 --peers 8 --targets-per-peer 100
python -m tools.loadbench.run --db /tmp/lb-small.db --json /tmp/lb-small.json
```

Each scenario uses a new process and a fresh writable copy of the
marked fixture. Disk copying is enabled by default and can be requested
explicitly with `--copy`. Use `--no-copy` to regenerate a private fixture
from the stored seed and settings for every scenario. Each run blocks network calls and replaces
Delta Chat RPC and outbox submission with in-memory counters.

Use `--only report_notices` to select a single scenario. The check-write
scenario includes separate steady-state variants for 3% DOWN and all UP.
`cache_pressure` counts second-pass DNS and vote cache hits across the fixture.
The JSON details also include the total DNS lock acquisition and hold times.
`rt_ack_queue` simulates a 3.5 s RPC queue delay and reports how many links
stay up when the stub core acknowledges frames on receipt.
`--functions` includes individual function metrics in Markdown. JSON
always includes them. `--profile` adds a cumulative cProfile top 15
across the event loop and executor jobs. `--memory` enables scenario
Python allocation peaks and per-function observed lower bounds.

Times exclude fixture copying and scenario setup. Function timings are
inclusive, so nested functions and parallel calls can overlap. Row
counts cover rows consumed by the instrumented SQLite reads. RPC
bytes count outgoing payload bytes, excluding transport overhead.
Mail totals count outbox submissions, before any pacing or merging.
Cleanup and startup are measured once per invocation.
