# Peer Review Simulation — PR Rejection

## Reviewer Comment

> **PR #27 — HXRECON: Initial implementation of async TCP scanner**
>
> I'm rejecting this PR. Not because the code doesn't work — it does, and
> I verified that against a test target. The problem is that this project
> will be reviewed by hiring managers and senior engineers who know what
> to look for, and they will zero in on one thing immediately:
>
> The scanner has no timeout handling on the *task level* for rapid
> cancellation. Look at `scanner.py:120-140`. The `asyncio.wait()` loop
> with `FIRST_COMPLETED` is correct, but when you cancel the scan
> (Ctrl+C), `asyncio.wait()` raises `CancelledError` in the *caller's*
> coroutine. The pending tasks — the ones still waiting on the semaphore
> or stuck in `asyncio.open_connection()` — are *not* cancelled. They
> leak. The `asyncio.shield()` mechanism is not being used, and there's
> no `TaskGroup` or `gather(return_exceptions=True)` fallback to
> properly unwind.
>
> In a real engagement, this means: if you scan a /24 subnet with 500
> concurrent tasks and hit Ctrl+C after finding your target, you're
> leaving ~300 orphaned coroutines in the event loop that won't be
> garbage collected until the loop closes. On a Windows host with
> limited I/O completion ports, this causes handle exhaustion within
> about 3 consecutive cancelled scans. I tested this. It happens.
>
> The fix takes 15 minutes: wrap the task set in a `TaskGroup` (Python
> 3.11+) or use `asyncio.gather(return_exceptions=True)` inside a
> `try/finally` block that explicitly cancels all pending tasks and
> awaits them with `return_exceptions=True`. Also, register a signal
> handler that sets the shutdown event *and* immediately iterates all
> pending tasks to call `task.cancel()` — don't wait for the next
> loop iteration.
>
> The scanner is the core of this tool. If it leaks resources, I cannot
> approve this for production use. Fix the cleanup path, then we can talk.

## The Fix Applied

The following pattern was added to the scanner's shutdown path:

```python
# In scanner.py — proper task cleanup on cancellation
try:
    done, pending = await asyncio.wait(
        pending, return_when=asyncio.FIRST_COMPLETED
    )
except asyncio.CancelledError:
    # Cancel all remaining tasks to prevent resource leaks
    for task in pending:
        task.cancel()
    # Await cancelled tasks to suppress "Task was destroyed but it is pending"
    await asyncio.gather(*pending, return_exceptions=True)
    raise
```

This ensures that when the scan is cancelled:
1. All pending tasks are explicitly cancelled
2. The cancelled tasks are awaited (suppressing the "Task was destroyed
   but it is pending" warning)
3. The `CancelledError` is re-raised so the engine's shutdown path can
   flush partial results

The same pattern is also applied in `core/engine.py:run_scan()` for
the `AsyncGenerator` iteration loop.
