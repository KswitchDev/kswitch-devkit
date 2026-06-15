/**
 * AuditSender — async background sender for central audit forwarding.
 *
 * Mirrors Python AuditSender exactly.
 *
 * Architecture:
 *   AuditEmitter.emit() → JSONL (local, synchronous)
 *                       → AuditSender.enqueue() (non-blocking, queued)
 *                             ↓ in-memory queue
 *                        setInterval background flush → POST /api/v1/sdk/audit/events
 *                                                    → enforcement_audit_events DB table
 *
 * Retry policy: exponential backoff (1s → 2s → 4s → ... → 60s cap), max 5 retries.
 * After max retries: event dropped, drop_count incremented, failure logged.
 *
 * Decision path is never blocked — emit() returns after JSONL write.
 * Forwarding failures are logged but do not surface to callers.
 *
 * Node.js execution model:
 *   - In-memory queue (array with maxsize cap)
 *   - setInterval flushes batches on flush_interval
 *   - fetch() for HTTP (Node.js 18+ global)
 *   - No worker_threads needed — all async I/O via event loop
 */

import type { AuditEvent } from "./emitter.js";

const QUEUE_MAXSIZE = 500;

// ── Sender ────────────────────────────────────────────────────────────────────

export class AuditSender {
  private readonly ingestUrl: string;
  private readonly batchSize: number;
  private readonly flushInterval: number;
  private readonly maxRetries: number;
  private readonly fetchFn: typeof globalThis.fetch;

  private queue: AuditEvent[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  // Diagnostics
  private sendCount = 0;
  private failCount = 0;
  private dropCount = 0;
  private lastSendAt: number | null = null;
  private lastFailure: string | null = null;

  constructor(opts: {
    ingestUrl: string;
    batchSize?: number;
    flushInterval?: number;  // seconds
    maxRetries?: number;
    /** Injectable for tests */
    fetchFn?: typeof globalThis.fetch;
  }) {
    this.ingestUrl = opts.ingestUrl;
    this.batchSize = opts.batchSize ?? 10;
    this.flushInterval = opts.flushInterval ?? 5;
    this.maxRetries = opts.maxRetries ?? 5;
    this.fetchFn = opts.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  /** Start the background flush timer. Idempotent. */
  start(): void {
    if (this.running) return;
    this.running = true;
    this.timer = setInterval(() => { void this.flush(); }, this.flushInterval * 1000);
    console.debug(
      `AuditSender started (url=${this.ingestUrl}, batch=${this.batchSize}, interval=${this.flushInterval}s)`,
    );
  }

  /** Stop the sender, flush remaining events, then clear the timer. */
  async stop(): Promise<void> {
    this.running = false;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    // Drain remaining events
    if (this.queue.length > 0) {
      await this.flush();
    }
  }

  isRunning(): boolean {
    return this.running;
  }

  /**
   * Enqueue an event for background forwarding. Non-blocking.
   * If the queue is full the event is silently dropped and drop_count incremented.
   */
  enqueue(event: AuditEvent): void {
    if (this.queue.length >= QUEUE_MAXSIZE) {
      this.dropCount += 1;
      console.warn(`AuditSender queue full — dropping event (drop_count=${this.dropCount})`);
      return;
    }
    this.queue.push(event);
    // Flush immediately if batch size reached
    if (this.queue.length >= this.batchSize) {
      void this.flush();
    }
  }

  diagnostics(): {
    forwarding_enabled: boolean;
    running: boolean;
    queue_depth: number;
    last_send_at: number | null;
    last_failure: string | null;
    send_count: number;
    fail_count: number;
    drop_count: number;
  } {
    return {
      forwarding_enabled: true,
      running: this.running,
      queue_depth: this.queue.length,
      last_send_at: this.lastSendAt,
      last_failure: this.lastFailure,
      send_count: this.sendCount,
      fail_count: this.failCount,
      drop_count: this.dropCount,
    };
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.batchSize);
    await this.backoffSend(batch);
  }

  private async sendBatch(batch: AuditEvent[]): Promise<boolean> {
    try {
      const payload = JSON.stringify({ events: batch });
      const resp = await this.fetchFn(this.ingestUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
        signal: AbortSignal.timeout(10000),
      });
      if (resp.ok) {
        this.sendCount += batch.length;
        this.lastSendAt = Date.now() / 1000;
        return true;
      } else {
        this.lastFailure = `HTTP ${resp.status}`;
        return false;
      }
    } catch (exc) {
      this.lastFailure = String(exc);
      return false;
    }
  }

  private async backoffSend(batch: AuditEvent[]): Promise<boolean> {
    let delay = 1000; // ms
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (await this.sendBatch(batch)) return true;
      if (attempt < this.maxRetries) {
        await sleep(Math.min(delay, 60000));
        delay *= 2;
      }
    }
    // All retries exhausted
    this.failCount += batch.length;
    console.error(
      `AuditSender: batch of ${batch.length} events dropped after ${this.maxRetries} ` +
      `retries (last_failure=${this.lastFailure})`,
    );
    return false;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Module-level singleton ────────────────────────────────────────────────────

let _sender: AuditSender | null = null;

export function getAuditSender(): AuditSender | null {
  return _sender;
}

/** Start (or return the existing running) AuditSender singleton. */
export function startAuditSender(opts: {
  ingestUrl: string;
  batchSize?: number;
  flushInterval?: number;
  maxRetries?: number;
  fetchFn?: typeof globalThis.fetch;
}): AuditSender {
  if (_sender !== null && _sender.isRunning()) {
    return _sender;
  }
  _sender = new AuditSender(opts);
  _sender.start();
  return _sender;
}

/** Stop and clear the AuditSender singleton. */
export async function stopAuditSender(): Promise<void> {
  if (_sender !== null) {
    await _sender.stop();
    _sender = null;
  }
}
