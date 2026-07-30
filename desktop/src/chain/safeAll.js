// Stream C T5 — partial-failure helpers for multi-read RPC polls.
// One throttled/429 read must not reject an entire Market/Earn refresh.

/**
 * Await Promise.allSettled and return fulfilled values in order.
 * Rejected slots are dropped (or replaced with `onRejected(reason, index)` if provided).
 *
 * @template T
 * @param {Iterable<Promise<T>>} promises
 * @param {{ onRejected?: (reason: unknown, index: number) => T | undefined }} [opts]
 * @returns {Promise<T[]>}
 */
export async function settledValues(promises, { onRejected } = {}) {
  const results = await Promise.allSettled([...promises]);
  const out = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled") {
      out.push(r.value);
    } else if (typeof onRejected === "function") {
      const v = onRejected(r.reason, i);
      if (v !== undefined) out.push(v);
    }
  });
  return out;
}

/**
 * Like settledValues but keeps a parallel array of errors (null if ok).
 * Useful when the UI wants a soft warning without blanking the list.
 *
 * @template T
 * @param {Iterable<Promise<T>>} promises
 * @returns {Promise<{ values: (T|null)[], errors: (unknown|null)[], okCount: number, failCount: number }>}
 */
export async function settledPartition(promises) {
  const results = await Promise.allSettled([...promises]);
  const values = [];
  const errors = [];
  let okCount = 0;
  let failCount = 0;
  for (const r of results) {
    if (r.status === "fulfilled") {
      values.push(r.value);
      errors.push(null);
      okCount += 1;
    } else {
      values.push(null);
      errors.push(r.reason);
      failCount += 1;
    }
  }
  return { values, errors, okCount, failCount };
}
