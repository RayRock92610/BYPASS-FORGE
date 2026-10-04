## Payload Hash Optimization

Implemented payload_hash verification optimization in `src/logger.ts`.

- Added `payload_hash` column to the `audit_events` table schema.
- At event insertion, compute and persist the pre-calculated payload hash: `payload_hash = hash(JSON.stringify(validatedEvent))`.
- Added a fast path in `verifyChainIntegrity` to compare stored `row.payload_hash` against `hash(row.payload)`. If matched, it bypasses repeated `JSON.parse()` and canonicalization.
- Maintained the fallback canonical path preserving the existing in-place deletion pattern (`parsed.integrity.event_hash = undefined`).

**Benchmark Metrics:**
- Baseline: ~2389.14 ms
- Optimized: ~353.76 ms (~85% reduction across 50,000 events)
