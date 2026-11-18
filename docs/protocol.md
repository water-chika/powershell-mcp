# Protocol

The runner emits RFC 7464 JSON text sequences. Output records precede exactly one terminal record, which must be last.

The producer validates record types, source, consecutive remote sequence numbers, result fields, framing, record size, and terminal cardinality/order. Late transport diagnostics are drained before terminal emission. Protocol corruption produces a bounded structured failure.

Raw records are diagnostic data and are excluded from ordinary MCP responses unless `include_raw_records` is true.
