# 🏛️ LogPeck v3.2.0 Refactor Baseline Snapshot

This file preserves the hardcoded forensic mapping logic before the migration to a modular `metrics.json` architecture.

## 1. Clinical Fields (parser.py)
```python
clinical_fields = [
    "keysExamined", "docsExamined", "nreturned", "ninserted", "keysInserted", "ndeleted", "keysDeleted",
    "nMatched", "nModified", "keysUpdated", "upserted", 
    "numYields", "reslen", "timeActiveMicros", "timeInactiveMicros", "totalReturnedUnits", 
    "nStages", "writeConflicts", "prepareReadConflictMillis", "flowControlMillis", "remoteOpWaitMillis",
    "cpuNanos", "waitForWriteConcernDurationMillis", "totalOplogSlotDurationMicros", "totalTimeQueuedMicros",
    "errCode", "errName", "errMsg", "ok", "workingMillis"
]
```

## 2. Field Display Names (specification.py)
```python
FIELD_DISPLAY = {
    "keysExamined": "Keys Examined", 
    "docsExamined": "Docs Examined", 
    "nreturned": "Docs Returned",
    "totalReturnedUnits": "Total Returned Units",
    "reslen": "Result Size (Bytes)",
    "nMatched": "Docs Matched",
    "nModified": "Docs Modified",
    "ninserted": "Docs Inserted",
    "ndeleted": "Docs Deleted",
    "upserted": "Docs Upserted",
    "numYields": "Lock Yields",
    "workingMillis": "Execution (ms)",
    "planning": "Planning Time (µs)",
    "lock_wait": "Lock Acquisition (ms)",
    "storage_wait": "Unified Storage I/O (ms)",
    "queued": "Execution Queue (ms)",
    "writeConflicts": "Write Conflicts",
    "flowControlMillis": "Flow Control Wait",
    "remoteOpWaitMillis": "Remote Op Wait",
    "prepareReadConflictMillis": "Read Conflict Wait",
    "timeActiveMicros": "Time Active (µs)",
    "timeInactiveMicros": "Time Inactive (µs)",
    "cpuNanos": "CPU Time (ns)",
    "waitForWriteConcernDurationMillis": "Write Concern Wait",
    "totalOplogSlotDurationMicros": "Oplog Slot Wait",
    "totalTimeQueuedMicros": "Global Queue Wait",
    "txnBytesDirty": "Cache Dirty (Bytes)",
    "shards": "Shards Involved",
    "mongot_wait": "Atlas Search Wait (ms)"
}
```

## 3. Metric Source Mapping (specification.py)
```python
METRIC_SOURCES = {
    "keysExamined": "attr.keysExamened",
    "docsExamined": "attr.docsExamined",
    "nreturned": "attr.nreturned",
    "totalReturnedUnits": "attr.nreturned (Alias for Docs Returned)",
    "nMatched": "attr.nMatched",
    "nModified": "attr.nModified",
    "ninserted": "attr.ninserted",
    "ndeleted": "attr.ndeleted",
    "upserted": "attr.upserted",
    "workingMillis": "attr.workingMillis (Raw execution time)",
    "numYields": "attr.numYields (Locks yielded during execution)",
    "planning": "attr.planningTimeMicros",
    "lock_wait": "attr.locks.timeAcquiringMicros",
    "storage_wait": "Cumulative I/O Effort (Total timeReading/timeWriting) + Oplog Slot Wait + Write Concern Wait",
    "writeConflicts": "attr.writeConflicts",
    "flowControlMillis": "attr.flowControlMillis",
    "remoteOpWaitMillis": "attr.remoteOpWaitMillis",
    "prepareReadConflictMillis": "attr.prepareReadConflictMillis",
    "timeActiveMicros": "attr.timeActiveMicros",
    "timeInactiveMicros": "attr.timeInactiveMicros",
    "cpuNanos": "attr.cpuNanos",
    "waitForWriteConcernDurationMillis": "attr.waitForWriteConcernDurationMillis",
    "totalOplogSlotDurationMicros": "attr.totalOplogSlotDurationMicros",
    "totalTimeQueuedMicros": "attr.queues.execution.totalTimeQueuedMicros",
    "txnBytesDirty": "attr.storage.data.txnBytesDirty",
    "shards": "attr.shardNames (Length)",
    "mongot_wait": "attr.mongot.timeWaitingMillis"
}
```
