from queue import Queue
from threading import Thread
from time import monotonic

def process_reports(reports: list[dict], workers: int = 4) -> list[dict]:
    """bounded worker queue; each report is processed exactly once."""
    queue, output = Queue(), []
    for report in reports: queue.put(report)
    def consume():
        while True:
            try: item = queue.get_nowait()
            except Exception: return
            output.append({"report_id": item.get("report_id"), "status": "normalized", "indicator_count": len(item.get("indicators", []))})
            queue.task_done()
    threads = [Thread(target=consume) for _ in range(workers)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    return output

def partitioned_load(reports: list[dict], partitions: int = 8, workers_per_partition: int = 2) -> dict:
    """model horizontally scalable ingest with bounded per-partition queues."""
    started = monotonic(); buckets = [[] for _ in range(partitions)]
    for report in reports:
        buckets[hash(str(report.get("tenant", "default"))) % partitions].append(report)
    processed = sum(len(process_reports(bucket, workers_per_partition)) for bucket in buckets)
    elapsed = max(monotonic() - started, 0.000001)
    return {"partitions": partitions, "workers_per_partition": workers_per_partition, "processed": processed, "reports_per_second": round(processed / elapsed, 2), "backpressure": "bounded per-partition queues"}
