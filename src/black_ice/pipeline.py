from queue import Queue
from threading import Thread

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
