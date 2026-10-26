import argparse, json, time
from kafka import KafkaProducer

parser = argparse.ArgumentParser(); parser.add_argument("--count", type=int, default=1000000); parser.add_argument("--bootstrap", default="localhost:9092"); args = parser.parse_args()
producer = KafkaProducer(bootstrap_servers=args.bootstrap, value_serializer=lambda value: json.dumps(value).encode())
started = time.perf_counter()
for index in range(args.count): producer.send("reports", {"report_id": str(index), "tenant": f"tenant-{index % 100}", "event": "synthetic"})
producer.flush()
print(json.dumps({"records": args.count, "seconds": round(time.perf_counter() - started, 3), "records_per_second": round(args.count / max(time.perf_counter() - started, 0.001), 2)}))
