import json, os, time
from kafka import KafkaConsumer

consumer = KafkaConsumer(os.getenv("KAFKA_TOPIC", "reports"), bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP", "localhost:9092"), group_id=os.getenv("KAFKA_GROUP", "black-ice-workers"), value_deserializer=lambda value: json.loads(value))
for message in consumer:
    report = message.value
    print(json.dumps({"partition": message.partition, "offset": message.offset, "report_id": report.get("report_id"), "status": "processed"}), flush=True)
    time.sleep(0.001)
