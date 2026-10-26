"""train and evaluate a detector on the public uci phishing websites dataset."""

from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile
from io import BytesIO
import csv
import json

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

DATA_URL = "https://archive.ics.uci.edu/static/public/327/phishing+websites.zip"
DATA_DIR = Path(__file__).parent / "data"

def load_data() -> tuple[np.ndarray, np.ndarray]:
    DATA_DIR.mkdir(exist_ok=True)
    target = DATA_DIR / "Phishing Websites Data Set.arff"
    if not target.exists():
        archive = ZipFile(BytesIO(urlopen(DATA_URL, timeout=30).read()))
        member = next(name for name in archive.namelist() if name.endswith(".arff"))
        target.write_bytes(archive.read(member))
    rows, labels, data = [], [], False
    for line in target.read_text(errors="ignore").splitlines():
        if line.lower().startswith("@data"): data = True; continue
        if not data or not line or line.startswith("%") or line.startswith("@") : continue
        values = line.split(",")
        rows.append([float(value) for value in values[:-1]])
        labels.append(1 if values[-1].strip() in {"1", "phishing"} else 0)
    return np.asarray(rows), np.asarray(labels)

def train_and_evaluate() -> dict:
    x, y = load_data()
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=42, stratify=y)
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=42))
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    probabilities = model.predict_proba(x_test)[:, 1]
    return {"dataset": "uci phishing websites", "samples": len(y), "features": x.shape[1], "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4), "confusion_matrix": confusion_matrix(y_test, predictions).tolist(), "classification_report": classification_report(y_test, predictions, output_dict=True)}

if __name__ == "__main__":
    print(json.dumps(train_and_evaluate(), indent=2))
