# labelled detector experiment

`phishing_detector.py` downloads the public uci phishing websites dataset, trains a logistic-regression classifier, and prints roc-auc, a confusion matrix, precision, recall, and f1 scores on a held-out test set.

```bash
pip install -r ml/requirements.txt
python ml/phishing_detector.py
```

the dataset is downloaded at runtime from the uci machine learning repository and is not committed to this repository. results should be recorded from the actual run; no accuracy number is hard-coded in the documentation.

the current reproducible baseline is saved in `ml/results/uci-baseline.json`: roc-auc 0.9826 and accuracy 0.9251 on a stratified 25 percent holdout with random state 42.
