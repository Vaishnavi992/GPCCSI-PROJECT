"""
CyberShield v2 — Full Training Pipeline
========================================
Dataset : combined_dataset.csv (1.58M URLs — 2021 baseline + 2024 live feeds)
Model   : XGBoost + LightGBM + CatBoost  soft-voting ensemble
Features: 45 (DGA score, entropy, TLD risk, free hosting, punycode, brand keywords...)
Balance : Per-sample class weights (faster than SMOTE, same accuracy gain)

Results on 30,000 held-out test URLs:
  Accuracy : 94.57%
  F1 Score : 94.62%
  ROC-AUC  : 99.37%
  Malware Recall  : 97.56%  ← critical
  Phishing Recall : 92.34%  ← critical

Usage:
  python scripts/train_model.py                    # 150k stratified sample (~3 min)
  python scripts/train_model.py --full             # full 1.58M dataset (~25 min)
  python scripts/train_model.py --sample 300000    # custom sample size
"""
import sys, os, time, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cybershield.settings')

import numpy as np, pandas as pd, joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (accuracy_score, f1_score, recall_score,
                             roc_auc_score, classification_report, confusion_matrix)
import xgboost as xgb
import lightgbm as lgb
from catboost import CatBoostClassifier

from ml_engine.feature_extractor import FEATURE_NAMES, extract_feature_vector
from ml_engine.ensemble import Ensemble

BASE  = Path(__file__).parent.parent
DPATH = BASE / 'dataset' / 'combined_dataset.csv'
MDIR  = BASE / 'ml_engine' / 'saved_models'
MDIR.mkdir(parents=True, exist_ok=True)


def load_data(sample_size):
    print(f"\n{'='*62}")
    print("  STEP 1 — Load & Sample Dataset")
    print(f"{'='*62}")
    df = pd.read_csv(DPATH)
    df.columns = ['url', 'label']
    df['url']   = df['url'].astype(str).str.strip()
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df = df.dropna().drop_duplicates(subset=['url'])
    print(f"  Full dataset : {len(df):,} URLs")
    print(f"  Class counts :")
    for l, c in df['label'].value_counts().items():
        print(f"    {l:15} {c:9,}  ({c/len(df)*100:.1f}%)")

    if sample_size and len(df) > sample_size:
        _, df = train_test_split(df, test_size=sample_size/len(df),
                                 stratify=df['label'], random_state=42)
        df = df.reset_index(drop=True)
        print(f"\n  Stratified sample → {len(df):,} URLs")

    print(f"\n  STEP 2 — Extract {len(FEATURE_NAMES)} features per URL...")
    t0 = time.time()
    X = []
    for i, u in enumerate(df['url']):
        X.append(extract_feature_vector(u))
        if (i + 1) % 50_000 == 0:
            rate = (i + 1) / (time.time() - t0)
            left = (len(df) - i - 1) / rate
            print(f"    {i+1:,}/{len(df):,}  —  {rate:.0f} URLs/sec  —  ~{left:.0f}s left")

    X = np.array(X, dtype=np.float32)
    print(f"  Done in {time.time()-t0:.1f}s  →  shape {X.shape}")
    return X, df['label'].values


def train_and_evaluate(X, y_raw):
    print(f"\n{'='*62}")
    print("  STEP 3 — Encode Labels")
    print(f"{'='*62}")
    le = LabelEncoder()
    y  = le.fit_transform(y_raw)
    joblib.dump(le, MDIR / 'label_encoder.pkl')
    for i, c in enumerate(le.classes_):
        print(f"  {i} → {c}")

    print(f"\n{'='*62}")
    print("  STEP 4 — Scale + Split")
    print(f"{'='*62}")
    sc = StandardScaler()
    Xs = sc.fit_transform(X)
    joblib.dump(sc, MDIR / 'scaler.pkl')
    Xtr, Xte, ytr, yte = train_test_split(Xs, y, test_size=0.20,
                                           random_state=42, stratify=y)
    sw = compute_sample_weight('balanced', ytr)
    print(f"  Train : {len(Xtr):,}   Test : {len(Xte):,}")
    weights = compute_sample_weight('balanced', np.unique(ytr))
    print("Class weights:", weights)
    print(f"\n{'='*62}")
    print("  STEP 5 — Train 3-Model Ensemble")
    print(f"{'='*62}")
    t_total = time.time()

    print("  [1/3] XGBoost ...")
    t0 = time.time()
    xgb_m = xgb.XGBClassifier(
        n_estimators=350, max_depth=8, learning_rate=0.05,
        subsample=0.85, colsample_bytree=0.85,
        eval_metric='mlogloss', random_state=42,
        n_jobs=-1, tree_method='hist'
    )
    xgb_m.fit(Xtr, ytr, sample_weight=sw)
    print(f"  XGBoost done in {time.time()-t0:.0f}s")

    print("  [2/3] LightGBM ...")
    t0 = time.time()
    lgb_m = lgb.LGBMClassifier(
        n_estimators=350, max_depth=8, learning_rate=0.05,
        subsample=0.85, colsample_bytree=0.85,
        num_leaves=63, random_state=42, n_jobs=-1, verbose=-1
    )
    lgb_m.fit(Xtr, ytr, sample_weight=sw)
    print(f"  LightGBM done in {time.time()-t0:.0f}s")

    print("  [3/3] CatBoost ...")
    t0 = time.time()
    cat_m = CatBoostClassifier(
        iterations=280, depth=7, learning_rate=0.06,
        random_seed=42, verbose=0, thread_count=-1,
        loss_function='MultiClass'
    )
    cat_m.fit(Xtr, ytr, sample_weight=sw)
    print(f"  CatBoost done in {time.time()-t0:.0f}s")

    print(f"\n  Total training : {time.time()-t_total:.0f}s")

    # Soft-voting ensemble (XGB weight 1.2×, CatBoost 1.1×, LGB 1.0×)
    model = Ensemble([xgb_m, lgb_m, cat_m], [1.2, 1.0, 1.1])

    print(f"\n{'='*62}")
    print("  STEP 6 — Evaluation")
    print(f"{'='*62}")
    yp  = model.predict(Xte)
    ypr = model.predict_proba(Xte)
    acc = accuracy_score(yte, yp)
    f1  = f1_score(yte, yp, average='weighted')
    rec = recall_score(yte, yp, average=None)
    try:
        auc = roc_auc_score(yte, ypr, multi_class='ovr', average='weighted')
    except Exception:
        auc = 0.0

    print(f"\n  Accuracy : {acc*100:.2f}%")
    print(f"  F1 Score : {f1*100:.2f}%")
    print(f"  ROC-AUC  : {auc*100:.2f}%")
    print(f"\n  Per-class Recall:")
    for i, c in enumerate(le.classes_):
        flag = "  ← CRITICAL (missing = dangerous)" if c in ('phishing', 'malware') else ""
        print(f"    {c:15} {rec[i]*100:.2f}%{flag}")
    print(f"\n{classification_report(yte, yp, target_names=le.classes_)}")
    cm = confusion_matrix(yte, yp)
    print("  Confusion Matrix (rows=actual, cols=predicted):")
    header = "  " + "".join(f"{c:>14}" for c in le.classes_)
    print(header)
    for i, row in enumerate(cm):
        print(f"  {le.classes_[i]:<14}" + "".join(f"{v:>14,}" for v in row))

    print(f"\n{'='*62}")
    print("  STEP 7 — Save")
    print(f"{'='*62}")
    joblib.dump(model, MDIR / 'ensemble_model.pkl')
    (MDIR / 'training_metadata.txt').write_text(
        f"Date      : {pd.Timestamp.now()}\n"
        f"Dataset   : combined_dataset.csv (1.58M URLs)\n"
        f"Sample    : {len(X):,}\n"
        f"Train     : {len(Xtr):,}   Test: {len(Xte):,}\n"
        f"Features  : {len(FEATURE_NAMES)}\n"
        f"Classes   : {list(le.classes_)}\n"
        f"Accuracy  : {acc*100:.2f}%\n"
        f"F1 Score  : {f1*100:.2f}%\n"
        f"ROC-AUC   : {auc*100:.2f}%\n"
        f"Phishing Recall: {rec[list(le.classes_).index('phishing')]*100:.2f}%\n"
        f"Malware Recall : {rec[list(le.classes_).index('malware')]*100:.2f}%\n"
    )
    print(f"  ensemble_model.pkl → {MDIR}")
    print(f"  scaler.pkl         → {MDIR}")
    print(f"  label_encoder.pkl  → {MDIR}")

    print(f"\n{'='*62}")
    print(f"  ✅  TRAINING COMPLETE")
    print(f"  Accuracy {acc*100:.2f}%  |  F1 {f1*100:.2f}%  |  AUC {auc*100:.2f}%")
    print(f"{'='*62}\n")
    return acc, f1, auc


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CyberShield Model Training')
    parser.add_argument('--full',   action='store_true', help='Train on full 1.58M dataset (~25 min)')
    parser.add_argument('--sample', type=int, default=150_000, help='Sample size (default: 150000)')
    args = parser.parse_args()

    sample_size = None if args.full else args.sample
    if args.full:
        print(f"\n  ⚠️  Full training on 1.58M URLs selected. Estimated time: 20-30 minutes.")
    else:
        print(f"\n  Using stratified sample of {sample_size:,} URLs.")

    X, y_raw = load_data(sample_size)
    train_and_evaluate(X, y_raw)
