# datasetv2.py — RandomForest with robust balancing, tuning, and reporting

import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE

# --- Configuration ---
DATA_PATH   = "E:/data/archive2/final_dataset.parquet"
MODEL_DIR   = "trained_model_v3"
REPORT_PATH = os.path.join(MODEL_DIR, "training_report.txt")
RANDOM_STATE= 42

FEATURE_COLUMNS = [
    'IN_BYTES','IN_PKTS','OUT_BYTES','OUT_PKTS',
    'FLOW_DURATION_MILLISECONDS','DURATION_IN','DURATION_OUT',
    'MIN_TTL','MAX_TTL','LONGEST_FLOW_PKT','SHORTEST_FLOW_PKT',
    'MIN_IP_PKT_LEN','MAX_IP_PKT_LEN','SRC_TO_DST_SECOND_BYTES',
    'DST_TO_SRC_SECOND_BYTES','RETRANSMITTED_IN_BYTES',
    'RETRANSMITTED_IN_PKTS','RETRANSMITTED_OUT_BYTES',
    'RETRANSMITTED_OUT_PKTS','SRC_TO_DST_AVG_THROUGHPUT',
    'DST_TO_SRC_AVG_THROUGHPUT','NUM_PKTS_UP_TO_128_BYTES',
    'NUM_PKTS_128_TO_256_BYTES','NUM_PKTS_256_TO_512_BYTES',
    'NUM_PKTS_512_TO_1024_BYTES','NUM_PKTS_1024_TO_1514_BYTES',
    'TCP_WIN_MAX_IN','TCP_WIN_MAX_OUT'
]

UNDERSAMPLE_TARGET = {0:200_000, 3:200_000, 2:100_000}
OVERSAMPLE_MIN     = 50_000

# --- Data Loading & Validation ---
def load_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Data file not found: {path}")
    print(f"Loading {path}...")
    df = pd.read_parquet(path, columns=FEATURE_COLUMNS+['Label'], engine='fastparquet')
    return df


def verify_labels(df):
    mask = df['Label'].notna()
    if mask.sum() < len(df):
        print(f"Dropping {len(df)-mask.sum()} rows with missing labels")
    df = df.loc[mask].copy()
    df['Label'] = df['Label'].astype(int)
    return df

# --- Balancing & Clipping ---
def balance_data(X,y):
    print("Original class counts:", np.bincount(y))
    rus = RandomUnderSampler(sampling_strategy=UNDERSAMPLE_TARGET, random_state=RANDOM_STATE)
    X_r,y_r = rus.fit_resample(X,y)
    print("After undersampling:", np.bincount(y_r))
    # SMOTE for minority classes
    counts = np.bincount(y_r)
    strategy = {cls:OVERSAMPLE_MIN for cls,cnt in enumerate(counts) if cnt<OVERSAMPLE_MIN}
    if strategy:
        sm = SMOTE(sampling_strategy=strategy, random_state=RANDOM_STATE)
        X_bal,y_bal = sm.fit_resample(X_r,y_r)
        print("After SMOTE:", np.bincount(y_bal))
    else:
        X_bal,y_bal = X_r,y_r
        print("SMOTE not required.")
    return X_bal,y_bal


def clip_extremes(X,low_q=0.001,up_q=0.999):
    print("Clipping outliers...")
    for col in FEATURE_COLUMNS:
        lo,hi = X[col].quantile([low_q,up_q])
        X[col] = X[col].clip(lo,hi)
    return X

# --- Training Pipeline ---
def train():
    # Load & verify
    df = load_data(DATA_PATH)
    df = verify_labels(df)
    X = df[FEATURE_COLUMNS]
    y = df['Label'].values

    # Encode labels
    le = LabelEncoder().fit(y)
    y_enc = le.transform(y)
    print("Classes:", list(le.classes_))

    # Balance & clip
    X_bal,y_bal = balance_data(X,y_enc)
    X_bal = clip_extremes(X_bal)

    # Split
    X_tr,X_te,y_tr,y_te = train_test_split(
        X_bal,y_bal,test_size=0.2,stratify=y_bal,random_state=RANDOM_STATE
    )

    # Scale
    scaler = RobustScaler().fit(X_tr)
    X_tr_s = scaler.transform(X_tr)
    X_te_s = scaler.transform(X_te)

    # RF & hyperparameter tuning
    rf = RandomForestClassifier(
        class_weight='balanced',
        n_jobs=-1,
        random_state=RANDOM_STATE
    )
    param_grid = {
        'n_estimators': [50,100],
        'max_depth':    [20, None],
        'min_samples_split': [10]
    }
    cv = StratifiedKFold(n_splits=3,shuffle=True,random_state=RANDOM_STATE)
    grid = GridSearchCV(
        rf, param_grid, scoring='f1_macro', cv=cv,
        n_jobs=1, verbose=2
    )
    print("Searching best RF...")
    grid.fit(X_tr_s,y_tr)
    best = grid.best_estimator_
    print("Best params:", grid.best_params_, "CV f1_macro=", grid.best_score_)

    # Evaluate holdout
    y_pred = best.predict(X_te_s)
    y_proba= best.predict_proba(X_te_s)
    cm = confusion_matrix(y_te,y_pred)
    cr = classification_report(y_te,y_pred)
    auc = roc_auc_score(y_te,y_proba, multi_class='ovr', average='weighted')

    print("Confusion Matrix:\n",cm)
    print("Classification Report:\n",cr)
    print("Holdout ROC‑OVR AUC:",auc)

    # Save artifacts
    os.makedirs(MODEL_DIR,exist_ok=True)
    joblib.dump(best, os.path.join(MODEL_DIR,'rf_model.joblib'))
    joblib.dump(scaler, os.path.join(MODEL_DIR,'scaler.joblib'))
    joblib.dump(le, os.path.join(MODEL_DIR,'label_encoder.joblib'))
    joblib.dump(FEATURE_COLUMNS, os.path.join(MODEL_DIR,'features.pkl'))

    # Write report
    with open(REPORT_PATH,'w') as f:
        f.write("# Training Report\n")
        f.write(f"Best params: {grid.best_params_}\n")
        f.write(f"CV f1_macro: {grid.best_score_:.4f}\n")
        f.write(f"Holdout ROC‑OVR AUC: {auc:.4f}\n\n")
        f.write("Confusion Matrix:\n")
        f.write(np.array2string(cm))
        f.write("\n\nClassification Report:\n")
        f.write(cr)

    print(f"Artifacts + report saved at {MODEL_DIR}")

if __name__=='__main__':
    train()
