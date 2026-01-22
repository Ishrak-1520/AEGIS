"""
AEGIS HIDS Training Script
Trains a RandomForest classifier on Windows PE API call sequence data.

Usage:
    python ai/train_hids.py
"""
import os
import sys
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

# Suppress warnings
warnings.filterwarnings("ignore")

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data", "host")
OUTPUT_DIR = os.path.join(BASE_DIR, "ai", "models")

# Model output paths
MODEL_PATH = os.path.join(OUTPUT_DIR, "hids_model.pkl")
SCALER_PATH = os.path.join(OUTPUT_DIR, "hids_scaler.pkl")
API_MAPPING_PATH = os.path.join(OUTPUT_DIR, "hids_api_mapping.pkl")

# Expected number of API sequence features (t_0 to t_99)
NUM_API_FEATURES = 100


def log(msg):
    """Print timestamped log message."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def load_data(data_dir):
    """Load the Windows PE API dataset."""
    # Find the CSV file
    csv_files = [f for f in os.listdir(data_dir) if f.endswith('.csv')]
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    
    csv_path = os.path.join(data_dir, csv_files[0])
    log(f"Loading: {csv_files[0]}")
    
    df = pd.read_csv(csv_path)
    log(f"  → {len(df):,} rows, {len(df.columns)} columns loaded")
    
    return df


def preprocess_data(df):
    """Clean and preprocess the dataset."""
    log("Preprocessing data...")
    
    # Identify feature columns (t_0 to t_99)
    feature_cols = [f"t_{i}" for i in range(NUM_API_FEATURES)]
    
    # Check if all expected columns exist
    missing_cols = [col for col in feature_cols if col not in df.columns]
    if missing_cols:
        log(f"  ⚠ Missing columns: {missing_cols[:5]}... (showing first 5)")
        # Use available t_* columns
        feature_cols = [col for col in df.columns if col.startswith('t_')]
        log(f"  Using {len(feature_cols)} available feature columns")
    
    # Check for label column
    if 'malware' not in df.columns:
        # Try alternative names
        label_candidates = ['Malware', 'label', 'Label', 'class', 'Class']
        for candidate in label_candidates:
            if candidate in df.columns:
                df = df.rename(columns={candidate: 'malware'})
                break
        else:
            raise ValueError("Could not find malware/label column")
    
    # Extract features and labels
    X = df[feature_cols].copy()
    y = df['malware'].copy()
    
    # Handle any non-numeric values
    log("  Converting to numeric...")
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
    
    # Handle NaN values
    X.fillna(0, inplace=True)
    
    # Ensure label is binary
    y = y.astype(int)
    
    # Log label distribution
    benign_count = (y == 0).sum()
    malware_count = (y == 1).sum()
    log(f"  Label distribution: BENIGN={benign_count:,}, MALWARE={malware_count:,}")
    
    # Build API value mapping for inference (unique values per position)
    log("  Building API value mapping for inference...")
    api_mapping = {}
    for col in feature_cols:
        unique_vals = df[col].dropna().unique()
        api_mapping[col] = {val: idx for idx, val in enumerate(sorted(unique_vals))}
    
    return X.values, y.values, feature_cols, api_mapping


def train_model(X, y):
    """Train the RandomForest classifier."""
    log("Splitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    log(f"  Training set: {len(X_train):,} samples")
    log(f"  Test set: {len(X_test):,} samples")
    
    # Scale features
    log("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train model
    log("Training RandomForestClassifier (n_estimators=100)...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        n_jobs=-1,
        random_state=42,
        verbose=1
    )
    
    model.fit(X_train_scaled, y_train)
    log("Training complete!")
    
    # Evaluate
    log("Evaluating model...")
    y_pred = model.predict(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    log(f"\n{'='*50}")
    log(f"ACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    log(f"{'='*50}\n")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "MALWARE"]))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]:,}  FP={cm[0,1]:,}")
    print(f"  FN={cm[1,0]:,}  TP={cm[1,1]:,}")
    
    # Top feature importance
    log("\nTop 10 Feature Importance:")
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:10]
    for idx in top_indices:
        log(f"  t_{idx}: {importances[idx]:.4f}")
    
    return model, scaler


def save_artifacts(model, scaler, api_mapping):
    """Save model, scaler, and API mapping to disk."""
    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    log(f"Saving model to: {MODEL_PATH}")
    joblib.dump(model, MODEL_PATH)
    
    log(f"Saving scaler to: {SCALER_PATH}")
    joblib.dump(scaler, SCALER_PATH)
    
    log(f"Saving API mapping to: {API_MAPPING_PATH}")
    joblib.dump(api_mapping, API_MAPPING_PATH)
    
    # Verify files were created
    model_size = os.path.getsize(MODEL_PATH) / (1024 * 1024)
    scaler_size = os.path.getsize(SCALER_PATH) / 1024
    mapping_size = os.path.getsize(API_MAPPING_PATH) / 1024
    
    log(f"\n✓ Model saved: {model_size:.2f} MB")
    log(f"✓ Scaler saved: {scaler_size:.2f} KB")
    log(f"✓ API Mapping saved: {mapping_size:.2f} KB")


def main():
    """Main training pipeline."""
    print("\n" + "="*60)
    print("AEGIS HIDS TRAINING PIPELINE")
    print("="*60 + "\n")
    
    try:
        # Load data
        df = load_data(DATA_DIR)
        
        # Preprocess
        X, y, feature_cols, api_mapping = preprocess_data(df)
        
        # Train
        model, scaler = train_model(X, y)
        
        # Save
        save_artifacts(model, scaler, api_mapping)
        
        print("\n" + "="*60)
        print("✓ TRAINING COMPLETE")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n✗ TRAINING FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
