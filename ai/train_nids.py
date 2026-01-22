"""
AEGIS NIDS Training Script
Trains a RandomForest classifier on CICIDS2017 network flow data.

Usage:
    python ai/train_nids.py
"""
import os
import sys
import glob
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
DATA_DIR = os.path.join(BASE_DIR, "data", "network")
OUTPUT_DIR = os.path.join(BASE_DIR, "ai", "models")

# Model output paths
MODEL_PATH = os.path.join(OUTPUT_DIR, "nids_model.pkl")
SCALER_PATH = os.path.join(OUTPUT_DIR, "nids_scaler.pkl")

# Feature mapping from CICIDS2017 columns to internal names
# Note: CICIDS2017 headers have leading spaces
FEATURE_COLUMNS = [
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    " Packet Length Mean",
    " Packet Length Std",
    " Flow IAT Mean"
]

LABEL_COLUMN = " Label"


def log(msg):
    """Print timestamped log message."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def load_all_csvs(data_dir):
    """Load all CSV files from the data directory."""
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    
    log(f"Found {len(csv_files)} CSV files to process")
    
    dataframes = []
    for csv_file in csv_files:
        filename = os.path.basename(csv_file)
        log(f"Loading: {filename}")
        
        try:
            df = pd.read_csv(csv_file, low_memory=False)
            log(f"  → {len(df):,} rows loaded")
            dataframes.append(df)
        except Exception as e:
            log(f"  ⚠ Error loading {filename}: {e}")
            continue
    
    if not dataframes:
        raise ValueError("No data could be loaded from CSV files")
    
    # Concatenate all dataframes
    combined_df = pd.concat(dataframes, ignore_index=True)
    log(f"Total combined rows: {len(combined_df):,}")
    
    return combined_df


def preprocess_data(df):
    """Clean and preprocess the dataset."""
    log("Preprocessing data...")
    
    # Check for required columns
    missing_cols = [col for col in FEATURE_COLUMNS + [LABEL_COLUMN] if col not in df.columns]
    if missing_cols:
        # Try without leading space
        alt_cols = [col.strip() for col in missing_cols]
        log(f"  Trying alternative column names: {alt_cols}")
        
        # Rename columns to add leading space if needed
        rename_map = {}
        for col in df.columns:
            if col.strip() in [c.strip() for c in FEATURE_COLUMNS + [LABEL_COLUMN]]:
                rename_map[col] = " " + col.strip() if not col.startswith(" ") else col
        
        if rename_map:
            df = df.rename(columns=rename_map)
    
    # Extract features and labels
    X = df[FEATURE_COLUMNS].copy()
    y = df[LABEL_COLUMN].copy()
    
    # Handle infinity values
    log("  Replacing infinity values...")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Handle NaN values
    nan_count = X.isna().sum().sum()
    if nan_count > 0:
        log(f"  Filling {nan_count:,} NaN values with 0")
        X.fillna(0, inplace=True)
    
    # Convert to numeric (handle any string values)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
    
    # Map labels: BENIGN -> 0, everything else -> 1
    log("  Mapping labels...")
    y_clean = y.str.strip().str.upper()
    y_binary = (y_clean != "BENIGN").astype(int)
    
    # Log label distribution
    benign_count = (y_binary == 0).sum()
    attack_count = (y_binary == 1).sum()
    log(f"  Label distribution: BENIGN={benign_count:,}, ATTACK={attack_count:,}")
    
    return X.values, y_binary.values


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
    log("  This may take several minutes...")
    
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
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0,0]:,}  FP={cm[0,1]:,}")
    print(f"  FN={cm[1,0]:,}  TP={cm[1,1]:,}")
    
    # Feature importance
    log("\nFeature Importance:")
    feature_names = ["Flow Duration", "Fwd Packets", "Bwd Packets", 
                     "Pkt Len Mean", "Pkt Len Std", "Flow IAT Mean"]
    importances = model.feature_importances_
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        log(f"  {name}: {imp:.4f}")
    
    return model, scaler


def save_artifacts(model, scaler):
    """Save model and scaler to disk."""
    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    log(f"Saving model to: {MODEL_PATH}")
    joblib.dump(model, MODEL_PATH)
    
    log(f"Saving scaler to: {SCALER_PATH}")
    joblib.dump(scaler, SCALER_PATH)
    
    # Verify files were created
    model_size = os.path.getsize(MODEL_PATH) / (1024 * 1024)
    scaler_size = os.path.getsize(SCALER_PATH) / 1024
    
    log(f"\n✓ Model saved: {model_size:.2f} MB")
    log(f"✓ Scaler saved: {scaler_size:.2f} KB")


def main():
    """Main training pipeline."""
    print("\n" + "="*60)
    print("AEGIS NIDS TRAINING PIPELINE")
    print("="*60 + "\n")
    
    try:
        # Load data
        df = load_all_csvs(DATA_DIR)
        
        # Preprocess
        X, y = preprocess_data(df)
        
        # Train
        model, scaler = train_model(X, y)
        
        # Save
        save_artifacts(model, scaler)
        
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
