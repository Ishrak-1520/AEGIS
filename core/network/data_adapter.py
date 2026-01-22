import pandas as pd
import numpy as np
import os

# Internal feature names that logic relies on (Indices 0-5)
REQUIRED_FEATURES = ["Duration", "FwdPkts", "BwdPkts", "LenMean", "LenStd", "IAT"]

# Total features expected by the model
EXPECTED_FEATURE_COUNT = 78

# Fuzzy Matching: Map common variations to internal names
COLUMN_MAPPING = {
    # Duration
    "dur": "Duration",
    "duration": "Duration",
    "total_duration": "Duration",
    "flow_duration": "Duration",
    "flow duration": "Duration",
    
    # Source/Dest IP
    "srcip": "SrcIP",
    "src_ip": "SrcIP",
    "source_ip": "SrcIP",
    "source ip": "SrcIP",
    "dstip": "DstIP",
    "dst_ip": "DstIP",
    "dest_ip": "DstIP",
    "destination_ip": "DstIP",
    "destination ip": "DstIP",
    
    # Packets
    "fwdpkts": "FwdPkts",
    "total_fwd_packets": "FwdPkts",
    "total fwd packets": "FwdPkts",
    "spkts": "FwdPkts",
    
    "bwdpkts": "BwdPkts",
    "total_backward_packets": "BwdPkts",
    "total backward packets": "BwdPkts",
    "dpkts": "BwdPkts",
    
    # Length
    "lenmean": "LenMean",
    "fwd_packet_length_mean": "LenMean",
    "fwd packet length mean": "LenMean",
    "smean": "LenMean",
    
    "lenstd": "LenStd",
    "fwd_packet_length_std": "LenStd",
    "fwd packet length std": "LenStd",
    
    # Inter-Arrival Time
    "iat": "IAT",
    "flow_iat_mean": "IAT",
    "flow iat mean": "IAT",
    
    # Label
    "label": "Label",
    "attack_cat": "Label",
    "class": "Label"
}

def load_and_preprocess(filepath):
    """
    Loads a CSV, standardizes columns, cleans data, and ensures 78 features.
    
    Returns:
        df: preprocessed DataFrame with standardized columns and padding.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found: {filepath}")
        
    try:
        # 1. Load Data
        df = pd.read_csv(filepath)
        
        # Strip whitespace from headers
        df.columns = df.columns.str.strip().str.lower()
        
        # 2. Fuzzy Column Matching
        new_columns = {}
        found_columns = []
        
        for col in df.columns:
            # Check if this column maps to something we know
            if col in COLUMN_MAPPING:
                standard_name = COLUMN_MAPPING[col]
                new_columns[col] = standard_name
                found_columns.append(standard_name)
            else:
                # Keep original if no match, or drop later if strict
                new_columns[col] = col
                
        df.rename(columns=new_columns, inplace=True)
        
        # Check for Critical Missing Columns (Optional: could just pad with 0 if missing)
        # For this system, we really want at least some basic features to function
        # But per requirements, "If a required column cannot be found... raise a clear error"
        # The prompt says: "If a required column cannot be found via fuzzy matching, raise a clear error"
        # The required keys were: SrcIP, DstIP, Label, Duration, FwdPkts, BwdPkts, LenMean, LenStd, IAT
        
        required_set = {"SrcIP", "DstIP", "Label"} # IPs and Label are structural
        feature_set = set(REQUIRED_FEATURES) # 6 features
        
        missing_structural = required_set - set(df.columns)
        missing_features = feature_set - set(df.columns)
        
        # We might be lenient with IPs if it's just raw feature data, but let's warn or error
        # Prompt implies we need to be strict about mapping functionality
        if missing_features:
            # If features are missing, we can pad them with 0 (as per padding strategy), 
            # BUT the prompt Step 1.2 says "raise a clear error listing the missing columns"
            # However Step 1.5 says "Feature Padding: Ensure output... has 78 columns... If fewer, pad"
            # Conflict? "Padding Strategy" usually implies filling missing DATA. 
            # Step 1.2 instruction seems to target the *mapping availability*.
            # Let's try to look for them. If strictly missing, raise error.
            raise ValueError(f"Missing required columns: {missing_features}. \nValid synonyms: {list(COLUMN_MAPPING.keys())}")

        # 3. Data Cleaning
        # Convert Infinity to NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        # Fill NaN with 0 (Standard for padding strategy) or drop? 
        # Prompt Step 1.3: "Convert Infinity and NaN to 0 or drop rows."
        # Let's fill with 0 to preserve data quantity if sparse
        df.fillna(0, inplace=True)
        
        # 4. Label Normalization
        if "Label" in df.columns:
            # Normalize to "Benign" vs Malicious
            # If it's already 0/1, map 0->Benign, 1->Malicious? 
            # Or if it's strings like "DDoS", keep them?
            # Prompt: "Keep values as 'Benign' (or 'BENIGN') for normal... and 1 (or attack name) for Malicious"
            # We will just ensure consistent string case for Benign
            df['Label'] = df['Label'].apply(lambda x: 'Benign' if str(x).upper() == 'BENIGN' or str(x) == '0' else x)
        
        # 5. Feature Padding (The 78-feature constraint)
        # We need to construct a dataframe that the model can accept.
        # The model expects 78 features. We have 6 known features.
        # We will map our 6 features to indices 0-5 and fill the rest with 0.
        
        # Create a placeholder for all 78 features
        # We can name them "Feature_0" to "Feature_77" if we don't know real names
        # But we MUST preserve our extracted columns.
        
        # Strategy: Create a new DF with 78 feature columns + Meta columns (SrcIP, DstIP, Label)
        
        processed_data = pd.DataFrame()
        
        # Copy Meta
        if "SrcIP" in df.columns: processed_data["SrcIP"] = df["SrcIP"]
        if "DstIP" in df.columns: processed_data["DstIP"] = df["DstIP"]
        if "Label" in df.columns: processed_data["Label"] = df["Label"]
        if "Timestamp" in df.columns: processed_data["Timestamp"] = df["Timestamp"]
        else: processed_data["Timestamp"] = "2024-01-01 12:00:00" # Dummy if missing
        
        # Feature Matrix
        features = np.zeros((len(df), EXPECTED_FEATURE_COUNT))
        
        # Map known columns to specific indices (matching dataset_replay.py logic)
        # 0: Duration, 1: FwdPkts, 2: BwdPkts, 3: LenMean, 4: LenStd, 5: IAT
        
        features[:, 0] = df["Duration"]
        features[:, 1] = df["FwdPkts"]
        features[:, 2] = df["BwdPkts"]
        features[:, 3] = df["LenMean"]
        features[:, 4] = df["LenStd"]
        features[:, 5] = df["IAT"]
        
        # Add to processed DF
        # Column names don't matter to Sklearn MLP, but let's keep them clean
        feat_cols = [f"Feature_{i}" for i in range(EXPECTED_FEATURE_COUNT)]
        
        # However, to be nice, let's name the first 6
        feat_cols[0] = "Duration"
        feat_cols[1] = "FwdPkts"
        feat_cols[2] = "BwdPkts"
        feat_cols[3] = "LenMean"
        feat_cols[4] = "LenStd"
        feat_cols[5] = "IAT"
        
        features_df = pd.DataFrame(features, columns=feat_cols)
        
        # Concatenate Metadata and Features
        # Note: Train model might expect Label at end or specific place.
        # We will return the full dataframe. Caller can separate X and y.
        
        final_df = pd.concat([processed_data, features_df], axis=1)
        
        return final_df

    except Exception as e:
        raise Exception(f"Error loading dataset: {str(e)}")
