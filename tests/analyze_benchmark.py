import sqlite3
import pandas as pd
import json
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Set style for academic charts
sns.set_theme(style="whitegrid")
DB_PATH = "benchmarking_results.db"

def get_db_data():
    """Connects to the local SQLite DB and loads the benchmark results."""
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: Database file '{DB_PATH}' not found.")
        return pd.DataFrame()

    conn = sqlite3.connect(DB_PATH)
    try:
        # Load only successful runs (where error_log is empty)
        df = pd.read_sql("SELECT * FROM benchmark_results WHERE error_log IS NULL OR error_log = ''", conn)
        return df
    except Exception as e:
        print(f"Error reading database: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

def calculate_metrics(df):
    """
    Calculates Precision, Recall, and F1 based on Ground Truth vs Sift Predictions.
    Also counts the specific 'Hallucinated Import' vulnerabilities for your report.
    """
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    
    hallucinations_caught = 0
    
    print(f"Analyzing {len(df)} records for detailed metrics...")
    
    for _, row in df.iterrows():
        # 1. Parse Sift Issues (The 'Prediction')
        try:
            sift_vulns = json.loads(row['sift_issues']) if row['sift_issues'] else []
            # Handle case where it might be a dictionary or string
            if isinstance(sift_vulns, str): sift_vulns = json.loads(sift_vulns)
            if not isinstance(sift_vulns, list): sift_vulns = [] 
        except:
            sift_vulns = []
            
        # 2. Parse Ground Truth (The 'Correct Answer')
        try:
            gt_vulns = json.loads(row['ground_truth']) if row['ground_truth'] else []
            if isinstance(gt_vulns, str): gt_vulns = json.loads(gt_vulns)
        except:
            gt_vulns = []

        # --- Research Feature: Count Hallucinations ---
        # We look for keywords "Hallucination" or "PyPI" in the vulnerability data
        for v in sift_vulns:
            # Safely get text fields
            desc = str(v.get('description', '')).lower() 
            title = str(v.get('title', '')).lower() 
            v_type = str(v.get('type', '')).lower()
            
            combined_text = f"{desc} {title} {v_type}"
            
            if 'hallucination' in combined_text or 'pypi' in combined_text:
                hallucinations_caught += 1

        # --- Calculate Strict Confusion Matrix ---
        has_real_issues = len(gt_vulns) > 0
        sift_found_issues = len(sift_vulns) > 0

        if has_real_issues:
            if sift_found_issues:
                true_positives += 1  # Correctly caught a bug
            else:
                false_negatives += 1 # Missed a real bug
        else:
            # The code was safe
            if sift_found_issues:
                false_positives += 1 # False Alarm (claimed bug where none existed)
            else:
                true_positives += 1  # Correctly identified safe code

    # 3. Calculate Final Scores
    total = true_positives + false_positives + false_negatives
    if total == 0: 
        print("Not enough data to calculate metrics.")
        return
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n" + "="*50)
    print(" 📊 FINAL RESEARCH METRICS (Copy to your Paper)")
    print("="*50)
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1 Score:  {f1:.2%}")
    print("-" * 50)
    print(f"🛡️  Registry Hallucinations Caught: {hallucinations_caught}")
    print(f"⏱️  Average Processing Time:        {df['processing_time'].mean():.2f}s")
    print("="*50 + "\n")

def plot_score_distribution(df):
    """Generates the main histogram chart for the paper."""
    try:
        plt.figure(figsize=(10, 6))
        # Plot histogram with a kernel density estimate (KDE) line
        sns.histplot(df['sift_score'], bins=20, kde=True, color='teal', edgecolor='black')
        
        plt.title('Distribution of Sift Security Scores (n=1000)', fontsize=14, fontweight='bold')
        plt.xlabel('Sift Security Score (0=Critical, 100=Safe)', fontsize=12)
        plt.ylabel('Frequency (Number of Files)', fontsize=12)
        
        # Add a vertical line for the average
        mean_score = df['sift_score'].mean()
        plt.axvline(mean_score, color='red', linestyle='--', linewidth=2, label=f"Mean: {mean_score:.1f}")
        plt.legend()
        
        # Save chart
        filename = "figure_1_score_distribution.png"
        plt.savefig(filename, dpi=300)
        print(f"✅ Chart saved successfully: {filename}")
        
    except Exception as e:
        print(f"Could not generate chart (check if matplotlib/seaborn is installed): {e}")

if __name__ == "__main__":
    print("Loading benchmark results from SQLite...")
    df = get_db_data()
    
    if not df.empty:
        calculate_metrics(df)
        plot_score_distribution(df)
    else:
        print("No successful data found in the database. Run the benchmark harness first.")