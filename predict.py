import os
import time
import pandas as pd
import numpy as np
import joblib

# Load pre-trained artifacts (assume copied to /app)
encoders = joblib.load('/app/label_encoders.pkl')  # Dict of LabelEncoders
scaler = joblib.load('/app/minmax_scaler.pkl')  # MinMaxScaler
le_attack = joblib.load('/app/attack_label_encoder.pkl')  # LabelEncoder for attacks
final_columns = joblib.load('/app/feature_columns.pkl')  # List of expected features

# Load ONNX models
sess_stage1 = ort.InferenceSession('/app/model_stage1.onnx')
sess_stage2 = ort.InferenceSession('/app/model_stage2.onnx')

# Get input names (from ONNX)
input_name_stage1 = sess_stage1.get_inputs()[0].name
input_name_stage2 = sess_stage2.get_inputs()[0].name

# Directory to monitor
capture_dir = '/tmp/captures'

# Hybrid prediction (ONNX version)
def hybrid_predict(new_data, sess_stage1, sess_stage2, le_attack, input_name_stage1, input_name_stage2):
    results = []
    for i in range(len(new_data)):
        row_data = new_data.iloc[[i]].values.astype(np.float32)  # ONNX expects float32
        # Stage 1: Binary
        pred_binary = sess_stage1.run(None, {input_name_stage1: row_data})[0] > 0.5
        if not pred_binary:
            results.append('Normal')
        else:
            # Stage 2: Multi-class
            pred_multi = np.argmax(sess_stage2.run(None, {input_name_stage2: row_data})[0])
            attack_type = le_attack.inverse_transform([pred_multi])[0]
            results.append(attack_type)
    return results

# Main loop to monitor and process CSVs
while True:
    try:
        # List CSV files in the directory
        csv_files = [f for f in os.listdir(capture_dir) if f.endswith('.csv')]
        
        for csv_file in csv_files:
            file_path = os.path.join(capture_dir, csv_file)
            print(f"Processing CSV: {file_path}")
            
            # Read CSV into DF
            df = pd.read_csv(file_path)
            
            if df.empty:
                print(f"Empty CSV: {csv_file}. Skipping.")
                os.remove(file_path)  # Delete even if empty
                continue
            
            # Clean: Drop IPs
            df = df.drop(columns=['src_ip', 'dst_ip'], errors='ignore')
            
            # Encode categorical columns using loaded encoders
            cat_cols = [col for col in df.select_dtypes(include=['object']).columns if col != 'attack_cat']
            for col in cat_cols:
                if col in encoders:
                    # Handle unseen labels by mapping to 'unknown'
                    df[col] = df[col].map(lambda x: x if x in encoders[col].classes_ else 'unknown')
                    # Add 'unknown' if not present
                    if 'unknown' not in encoders[col].classes_:
                        encoders[col].classes_ = np.append(encoders[col].classes_, 'unknown')
                    df[col] = encoders[col].transform(df[col])
            
            # Ensure columns match final_columns (add missing with NaN, drop extra)
            missing_cols = set(final_columns) - set(df.columns)
            for col in missing_cols:
                df[col] = np.nan  # Or 0, depending on your data
            extra_cols = set(df.columns) - set(final_columns)
            df = df.drop(columns=extra_cols, errors='ignore')
            df = df[final_columns]  # Reorder to match
            
            # Scale numerical features
            num_cols = df.select_dtypes(include=['number']).columns
            df[num_cols] = scaler.transform(df[num_cols])
            
            # Predict using hybrid function
            predictions = hybrid_predict(df, model_stage1, model_stage2, le_attack)
            
            # Log predictions
            for i, pred in enumerate(predictions):
                print(f"Row {i+1}: {'Attack - Type: ' + pred if pred != 'Normal' else 'Normal'}")
            
            # Delete the processed CSV
            os.remove(file_path)
            print(f"Deleted CSV: {csv_file}")
        
        # Sleep briefly before checking again
        time.sleep(5)  # Adjust polling interval as needed
    
    except Exception as e:
        print(f"Error during processing: {e}")
        time.sleep(10)  # Backoff on error
