import joblib
import pickle
import pandas as pd
import sys
import os
import glob
import time

# Load artifacts
model_stage1 = joblib.load('stage1_model.pkl')
model_stage2 = joblib.load('stage2_model.pkl')
scaler = joblib.load('scaler.pkl')
with open('le_attack.pkl', 'rb') as f:
    le_attack = pickle.load(f)
with open('encoders.pkl', 'rb') as f:
    encoders = pickle.load(f)

# Categorical columns to encode
cat_cols = ['proto', 'state', 'service']

def preprocess(new_data_df):
    # Handle categorical encoding using loaded encoders
    for col in cat_cols:
        if col in new_data_df.columns and col in encoders:
            le = encoders[col]
            # Replace unseen categories with the first known class (which encodes to 0)
            new_data_df[col] = new_data_df[col].astype(str).apply(lambda x: x if x in le.classes_ else le.classes_[0])
            new_data_df[col] = le.transform(new_data_df[col])
    # Normalize using loaded scaler
    # Ensure columns match training X.columns
    expected_columns = scaler.feature_names_in_
    new_data_df = new_data_df.reindex(columns=expected_columns, fill_value=0)  # Fill missing columns with 0 or appropriate value
    new_data_scaled = pd.DataFrame(scaler.transform(new_data_df), columns=new_data_df.columns)
  
    return new_data_scaled

# Hybrid predict function
def hybrid_predict(new_data, model_stage1, model_stage2, le_attack):
    pred_binary = model_stage1.predict(new_data)
    results = []
    for i, is_attack in enumerate(pred_binary):
        if is_attack == 0:
            results.append('Normal')
        else:
            pred_multi = model_stage2.predict(new_data.iloc[[i]])[0]
            attack_type = le_attack.inverse_transform([pred_multi])[0]
            results.append(attack_type)
    return results

# Main script
if __name__ == "__main__":
    directory_path = "/tmp/captures"
    
    # Ensure the directory exists
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
    
    print("Starting continuous monitoring of directory:", directory_path)
    
    while True:
        # Find all CSV files in the directory
        csv_files = glob.glob(os.path.join(directory_path, "*.csv"))
        
        if not csv_files:
            # No files, sleep and check again
            time.sleep(5)  # Sleep for 5 seconds; adjust as needed
            continue
        
        for csv_path in csv_files:
            print(f"\nProcessing file: {csv_path}")
            try:
                df = pd.read_csv(csv_path)
                
                if df.empty:
                    print("Empty DataFrame after loading.")
                else:
                    # Preprocess and predict (unseen handled in preprocess)
                    df_scaled = preprocess(df)
                    predictions = hybrid_predict(df_scaled, model_stage1, model_stage2, le_attack)
                    
                    print("Predictions:")
                    for i, pred in enumerate(predictions):
                        print(f"Sample {i}: {pred}")
                
            except Exception as e:
                print(f"Error processing {csv_path}: {e}")
            
            # Delete the file after processing
            try:
                os.remove(csv_path)
                print(f"Deleted file: {csv_path}")
            except Exception as e:
                print(f"Error deleting {csv_path}: {e}")
        
        # Short sleep after processing batch to avoid high CPU usage
        time.sleep(1)
