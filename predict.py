import tensorflow as tf
import joblib
import pickle
import pandas as pd
import numpy as np
import sys
import os
import glob

# Load artifacts
model_stage1 = tf.keras.models.load_model('stage1_model.h5')
model_stage2 = tf.keras.models.load_model('stage2_model.h5')
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
            # Handle unseen labels by mapping to 'NaN' (assuming 'NaN' was in training)
            new_data_df[col] = new_data_df[col].astype(str).apply(lambda x: x if x in le.classes_ else 'NaN')
            new_data_df[col] = le.transform(new_data_df[col])

    # Normalize using loaded scaler
    # Ensure columns match training X.columns
    expected_columns = scaler.feature_names_in_  # If available; otherwise, assume order matches
    new_data_df = new_data_df.reindex(columns=expected_columns, fill_value=0)  # Fill missing with 0 or appropriate
    new_data_scaled = pd.DataFrame(scaler.transform(new_data_df), columns=new_data_df.columns)
    
    return new_data_scaled

# Hybrid predict function
def hybrid_predict(new_data, model_stage1, model_stage2, le_attack):
    pred_binary = (model_stage1.predict(new_data) > 0.5).astype(int).flatten()
    results = []
    for i, is_attack in enumerate(pred_binary):
        if is_attack == 0:
            results.append('Normal')
        else:
            pred_multi = np.argmax(model_stage2.predict(new_data.iloc[[i]]), axis=1)[0]
            attack_type = le_attack.inverse_transform([pred_multi])[0]
            results.append(attack_type)
    return results

# Main script
if __name__ == "__main__":
    directory_path = "/tmp/captures"
    
    # Find all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory_path, "*.csv"))
    
    if not csv_files:
        print(f"No CSV files found in {directory_path}")
        sys.exit(1)
    
    for csv_path in csv_files:
        print(f"\nProcessing file: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # Assume CSV has the features (no label/attack_cat), missing handled, categoricals as strings
        df_scaled = preprocess(df)
        
        predictions = hybrid_predict(df_scaled, model_stage1, model_stage2, le_attack)
        
        print("Predictions:")
        for i, pred in enumerate(predictions):
            print(f"Sample {i}: {pred}")
