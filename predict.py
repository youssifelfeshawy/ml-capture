import os
import time
import pandas as pd
import numpy as np
import joblib
import tensorflow as tf

# === Load pre-trained artifacts (assume copied to /app) ===
encoders = joblib.load('/app/label_encoders.pkl')  # Dict of LabelEncoders
scaler = joblib.load('/app/minmax_scaler.pkl')     # MinMaxScaler
le_attack = joblib.load('/app/attack_label_encoder.pkl')  # LabelEncoder for attacks
final_columns = joblib.load('/app/feature_columns.pkl')   # List of expected features

# === Load TensorFlow Lite models ===
interpreter_stage1 = tf.lite.Interpreter(model_path="/app/model_stage1.tflite")
interpreter_stage2 = tf.lite.Interpreter(model_path="/app/model_stage2.tflite")

interpreter_stage1.allocate_tensors()
interpreter_stage2.allocate_tensors()

# Get input/output details
input_details_stage1 = interpreter_stage1.get_input_details()
output_details_stage1 = interpreter_stage1.get_output_details()

input_details_stage2 = interpreter_stage2.get_input_details()
output_details_stage2 = interpreter_stage2.get_output_details()

# === Directory to monitor ===
capture_dir = '/tmp/captures'


# === Hybrid prediction (TFLite version) ===
def hybrid_predict(new_data, interpreter_stage1, interpreter_stage2, le_attack):
    results = []

    for i in range(len(new_data)):
        row_data = new_data.iloc[[i]].values.astype(np.float32)

        # ---- Stage 1: Binary Classification (Normal vs Attack) ----
        interpreter_stage1.set_tensor(input_details_stage1[0]['index'], row_data)
        interpreter_stage1.invoke()
        pred_binary = interpreter_stage1.get_tensor(output_details_stage1[0]['index'])[0][0]

        if pred_binary < 0.5:
            results.append('Normal')
        else:
            # ---- Stage 2: Multi-class Classification ----
            interpreter_stage2.set_tensor(input_details_stage2[0]['index'], row_data)
            interpreter_stage2.invoke()
            pred_multi = interpreter_stage2.get_tensor(output_details_stage2[0]['index'])[0]
            attack_class = np.argmax(pred_multi)
            attack_type = le_attack.inverse_transform([attack_class])[0]
            results.append(attack_type)

    return results


# === Main loop to monitor and process CSVs ===
while True:
    try:
        csv_files = [f for f in os.listdir(capture_dir) if f.endswith('.csv')]

        for csv_file in csv_files:
            file_path = os.path.join(capture_dir, csv_file)
            print(f"Processing CSV: {file_path}")

            df = pd.read_csv(file_path)

            if df.empty:
                print(f"Empty CSV: {csv_file}. Skipping.")
                os.remove(file_path)
                continue

            # Drop IPs or unnecessary columns
            df = df.drop(columns=['src_ip', 'dst_ip'], errors='ignore')

            # Encode categorical columns
            cat_cols = [col for col in df.select_dtypes(include=['object']).columns if col != 'attack_cat']
            for col in cat_cols:
                if col in encoders:
                    df[col] = df[col].map(lambda x: x if x in encoders[col].classes_ else 'unknown')
                    if 'unknown' not in encoders[col].classes_:
                        encoders[col].classes_ = np.append(encoders[col].classes_, 'unknown')
                    df[col] = encoders[col].transform(df[col])

            # Match feature columns
            missing_cols = set(final_columns) - set(df.columns)
            for col in missing_cols:
                df[col] = np.nan
            extra_cols = set(df.columns) - set(final_columns)
            df = df.drop(columns=extra_cols, errors='ignore')
            df = df[final_columns]

            # Scale numerical data
            num_cols = df.select_dtypes(include=['number']).columns
            df[num_cols] = scaler.transform(df[num_cols])

            # Hybrid prediction using TFLite models
            predictions = hybrid_predict(df, interpreter_stage1, interpreter_stage2, le_attack)

            # Log results
            for i, pred in enumerate(predictions):
                print(f"Row {i+1}: {'Attack - ' + pred if pred != 'Normal' else 'Normal'}")

            os.remove(file_path)
            print(f"Deleted CSV: {csv_file}")

        time.sleep(5)  # check again every 5 seconds

    except Exception as e:
        print(f"Error during processing: {e}")
        time.sleep(10)
