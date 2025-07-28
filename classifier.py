import os
import shutil
import time
import pandas as pd
import tensorflow as tf
import joblib
import ipaddress
import numpy as np

# Load the model, scaler and imputer
model = tf.keras.models.load_model('trained_traffic_classifier.keras')
scaler = joblib.load('scaler.pkl')
imputer = joblib.load('imputer.pkl')

# Directories
source_dir = "/opt/DDOS/generated"
destination_dir = "/opt/DDOS/read"

# Create the destination directory if it doesn't exist
os.makedirs(destination_dir, exist_ok=True)

print("DDoS Classifier is running. Waiting for files...")

while True:
    csv_files = [f for f in os.listdir(source_dir) if f.endswith(".csv")]

    if csv_files:
        for file_name in csv_files:
            source_path = os.path.join(source_dir, file_name)
            destination_path = os.path.join(destination_dir, file_name)

            try:
                # Read the CSV file with pandas
                df = pd.read_csv(source_path)
                print(f"Processing {file_name}: {len(df)} rows read")

                # Save original IPs
                source_ips = df['Source IP'].copy()
                destination_ips = df['Destination IP'].copy()

                start = time.time()

                # Data preprocessing
                df = df.drop('Label', axis=1)
                df['Source IP'] = df['Source IP'].apply(lambda x: int(ipaddress.IPv4Address(x)))
                df['Destination IP'] = df['Destination IP'].apply(lambda x: int(ipaddress.IPv4Address(x)))

                df = imputer.transform(df.values)
                df_scaled = scaler.transform(df)

                # Predict
                pred = model.predict(df_scaled)
                pred_1d = pred.squeeze()

                # Print prediction distribution
                pred_series = pd.Series(pred_1d).value_counts().sort_index()
                print("Prediction counts:\n", pred_series)

                # Filter DDoS IPs (1)
                ddos_indices = np.where(pred_1d == 1)[0]
                if len(ddos_indices) > 0:
                    print("DDoS IPs detected:")
                    for idx in ddos_indices:
                        print(f"Source IP: {source_ips.iloc[idx]} -> Destination IP: {destination_ips.iloc[idx]}")
                else:
                    print("No DDoS IPs detected.")

                end = time.time()
                print(f"Execution time: {end - start:.2f} seconds.")

                # Move the file to the destination directory
                shutil.move(source_path, destination_path)
                print(f"{file_name} moved to {destination_dir}")

            except Exception as e:
                print(f"Error processing {file_name}: {e}")
    else:
        print("No CSV files found, waiting...")

    # Wait 10 seconds before checking again
    time.sleep(10)
