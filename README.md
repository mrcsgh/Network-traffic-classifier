# Network-traffic-classifier
Development of different machine learning models for network traffic classification and their subsequent application to real network traffic, combining machine learning with cybersecurity.


## How It Works

### Network Traffic Capture
The program uses tools like `tshark` and Python libraries to intercept incoming network traffic to the machine.

### Data Extraction and Processing
For each identified network flow, specific metrics are generated (source and destination IPs, ports, packet size, etc.). This data is stored in a CSV file.

### AI-Based Detection
The generated CSV file is analyzed by an AI model trained on the [CIC-DDoS2019](https://www.kaggle.com/datasets/aymenabb/ddos-evaluation-dataset-cic-ddos2019) dataset. The model determines whether the traffic corresponds to legitimate behavior or a DDoS attack.


## Installation Guide

### 1. Clone the Repository

```bash
git clone https://github.com/ctfhacks/Network-traffic-classifier.git
cd Network-traffic-classifier
```

### 2. Install Python Dependencies

Make sure you have Python 3.9 or higher installed.

```bash
pip install -r requirements.txt --break-system-packages
```

### 3. Install `tshark`

`tshark` is required to capture and analyze network traffic.

#### On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install tshark
```
---

Once all dependencies are installed, you can run the capture script and begin analyzing traffic.

### 4. Run the Traffic Capture Tool

To start capturing incoming network traffic, use the following command:

```bash
python3 ddos_flow_capture.py -i eth1
```

Replace `eth1` with the name of the network interface you want to monitor (you can list available interfaces using `ip a`).

The script will begin capturing **incoming traffic to the machine**, and once it reaches **10,000 packets**, it will automatically process the data and export it to a CSV file. Each row in the CSV represents a **complete network flow** with extracted features suitable for analysis by the AI model.

### 5. CSV File Output and Folder Structure

Once a CSV file is generated (after capturing 10,000 packets), it is stored under the following directory:

```
/opt/DDOS/
```

Inside this main folder, there are **three subdirectories** used to organize the CSV files depending on their processing status:

- `/opt/DDOS/scanning/`  
  Contains **CSV files currently being created**. These are flows that have not yet reached the 10,000-packet threshold.

- `/opt/DDOS/generated/`  
  Stores **completed CSV files** that have reached 10,000 packets and are ready to be analyzed by the AI model.

- `/opt/DDOS/read/`  
  Contains **CSV files that have already been processed** and classified by the AI as either legitimate or DDoS traffic.

This structure helps ensure a clean pipeline between the traffic capture component and the detection component based on the AI model.


## Authors and Contributions

This project is a collaboration between two developers combining machine learning with real-time network traffic analysis:

- [@mrcsgh](https://github.com/mrcsgh)  
  Responsible for developing, training, and validating the machine learning model used to classify network traffic based on the CIC-DDoS2019 dataset.

- [@ctfhacks](https://github.com/ctfhacks)  
  Developed the Python-based system for **real-time network traffic capture**, data extraction, CSV generation, and integration with the AI model for detection.

Together, this project enables automated detection of DDoS attacks by bridging cybersecurity and AI.
