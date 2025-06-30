import pandas as pd
import os
import glob
import gc
import logging
import csv
"""
logging.basicConfig(
    filename=r"E:/data/archive/filter_log_split.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

csv_dir = r"E:\\data\\archive"
output_dir = r"E:\\data\\archive\\filtered_dataset"
if os.path.exists(output_dir):
    for file in os.listdir(output_dir):
        os.remove(os.path.join(output_dir, file))
else:
    os.makedirs(output_dir)

selected_attacks = [
    'Benign', 'Brute For', 'Brute Force', 'Brute Force0', 'Exploits', 'Exploits0',
    'Backdoor', 'ransomware', 'injectio', 'injection', 'xss', 'xss0', 'xss192.168.1.195',
    'Reconnaissan', 'Reconnaissance', 'Reconnaissance0', 'scan.0', 'scanning', 'scanning0',
    'DDo', 'DDoS', 'DDoS0', 'DDoS2', 'mitm', 'Fuzzers', 'Fuzzers0', 'Shellcode',
    'Worms', 'Bot', 'Bot0', 'Generic', 'Infilteratio', 'Infilteration', 'Theft'
]

columns = [
    'IPV4_SRC_ADDR', 'L4_SRC_PORT', 'IPV4_DST_ADDR', 'L4_DST_PORT', 'PROTOCOL',
    'L7_PROTO', 'IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS', 'TCP_FLAGS',
    'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS', 'FLOW_DURATION_MILLISECONDS',
    'DURATION_IN', 'DURATION_OUT', 'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT',
    'SHORTEST_FLOW_PKT', 'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'SRC_TO_DST_SECOND_BYTES',
    'DST_TO_SRC_SECOND_BYTES', 'RETRANSMITTED_IN_BYTES', 'RETRANSMITTED_IN_PKTS',
    'RETRANSMITTED_OUT_BYTES', 'RETRANSMITTED_OUT_PKTS', 'SRC_TO_DST_AVG_THROUGHPUT',
    'DST_TO_SRC_AVG_THROUGHPUT', 'NUM_PKTS_UP_TO_128_BYTES', 'NUM_PKTS_128_TO_256_BYTES',
    'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES', 'NUM_PKTS_1024_TO_1514_BYTES',
    'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 'ICMP_TYPE', 'ICMP_IPV4_TYPE', 'DNS_QUERY_ID',
    'DNS_QUERY_TYPE', 'DNS_TTL_ANSWER', 'FTP_COMMAND_RET_CODE', 'Label', 'Attack'
]

# Debug: List split files
split_files = glob.glob(os.path.join(csv_dir, "split_*"))
logging.info(f"Found {len(split_files)} split files: {split_files}")
print(f"Found {len(split_files)} split files: {split_files}")

if not split_files:
    raise FileNotFoundError("No split files found in E:\\data\\archive")

total_rows = 0
filtered_rows = 0
i = 0

for csv_file in split_files:
    logging.info(f"Processing {csv_file}")
    print(f"Processing {csv_file}")
    try:
        for chunk in pd.read_csv(
            csv_file,
            encoding='latin1',
            usecols=columns,
            chunksize=100,
            low_memory=True
        ):
            if 'Attack' in chunk.columns:
                filtered_chunk = chunk[chunk['Attack'].isin(selected_attacks)]
                if not filtered_chunk.empty:
                    filtered_chunk.to_parquet(
                        os.path.join(output_dir, f'part_{i}.parquet'),
                        index=False,
                        engine='pyarrow'
                    )
                    filtered_rows += len(filtered_chunk)
                    i += 1
            total_rows += len(chunk)
            del chunk
            gc.collect()
        logging.info(f"Processed {csv_file}: {total_rows} rows, {filtered_rows} filtered")
    except Exception as e:
        logging.error(f"Error processing {csv_file}: {e}")
        print(f"Error processing {csv_file}: {e}")

print(f"Processed {total_rows} rows")
print(f"Filtered {filtered_rows} rows saved to {output_dir}")
print(f"Parquet files created: {len(os.listdir(output_dir))}")
"""
import dask.dataframe as dd
import os

input_path = r"E:\data\archive\filtered_dataset"
output_dir = r"E:\data\archive\filtered_dataset"

# Read Parquet files
df = dd.read_parquet(input_path, engine='pyarrow')

# Print metadata
print(f"Total rows: {len(df)}")
print("Columns:", df.columns.tolist())
print("Dtypes:\n", df.dtypes)
print("Sample data (first 5 rows):\n", df.head())
print("Attack value counts:\n", df['Attack'].value_counts().compute())

# List Parquet files
parquet_files = [f for f in os.listdir(output_dir) if f.endswith('.parquet')]
print(f"Parquet files: {parquet_files}")