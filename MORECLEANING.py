import pandas as pd

# 1) Load original data
INPUT_PATH  = "E:/data/archive2/combined_dataset.parquet"
OUTPUT_PATH = "E:/data/archive2/final_dataset.parquet"

# 2) Define variant→canonical label mapping
use_cols = [
    'IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS',
    'FLOW_DURATION_MILLISECONDS', 'DURATION_IN', 'DURATION_OUT',
    'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT',
    'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'SRC_TO_DST_SECOND_BYTES',
    'DST_TO_SRC_SECOND_BYTES', 'RETRANSMITTED_IN_BYTES',
    'RETRANSMITTED_IN_PKTS', 'RETRANSMITTED_OUT_BYTES',
    'RETRANSMITTED_OUT_PKTS', 'SRC_TO_DST_AVG_THROUGHPUT',
    'DST_TO_SRC_AVG_THROUGHPUT', 'NUM_PKTS_UP_TO_128_BYTES',
    'NUM_PKTS_128_TO_256_BYTES', 'NUM_PKTS_256_TO_512_BYTES',
    'NUM_PKTS_512_TO_1024_BYTES', 'NUM_PKTS_1024_TO_1514_BYTES',
    'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT',
    'Attack'  # we need this to clean/map labels
]

# 2) Load just these columns
df = pd.read_parquet(INPUT_PATH, columns=use_cols, engine='fastparquet')  # if you have fastparquet

# 3) Prepare the variant→canonical mapping
variant_map = {
    'scanning': 'Reconnaissance',
    'Reconnaissance0': 'Reconnaissance',
    'Reconnaissan': 'Reconnaissance',
    'scan.0': 'Reconnaissance',
    'Analysis': 'Reconnaissance',
    'DoS': 'DDoS',
    'DDoS2': 'DDoS',
    'DDoS0': 'DDoS',
    'xss0': 'xss',
    'xss192.168.1.195': 'xss',
    'XSS': 'xss',
    'password': 'Brute Force',
    'Brute Force0': 'Brute Force',
    'Brute For': 'Brute Force',
    'Bot0': 'Bot',
    'Fuzzers0': 'Fuzzers',
    'Exploits0': 'Exploits',
    'injectio': 'injection',
    'Infilteratio': 'Infilteration',
    'Generic': 'Generic',
}

# 4) Clean original Attack strings
df['Attack_clean'] = df['Attack'].str.strip().replace(variant_map)

# 5) Map to numeric Label
LABEL_MAP = {
    'Benign': 0, 'Generic': 1, 'Reconnaissance': 2,
    'DDoS': 3, 'xss': 4, 'Bot': 5, 'Fuzzers': 6,
    'injection': 7, 'Infilteration': 8, 'Brute Force': 9,
    'Exploits': 10, 'Backdoor': 11, 'mitm': 12,
    'ransomware': 13, 'Theft': 14, 'Worms': 15,
    'Shellcode': 16
}
df['Label'] = df['Attack_clean'].map(LABEL_MAP)

# 6) Report how many are unmapped
n_unmapped = df['Label'].isna().sum()
print(f"Rows still unmapped after cleaning: {n_unmapped}")
print("=== BEFORE DROPNA ===")
print("Unique raw Attack:", df['Attack'].unique()[:10])
print("Unique Attack_clean:", df['Attack_clean'].unique()[:10])
print("Attack_clean counts:\n", df['Attack_clean'].value_counts().head(10))
print("Label counts:\n", df['Label'].value_counts().head(10))
# 8) Drop helper columns ASAP to free memory
# 7) Drop rows with no Label via boolean mask (no full DataFrame copy)
df = df[df['Label'].notna()]
# Before dropping anything, verify the cleaning:

df = df.drop(columns=['Attack', 'Attack_clean'])
# 9) Convert Label to int
df['Label'] = df['Label'].astype('int8')

# 10) Save cleaned Parquet
df.to_parquet(OUTPUT_PATH, index=False)
print(f"Cleaned dataset saved to {OUTPUT_PATH}, shape {df.shape}")