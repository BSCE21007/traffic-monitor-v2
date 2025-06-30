import dask.dataframe as dd
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.feature_selection import VarianceThreshold
import seaborn as sns
import matplotlib.pyplot as plt
import os

# Paths
input_path = r"E:\data\archive\filtered_dataset\filtered_dataset.parquet"
output_dir = r"E:\data\archive\feature_selection_results"
os.makedirs(output_dir, exist_ok=True)

# Read dataset with Dask
df = dd.read_parquet(input_path, engine='pyarrow')

# Sample 10% of the data
sample_fraction = 0.1
df_sample = df.sample(frac=sample_fraction, random_state=42).compute()

print(f"Sampled {len(df_sample)} rows")
print("Column dtypes:\n", df_sample.dtypes)
print("Sample data (first 5 rows):\n", df_sample.head())

# Save sample for inspection
df_sample.to_csv(os.path.join(output_dir, 'sample_data.csv'), index=False)

# Separate features and target
X = df_sample.drop('Attack', axis=1)
y = df_sample['Attack']

# Identify numerical and categorical columns
numerical_columns = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
categorical_columns = X.select_dtypes(include=['object', 'category']).columns.tolist()

print(f"Initial numerical columns: {numerical_columns}")
print(f"Initial categorical columns: {categorical_columns}")

# Inspect potential numerical columns
potential_numerical = ['spkts', 'dpkts', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sload', 'dload', 'sinpkt', 'dinpkt']
for col in potential_numerical:
    if col in X.columns and col in categorical_columns:
        # Check unique values to diagnose non-numeric content
        unique_vals = X[col].unique()[:10]
        print(f"Unique values in {col} (first 10): {unique_vals}")
        try:
            # Convert to numeric, replacing non-numeric with NaN
            X[col] = pd.to_numeric(X[col], errors='coerce')
            if X[col].notna().sum() > 0:  # Ensure some valid numeric values
                numerical_columns.append(col)
                categorical_columns.remove(col)
                print(f"Converted {col} to numerical")
            else:
                print(f"{col} contains no valid numeric values after conversion")
        except Exception as e:
            print(f"Failed to convert {col} to numerical: {e}")

# Debug numerical columns content
for col in numerical_columns:
    print(f"{col} - NaN count: {X[col].isna().sum()}, Sample values: {X[col].dropna().head().tolist()}")

# Handle missing values
for col in numerical_columns:
    if X[col].notna().sum() > 0:  # Only impute if non-NaN values exist
        X[col] = X[col].fillna(X[col].mean())
    else:
        numerical_columns.remove(col)
        print(f"Removed {col} from numerical columns due to all NaNs")
for col in categorical_columns:
    X[col] = X[col].fillna(X[col].mode()[0])

# Normalize numerical features if any exist
if numerical_columns:
    try:
        scaler = StandardScaler()
        X[numerical_columns] = scaler.fit_transform(X[numerical_columns])
        print("Normalized numerical columns:", numerical_columns)
    except Exception as e:
        print(f"Normalization failed: {e}")
        numerical_columns = []  # Skip normalization
else:
    print("No valid numerical columns to normalize")

# Encode categorical features
label_encoders = {}
for col in categorical_columns:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))
    label_encoders[col] = le

# Remove low-variance features
selector = VarianceThreshold(threshold=0.01)
X_var = selector.fit_transform(X)
selected_features = X.columns[selector.get_support()].tolist()

print(f"Features after VarianceThreshold: {selected_features}")

# Train Random Forest
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X_var, y)

# Get feature importances
importances = pd.DataFrame({
    'Feature': selected_features,
    'Importance': rf.feature_importances_
}).sort_values(by='Importance', ascending=False)

# Save feature importances
importances.to_csv(os.path.join(output_dir, 'feature_importances.csv'), index=False)
print("Top 10 features by importance:")
print(importances.head(10))

# Compute correlation matrix for numerical features
if numerical_columns:
    corr_matrix = X[numerical_columns].corr()
    plt.figure(figsize=(12, 8))
    sns.heatmap(corr_matrix, annot=False, cmap='coolwarm')
    plt.title('Correlation Matrix of Numerical Features')
    plt.savefig(os.path.join(output_dir, 'correlation_matrix.png'))
    plt.close()

    # Identify high-correlation pairs
    high_corr_pairs = [(i, j) for i in range(len(corr_matrix)) for j in range(i+1, len(corr_matrix))
                       if abs(corr_matrix.iloc[i, j]) > 0.8]
    if high_corr_pairs:
        print("High correlation pairs (|corr| > 0.8):")
        for i, j in high_corr_pairs:
            print(f"{corr_matrix.columns[i]} vs {corr_matrix.columns[j]}: {corr_matrix.iloc[i, j]}")

# Select top features
top_features = importances['Feature'].head(15).tolist()
print(f"Recommended top features: {top_features}")

# Save top features
with open(os.path.join(output_dir, 'top_features.txt'), 'w') as f:
    f.write('\n'.join(top_features))