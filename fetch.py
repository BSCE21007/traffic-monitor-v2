import pandas as pd
import sys

def filter_transport_layer_attacks(df):
    """
    Filter dataset to keep only rows where the 'Attack' column contains 'BENIGN' or 'DoS'.
    
    Args:
        df: DataFrame with 'Attack' column containing attack classifications
    
    Returns:
        DataFrame containing only relevant rows
    """
    try:
        print(f"Initial dataframe shape: {df.shape}")
        print("\nAvailable columns:", df.columns.tolist())

        # Check if 'Attack' column exists
        if 'Attack' not in df.columns:
            print("\nWarning: 'Attack' column not found. Available columns are:", df.columns.tolist())
            print("Checking for alternative attack column names...")
            possible_labels = [col for col in df.columns if 'attack' in col.lower()]
            if possible_labels:
                print(f"Found possible attack columns: {possible_labels}")
            return None

        # Convert the column to string type in case it has mixed types
        df['Attack'] = df['Attack'].astype(str)

        print("\nUnique attack types in dataset:", df['Attack'].unique())

        # Filter rows where 'Attack' contains "BENIGN" or "DoS"
        mask = df['Attack'].str.contains(r'BENIGN|DoS', case=False, na=False)

        # Filter dataset
        filtered_df = df[mask].copy()

        print("\nDataset Statistics:")
        print("------------------")
        print(filtered_df['Attack'].value_counts())
        print(f"\nFiltered dataframe shape: {filtered_df.shape}")

        return filtered_df

    except Exception as e:
        print(f"\nError in filter_transport_layer_attacks: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        return None

# Main execution
try:
    file_p = r'F:\data\NF-UQ-NIDS-v2.csv'
    dest_p = r'F:\data\filtered_dataset.csv'

    print(f"\nReading file from: {file_p}")
    df = pd.read_csv(file_p)
    print(f"Successfully read CSV file. Shape: {df.shape}")

    filtered_df = filter_transport_layer_attacks(df)

    if filtered_df is not None and not filtered_df.empty:
        print(f"\nSaving filtered dataset to: {dest_p}")
        filtered_df.to_csv(dest_p, index=False)
        print("File saved successfully!")
    else:
        print("\nError: No data to save after filtering")

except Exception as e:
    print(f"\nError in main execution: {str(e)}")
    print(f"Error type: {type(e).__name__}")
