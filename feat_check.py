counts = df['Label'].value_counts().sort_index()
print(counts)
print((counts / len(df)).round(4))
