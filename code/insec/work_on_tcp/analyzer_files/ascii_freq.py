import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV data
df = pd.read_csv('recv_log.csv')

# Drop rows where 'ascii' is NaN
df = df.dropna(subset=['ascii'])

# Convert ASCII values to characters for better readability
df['char'] = df['ascii'].apply(lambda x: chr(int(x)) if 32 <= int(x) <= 126 else f"[{int(x)}]")

# Group by run and character, count occurrences
char_freq = df.groupby(['run', 'char']).size().unstack(fill_value=0)

# Plot as bar chart
char_freq.T.plot(kind='bar', figsize=(15, 6), width=0.85)
plt.title('ASCII Frequency per Run')
plt.xlabel('Character')
plt.ylabel('Frequency')
plt.xticks(rotation=90)
plt.grid(True)
plt.tight_layout()
plt.show()
