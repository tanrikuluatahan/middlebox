import matplotlib.pyplot as plt
import pandas as pd

# Load the CSV file
df = pd.read_csv("recv_log.csv")

# Calculate inter-arrival times per run
df['time_diff'] = df.groupby('run')['time_us'].diff()

# Rolling average for smoother visualization (window size 5)
df['rolling_avg'] = df.groupby('run')['time_diff'].transform(lambda x: x.rolling(window=5, min_periods=1).mean())

# Create the plot
plt.figure(figsize=(12, 6))
runs = df['run'].unique()

offset = 0
for run in runs:
    subset = df[df['run'] == run].copy()
    plt.plot(subset['index'], subset['rolling_avg'] + offset, label=f'Run {run}')
    offset += 500  # Vertical offset between runs for clarity

plt.xlabel('Byte Index')
plt.ylabel('Inter-arrival Time (us, offset per run)')
plt.title('Rolling Average of Inter-arrival Times (per Run)')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
