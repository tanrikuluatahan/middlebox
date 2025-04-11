import pandas as pd
import matplotlib.pyplot as plt

# Load the dataset
df = pd.read_csv("recv_log.csv")

# Drop rows with missing values in 'ascii' or 'time_us'
df = df.dropna(subset=['ascii', 'time_us'])

# Ensure time_us is sorted per run and index
df = df.sort_values(by=['run', 'index'])

# Calculate inter-arrival time per run
df['inter_arrival_us'] = df.groupby('run')['time_us'].diff()

# Plot inter-arrival times per run
plt.figure(figsize=(14, 6))
for run_id, run_data in df.groupby('run'):
    plt.plot(run_data['index'], run_data['inter_arrival_us'], label=f'Run {run_id}', alpha=0.7)

plt.title("Character Inter-Arrival Time per Run")
plt.xlabel("Character Index")
plt.ylabel("Inter-Arrival Time (μs)")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
