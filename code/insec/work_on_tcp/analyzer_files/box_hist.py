import pandas as pd
import matplotlib.pyplot as plt

# Load the data
file_path = "recv_log.csv"
df = pd.read_csv(file_path)

# Convert time to microseconds and sort by time
df = df.sort_values(by="time_us")

# Calculate inter-arrival times
df['inter_arrival'] = df['time_us'].diff()
df['inter_arrival'] = df['inter_arrival'].fillna(0)

# Histogram of inter-arrival times
plt.figure(figsize=(10, 6))
plt.hist(df['inter_arrival'], bins=50, edgecolor='black')
plt.title("Histogram of Inter-Arrival Times")
plt.xlabel("Time Difference (microseconds)")
plt.ylabel("Frequency")
plt.grid(True)
plt.tight_layout()
plt.show()
