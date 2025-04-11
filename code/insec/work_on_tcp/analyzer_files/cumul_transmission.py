import pandas as pd
import matplotlib.pyplot as plt

# Load data
df = pd.read_csv("recv_log.csv")

# Drop rows with missing or non-numeric time_us values
df = df[pd.to_numeric(df["time_us"], errors="coerce").notna()]
df["time_us"] = df["time_us"].astype(int)

# Calculate cumulative transmission time for each run
first_times = df.groupby("run")["time_us"].min()
last_times = df.groupby("run")["time_us"].max()
cumulative_durations = (last_times - first_times) / 1e6  # Convert to seconds

# Plot
plt.figure(figsize=(10, 6))
cumulative_durations.plot(kind="bar", color="skyblue")
plt.title("Cumulative Transmission Time per Run")
plt.xlabel("Run Number")
plt.ylabel("Duration (seconds)")
plt.grid(True)
plt.tight_layout()
plt.show()
