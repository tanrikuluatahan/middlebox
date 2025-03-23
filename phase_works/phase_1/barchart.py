import matplotlib.pyplot as plt
import numpy as np

# Example data (replace with your actual data)
delays = np.array([5e-2, 1e-2, 5e-3, 1e-3, 5e-4,
                    1e-4, 5e-5, 1e-5, 5e-6, 1e-6,
                    5e-7,1e-7,5e-8,1e-8])  # Exponential delay values
rtt_min = np.array([
38.318,27.528, #5e-2,1e-2

20.562,11.817, #5e-3,1e-3

7.750,5.622, #5e-4,1e-4

7.785,7.223, #5e-5,1e-5

6.261,4.854, #5e-6,1e-6

6.074,6.053, #5e-7,1e-7

5.827,5.760 #5e-8,1e-8
])
rtt_avg = np.array([
45.346,31.857, #5e-2,1e-2

26.728,12.519, #5e-3,1e-3

9.269,7.914, #5e-4,1e-4

8.024,7.782, #5e-5,1e-5

6.708,6.132, #5e-6,1e-6

6.419,6.962, #5e-7,1e-7

6.573,6.275, #5e-8,1e-8

])
rtt_max = np.array([
52.486,39.860, #5e-2,1e-2

34.034,13.005, #5e-3,1e-3

10.692,9.074, #5e-4,1e-4

8.384,8.295, #5e-5,1e-5

7.473,7.075, #5e-6,1e-6

6.809,7.582, #5e-7,1e-7

7.730,7.05, #5e-8,1e-8
])
rtt_mdev = np.array([
5.784,5.665, #5e-2,1e-2

5.558,0.508, #5e-3,1e-3

1.203,1.620, #5e-4,1e-4

0.258,0.438, #5e-5,1e-5

0.543,0.937, #5e-6,1e-6

0.301,0.656, #5e-7,1e-7

0.829,0.559, #5e-8,1e-8
])

bar_width = 0.2
indices = np.arange(len(delays))

plt.figure(figsize=(10, 6))
plt.bar(indices - bar_width*1.5, rtt_min, width=bar_width, label='Min RTT')
plt.bar(indices - bar_width/2, rtt_avg, width=bar_width, label='Avg RTT')
plt.bar(indices + bar_width/2, rtt_max, width=bar_width, label='Max RTT')
plt.bar(indices + bar_width*1.5, rtt_mdev, width=bar_width, label='mdev')

plt.xlabel('Exponential Delay Index')
plt.ylabel('RTT (ms)')
plt.title('Network Test: RTT Metrics at Each Exponential Delay')
plt.xticks(indices, delays)
plt.legend()
plt.grid(True, axis='y')
plt.show()