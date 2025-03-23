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

fig, axs = plt.subplots(2, 2, figsize=(12, 10))

axs[0, 0].plot(delays, rtt_min, marker='o')
axs[0, 0].set_title('Min RTT')
axs[0, 0].set_xscale('log')
axs[0, 0].grid(True)

axs[0, 1].errorbar(delays, rtt_avg, yerr=rtt_mdev, marker='o', fmt='-')
axs[0, 1].set_title('Avg RTT with mdev')
axs[0, 1].set_xscale('log')
axs[0, 1].grid(True)

axs[1, 0].plot(delays, rtt_max, marker='o')
axs[1, 0].set_title('Max RTT')
axs[1, 0].set_xscale('log')
axs[1, 0].grid(True)

axs[1, 1].plot(delays, rtt_mdev, marker='o')
axs[1, 1].set_title('mdev')
axs[1, 1].set_xscale('log')
axs[1, 1].grid(True)

for ax in axs.flat:
    ax.set(xlabel='Exponential Delay', ylabel='RTT (ms)')

plt.tight_layout()
plt.show()