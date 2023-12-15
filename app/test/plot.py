import numpy as np
import matplotlib.pyplot as plt

# Define the functions
def func1(x):
    return 68856 / x

def func2(x):
    return 68856 % x

# Generate x values (excluding zero to avoid division by zero issues)
x = np.linspace(2500, 3200, 100)

# Calculate y values for each function
y1 = func1(x)
y2 = func2(x)

# Create two subplots
fig, axs = plt.subplots(2, 1, sharex=True)

# Plot the functions on separate subplots
axs[0].plot(x, y1, label='min(68856/x)')
axs[1].plot(x, y2, label='max(68856%x)')

# Set limits on both x and y axes for each subplot
axs[0].set_xlim(left=2800, right=3000)
axs[0].set_ylim(bottom=0, top=100)

axs[1].set_xlim(left=2800, right=3000)
axs[1].set_ylim(bottom=0, top=3000)

# Add labels and legends
axs[0].set_ylabel('y-axis for min(68856/x)')
axs[1].set_xlabel('x-axis')
# axs[1].set_ylabel('y-axis for max(68856%x)')

# Adjust layout
plt.tight_layout()

# Show the plot
plt.show()