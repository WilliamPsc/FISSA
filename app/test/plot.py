import numpy as np
import matplotlib.pyplot as plt

# Define the functions
def func1(x):
    return 187776 / x

def func2(x):
    return 187776 % x

# Generate x values (excluding zero to avoid division by zero issues)
x = np.linspace(1900, 2200, 100)

# Calculate y values for each function
y1 = func1(x)
y2 = func2(x)

# Create two subplots
fig, axs = plt.subplots(2, 1, sharex=True)

# Plot the functions on separate subplots
axs[0].plot(x, y1, label='min(187776/x)')
axs[1].plot(x, y2, label='max(187776%x)')

# Set limits on both x and y axes for each subplot
axs[0].set_xlim(left=1900, right=2200)
axs[0].set_ylim(bottom=0, top=100)

axs[1].set_xlim(left=1900, right=2200)
axs[1].set_ylim(bottom=0, top=2200)

# Add labels and legends
axs[0].set_ylabel('y-axis for min(68856/x)')
axs[1].set_xlabel('x-axis')
# axs[1].set_ylabel('y-axis for max(68856%x)')

# Adjust layout
plt.tight_layout()

# Show the plot
plt.show()