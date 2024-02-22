import numpy as np
import matplotlib.pyplot as plt

# Define the functions
def func1(nb_simu, x):
    return nb_simu / x

def func2(nb_simu, x):
    return nb_simu % x

nb_simulations = int(input("How many simulations do you want to execute? "))


# Generate x values (excluding zero to avoid division by zero issues)
x = np.linspace(1900, 2200, 100)

# Calculate y values for each function
y1 = func1(nb_simulations, x)
y2 = func2(nb_simulations, x)

# Create two subplots
fig, axs = plt.subplots(2, 1, sharex=True)

# Plot the functions on separate subplots
axs[0].plot(x, y1, label=f'min({nb_simulations}/x)')
axs[1].plot(x, y2, label=f'max({nb_simulations}%x)')

# Set limits on both x and y axes for each subplot
axs[0].set_xlim(left=1900, right=2200)
axs[0].set_ylim(bottom=0, top=200)

axs[1].set_xlim(left=1900, right=2200)
axs[1].set_ylim(bottom=0, top=2200)

# Add labels and legends
axs[0].set_ylabel(f'y-axis for min({nb_simulations}/x)')
axs[1].set_xlabel('x-axis')
# axs[1].set_ylabel(f'y-axis for max({nb_simulations}%x)')

# Adjust layout
plt.tight_layout()

# Show the plot
plt.show()