import numpy as np
import matplotlib.pyplot as plt

# Define the functions
def nb_files(nb_simu, x):
    return nb_simu / x

def sim_numbers_finals(nb_simu, x):
    return nb_simu % x

# Choose between user input and fixed value
nb_simulations = int(input("How many simulations do you want to execute? "))

sim_max = 2200
sim_min = 1900

# Generate x values with only integer values
x = np.arange(sim_min, sim_max + 1)

# Calculate y values for each function
y1 = nb_files(nb_simulations, x)
y2 = sim_numbers_finals(nb_simulations, x)

# Find the maximum values and their indices
max_y1_value = np.max(y1)
max_y1_index = np.argmax(y1)
max_y1_x_value = x[max_y1_index]

max_y2_value = np.max(y2)
max_y2_index = np.argmax(y2)
max_y2_x_value = x[max_y2_index]

# Create two subplots
fig, axs = plt.subplots(2, 1, sharex=True)

# Plot the functions on separate subplots
axs[0].plot(x, y1, marker='o', linestyle='-', label=f'min({nb_simulations}/x)')
axs[1].plot(x, y2, marker='o', linestyle='-', label=f'max({nb_simulations}%x)')

# Annotate maximum values
axs[0].annotate(f'Max: {max_y1_value:.2f}', xy=(max_y1_x_value, max_y1_value),
                xytext=(10, 10), textcoords='offset points', arrowprops=dict(arrowstyle="->"))
axs[1].annotate(f'Max: {max_y2_value:.2f}', xy=(max_y2_x_value, max_y2_value),
                xytext=(10, 10), textcoords='offset points', arrowprops=dict(arrowstyle="->"))

# Set limits on both x and y axes for each subplot
axs[0].set_xlim(left=sim_min, right=sim_max)
axs[0].set_ylim(bottom=0, top=300)  # Adjust the y-axis limits as needed

axs[1].set_xlim(left=sim_min, right=sim_max)
axs[1].set_ylim(bottom=0, top=sim_max)  # Adjust the y-axis limits as needed

# Add x-axis value annotation
axs[0].axvline(x=max_y1_x_value, color='r', linestyle='--', label=f'Max x: {max_y1_x_value}')
axs[1].axvline(x=max_y2_x_value, color='r', linestyle='--', label=f'Max x: {max_y2_x_value}')

# Add x-value annotation near the maximum point
axs[0].text(max_y1_x_value + 10, max_y1_value - 10, f'{max_y1_x_value}', color='r')
axs[1].text(max_y2_x_value + 10, max_y2_value - 10, f'{max_y2_x_value}', color='r')

# Add labels and legends
axs[0].set_ylabel(f'Number of Files (min({nb_simulations}/x))')
axs[1].set_xlabel('x-axis')
axs[1].set_ylabel(f'Remainder (max({nb_simulations}%x))')

# Add legends
axs[0].legend()
axs[1].legend()

# Adjust layout
plt.tight_layout()

# Show the plot
plt.show()