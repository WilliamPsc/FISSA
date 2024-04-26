import numpy as np
import matplotlib.pyplot as plt

class SimulationPlotter:
    def __init__(self, nb_simulations, sim_min=200, sim_max=2200):
        self.__nb_simulations = nb_simulations
        self.__sim_min = sim_min
        self.__sim_max = sim_max

    def __nb_files(self, x):
        return self.__nb_simulations // x  # Use integer division to get integer values

    def __sim_numbers_finals(self, x):
        return self.__nb_simulations % x

    def get_best_value(self):
        x = np.arange(self.__sim_min, self.__sim_max + 1)
        y1 = self.__nb_files(x)
        y2 = self.__sim_numbers_finals(x)

        max_y1_value = self.__nb_files(self.get_best_y2_x_value())  # Get number of files for max_y2_x_value
        max_y1_index = np.argmax(y1)
        max_y1_x_value = x[max_y1_index]

        max_y2_value = np.max(y2)
        max_y2_index = np.argmax(y2)
        max_y2_x_value = x[max_y2_index]

        return {
            'max_y1_value': max_y1_value,
            'max_y1_x_value': max_y1_x_value,
            'max_y2_value': max_y2_value,
            'max_y2_x_value': max_y2_x_value
        }

    def get_best_y2_x_value(self):
        x = np.arange(self.__sim_min, self.__sim_max + 1)
        y2 = self.__sim_numbers_finals(x)
        max_y2_index = np.argmax(y2)
        return x[max_y2_index]

    def plot_simulation(self):
        x = np.arange(self.__sim_min, self.__sim_max + 1)
        y1 = self.__nb_files(x)
        y2 = self.__sim_numbers_finals(x)

        best_values = self.get_best_value()

        fig, axs = plt.subplots(2, 1, sharex=True)

        axs[0].plot(x, y1, marker='o', linestyle='-', label=f'min({self.__nb_simulations}/x)')
        axs[1].plot(x, y2, marker='o', linestyle='-', label=f'max({self.__nb_simulations}%x)')

        axs[0].annotate(f'Files at Max x: {best_values["max_y2_x_value"]}: {best_values["max_y1_value"]}', xy=(best_values["max_y1_x_value"], best_values["max_y1_value"]),
                        xytext=(-50, 10), textcoords='offset points', arrowprops=dict(arrowstyle="->"))
        axs[1].annotate(f'Max: {best_values["max_y2_value"]:.2f}', xy=(best_values["max_y2_x_value"], best_values["max_y2_value"]),
                        xytext=(10, 10), textcoords='offset points', arrowprops=dict(arrowstyle="->"))

        axs[0].set_xlim(left=self.__sim_min, right=self.__sim_max)
        axs[0].set_ylim(bottom=0, top=300)

        axs[1].set_xlim(left=self.__sim_min, right=self.__sim_max)
        axs[1].set_ylim(bottom=0, top=self.__sim_max)

        axs[0].axvline(x=best_values["max_y1_x_value"], color='r', linestyle='--', label=f'Max x: {best_values["max_y1_x_value"]}')
        axs[1].axvline(x=best_values["max_y2_x_value"], color='r', linestyle='--', label=f'Max x: {best_values["max_y2_x_value"]}')

        axs[0].text(best_values["max_y1_x_value"] + 10, best_values["max_y1_value"] - 10, f'{best_values["max_y1_value"]}', color='r', ha='right')
        axs[1].text(best_values["max_y2_x_value"] + 10, best_values["max_y2_value"] - 10, f'{best_values["max_y2_x_value"]}', color='r')

        axs[0].set_ylabel(f'Number of Files (min({self.__nb_simulations}/x))')
        axs[1].set_xlabel('x-axis')
        axs[1].set_ylabel(f'Remainder (max({self.__nb_simulations}%x))')

        axs[0].legend()
        axs[1].legend()

        plt.tight_layout()

        # Save the plot as a PDF file
        # plt.savefig('tools/simulation_plot.pdf')

        # Display the plot window asynchronously
        plt.show()

# Example usage:
nb_simulations = int(input("How many simulations do you want to execute? "))
plotter = SimulationPlotter(nb_simulations)
print("Best Values:", plotter.get_best_value())
plotter.plot_simulation()
