"""
## @Author : William PENSEC
## @Version : 0.0
## @Date : 14 février 2023
## @Description :
"""

### Import packages ###
import os
import shutil
from matplotlib.colors import ListedColormap
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

### Class ###
class AnalyseResults:
    """Analyses the results of simulations and manages the analysis in table or graph"""
    def __init__(self, data):
        self.__table_data = pd.DataFrame()
        self.__table_data_filtered = pd.DataFrame()
        self.__config = data
        self.__idx_app = list()
        self.__table1 = self.__config['path_files_sim'] + "analyse/table_1/"
        if os.path.exists(self.__table1):
            shutil.rmtree(self.__table1)
        os.makedirs(self.__table1)
        self.__table2 = self.__config['path_files_sim'] + "analyse/heatmap/"
        if os.path.exists(self.__table2):
            shutil.rmtree(self.__table2)
        os.makedirs(self.__table2)

    def get_codes(self):
        return self.__config['codes']

    def write_results(self, filename, data):
        try:
            with open(filename, 'w') as file:
                file.write(data)
        except Exception as e:
            print("An exception has occurred : {exc}".format(exc=e.args[1]))
            return 1
        return 0

    def table_res(self, appli:str, value:pd.DataFrame, t1:pd.DataFrame):
        """Display results in a table latex format"""
        total = len(value)
        self.__idx_app.append(appli)
        crash = value.query('status_end == 1')
        nstr = value.query('status_end == 2')
        delay = value.query('status_end == 3')
        success = value.query('status_end == 4')

        percent_success = f'{round(len(success)*100/total, 2):.2f}'
        list_table1 = [len(crash), len(nstr), len(delay), str(len(success)) + " (" + percent_success + "\%)", total]
        t1.loc[len(t1)] = list_table1

    # def bar_plot_res(self):
        """Display results in a bar plot"""

    def analyse_results(self):
        test:bool = True
        if(test):
            applications = ["propagationTagV2", "secretFunction"]
        else:
            applications = self.get_codes()
        df_t1 = pd.DataFrame([], columns=["Crash", "NSTR", "Delay", "Success", "Total"])
        for appli in applications:
            self.__table_data = pd.DataFrame()
            for threat in self.__config['threat_model']:
                print("=================== " + self.__config['name_results'][appli] + " ===================")
                # Ouverture de chaque fichier résultat
                path_to_filename = self.__config["path_results_sim"] + appli + "/" + appli + "-" + self.__config['prot'] + "_" + threat + "/"
                json_files = [pos_json for pos_json in os.listdir(path_to_filename) if pos_json.endswith('.json')]
                # Enregistrement sous forme de DataFrame panda
                for file in json_files:
                    value_basique = pd.read_json(os.path.join(path_to_filename, file)).transpose().drop(index=['start', 'simulation_0', 'end'])
                    self.__table_data = pd.concat([self.__table_data, value_basique], ignore_index=True)
                # ==================== TABLE 1 ====================
                self.table_res(self.__config['name_results'][appli], self.__table_data, df_t1)
                print("==================== TABLE 1 ====================")
                df_t1 = df_t1.set_axis(self.__idx_app, axis='index')
                print(df_t1)
                # =================================================

                # ==================== TABLE 2 ====================
                self.__table_data_filtered = self.__table_data[self.__table_data['status_end'] == 4].copy()
                # Extract the last part of the strings after the last '/'
                self.__table_data_filtered['faulted_register_0'] = self.__table_data_filtered['faulted_register_0'].str.split('/').str[-1]
                self.__table_data_filtered['faulted_register_1'] = self.__table_data_filtered['faulted_register_1'].str.split('/').str[-1]

                # Create a pivot table for 'faulted_register' on both axes and count occurrences
                heatmap_data = self.__table_data_filtered.pivot_table(index='faulted_register_1', columns='faulted_register_0', values='status_end', aggfunc='count', fill_value=0)

                # Create a heatmap using seaborn with white background for 0 values
                plt.figure(figsize=(12, 8))
                sns.heatmap(heatmap_data, annot=True, cmap='coolwarm', fmt='g', cbar_kws={'label': 'Number of success'},
                            vmin=0, vmax=heatmap_data.values.max(), center=None, linewidths=0.5, linecolor='black',
                            mask=(heatmap_data == 0), annot_kws={'fontsize': 6, 'ha': 'center', 'va': 'center'})

                plt.title('Heatmap of success based on both faulted registers values')

                # Adjust layout to eliminate extra white space
                plt.tight_layout()
                # Save the figure to a file (e.g., PNG format)
                plt.savefig(self.__table2 + "heatmap_" + appli + ".pdf", format='pdf')
                # =================================================
                print("\n")

        # Tableau avec résultats globaux
        print("==================== TABLE 1 ====================")
        df_t1 = df_t1.set_axis(self.__idx_app, axis='index')
        print(df_t1)
        self.write_results(self.__table1 + "table.tex", df_t1.style.format_index(escape="latex").to_latex(caption="End of simulation for buffer overflow and final state", label="table:end_sim_by_status", position_float="centering", multicol_align="c", hrules=True, position="H"))