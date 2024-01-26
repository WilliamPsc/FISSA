"""
## @Author : William PENSEC
## @Version : 0.0
## @Date : 14 février 2023
## @Description :
"""

### Import packages ###
import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime

### Class ###
class AnalyseResults:
    """Analyses the results of simulations and manages the analysis in table or graph"""
    def __init__(self, data):
        self.__table_data = pd.DataFrame()
        self.__table_data_filtered = pd.DataFrame()
        self.__config = data
        self.__idx_app = list()
        self.__table1 = self.__config['path_files_sim'] + "analyse/table_1/"
        if not os.path.exists(self.__table1):
        #     shutil.rmtree(self.__table1)
            os.makedirs(self.__table1)
        self.__table2 = self.__config['path_files_sim'] + "analyse/heatmap/"
        if not os.path.exists(self.__table2):
            # shutil.rmtree(self.__table2)
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

    # def table_res(self, appli:str, value:pd.DataFrame, t1:pd.DataFrame):
    #     """Display results in a table latex format"""
    #     total = len(value)
    #     self.__idx_app.append(appli)
    #     crash = value.query('status_end == 1')
    #     nstr = value.query('status_end == 2')
    #     delay = value.query('status_end == 3')
    #     success = value.query('status_end == 4')

    #     percent_success = f'{round(len(success)*100/total, 2):.2f}'
    #     list_table1 = [len(crash), len(nstr), len(delay), str(len(success)) + " (" + percent_success + "\%)", total]
    #     t1.loc[len(t1)] = list_table1

    def table_res(self, appli: str, value: pd.DataFrame, t1: pd.DataFrame):
        """Display results in a table latex format"""
        total = len(value)
        self.__idx_app.append(appli)
        status_counts = value['status_end'].value_counts()

        # Extract counts for each status or set to 0 if not present
        crash = status_counts.get(1, 0)
        nstr = status_counts.get(2, 0)
        delay = status_counts.get(3, 0)
        success = status_counts.get(4, 0)

        # Calculate percentage of success
        percent_success = f'{(success / total) * 100:.2f}'

        # Update t1 DataFrame
        t1.loc[len(t1)] = [crash, nstr, delay, f'{success} ({percent_success}\%)', total]


    def heatmap(self, appli:str, name_appli:str, threat:str):
        """Display results as a heatmap with faulted register in both axis and a value for the number of success for each couple"""
        self.__table_data_filtered = self.__table_data[self.__table_data['status_end'] == 4].copy()
        # Extract the last part of the strings after the last '/'
        self.__table_data_filtered['faulted_register_0'] = self.__table_data_filtered['faulted_register_0'].apply(lambda x: x.split('/hc_o_32')[0][-3:] + '/hc_o_32' if x.endswith('/hc_o_32') else x.split('/')[-1])
        self.__table_data_filtered['faulted_register_1'] = self.__table_data_filtered['faulted_register_1'].apply(lambda x: x.split('/hc_o_32')[0][-3:] + '/hc_o_32' if x.endswith('/hc_o_32') else x.split('/')[-1])


        # Create a pivot table for 'faulted_register' on both axes and count occurrences
        heatmap_data = self.__table_data_filtered.pivot_table(index='faulted_register_1', columns='faulted_register_0', values='status_end', aggfunc='count', fill_value=0)

        # Create a heatmap using seaborn with white background for 0 values
        plt.figure(figsize=(12, 10))
        # vmax_value = heatmap_data.values.max()
        match appli:
            case "buffer_overflow":
                if(threat == "multi_bitflip_reg_multi"):
                    vmax_value = 315
                if(threat == "multi_bitflip_spatial"):
                    vmax_value = 272
            case "secretFunction":
                if(threat == "multi_bitflip_reg_multi"):
                    vmax_value = 195
                if(threat == "multi_bitflip_spatial"):
                    vmax_value = 524
            case "propagationTagV2":
                if(threat == "multi_bitflip_reg_multi"):
                    vmax_value = 248
                if(threat == "multi_bitflip_spatial"):
                    vmax_value = 154
        sns.heatmap(heatmap_data, annot=True, cmap='coolwarm', fmt='g', cbar_kws={'label': 'Number of success'},
                    vmin=0, vmax=vmax_value, center=None, linewidths=0.5, linecolor='black',
                    mask=(heatmap_data == 0), annot_kws={'fontsize': 6, 'ha': 'center', 'va': 'center'})
        plt.title(f'Heatmap of success based on both faulted registers values for {name_appli}')

        # Set fontsize for x and y-axis labels
        plt.xticks(fontsize=8)
        plt.yticks(fontsize=8)

        # Set fontsize for x and y-axis labels
        plt.xlabel('Faulted Register 0', fontsize=10)
        plt.ylabel('Faulted Register 1', fontsize=10)

        # Adjust layout to eliminate extra white space
        plt.tight_layout()

        # Save the figure to a PDF file
        plt.savefig(self.__table2 + "heatmap_" + appli + "-" + self.__config['prot'] + "_" + threat + ".pdf", format='pdf')

    def calculate_time_difference(self, start, end):
        # Convert the date strings to datetime objects
        date_format = "%Y/%m/%d:%H:%M:%S"
        date1 = datetime.strptime(start, date_format)
        date2 = datetime.strptime(end, date_format)

        # Calculate the difference between the two dates
        time_difference = date2 - date1

        # Extract days, hours, and minutes from the time difference
        days = time_difference.days
        hours, remainder = divmod(time_difference.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        # Print the difference
        print(f"\t\t\t>>>> The simulation time was: {days} days, {hours} hours, {minutes} minutes")

    def analyse_results(self):
        """"""
        test:bool = False
        if(test):
            applications = ["secretFunction"]
        else:
            applications = self.get_codes()
        
        for threat in self.__config['threat_model']:
            df_t1 = pd.DataFrame([], columns=["Crash", "NSTR", "Delay", "Success", "Total"])
            for appli in applications:
                self.__table_data = pd.DataFrame()
                print("=================== " + self.__config['name_results'][appli] + " ===================")
                print(f"\t======= >>> {threat} <<< =======")
                # Ouverture de chaque fichier résultat
                print("\t\t>>> Opening result file")
                path_to_filename = os.path.join(self.__config["path_results_sim"], appli, f"{appli}-{self.__config['prot']}_{threat}/")
                # Check if the directory exists
                if os.path.exists(path_to_filename):
                    json_files = [pos_json for pos_json in os.listdir(path_to_filename) if pos_json.endswith('.json')] # Enregistrement sous forme de DataFrame panda
                    if(len(json_files) != 0):
                        print("\t\t>>> READING FILE ...")
                        start_value = 0
                        end_value = 0
                        for file in json_files:
                            try:
                                value_basique = pd.read_json(os.path.join(path_to_filename, file)).transpose()
                            except ValueError as e:
                                print(f"Error reading JSON file {os.path.join(path_to_filename, file)}: {e}")
                                continue
                            # Extract values associated with 'start' and 'end' from index
                            if 'start' in value_basique.index:
                                start_value = value_basique.loc['start'].iloc[0]  # Assuming 'start' is in the index
                            if 'end' in value_basique.index:
                                end_value = value_basique.loc['end'].iloc[0]  # Assuming 'end' is in the index
                            self.__table_data = pd.concat([self.__table_data, value_basique], axis=0, ignore_index=False)
                        self.__table_data = self.__table_data.drop(index=['start', 'simulation_0', 'end'])
                        if(start_value != 0 and end_value != 0):
                            self.calculate_time_difference(start_value, end_value)
                        # ==================== TABLE 1 ====================
                        self.table_res(self.__config['name_results'][appli], self.__table_data, df_t1)
                        print("\t\t>>> TABLE 1")
                        df_t1 = df_t1.set_axis(self.__idx_app, axis='index')
                        # =================================================

                        # ==================== TABLE 2 ====================
                        success = self.__table_data.query('status_end == 4')
                        if(threat in ["multi_bitflip_spatial","multi_bitflip_reg_multi"] and len(success) > 0):
                            print("\t\t>>> Heatmap")
                            self.heatmap(appli=appli, name_appli=self.__config['name_results'][appli], threat=threat)
                        # =================================================
                    else:
                        print(f"The directory \"{path_to_filename}\" is empty.")
                else:
                    print(f"The directory \"{path_to_filename}\" does not exist.")
                print()

            # # Tableau avec résultats globaux
            print("==================== TABLE 1 ====================")
            df_t1 = df_t1.set_axis(self.__idx_app, axis='index')
            print(df_t1)
            self.write_results(self.__table1 + self.__config['prot'] + "_" + threat + ".tex", df_t1.style.format_index(escape="latex").to_latex(caption="Logical fault injection simulation campaigns results", label="table:end_sim_by_status_" + self.__config['prot'] + "_" + '_'.join(self.__config['threat_model']), position_float="centering", multicol_align="c", hrules=True, position="H"))