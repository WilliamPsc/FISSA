"""
## @Author : William PENSEC
## @Version : 0.0
## @Date : 06 may 2024
## @Description :
"""

### Import packages ###
import os
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime
from timeit import default_timer as timer

### Class ###
class AnalyseResults:
    """Analyses the results of simulations and manages the analysis in table or graph"""
    def __init__(self, data):
        self.__table_data = pd.DataFrame()
        self.__table_data_filtered = pd.DataFrame()
        self.__config = data
        self.__implem_version = self.__config['version']
        self.__idx_app = list()
        self.__table1 = self.__config['path_files_sim'] + "analyse/table_1/"
        if not os.path.exists(self.__table1):
            os.makedirs(self.__table1)
        self.__table2 = self.__config['path_files_sim'] + "analyse/heatmap/"
        if not os.path.exists(self.__table2):
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
        detection = status_counts.get(5, 0)
        detect_and_correct = status_counts.get(6,0)
        double_errors_detect = status_counts.get(7,0)

        # Calculate percentage of success
        percent_success = f'{(success / total) * 100:.2f}'

        # Update t1 DataFrame
        t1.loc[len(t1)] = [crash, nstr, delay, detection, detect_and_correct, double_errors_detect, f'{success} ({percent_success}\%)', total]

    def heatmap(self, appli:str, name_appli:str, threat:str):
        """Display results as a heatmap with faulted register in both axis and a value for the number of success for each couple"""
        self.__table_data_filtered = self.__table_data[self.__table_data['status_end'] == 4].copy()
        # Extract the last part of the strings after the last '/'
        self.__table_data_filtered['faulted_register_0'] = self.__table_data_filtered['faulted_register_0'].apply(
            lambda x: '/'.join(x.split('/')[-2:]) if x.endswith('/hc_o') else x.split('/')[-1])
        self.__table_data_filtered['faulted_register_0'] = self.__table_data_filtered['faulted_register_0'].apply(
            lambda x: x.replace("hamming_code_encoder_", "hc_") if x.startswith('hamming_code_encoder') else x)

        self.__table_data_filtered['faulted_register_1'] = self.__table_data_filtered['faulted_register_1'].apply(
            lambda x: '/'.join(x.split('/')[-2:]) if x.endswith('/hc_o') else x.split('/')[-1])
        self.__table_data_filtered['faulted_register_1'] = self.__table_data_filtered['faulted_register_1'].apply(
            lambda x: x.replace("hamming_code_encoder_", "hc_") if x.startswith('hamming_code_encoder') else x)

        # Create a pivot table for 'faulted_register' on both axes and count occurrences
        heatmap_data = self.__table_data_filtered.pivot_table(index='faulted_register_1', columns='faulted_register_0', values='status_end', aggfunc='count', fill_value=0)

        # Create a heatmap using seaborn with white background for 0 values
        plt.figure(figsize=(15, 12))
        vmax_value = heatmap_data.values.max()
        # match appli:
        #     case "buffer_overflow":
        #         if(threat == "multi_bitflip_reg_multi"):
        #             vmax_value = 500
        #         if(threat == "single_bitflip_spatial"):
        #             vmax_value = 272
        #         if(threat == "single_bitflip_temporel"):
        #             vmax_value = 320
        #     case "secretFunction":
        #         if(threat == "multi_bitflip_reg_multi"):
        #             vmax_value = 680
        #         if(threat == "single_bitflip_spatial"):
        #             vmax_value = 524
        #         if(threat == "single_bitflip_temporel"):
        #             vmax_value = 672
        #     case "propagationTagV2":
        #         if(threat == "multi_bitflip_reg_multi"):
        #             vmax_value = 248
        #         if(threat == "single_bitflip_spatial"):
        #             vmax_value = 154
        #         if(threat == "single_bitflip_temporel"):
        #             vmax_value = 96
        if(self.__config['prot'] == "wop"):
            sns.heatmap(heatmap_data, annot=True, cmap='copper_r', fmt='g', cbar_kws={'label': 'Number of success', 'shrink': 0.8}, vmin=0, vmax=vmax_value,
                    center=None, linewidths=0.5, linecolor='black', mask=(heatmap_data == 0),
                    annot_kws={'fontsize': 8, 'ha': 'center', 'va': 'center'}, square=False)
            
            # Set fontsize for x and y-axis labels
            plt.yticks(fontsize=9)
            plt.xticks(fontsize=9)
            # Set axis labels to None to remove them
            plt.xlabel(None)
            plt.ylabel(None)
            # Adjust layout to eliminate extra white space
            plt.tight_layout()
        else:
            sns.heatmap(heatmap_data, annot=True, cmap='copper_r', fmt='g', cbar_kws={'label': 'Number of success', 'shrink': 0.8},
                    vmin=0, vmax=vmax_value, center=None, linewidths=0.5, linecolor='black',
                    mask=(heatmap_data == 0), annot_kws={'fontsize': 5, 'ha': 'center', 'va': 'center'}, square=False)
            
            # Set fontsize for x and y-axis labels
            plt.xticks(fontsize=7)
            plt.yticks(fontsize=7)
            # Set axis labels to None to remove them
            plt.xlabel(None)
            plt.ylabel(None)
            # Adjust layout to eliminate extra white space
            plt.tight_layout()

            # Remove all the blank space around the figure
            plt.axis('tight')

        # Save the figure to a PDF file
        plt.savefig(f"{self.__table2}heatmap_{appli}_{self.__config['prot']}_{self.__implem_version}_{threat}_{str(self.__config['multi_fault_injection'])}.pdf", format='pdf', bbox_inches='tight')

    def heatmap_from_list(self, appli: str, name_appli: str, threat: str, filter_names: list):
        """Display results as a heatmap with faulted register in both axis and a value for the number of success for each couple, 
        considering only a provided list of names."""
        
        self.__table_data_filtered = self.__table_data[self.__table_data['status_end'] == 4].copy()

        # Apply transformations to faulted_register_0 and faulted_register_1
        self.__table_data_filtered['faulted_register_0'] = self.__table_data_filtered['faulted_register_0'].apply(
            lambda x: '/'.join(x.split('/')[-2:]) if x.endswith('/hc_o') else x.split('/')[-1])
        self.__table_data_filtered['faulted_register_0'] = self.__table_data_filtered['faulted_register_0'].apply(
            lambda x: x.replace("hamming_code_encoder_", "hc_") if x.startswith('hamming_code_encoder') else x)

        self.__table_data_filtered['faulted_register_1'] = self.__table_data_filtered['faulted_register_1'].apply(
            lambda x: '/'.join(x.split('/')[-2:]) if x.endswith('/hc_o') else x.split('/')[-1])
        self.__table_data_filtered['faulted_register_1'] = self.__table_data_filtered['faulted_register_1'].apply(
            lambda x: x.replace("hamming_code_encoder_", "hc_") if x.startswith('hamming_code_encoder') else x)

        # Filter based on the provided list of names
        self.__table_data_filtered = self.__table_data_filtered[
            (self.__table_data_filtered['faulted_register_0'].isin(filter_names)) &
            (self.__table_data_filtered['faulted_register_1'].isin(filter_names))
        ]

        # Create a pivot table for 'faulted_register' on both axes and count occurrences
        heatmap_data = self.__table_data_filtered.pivot_table(
            index='faulted_register_1', 
            columns='faulted_register_0', 
            values='status_end', 
            aggfunc='count', 
            fill_value=0
        )

        # Create a heatmap using seaborn with white background for 0 values
        plt.figure(figsize=(10, 8))
        vmax_value = heatmap_data.values.max()

        if self.__config['prot'] == "wop":
            sns.heatmap(heatmap_data, annot=True, cmap='copper_r', fmt='g', cbar_kws={'label': 'Number of success', 'shrink': 0.8},
                        vmin=0, vmax=vmax_value, center=None, linewidths=0.5, linecolor='black', mask=(heatmap_data == 0),
                        annot_kws={'fontsize': 12, 'ha': 'center', 'va': 'center'}, square=True)
            plt.yticks(fontsize=12)
            plt.xticks(fontsize=12)
        else:
            sns.heatmap(heatmap_data, annot=True, cmap='copper_r', fmt='g', cbar_kws={'label': 'Number of success', 'shrink': 0.8},
                        vmin=0, vmax=vmax_value, center=None, linewidths=0.5, linecolor='black', mask=(heatmap_data == 0),
                        annot_kws={'fontsize': 12, 'ha': 'center', 'va': 'center'}, square=False)
            plt.xticks(fontsize=12)
            plt.yticks(fontsize=12)

        plt.xlabel(None)
        plt.ylabel(None)
        plt.tight_layout()

        # Save the figure to a PDF file
        plt.savefig(f"{self.__table2}heatmap_{appli}_{self.__config['prot']}_{self.__implem_version}_{threat}_{str(self.__config['multi_fault_injection'])}.pdf", format='pdf', bbox_inches='tight')


    def calculate_time_difference(self, start, end):
        # Convert the date strings to datetime objects
        date_format = "%Y/%m/%d:%H:%M:%S"
        date1 = datetime.strptime(start.strftime(date_format), date_format)
        date2 = datetime.strptime(end.strftime(date_format), date_format)

        # Calculate the difference between the two dates
        time_difference = date2 - date1

        # Extract days, hours, and minutes from the time difference
        days = time_difference.days
        hours, remainder = divmod(time_difference.seconds, 3600)
        minutes, _ = divmod(remainder, 60)

        hours_total = hours + (days*24)

        # Print the difference
        print(f"\t\t\t>>>> The simulation time was: {days} days, {hours} hours, {minutes} minutes")
        print(f"\t\t\t>>>> The total simulation time was in hours: {hours_total} hours, {minutes} minutes")

    def free_memory_attr(self):
        del self.__table_data
        del self.__table_data_filtered

    def analyse_results(self, threat):
        """"""
        applications = self.get_codes()
        df_t1 = pd.DataFrame([], columns=["Crash", "Silent", "Delay", "Detection", "Detection and Correction", "Double Errors Detection", "Success", "Total"])
        for appli in applications:
            self.__table_data = pd.DataFrame()
            print("\t=================== " + self.__config['name_results'][appli] + " ===================")
            print(f"\t=================== Implementation {self.__config['version']} ===================")
            print(f"\t\t======= >>> {threat} <<< =======")
            # Ouverture de chaque fichier résultat
            print("\t\t>>> Opening result file")
            path_to_filename = os.path.join(self.__config["path_results_sim"], appli, f"{appli}_{self.__config['prot']}_{self.__implem_version}_{threat}_{str(self.__config['multi_fault_injection'])}/")
            # Check if the directory exists
            if os.path.exists(path_to_filename):
                json_files = [pos_json for pos_json in os.listdir(path_to_filename) if pos_json.endswith('.json')] # Enregistrement sous forme de DataFrame panda
                if(len(json_files) != 0):
                    if(len(json_files) == 1):
                        print("\t\t>>> READING FILE ...")
                    else:
                        print(f"\t\t>>> READING {len(json_files)} FILES ...")
                    start_value = pd.Timestamp.max
                    end_value = pd.Timestamp.min
                    time_read = 0
                    time_concat = 0
                    list_dataframe_files = list()

                    for file in json_files:
                        start_time_read = timer()
                        try:
                            # Open the file using with statement to ensure it's closed after reading
                            with open(os.path.join(path_to_filename, file)) as f:
                                # Read JSON file
                                value_basique = pd.read_json(f).transpose()

                            # Extract values associated with 'start' and 'end' from index
                            if 'start' in value_basique.index:
                                start_str = value_basique.loc['start'].iloc[0]
                                start_datetime = pd.to_datetime(start_str, format="%Y/%m/%d:%H:%M:%S", errors='coerce')
                                if pd.notna(start_datetime):
                                    start_value = min(start_value, start_datetime)
                            if 'end' in value_basique.index:
                                end_str = value_basique.loc['end'].iloc[0]
                                end_datetime = pd.to_datetime(end_str, format="%Y/%m/%d:%H:%M:%S", errors='coerce')
                                if pd.notna(end_datetime):
                                    end_value = max(end_value, end_datetime)
                        except ValueError as e:
                            print(f"Error reading JSON file {os.path.join(path_to_filename, file)}: {e}")
                            break
                        end_time_read = timer()
                        if(time_read == 0):
                            time_read = (end_time_read - start_time_read)
                        else:
                            time_read += (end_time_read - start_time_read)
                        list_dataframe_files.append(value_basique)

                    start_time_concat = timer()
                    self.__table_data = pd.concat(list_dataframe_files, axis=0, ignore_index=False)
                    end_time_concat = timer()
                    if(time_concat == 0):
                        time_concat = (end_time_concat - start_time_concat)
                    else:
                        time_concat += (end_time_concat - start_time_concat)

                    start_time_drop = timer()
                    self.__table_data = self.__table_data.drop(index=['start', 'simulation_0', 'end'])
                    end_time_drop = timer()
                    print(f'\t\t\t>>>> Execute time read : {round(1000*(time_read), 2)} ms')
                    print(f'\t\t\t>>>> Execute time concat : {round(1000*(time_concat), 2)} ms')
                    print(f'\t\t\t>>>> Execute time drop : {round(1000*(end_time_drop - start_time_drop), 2)} ms')
                    if(start_value != 0 and end_value != 0):
                        self.calculate_time_difference(start_value, end_value)
                    # ==================== TABLE 1 ====================
                    print("\t\t>>> TABLE 1")
                    self.table_res(self.__config['name_results'][appli], self.__table_data, df_t1)
                    df_t1 = df_t1.set_axis(self.__idx_app, axis='index')
                    # =================================================

                    # ==================== HEATMAP ====================
                    success = self.__table_data.query('status_end == 4')
                    if(threat in ["single_bitflip_spatial","multi_bitflip_reg_multi", "single_bitflip_temporel"] and len(success) > 0 and int(self.__config['multi_fault_injection']) == 2):
                        print("\t\t>>> Heatmap")
                        self.heatmap(appli=appli, name_appli=self.__config['name_results'][appli], threat=threat)
                        # registers = ["pc_if_o_tag", "memory_set_o_tag", "tcr_q", "tpr_q", "rf_reg[1]", "rf_reg[2]"]
                        # self.heatmap_from_list(appli=appli, name_appli=self.__config['name_results'][appli], threat=threat, filter_names=registers)
                    # =================================================
                else:
                    print(f"The directory \"{path_to_filename}\" is empty.")
            else:
                print(f"The directory \"{path_to_filename}\" does not exist.")
            print()

            # Tableau avec résultats globaux
        print("==================== TABLE 1 ====================")
        if not df_t1.empty:
            df_t1 = df_t1.set_axis(self.__idx_app, axis='index')
            print(df_t1)
            path_table1 = f"{self.__table1}{self.__config['prot']}_{self.__implem_version}_{threat}.tex"
            caption = f"Results for {threat} for the {self.__config['prot']} version"
            label = f"table:end_sim_by_status_{self.__config['prot']}_{self.__implem_version}_{threat}"
            self.write_results(path_table1, df_t1.style.format_index(escape="latex").to_latex(caption=caption, label=label, position_float="centering", multicol_align="c", hrules=True, position="t"))
        
        del df_t1
        del list_dataframe_files
        # self.free_memory_attr()