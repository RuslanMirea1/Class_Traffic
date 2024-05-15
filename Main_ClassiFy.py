import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from functools import partial
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MaxAbsScaler, LabelEncoder, OneHotEncoder
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier
from sklearn.ensemble import BaggingClassifier
import joblib
import os
import subprocess
import platform
import time
import seaborn as sns
import matplotlib.pyplot as plt
import Anomaly_analize

os.environ['MPLBACKEND'] = 'TkAgg'

from tcpdump_gui import TcpdumpGUI

def browse_file(entry, filetypes):
    filename = filedialog.askopenfilename(filetypes=filetypes)
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def train_and_predict(filename, output_text, output_frame, root):
    try:
        # Load data
        data = pd.read_csv(filename)

        # Remove values Unknown, Unencryped_Jabber, Apple, NTP from protocols
        data = data[~data['proto'].isin(['Unknown', 'Unencryped_Jabber', 'Apple', 'NTP'])]

        # Combine protocols SSL and SSL_No_Cert
        data['proto'] = data['proto'].replace('SSL_No_Cert', 'SSL')

        # Split features and target variable
        features = data.drop('proto', axis=1)
        target = data['proto']

        # Check unique values in 'proto' column
        all_protos = data['proto'].unique()

        # Split into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.6, random_state=42)

        # Ensure all unique 'proto' values are present in training and testing datasets
        missing_from_train = set(all_protos) - set(y_train.unique())
        missing_from_test = set(all_protos) - set(y_test.unique())

        if missing_from_train or missing_from_test:
            messagebox.showwarning("Warning", "Some unique values in 'proto' are missing in the training or testing data.")
            print("Missing in training data:", missing_from_train)
            print("Missing in testing data:", missing_from_test)
            print("Removing these values from the dataset.")

            # Remove rows with missing 'proto' values
            data = data[~data['proto'].isin(missing_from_train.union(missing_from_test))]
            features = data.drop('proto', axis=1)
            target = data['proto']

            # Update training and testing datasets
            X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.6, random_state=42)

        # One-hot encoding for categorical features
        encoder = OneHotEncoder(handle_unknown='ignore')
        X_train_encoded = encoder.fit_transform(X_train)
        X_test_encoded = encoder.transform(X_test)

        # Feature scaling
        scaler = MaxAbsScaler()
        X_train_scaled = scaler.fit_transform(X_train_encoded)
        X_test_scaled = scaler.transform(X_test_encoded)

        # Encoding labels based on training dataset only
        labeler = LabelEncoder()
        y_train_encoded = labeler.fit_transform(y_train)
        y_test_encoded = labeler.transform(y_test)

        # Train and evaluate the model
        dt_classifier = DecisionTreeClassifier()
        xgb_classifier = XGBClassifier()
        bg_classifier = BaggingClassifier()

        start_time = time.time()

        # Train first classifier
        dt_clf = DecisionTreeClassifier()
        dt_clf.fit(X_train_scaled, y_train_encoded)

        # Predict using first classifier
        dt_predictions = dt_clf.predict(X_train_scaled)

        # Train second classifier based on predictions of the first one
        xgb_clf = XGBClassifier()
        xgb_clf.fit(dt_predictions.reshape(-1, 1), y_train_encoded)

        end_time = time.time()

        # Predict on test data
        dt_test_predictions = dt_clf.predict(X_test_scaled)
        xgb_test_predictions = xgb_clf.predict(dt_test_predictions.reshape(-1, 1))

        # Save classification results to a CSV file
        classification_results = pd.DataFrame({'Actual': labeler.inverse_transform(y_test_encoded), 'Predicted': labeler.inverse_transform(xgb_test_predictions)})
        classification_results.to_csv('classification_results.csv', index=False)

        # Evaluate results
        report = classification_report(y_test_encoded, xgb_test_predictions, output_dict=True)
        confusion_mat = confusion_matrix(y_test_encoded, xgb_test_predictions)

        accuracy = report['accuracy']
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, f"Accuracy: {accuracy}\nTraining Time (s): {round(end_time - start_time, 2)}\n\n")

        # Visualize confusion matrix
        plt.figure(figsize=(8, 6))
        cm_df = pd.DataFrame(confusion_mat, index=labeler.classes_, columns=labeler.classes_)
        plt.title('Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        sns.heatmap(cm_df, annot=True, fmt='g', cmap='Blues')
        plt.show()

        # Display classification report in text
        output_text.insert(tk.END, "Classification Report:\n")
        output_text.insert(tk.END, classification_report(y_test_encoded, xgb_test_predictions))

        # Calculate F1 scores
        f1_scores = f1_score(y_test_encoded, xgb_test_predictions, average=None)
        f1_macro_avg = f1_score(y_test_encoded, xgb_test_predictions, average='macro')
        f1_micro_avg = f1_score(y_test_encoded, xgb_test_predictions, average='micro')
        
        f1_scores_df = pd.DataFrame(f1_scores, index=labeler.classes_, columns=['F1 Score'])
        f1_scores_df.loc['Macro Average'] = f1_macro_avg
        f1_scores_df.loc['Micro Average'] = f1_micro_avg

        output_frame.destroy()
        output_frame = tk.Frame(root)
        output_frame.pack(padx=10, pady=10)
        output_label = tk.Label(output_frame, text="F1 Scores:")
        output_label.grid(row=0, column=0, padx=5, pady=5)
        output_table = tk.Text(output_frame, height=10, width=30)
        output_table.grid(row=0, column=1, padx=5, pady=5)
        output_table.insert(tk.END, f1_scores_df)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def start_analysis(csv_file, output_text_anomaly):
    try:
        # Redirect stdout to capture output
        import sys
        from io import StringIO
        original_stdout = sys.stdout
        sys.stdout = StringIO()

        # Call the main function from Anomaly_analize module
        Anomaly_analize.main(csv_file)

        # Get the output and display it in the GUI
        output = sys.stdout.getvalue()
        output_text_anomaly.insert(tk.END, output)

        # Restore stdout
        sys.stdout = original_stdout
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during analysis: {str(e)}")

def open_cmd():
    system = platform.system()
    if system == "Windows":
        subprocess.Popen(['cmd.exe'])
    elif system == "Linux":
        subprocess.Popen(['gnome-terminal'])  # Change this to the terminal emulator you're using
    elif system == "Darwin":  # macOS
        subprocess.Popen(['Terminal'])
    else:
        messagebox.showerror("Error", "Unsupported operating system.")

def execute_command(python_version_var, script_name_var, output_file_entry, sample_value_entry, pcap_file_entry):
    # This function will execute the command entered by the user
    # Construct the command based on the user inputs
    command = f'"{python_version_var.get()}" "{script_name_var.get()}" "-o" "{output_file_entry.get()}" "-s" "{sample_value_entry.get()}" "{pcap_file_entry.get()}"'

    # Execute the command based on the platform
    system = platform.system()
    if system == "Windows":
        subprocess.Popen(['cmd.exe', '/c', command])
    elif system == "Linux":
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', command])
    elif system == "Darwin":
        subprocess.Popen(['Terminal', '-e', command])
    else:
        messagebox.showerror("Error", "Unsupported operating system.")


def create_gui():
    root = tk.Tk()
    root.title("Classifier Trainer")

    # Create a notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(padx=10, pady=10, fill='both', expand=True)

    # Create tab for Classifier Trainer
    classifier_tab = tk.Frame(notebook)
    notebook.add(classifier_tab, text='ClassiFy')

    file_label = tk.Label(classifier_tab, text="Select CSV File:")
    file_label.grid(row=0, column=0, padx=5, pady=5)

    file_entry = tk.Entry(classifier_tab, width=50)
    file_entry.grid(row=0, column=1, padx=5, pady=5)

    browse_button = tk.Button(classifier_tab, text="Browse", command=partial(browse_file, file_entry, [("CSV files", "*.csv")]))
    browse_button.grid(row=0, column=2, padx=5, pady=5)

    train_button = tk.Button(classifier_tab, text="Start classify", command=lambda: train_and_predict(file_entry.get(), output_text, output_frame, root))
    train_button.grid(row=1, column=1, padx=5, pady=5)

    output_text = tk.Text(classifier_tab, height=20, width=80)
    output_text.grid(row=2, columnspan=3, padx=5, pady=5)

    output_frame = tk.Frame(classifier_tab)
    output_frame.grid(row=3, columnspan=3, padx=5, pady=5)
    
    # Create tab for PCAP Recorder
    pcap_tab = tk.Frame(notebook)
    notebook.add(pcap_tab, text='PCAP Recorder')
    tcpdump_gui = TcpdumpGUI(pcap_tab)
    notebook.pack(expand=True, fill='both')

    # Create tab for Command Line
    cmd_tab = tk.Frame(notebook)
    notebook.add(cmd_tab, text='PCAP Converter')

    python_version_label = tk.Label(cmd_tab, text="Python Version:")
    python_version_label.grid(row=0, column=0, padx=5, pady=5)
    python_version_var = tk.StringVar(cmd_tab)
    python_version_var.set("python3")  # Default value
    python_version_option = tk.OptionMenu(cmd_tab, python_version_var, "python2.7", "python3")
    python_version_option.grid(row=0, column=1, padx=5, pady=5)

    script_name_label = tk.Label(cmd_tab, text="Script Name:")
    script_name_label.grid(row=1, column=0, padx=5, pady=5)
    script_name_var = tk.StringVar(cmd_tab)
    script_name_var.set("pcaptocsv_3_good.py")  # Default value
    script_name_entry = tk.Entry(cmd_tab, state="disabled", textvariable=script_name_var)
    script_name_entry.grid(row=1, column=1, padx=5, pady=5)

    output_file_label = tk.Label(cmd_tab, text="Output File:")
    output_file_label.grid(row=2, column=0, padx=5, pady=5)
    output_file_entry = tk.Entry(cmd_tab)
    output_file_entry.grid(row=2, column=1, padx=5, pady=5)

    sample_value_label = tk.Label(cmd_tab, text="Sample Value:")
    sample_value_label.grid(row=3, column=0, padx=5, pady=5)
    sample_value_entry = tk.Entry(cmd_tab)
    sample_value_entry.grid(row=3, column=1, padx=5, pady=5)

    pcap_file_label = tk.Label(cmd_tab, text="PCAP File:")
    pcap_file_label.grid(row=4, column=0, padx=5, pady=5)
    pcap_file_entry = tk.Entry(cmd_tab, width=50)
    pcap_file_entry.grid(row=4, column=1, padx=5, pady=5)
    browse_button = tk.Button(cmd_tab, text="Browse", command=partial(browse_file, pcap_file_entry, [("PCAP files", "*.pcap")]))
    browse_button.grid(row=4, column=2, padx=5, pady=5)

    execute_button = tk.Button(cmd_tab, text="Start convert", command=lambda: execute_command(python_version_var, script_name_var, output_file_entry, sample_value_entry, pcap_file_entry))
    execute_button.grid(row=5, columnspan=2, padx=5, pady=5)

    # Create tab for Anomaly Analysis
    anomaly_tab = tk.Frame(notebook)
    notebook.add(anomaly_tab, text='Anomaly Analysis')

    file_label_anomaly = tk.Label(anomaly_tab, text="Select CSV File:")
    file_label_anomaly.grid(row=0, column=0, padx=5, pady=5)

    file_entry_anomaly = tk.Entry(anomaly_tab, width=50)
    file_entry_anomaly.grid(row=0, column=1, padx=5, pady=5)

    browse_button_anomaly = tk.Button(anomaly_tab, text="Browse", command=lambda: browse_file(file_entry_anomaly, [("CSV files", "*.csv")]))
    browse_button_anomaly.grid(row=0, column=2, padx=5, pady=5)

    analyze_button = tk.Button(anomaly_tab, text="Start Analysis", command=lambda: start_analysis(file_entry_anomaly.get(), output_text_anomaly))
    analyze_button.grid(row=1, column=1, padx=5, pady=5)

    output_text_anomaly = tk.Text(anomaly_tab, height=20, width=80)
    output_text_anomaly.grid(row=2, columnspan=3, padx=5, pady=5)

    output_text_anomaly = tk.Text(anomaly_tab, height=20, width=80)
    output_text_anomaly.grid(row=2, columnspan=3, padx=5, pady=5, sticky="NSEW")

    anomaly_tab.rowconfigure(2, weight=1)  # Разрешить расширение строки с output_text_anomaly
    anomaly_tab.columnconfigure(0, weight=1)  # Разрешить расширение первого столбца

    notebook.pack(expand=True, fill='both')

    root.mainloop()

if __name__ == "__main__":
    create_gui()
