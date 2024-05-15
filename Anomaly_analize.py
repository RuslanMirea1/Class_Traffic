import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import sys

def extract_features_from_csv(csv_file):
    data = pd.read_csv(csv_file)

    # Исключаем первый столбец (идентификаторы строк)
    data = data.iloc[:, 1:]

    # Проверка наличия столбца 'Proto'
    if 'Proto' not in data.columns:
        print("Внимание: Столбец 'Proto' отсутствует в CSV файле. Используются все остальные столбцы.")

    # One-hot кодирование категориальных признаков
    data = pd.get_dummies(data)

    return data

def main(csv_file):
    features = extract_features_from_csv(csv_file)

    # Аномалийный обнаружение с использованием изоляционного леса
    clf = IsolationForest(contamination=0.1)
    clf.fit(features)
    preds = clf.predict(features)
    anomalies = features[preds == -1]

    if not anomalies.empty:
        # Выбор только наиболее значимых столбцов для вывода
        # Находим наиболее важные колонки после анализа аномалий
        important_columns = anomalies.nunique().nlargest(5).index.tolist()
        print("Наиболее важные колонки после анализа аномалий:")
        print(important_columns)

        # Фильтруем subproto_ столбцы, оставляем только те, в которых есть хотя бы одно True
        subproto_columns = [col for col in anomalies.columns if col.startswith('subproto_') and anomalies[col].any()]
        
        # Создаем копию DataFrame, чтобы избежать предупреждения о SettingWithCopyWarning
        anomalies_copy = anomalies.copy()
        
        # Добавляем новый столбец для отображения subproto_ столбцов с True
        anomalies_copy.loc[:, 'subproto_arg'] = anomalies[subproto_columns].apply(lambda x: ','.join(x.index[x].tolist()), axis=1)

        print("Количество обнаруженных аномалий:", len(anomalies))

        # Выводим значения только для важных колонок и subproto_ колонок с True
        print(anomalies_copy[important_columns + ['subproto_arg']])

        # Подсчитываем количество каждого аргумента в колонке subproto_arg
        subproto_counts = anomalies_copy['subproto_arg'].str.split(',', expand=True).stack()
        subproto_counts = subproto_counts[subproto_counts.str.startswith('subproto_')].value_counts()
        print("Количество каждого аргумента в колонке subproto_arg:")
        print(subproto_counts)

    else:
        print("Аномалий не обнаружено.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python script.py <путь_к_csv_файлу>")
    else:
        csv_file = sys.argv[1]
        main(csv_file)
