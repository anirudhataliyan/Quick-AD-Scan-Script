import json
import csv

def save_to_json(data, filename):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

def save_to_csv(data, filename):
    if data:
        keys = data[0].keys()
        with open(filename, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
