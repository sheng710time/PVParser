from pathlib import Path
import pandas as pd


if __name__ == "__main__":
    # Example usage
    project_root = Path(__file__).resolve().parent.parent
    csv_path = project_root / "dataset" / "swat" / "Dec2019_dealed.csv"
    all_data = pd.read_csv(csv_path, dtype=str)
    for entry in all_data:
        print(entry)