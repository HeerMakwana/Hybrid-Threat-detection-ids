"""Generate simulation data by randomly sampling 200 entries from the dataset."""
import argparse
import pandas as pd
import os


def create_simulation_data(input_csv, output_csv, n_samples=200, random_state=42):
    print(f"Loading dataset: {input_csv}", flush=True)
    df = pd.read_csv(input_csv)
    print(f"Total rows in dataset: {len(df)}", flush=True)
    
    # Randomly sample n_samples entries
    simulation_df = df.sample(n=min(n_samples, len(df)), random_state=random_state).reset_index(drop=True)
    print(f"Sampled {len(simulation_df)} rows for simulation", flush=True)
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    
    # Save simulation data
    simulation_df.to_csv(output_csv, index=False)
    print(f"Saved simulation data to {output_csv}", flush=True)
    
    # Print summary stats
    if "Label" in simulation_df.columns or "label" in simulation_df.columns:
        label_col = "Label" if "Label" in simulation_df.columns else "label"
        print(f"\nSimulation data label distribution:")
        print(simulation_df[label_col].value_counts())


def main():
    parser = argparse.ArgumentParser(description="Create simulation data by sampling from dataset")
    parser.add_argument("--input", default="data/combined.csv", help="Input CSV dataset")
    parser.add_argument("--output", default="data/simulation_data.csv", help="Output CSV file for simulation")
    parser.add_argument("--samples", type=int, default=200, help="Number of samples to generate (default: 200)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()
    
    create_simulation_data(args.input, args.output, n_samples=args.samples, random_state=args.seed)


if __name__ == "__main__":
    main()
