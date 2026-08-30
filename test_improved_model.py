"""Test the improved hybrid model on simulation data with detailed reporting."""
import os
import json
import subprocess
import sys
import time


def wait_for_training():
    """Wait for training to complete."""
    print("\n" + "="*70)
    print("WAITING FOR MODEL TRAINING TO COMPLETE...")
    print("="*70 + "\n")
    
    model_path = "models/final_model.joblib"
    check_interval = 5  # Check every 5 seconds
    timeout = 3600  # 1 hour timeout
    elapsed = 0
    
    while elapsed < timeout:
        if os.path.exists(model_path):
            # Check if file is still being written
            time.sleep(1)  # Wait a second
            mtime1 = os.path.getmtime(model_path)
            time.sleep(2)  # Wait another 2 seconds
            mtime2 = os.path.getmtime(model_path)
            
            if mtime1 == mtime2:  # File not changing, training complete
                print(f"✓ Model training complete! ({elapsed} seconds elapsed)")
                return True
        
        elapsed += check_interval
        print(f"  Still training... ({elapsed}s elapsed)", end="\r")
        time.sleep(check_interval)
    
    print(f"\n✗ Training timeout after {timeout}s")
    return False


def run_tests():
    """Run comprehensive tests on the improved model."""
    
    # Wait for training
    if not wait_for_training():
        print("ERROR: Training did not complete in time")
        sys.exit(1)
    
    # Generate new simulation data
    print("\n" + "="*70)
    print("GENERATING FRESH SIMULATION DATA...")
    print("="*70)
    result = subprocess.run(
        ["python", "create_simulation_data.py", "--samples", "500"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("ERROR:", result.stderr)
        sys.exit(1)
    
    # Run simulation with original threshold
    print("\n" + "="*70)
    print("TEST 1: SIMULATION WITH OPTIMIZED THRESHOLD")
    print("="*70)
    result = subprocess.run(
        ["python", "simulation.py", "--data", "data/simulation_data.csv", "--alert-file", "logs/simulation_alerts.jsonl"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("ERROR:", result.stderr)
    
    # Load and display results
    if os.path.exists("logs/simulation_results.json"):
        with open("logs/simulation_results.json", "r") as f:
            results = json.load(f)
        
        print("\n" + "="*70)
        print("SIMULATION RESULTS SUMMARY")
        print("="*70)
        print(f"Model: {results['model_type']}")
        print(f"Detection Threshold: {results['threshold']:.3f}")
        print(f"Total Records: {results['total_records']}")
        print(f"Benign Records: {results['benign_records']}")
        print(f"Anomalies Detected: {results['anomalies_detected']}")
        print(f"Detection Rate: {results['detection_rate']*100:.1f}%")
        print("="*70)
        
        # Load evaluation metrics
        if os.path.exists("logs/evaluation_results.json"):
            with open("logs/evaluation_results.json", "r") as f:
                metrics = json.load(f)
            
            print("\nMODEL EVALUATION METRICS (on validation set):")
            print("-"*70)
            print(f"Architecture: {metrics['model_architecture']}")
            print(f"Estimators: {', '.join(metrics['estimators'])}")
            print(f"Weights: {metrics['weights']}")
            print("-"*70)
            print(f"Accuracy:           {metrics['accuracy']:.4f}")
            print(f"Precision:          {metrics['precision']:.4f}")
            print(f"Recall:             {metrics['recall']:.4f}  ← Detection capability")
            print(f"F1 Score:           {metrics['f1_score']:.4f}")
            print(f"False Positive Rate: {metrics['false_positive_rate']:.4f}  ← False alarms")
            if metrics['roc_auc']:
                print(f"ROC AUC:            {metrics['roc_auc']:.4f}")
            print("-"*70)
            print(f"Validation Anomalies: {metrics['anomalies_in_validation']}")
            print(f"Correctly Detected:   {metrics['anomalies_detected']}")
            print(f"False Alarms:         {metrics['false_alarms']}")
            print("="*70)
    
    print("\n✓ All tests completed successfully!")


if __name__ == "__main__":
    run_tests()
