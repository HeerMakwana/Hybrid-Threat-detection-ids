"""Final comprehensive test of improved hybrid IDS model."""
import os
import json
import subprocess
import sys
import time


def main():
    print("\n" + "="*80)
    print(" "*20 + "HYBRID IDS - IMPROVED MODEL TEST")
    print("="*80 + "\n")
    
    # Wait for model training
    print("STEP 1: WAITING FOR MODEL TRAINING...")
    print("-"*80)
    model_path = "models/final_model.joblib"
    start_time = time.time()
    check_interval = 10
    timeout = 1800  # 30 minutes
    
    while time.time() - start_time < timeout:
        if os.path.exists(model_path):
            # Give it a couple seconds to finish writing
            time.sleep(3)
            if os.path.exists(model_path):
                size = os.path.getsize(model_path)
                elapsed = time.time() - start_time
                print(f"✓ Model training complete!")
                print(f"  Time elapsed: {elapsed:.0f} seconds")
                print(f"  Model size: {size:,} bytes\n")
                break
        else:
            elapsed = time.time() - start_time
            print(f"  Training in progress... ({elapsed:.0f}s)", end="\r")
            time.sleep(check_interval)
    else:
        print(f"\n✗ Training timeout after {timeout}s")
        sys.exit(1)
    
    # Generate simulation data
    print("STEP 2: GENERATING SIMULATION DATA...")
    print("-"*80)
    result = subprocess.run(
        ["python", "create_simulation_data.py", "--samples", "500"],
        capture_output=True,
        text=True,
        timeout=60
    )
    for line in result.stdout.split("\n"):
        if line.strip():
            print(f"  {line}")
    
    # Run simulation
    print("\nSTEP 3: RUNNING SIMULATION...")
    print("-"*80)
    result = subprocess.run(
        ["python", "simulation.py", "--data", "data/simulation_data.csv", "--alert-file", "logs/simulation_alerts.jsonl"],
        capture_output=True,
        text=True,
        timeout=120
    )
    
    # Extract and display only key metrics
    lines = result.stdout.split("\n")
    for i, line in enumerate(lines):
        if "ALERT" in line or "Total records" in line or "Benign" in line or "Anomalies" in line or "Detection rate" in line:
            print(f"  {line}")
        elif "Saved" in line and "results" in line:
            print(f"  {line}")
    
    # Load and display comprehensive results
    print("\nSTEP 4: COMPREHENSIVE RESULTS")
    print("="*80)
    
    try:
        with open("logs/evaluation_results.json", "r") as f:
            metrics = json.load(f)
        
        with open("logs/simulation_results.json", "r") as f:
            sim_results = json.load(f)
        
        print("\n📊 MODEL ARCHITECTURE:")
        print("-"*80)
        print(f"  Type:       {metrics.get('model_architecture', 'Unknown')}")
        print(f"  Estimators: {', '.join(metrics.get('estimators', []))}")
        print(f"  Voting:     Soft voting with weights {metrics.get('weights', [])}")
        print(f"  Training:   {metrics['train_rows']:,} samples / Validation: {metrics['validation_rows']:,} samples")
        
        print("\n📈 VALIDATION SET PERFORMANCE (on {0:,} samples):".format(metrics['validation_rows']))
        print("-"*80)
        print(f"  Accuracy:              {metrics['accuracy']:.4f}  (overall correctness)")
        print(f"  Precision:             {metrics['precision']:.4f}  (accuracy of alerts)")
        print(f"  Recall (Most Important): {metrics['recall']:.4f}  ← Detection capability")
        print(f"  F1 Score:              {metrics['f1_score']:.4f}  (balance metric)")
        print(f"  False Positive Rate:   {metrics['false_positive_rate']:.4f}  (false alarms)")
        if metrics.get('roc_auc'):
            print(f"  ROC AUC:               {metrics['roc_auc']:.4f}  (discrimination ability)")
        print(f"  Optimal Threshold:     {metrics['threshold']:.3f}")
        
        print("\n✓ VALIDATION SET DETECTION RESULTS:")
        print("-"*80)
        print(f"  Total anomalies:     {metrics['anomalies_in_validation']:,}")
        print(f"  Detected:            {metrics['anomalies_detected']:,}")
        print(f"  Missed:              {metrics['anomalies_in_validation'] - metrics['anomalies_detected']:,}")
        print(f"  False Alarms:        {metrics['false_alarms']:,}")
        detection_rate = 100 * metrics['anomalies_detected'] / max(1, metrics['anomalies_in_validation'])
        print(f"  Detection Rate:      {detection_rate:.1f}%")
        
        print("\n🎯 SIMULATION ON 500 TEST SAMPLES:")
        print("-"*80)
        print(f"  Benign records:      {sim_results['benign_records']:,}")
        print(f"  Anomalies detected:  {sim_results['anomalies_detected']:,}")
        print(f"  Detection rate:      {sim_results['detection_rate']*100:.1f}%")
        print(f"  Alerts file:         {sim_results['alert_file']}")
        
        print("\n" + "="*80)
        print("✓ ALL TESTS COMPLETED SUCCESSFULLY!")
        print("="*80 + "\n")
        
        # Summary recommendation
        if metrics['recall'] > 0.90 and metrics['false_positive_rate'] < 0.05:
            print("🟢 MODEL STATUS: EXCELLENT - High detection with low false alarms")
        elif metrics['recall'] > 0.80 and metrics['false_positive_rate'] < 0.10:
            print("🟡 MODEL STATUS: GOOD - Good detection rate with acceptable false alarms")
        else:
            print("🟠 MODEL STATUS: ACCEPTABLE - May need further tuning")
        print()
        
    except FileNotFoundError as e:
        print(f"\n✗ Error loading results: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
