"""Monitor training completion and notify when done."""
import os
import time
import sys

model_path = "models/final_model.joblib"
print("Monitoring training progress...")
print(f"Looking for: {model_path}")
print()

last_time = 0
check_count = 0
max_checks = 360  # 30 minutes with 5-second checks

while check_count < max_checks:
    if os.path.exists(model_path):
        # File exists, check if still being written
        time.sleep(2)
        if os.path.exists(model_path):
            mtime = os.path.getmtime(model_path)
            size = os.path.getsize(model_path)
            
            if mtime == last_time:  # File not changing
                print(f"\n✓ TRAINING COMPLETE!")
                print(f"  File: {model_path}")
                print(f"  Size: {size:,} bytes")
                print(f"  Created: {time.ctime(mtime)}")
                sys.exit(0)
            last_time = mtime
            print(f"[{check_count}] Model file detected: {size:,} bytes | Last update: {time.ctime(mtime)}")
    else:
        print(f"[{check_count}] Waiting for model file... ({check_count*5}s elapsed)", end="\r")
    
    check_count += 1
    time.sleep(5)

print(f"\n✗ Training timeout after {max_checks*5}s")
sys.exit(1)
