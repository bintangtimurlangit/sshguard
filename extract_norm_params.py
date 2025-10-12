#!/usr/bin/env python3
"""
Extract normalization parameters from the trained model's sequences.
Run this after executing the training notebook cells.
"""

import numpy as np
import pickle
import os

# Try to load from the notebook's saved sequences
try:
    # If you saved sequences_A as a pickle file, load it
    # Otherwise, you need to run the notebook first
    
    print("Please run the following in your Jupyter notebook:")
    print("=" * 70)
    print("""
# After running Cell 20, execute this:
mean_A = sequences_A["normalization"]["mean"]
std_A = sequences_A["normalization"]["std"]
feature_columns = sequences_A["normalization"]["feature_columns"]

print("\\nFEATURE_MEAN = np.array([")
for i, (feat, mean_val) in enumerate(zip(feature_columns, mean_A)):
    print(f"    {mean_val},  # {feat}")
print("], dtype=np.float32)")

print("\\nFEATURE_STD = np.array([")
for i, (feat, std_val) in enumerate(zip(feature_columns, std_A)):
    print(f"    {std_val},  # {feat}")
print("], dtype=np.float32)")

# Also show the values for direct copy-paste
print("\\n" + "="*70)
print("COPY THESE VALUES:")
print("="*70)
print(f"mean_A = {list(mean_A)}")
print(f"std_A = {list(std_A)}")
    """)
    print("=" * 70)
    
except Exception as e:
    print(f"Error: {e}")
    print("\nPlease run Cell 20 and Cell 21 in your notebook to generate the parameters.")


