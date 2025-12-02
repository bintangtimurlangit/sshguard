# Build Fix Applied

## Issue
Build was failing with:
```
error: can't copy 'models/lstm-ids.keras': doesn't exist or not a regular file
```

## Root Cause
The old model file `lstm-ids.keras` was referenced in `setup.py` but no longer exists. The new model requires three files:
- `lstm_model.keras`
- `scaler.pkl`
- `label_encoder.pkl`

## Files Updated

### 1. `setup.py` (Line 42-46)
**Before:**
```python
data_files=[
    ('share/sshguard/models', ['models/lstm-ids.keras']),
    ('etc/sshguard', ['config/sshguard.conf']),
],
```

**After:**
```python
data_files=[
    ('share/sshguard/models', [
        'models/lstm_model.keras',
        'models/scaler.pkl',
        'models/label_encoder.pkl'
    ]),
    ('etc/sshguard', ['config/sshguard.conf']),
],
```

### 2. `MANIFEST.in` (Line 4)
**Before:**
```
recursive-include models *.keras
```

**After:**
```
recursive-include models *.keras *.pkl
```

## Verification
All required model files exist:
```
models/
├── lstm_model.keras (933 KB)
├── scaler.pkl (1.1 KB)
└── label_encoder.pkl (60 B)
```

## Status
✅ Build configuration fixed
✅ All model files present
✅ Ready for `dpkg-buildpackage`

## Build Command
```bash
dpkg-buildpackage -us -uc -b
```

Should now complete successfully.










