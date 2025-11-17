# SSHGuard Model Migration Notes

## Summary of Changes

The SSHGuard detector has been refactored to use the new LSTM model trained on sliding window aggregated features (96.34% slow attack detection rate).

## Model Changes

### Old Model
- **File**: `lstm-ids.keras`
- **Input**: (batch, 12, 5) - 12 timesteps of 5 features
- **Features**: total_events, unique_source_ips, avg_interarrival_time, burstiness, event_entropy
- **Approach**: Time-bucketed sequences with hardcoded normalization

### New Model  
- **File**: `lstm_model.keras`
- **Input**: (batch, 15, 1) - 15 features reshaped
- **Features**: n_events, n_failed_password, n_invalid_user, n_auth_failure, n_disconnects, n_distinct_users, accepted_sessions, duration, median_dt, success_ratio, n_days_seen, log_duration, log_median_dt, fail_rate, events_per_second
- **Approach**: Aggregated window statistics with StandardScaler normalization

## Required Files

The following files must be present in `/usr/lib/sshguard/models/`:

1. **lstm_model.keras** - The trained LSTM model
2. **scaler.pkl** - StandardScaler for feature normalization
3. **label_encoder.pkl** - Label encoder for prediction decoding

## Code Changes

### 1. `detector.py` - Complete Rewrite
- Removed time-bucket and event-bucket sequence building
- Implemented 15-feature calculation matching training data
- Load scaler and label_encoder from pickle files
- Changed input reshaping from (1, 12, 5) to (1, 15, 1)
- Updated prediction logic to decode using label_encoder

### 2. `__main__.py`
- Removed old detector parameters: `sequence_horizon_seconds`, `bucket_count`, `fast_threshold`, `slow_threshold`, `min_class_confidence`
- Added `window_seconds` parameter (default: 86400 = 24 hours)

### 3. `config/sshguard.conf`
- Updated `model_path` to `lstm_model.keras`
- Changed `detection_threshold` from 0.5 to 0.7 (recommended for better precision)
- Added `window_seconds = 86400`

### 4. `debian/install`
- Added `scaler.pkl` and `label_encoder.pkl` to installation

### 5. `README.md`
- Updated installation instructions to copy all three model files

## Feature Mapping

The new detector calculates these features from SSH events:

| Feature | Calculation | Source |
|---------|-------------|--------|
| n_events | Count of all events | len(events) |
| n_failed_password | Failed auth attempts | event_type == 'failed_auth' |
| n_invalid_user | Invalid user attempts | event_type == 'invalid_user' |
| n_auth_failure | Same as failed_password | n_failed_password |
| n_disconnects | Disconnections (not tracked in current logs) | 0 |
| n_distinct_users | Unique usernames | set(usernames) |
| accepted_sessions | Successful logins | event_type == 'accepted_auth' |
| duration | Time span of events | last_ts - first_ts |
| median_dt | Median inter-event time | median(intervals) |
| success_ratio | Login success rate | accepted / (accepted + failed) |
| n_days_seen | Days IP seen (not tracked) | 1.0 |
| log_duration | log(1 + duration) | np.log1p(duration) |
| log_median_dt | log(1 + median_dt) | np.log1p(median_dt) |
| fail_rate | Failures per second | failed / duration |
| events_per_second | Events per second | events / duration |

## Configuration Recommendations

- **detection_threshold**: 0.7 (stricter than 0.5, reduces false positives)
- **window_size**: 100 events per IP (unchanged)
- **window_seconds**: 86400 (24 hour window for feature calculation)

## Testing

After deployment, monitor:
1. Detection logs for classification: SLOW_ATTACK, FAST_ATTACK, UNKNOWN
2. Prediction probabilities in debug logs
3. False positive rate (legitimate IPs being blocked)

## Rollback

To revert to old model:
1. Copy `lstm-ids.keras` back to models directory
2. Restore old `detector.py` from git history
3. Update config to use `lstm-ids.keras`
4. Remove `scaler.pkl` and `label_encoder.pkl` references

## Performance Notes

- New model achieved 96.34% slow attack detection vs old model
- Slightly lower overall accuracy (97.57%) due to tabular data being better suited for tree models
- XGBoost achieved 99.96% but LSTM is used for deployment flexibility

