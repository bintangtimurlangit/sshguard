import numpy as np
import math
from typing import List, Dict
import logging
from collections import defaultdict

try:
    import tensorflow as tf
    from tensorflow import keras
except ImportError:
    tf = None
    keras = None

from .log_monitor import SSHEvent


class AnomalyDetector:
    SEQUENCE_LENGTH = 12
    FEATURE_COUNT = 6
    
    CLASS_NAMES = ['benign', 'fast_attack', 'slow_rate_attack']
    ATTACK_CLASSES = [1, 2]
    
    def __init__(self, model_path: str, threshold: float = 0.5,
                 sequence_horizon_seconds: int = 60,
                 bucket_count: int = 12,
                 fast_threshold: float | None = None,
                 slow_threshold: float | None = None):
        """Initialize anomaly detector.
        
        Args:
            model_path: Path to trained LSTM model (.keras file)
            threshold: Detection threshold (0-1) - probability threshold for attack classes
        """
        self.model_path = model_path
        self.threshold = threshold
        self.model = None
        self.logger = logging.getLogger(__name__)
        # Inference knobs
        self.sequence_horizon_seconds = max(6, int(sequence_horizon_seconds))
        self.bucket_count = max(1, int(bucket_count))
        # Optional per-class thresholds (if set, override combined threshold decision)
        self.fast_threshold = fast_threshold
        self.slow_threshold = slow_threshold
        
        # Exact normalization parameters from Config C training (mixed dataset)
        # Feature order: total_events, unique_source_ips, majority_ratio, 
        #                avg_interarrival_time, burstiness, event_entropy
        self.feature_mean = np.array([
            603.18432617,    # total_events
            21.29883957,     # unique_source_ips
            0.77969247,      # majority_ratio
            8.67684555,      # avg_interarrival_time
            2.41349888,      # burstiness
            0.78907585,      # event_entropy
        ], dtype=np.float32)
        
        self.feature_std = np.array([
            1775.83642578,   # total_events
            21.85165024,     # unique_source_ips
            0.15343687,      # majority_ratio
            27.78080368,     # avg_interarrival_time
            1.47318995,      # burstiness
            0.38233167,      # event_entropy
        ], dtype=np.float32)
        
        if tf is None or keras is None:
            raise ImportError("TensorFlow is required for anomaly detection")
        
        self._load_model()
    
    def _load_model(self):
        """Load the trained LSTM model."""
        try:
            self.model = keras.models.load_model(self.model_path)
            self.logger.info(f"Loaded LSTM model from {self.model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise
    
    def calculate_features(self, ssh_events_window: List[SSHEvent]) -> np.ndarray:
        """Calculate the 6 required features for model input.
        
        Features:
        1. total_events - Activity level
        2. unique_source_ips - IP diversity  
        3. majority_ratio - Label confidence
        4. avg_interarrival_time - Timing pattern
        5. burstiness - Timing regularity
        6. event_entropy - Pattern diversity
        """
        
        # 1. total_events - Count of SSH events in window
        total_events = len(ssh_events_window)
        
        # 2. unique_source_ips - Number of unique source IPs
        unique_source_ips = len(set(event.ip for event in ssh_events_window))
        
        # 3. majority_ratio (runtime proxy): use ratio_failed = failed_auth / total_events
        if total_events > 0:
            label_counts = defaultdict(int)
            for event in ssh_events_window:
                label_counts[event.event_type] += 1
            ratio_failed = label_counts['failed_auth'] / total_events
        else:
            ratio_failed = 0.0
        
        # 4. avg_interarrival_time - Average time between events
        if total_events > 1:
            timestamps = sorted([event.timestamp for event in ssh_events_window])
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interarrival_time = sum(intervals) / len(intervals)
        else:
            avg_interarrival_time = 0.0
        
        # 5. burstiness - Measure of timing regularity (coefficient of variation)
        if total_events > 2:
            timestamps = sorted([event.timestamp for event in ssh_events_window])
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            if len(intervals) > 1:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
                std_interval = variance ** 0.5
                burstiness = std_interval / mean_interval if mean_interval > 0 else 0.0
            else:
                burstiness = 0.0
        else:
            burstiness = 0.0
        
        # 6. event_entropy - Shannon entropy of event types
        if total_events > 0:
            type_counts = defaultdict(int)
            for event in ssh_events_window:
                type_counts[event.event_type] += 1
            
            entropy = 0.0
            for count in type_counts.values():
                p = count / total_events
                if p > 0:
                    entropy -= p * math.log2(p)
            event_entropy = entropy
        else:
            event_entropy = 0.0
        
        return np.array([
            total_events,
            unique_source_ips,
            ratio_failed,
            avg_interarrival_time,
            burstiness,
            event_entropy
        ], dtype=np.float32)

    def _build_time_bucket_sequence(self, events: List[SSHEvent], total_horizon_seconds: int | None = None,
                                    bucket_count: int | None = None) -> np.ndarray:
        if total_horizon_seconds is None:
            total_horizon_seconds = self.sequence_horizon_seconds
        if bucket_count is None:
            bucket_count = self.bucket_count
        if not events:
            # Return zeros with desired bucket_count; caller will adapt to 12
            return np.zeros((bucket_count, self.FEATURE_COUNT), dtype=np.float32)

        latest_ts = max(e.timestamp for e in events)
        bucket_len = max(1, total_horizon_seconds // bucket_count)
        horizon_start = latest_ts - total_horizon_seconds
        sequence_rows: List[np.ndarray] = []

        for i in range(bucket_count):
            start_ts = horizon_start + i * bucket_len
            end_ts = start_ts + bucket_len
            bucket_events = [e for e in events if (e.timestamp >= start_ts and e.timestamp < end_ts)]
            features = self.calculate_features(bucket_events)
            sequence_rows.append(features)

        seq = np.stack(sequence_rows, axis=0)
        # Adapt to model-required 12 timesteps (pad or take last 12)
        if seq.shape[0] < self.SEQUENCE_LENGTH:
            pad_rows = np.zeros((self.SEQUENCE_LENGTH - seq.shape[0], self.FEATURE_COUNT), dtype=np.float32)
            seq = np.vstack([pad_rows, seq])
        elif seq.shape[0] > self.SEQUENCE_LENGTH:
            seq = seq[-self.SEQUENCE_LENGTH:]
        return seq

    def _build_event_bucket_sequence(self, events: List[SSHEvent], events_per_bucket: int = 5,
                                     bucket_count: int | None = None) -> np.ndarray:
        """Build a (12,6) sequence using fixed number of events per bucket.

        Takes the last (bucket_count * events_per_bucket) events for the IP,
        splits them into contiguous buckets (oldest to newest), and computes
        features per bucket.
        """
        if bucket_count is None:
            bucket_count = self.bucket_count
        if events_per_bucket <= 0:
            events_per_bucket = 5
        if not events:
            return np.zeros((self.SEQUENCE_LENGTH, self.FEATURE_COUNT), dtype=np.float32)

        # Take only the last N events to form buckets
        needed = bucket_count * events_per_bucket
        slice_events = events[-needed:]
        # If fewer events than needed, left-pad with empty buckets later
        buckets: List[np.ndarray] = []

        # If not enough events to fill one bucket, return zeros padded except last bucket with whatever exists
        if len(slice_events) < events_per_bucket:
            feat = self.calculate_features(slice_events)
            seq = [np.zeros(self.FEATURE_COUNT, dtype=np.float32)] * (self.SEQUENCE_LENGTH - 1) + [feat]
            return np.stack(seq, axis=0)

        # Build buckets from oldest to newest
        for i in range(0, len(slice_events), events_per_bucket):
            bucket = slice_events[i:i + events_per_bucket]
            if not bucket:
                continue
            buckets.append(self.calculate_features(bucket))

        seq = np.stack(buckets, axis=0) if buckets else np.zeros((0, self.FEATURE_COUNT), dtype=np.float32)
        # Adapt to 12 timesteps
        if seq.shape[0] < self.SEQUENCE_LENGTH:
            pad_rows = np.zeros((self.SEQUENCE_LENGTH - seq.shape[0], self.FEATURE_COUNT), dtype=np.float32)
            seq = np.vstack([pad_rows, seq])
        elif seq.shape[0] > self.SEQUENCE_LENGTH:
            seq = seq[-self.SEQUENCE_LENGTH:]
        return seq
    
    def prepare_model_input(self, feature_windows: List[np.ndarray]) -> np.ndarray:
        """Prepare 12-timestep sequence for model input."""
        
        # Ensure we have exactly 12 timesteps
        if len(feature_windows) < self.SEQUENCE_LENGTH:
            # Pad with zeros or repeat last window
            padding_needed = self.SEQUENCE_LENGTH - len(feature_windows)
            if len(feature_windows) > 0:
                # Repeat last window
                last_window = feature_windows[-1]
                feature_windows.extend([last_window] * padding_needed)
            else:
                # All zeros
                feature_windows = [np.zeros(self.FEATURE_COUNT, dtype=np.float32)] * self.SEQUENCE_LENGTH
        elif len(feature_windows) > self.SEQUENCE_LENGTH:
            # Take last 12 windows
            feature_windows = feature_windows[-self.SEQUENCE_LENGTH:]
        
        # Stack into sequence: shape (12, 6)
        sequence = np.stack(feature_windows)
        
        # Add batch dimension: shape (1, 12, 6)
        sequence = np.expand_dims(sequence, axis=0)
        
        return sequence
    
    def normalize_features(self, sequence: np.ndarray) -> np.ndarray:
        """Apply training normalization to input sequence."""
        return (sequence - self.feature_mean) / self.feature_std
    
    def predict(self, events: List[SSHEvent]) -> float:
        """Predict anomaly score for event sequence.
        
        Args:
            events: List of SSH events
            
        Returns:
            Anomaly score (0-1, higher = more suspicious) - combined probability of attack classes
        """
        if not events:
            return 0.0
        
        try:
            # Prefer event-bucketed sequence to better match training step windows (≈3)
            seq_12x6 = self._build_event_bucket_sequence(events, events_per_bucket=3)
            feature_windows = [seq_12x6[i] for i in range(self.SEQUENCE_LENGTH)]
            sequence = self.prepare_model_input(feature_windows)
            
            # Normalize
            sequence_normalized = self.normalize_features(sequence)
            
            # Run inference - model outputs probabilities for 3 classes: [benign, fast_attack, slow_rate_attack]
            prediction = self.model.predict(sequence_normalized, verbose=0)
            probs = prediction[0]
            attack_score = float(probs[1] + probs[2])
            self.logger.debug(f"Class probabilities - Benign: {probs[0]:.3f}, Fast: {probs[1]:.3f}, Slow: {probs[2]:.3f}")
            return min(max(attack_score, 0.0), 1.0)
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}", exc_info=True)
            # Fallback: simple heuristic based on failed attempts
            failed_events = [e for e in events if e.event_type in ['failed_auth', 'invalid_user']]
            if len(failed_events) >= 5:
                return 0.9  # High suspicion for many failed attempts
            elif len(failed_events) >= 3:
                return 0.7  # Medium suspicion
            else:
                return 0.3  # Low suspicion
    
    def is_attack(self, events: List[SSHEvent]) -> tuple[bool, float]:
        """Determine if event sequence indicates an attack.
        
        Args:
            events: List of SSH events
            
        Returns:
            Tuple of (is_attack, score)
        """
        score = self.predict(events)
        return score >= self.threshold, score
    
    def analyze_ip(self, ip: str, events: List[SSHEvent]) -> Dict:
        """Analyze all events for an IP address.
        
        Args:
            ip: IP address
            events: List of SSH events for this IP
            
        Returns:
            Analysis results dictionary
        """
        # Compute probabilities and class using time-bucketed sequence
        try:
            seq_12x6 = self._build_event_bucket_sequence(events, events_per_bucket=3)
            feature_windows = [seq_12x6[i] for i in range(self.SEQUENCE_LENGTH)]
            sequence = self.prepare_model_input(feature_windows)
            sequence_normalized = self.normalize_features(sequence)
            pred = self.model.predict(sequence_normalized, verbose=0)
            probs = pred[0]
            score = float(probs[1] + probs[2])
        except Exception:
            # Fallback to simple predict
            score = self.predict(events)
            probs = np.array([1.0 - score, score * 0.6, score * 0.4], dtype=np.float32)
        # Decision rule: per-class thresholds if provided, otherwise combined
        # Decision: combined OR per-class (if provided)
        is_attack = (score >= self.threshold)
        if self.fast_threshold is not None:
            is_attack = is_attack or (probs[1] >= self.fast_threshold)
        if self.slow_threshold is not None:
            is_attack = is_attack or (probs[2] >= self.slow_threshold)
        predicted_class_idx = int(np.argmax(probs))
        predicted_class = self.CLASS_NAMES[predicted_class_idx]
        
        # Count event types
        event_counts = {
            'failed_auth': 0,
            'accepted_auth': 0,
            'invalid_user': 0
        }
        
        for event in events:
            if event.event_type in event_counts:
                event_counts[event.event_type] += 1
        
        return {
            'ip': ip,
            'is_attack': is_attack,
            'score': score,
            'event_count': len(events),
            'event_types': event_counts,
            'threshold': self.threshold,
            'predicted_class': predicted_class,
            'class_probs': {
                'benign': float(probs[0]),
                'fast_attack': float(probs[1]),
                'slow_rate_attack': float(probs[2])
            }
        }

