"""LSTM-based detection engine."""

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
    """LSTM-based anomaly detection for SSH authentication patterns."""
    
    # Model configuration
    SEQUENCE_LENGTH = 12  # 12 timesteps as per training
    FEATURE_COUNT = 6     # 6 features per timestep
    
    # Class mapping from Config C training
    CLASS_NAMES = ['benign', 'fast_attack', 'slow_rate_attack']
    ATTACK_CLASSES = [1, 2]  # fast_attack and slow_rate_attack indices
    
    def __init__(self, model_path: str, threshold: float = 0.5):
        """Initialize anomaly detector.
        
        Args:
            model_path: Path to trained LSTM model (.keras file)
            threshold: Detection threshold (0-1) - probability threshold for attack classes
        """
        self.model_path = model_path
        self.threshold = threshold
        self.model = None
        self.logger = logging.getLogger(__name__)
        
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
        
        # 3. majority_ratio - Ratio of most common label type
        if total_events > 0:
            label_counts = defaultdict(int)
            for event in ssh_events_window:
                label_counts[event.event_type] += 1
            majority_ratio = max(label_counts.values()) / total_events
        else:
            majority_ratio = 0.0
        
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
            majority_ratio,
            avg_interarrival_time,
            burstiness,
            event_entropy
        ], dtype=np.float32)
    
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
            # For now, create a single window from all events
            # In a more sophisticated implementation, you might create multiple time windows
            features = self.calculate_features(events)
            
            # Create feature windows (for now, just repeat the same features 12 times)
            # TODO: Implement proper time windowing based on your training approach
            feature_windows = [features] * self.SEQUENCE_LENGTH
            
            # Prepare model input
            sequence = self.prepare_model_input(feature_windows)
            
            # Normalize
            sequence_normalized = self.normalize_features(sequence)
            
            # Run inference - model outputs probabilities for 3 classes: [benign, fast_attack, slow_rate_attack]
            prediction = self.model.predict(sequence_normalized, verbose=0)
            
            # Extract probabilities
            probs = prediction[0]  # Shape: (3,)
            
            # Calculate attack score: sum of fast_attack + slow_rate_attack probabilities
            attack_score = float(probs[1] + probs[2])  # indices 1 and 2 are attack classes
            
            # Log detailed prediction for debugging
            self.logger.debug(f"Class probabilities - Benign: {probs[0]:.3f}, Fast: {probs[1]:.3f}, Slow: {probs[2]:.3f}")
            
            return min(max(attack_score, 0.0), 1.0)  # Clamp to [0,1]
            
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
        is_attack, score = self.is_attack(events)
        
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
            'threshold': self.threshold
        }

