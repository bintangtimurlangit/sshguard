"""LSTM-based detection engine."""

import numpy as np
from typing import List, Dict
import logging

try:
    import tensorflow as tf
    from tensorflow import keras
except ImportError:
    tf = None
    keras = None

from .log_monitor import SSHEvent


class AnomalyDetector:
    """LSTM-based anomaly detection for SSH authentication patterns."""
    
    # Feature encoding maps
    EVENT_TYPE_MAP = {
        'failed_auth': 0,
        'accepted_auth': 1,
        'invalid_user': 2
    }
    
    def __init__(self, model_path: str, threshold: float = 0.8):
        """Initialize anomaly detector.
        
        Args:
            model_path: Path to trained LSTM model (.keras file)
            threshold: Detection threshold (0-1)
        """
        self.model_path = model_path
        self.threshold = threshold
        self.model = None
        self.logger = logging.getLogger(__name__)
        
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
    
    def preprocess_sequence(self, events: List[SSHEvent], target_length: int = 100) -> np.ndarray:
        """Convert event sequence to model input format.
        
        Args:
            events: List of SSH events
            target_length: Target sequence length (padding/truncation)
            
        Returns:
            Preprocessed numpy array ready for model input
        """
        if not events:
            # Return zero-filled sequence if no events
            return np.zeros((1, target_length, 3))
        
        # Extract features from events
        features = []
        for event in events:
            # Features: [event_type, time_delta, username_entropy]
            event_type = self.EVENT_TYPE_MAP.get(event.event_type, 0)
            
            # Calculate time delta (seconds since last event)
            if features:
                prev_timestamp = events[len(features) - 1].timestamp
                time_delta = event.timestamp - prev_timestamp
            else:
                time_delta = 0
            
            # Simple username entropy (length as proxy)
            username_entropy = len(event.username) / 20.0  # Normalize
            
            features.append([event_type, time_delta, username_entropy])
        
        # Convert to numpy array
        features = np.array(features)
        
        # Pad or truncate to target length
        if len(features) < target_length:
            # Pad with zeros
            padding = np.zeros((target_length - len(features), 3))
            features = np.vstack([padding, features])
        elif len(features) > target_length:
            # Take last target_length events
            features = features[-target_length:]
        
        # Reshape for model input (batch_size, timesteps, features)
        return features.reshape(1, target_length, 3)
    
    def predict(self, events: List[SSHEvent]) -> float:
        """Predict anomaly score for event sequence.
        
        Args:
            events: List of SSH events
            
        Returns:
            Anomaly score (0-1, higher = more suspicious)
        """
        if not events:
            return 0.0
        
        # Preprocess events
        X = self.preprocess_sequence(events)
        
        # Run inference
        try:
            prediction = self.model.predict(X, verbose=0)
            score = float(prediction[0][0])
            return score
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return 0.0
    
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

