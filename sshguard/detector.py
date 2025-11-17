import numpy as np
import pickle
from pathlib import Path
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
    FEATURE_COUNT = 15
    
    def __init__(self, model_path: str, threshold: float = 0.5,
                 window_seconds: int = 86400):
        self.model_path = model_path
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.label_decoder = None
        self.logger = logging.getLogger(__name__)
        
        if tf is None or keras is None:
            raise ImportError("TensorFlow is required for anomaly detection")
        
        self._load_model()
        self._load_preprocessing()
    
    def _load_model(self):
        try:
            self.model = keras.models.load_model(self.model_path)
            self.logger.info(f"Loaded LSTM model from {self.model_path}")
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise
    
    def _load_preprocessing(self):
        try:
            models_dir = Path(self.model_path).parent
            
            with open(models_dir / "scaler.pkl", "rb") as f:
                self.scaler = pickle.load(f)
            self.logger.info("Loaded scaler")
            
            with open(models_dir / "label_encoder.pkl", "rb") as f:
                self.label_encoder = pickle.load(f)
                self.label_decoder = {idx: label for label, idx in self.label_encoder.items()}
            self.logger.info("Loaded label encoder")
            
        except Exception as e:
            self.logger.error(f"Failed to load preprocessing objects: {e}")
            raise
    
    def calculate_features(self, events: List[SSHEvent]) -> np.ndarray:
        if not events:
            return np.zeros(self.FEATURE_COUNT, dtype=np.float32)
        
        timestamps = sorted([e.timestamp for e in events])
        first_ts = timestamps[0]
        last_ts = timestamps[-1]
        duration = max(last_ts - first_ts, 1.0)
        
        n_events = len(events)
        n_failed_password = sum(1 for e in events if e.event_type == 'failed_password')
        n_invalid_user = sum(1 for e in events if e.event_type == 'invalid_user')
        n_auth_failure = sum(1 for e in events if e.event_type == 'auth_failure')
        n_disconnects = 0
        
        usernames = set(e.username for e in events if e.username)
        n_distinct_users = len(usernames)
        
        accepted_sessions = sum(1 for e in events if e.event_type == 'accepted_password')
        
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            median_dt = np.median(intervals) if intervals else 0.0
        else:
            median_dt = 0.0
        
        if accepted_sessions + n_failed_password > 0:
            success_ratio = accepted_sessions / (accepted_sessions + n_failed_password)
        else:
            success_ratio = 0.0
        
        n_days_seen = 1.0
        
        log_duration = np.log1p(duration)
        log_median_dt = np.log1p(median_dt)
        fail_rate = n_failed_password / duration if duration > 0 else 0.0
        events_per_second = n_events / duration if duration > 0 else 0.0
        
        features = np.array([
            n_events,
            n_failed_password,
            n_invalid_user,
            n_auth_failure,
            n_disconnects,
            n_distinct_users,
            accepted_sessions,
            duration,
            median_dt,
            success_ratio,
            n_days_seen,
            log_duration,
            log_median_dt,
            fail_rate,
            events_per_second
        ], dtype=np.float32)
        
        return features
    
    def prepare_model_input(self, features: np.ndarray) -> np.ndarray:
        features_scaled = self.scaler.transform(features.reshape(1, -1))
        
        features_reshaped = features_scaled.reshape(1, self.FEATURE_COUNT, 1)
        
        return features_reshaped
    
    def predict(self, events: List[SSHEvent]) -> float:
        if not events:
            return 0.0
        
        try:
            features = self.calculate_features(events)
            
            model_input = self.prepare_model_input(features)
            
            prediction = self.model.predict(model_input, verbose=0)
            probs = prediction[0]
            
            predicted_class_idx = int(np.argmax(probs))
            predicted_label = self.label_decoder[predicted_class_idx]
            
            if predicted_label == "SLOW_ATTACK":
                score = float(probs[predicted_class_idx])
            elif predicted_label == "FAST_ATTACK":
                score = float(probs[predicted_class_idx])
            else:
                score = 0.0
            
            self.logger.debug(f"Prediction: {predicted_label}, Probabilities: {probs}")
            
            return min(max(score, 0.0), 1.0)
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}", exc_info=True)
            failed_events = [e for e in events if e.event_type in ['failed_password', 'auth_failure', 'invalid_user']]
            if len(failed_events) >= 5:
                return 0.9
            elif len(failed_events) >= 3:
                return 0.7
            else:
                return 0.3
    
    def is_attack(self, events: List[SSHEvent]) -> tuple[bool, float]:
        score = self.predict(events)
        return score >= self.threshold, score
    
    def analyze_ip(self, ip: str, events: List[SSHEvent]) -> Dict:
        try:
            features = self.calculate_features(events)
            model_input = self.prepare_model_input(features)
            
            pred = self.model.predict(model_input, verbose=0)
            probs = pred[0]
            
            predicted_class_idx = int(np.argmax(probs))
            predicted_label = self.label_decoder[predicted_class_idx]
            
            if predicted_label in ["SLOW_ATTACK", "FAST_ATTACK"]:
                score = float(probs[predicted_class_idx])
                is_attack = score >= self.threshold
            else:
                score = 0.0
                is_attack = False
                
        except Exception as e:
            self.logger.error(f"Analysis error: {e}", exc_info=True)
            score = self.predict(events)
            probs = np.array([1.0 - score, score, 0.0], dtype=np.float32)
            predicted_label = "UNKNOWN"
            is_attack = score >= self.threshold
        
        event_counts = {
            'failed_password': 0,
            'auth_failure': 0,
            'accepted_password': 0,
            'invalid_user': 0
        }
        
        for event in events:
            if event.event_type in event_counts:
                event_counts[event.event_type] += 1
        
        class_probs = {}
        for idx, prob in enumerate(probs):
            label = self.label_decoder.get(idx, f"class_{idx}")
            class_probs[label] = float(prob)
        
        return {
            'ip': ip,
            'is_attack': is_attack,
            'score': score,
            'event_count': len(events),
            'event_types': event_counts,
            'threshold': self.threshold,
            'predicted_class': predicted_label,
            'class_probs': class_probs
        }
