import numpy as np
import pickle
import time
from pathlib import Path
from typing import List, Dict, Optional
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta

try:
    import tensorflow as tf
    from tensorflow import keras
except ImportError:
    tf = None
    keras = None

from .log_monitor import SSHEvent


# Define focal loss function for model loading
def focal_loss_fixed(y_true, y_pred, alpha=0.25, gamma=2.0):
    """
    Focal loss function for handling class imbalance.
    This function must be registered before loading models that use it.
    """
    import tensorflow as tf
    
    # Convert to float32
    y_true = tf.cast(y_true, tf.float32)
    y_pred = tf.cast(y_pred, tf.float32)
    
    # Clip predictions to avoid numerical instability
    y_pred = tf.clip_by_value(y_pred, 1e-7, 1.0 - 1e-7)
    
    # Calculate cross entropy
    ce = -y_true * tf.math.log(y_pred)
    
    # Calculate p_t
    p_t = y_true * y_pred + (1 - y_true) * (1 - y_pred)
    
    # Calculate focal weight
    focal_weight = tf.pow(1 - p_t, gamma)
    
    # Apply alpha weighting
    alpha_t = y_true * alpha + (1 - y_true) * (1 - alpha)
    
    # Calculate focal loss
    focal_loss = alpha_t * focal_weight * ce
    
    return tf.reduce_mean(focal_loss)


# Register the function with Keras if available
if keras is not None:
    try:
        keras.saving.register_keras_serializable(package="sshguard", name="focal_loss_fixed")(focal_loss_fixed)
    except Exception:
        # If registration fails, we'll use custom_objects when loading
        pass


class AnomalyDetector:
    FEATURE_COUNT = 9
    SEQUENCE_LENGTH = 3
    
    def __init__(self, model_path: str, threshold: float = 0.5,
                 window_seconds: int = 3600):
        self.model_path = model_path
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.label_decoder = None
        self.model_config = None
        self.logger = logging.getLogger(__name__)
        
        self.ip_failed_days: Dict[str, set] = defaultdict(set)
        self.ip_window_history: Dict[str, List[Dict]] = defaultdict(list)
        
        if tf is None or keras is None:
            raise ImportError("TensorFlow is required for anomaly detection")
        
        self._load_model()
        self._load_preprocessing()
    
    def _load_model(self):
        try:
            # Register custom objects before loading
            custom_objects = {
                'focal_loss_fixed': focal_loss_fixed
            }
            self.model = keras.models.load_model(
                self.model_path,
                custom_objects=custom_objects
            )
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
                self.label_decoder = {idx: label for idx, label in enumerate(self.label_encoder.classes_)}
            self.logger.info("Loaded label encoder")
            
            with open(models_dir / "model_config.pkl", "rb") as f:
                self.model_config = pickle.load(f)
                if "sequence_length" in self.model_config:
                    self.SEQUENCE_LENGTH = self.model_config["sequence_length"]
            self.logger.info("Loaded model config")
            
        except Exception as e:
            self.logger.error(f"Failed to load preprocessing objects: {e}")
            raise
    
    def _compute_entropy(self, values: List) -> float:
        if len(values) == 0:
            return 0.0
        counts = Counter(values)
        total = len(values)
        probs = [count / total for count in counts.values()]
        return -sum(p * np.log2(p + 1e-10) for p in probs)
    
    def _update_failed_days(self, ip: str, events: List[SSHEvent]):
        for e in events:
            if e.event_type == "failed_password":
                dt = datetime.fromtimestamp(e.timestamp)
                self.ip_failed_days[ip].add(dt.date())
    
    def _get_num_failed_days(self, ip: str) -> float:
        return float(len(self.ip_failed_days.get(ip, set())))
    
    def _group_events_by_hour(self, events: List[SSHEvent]) -> Dict[datetime, List[SSHEvent]]:
        hourly_groups = defaultdict(list)
        for e in events:
            dt = datetime.fromtimestamp(e.timestamp)
            hour_start = dt.replace(minute=0, second=0, microsecond=0)
            hourly_groups[hour_start].append(e)
        return dict(hourly_groups)
    
    def _group_events_by_time_window(self, events: List[SSHEvent], window_minutes: int = 15) -> Dict[datetime, List[SSHEvent]]:
        """Group events into time windows (e.g., 15-minute windows) for rapid attack detection."""
        window_groups = defaultdict(list)
        for e in events:
            dt = datetime.fromtimestamp(e.timestamp)
            # Round down to nearest window_minutes
            minutes = (dt.minute // window_minutes) * window_minutes
            window_start = dt.replace(minute=minutes, second=0, microsecond=0)
            window_groups[window_start].append(e)
        return dict(window_groups)
    
    def calculate_features(self, events: List[SSHEvent], ip: Optional[str] = None) -> np.ndarray:
        if not events:
            return np.zeros(self.FEATURE_COUNT, dtype=np.float32)
        
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        
        failed = [e for e in events if e.event_type == "failed_password"]
        accepted = [e for e in events if "accepted" in e.event_type.lower()]
        
        n_failed_password = len(failed)
        n_distinct_users = len(set(e.username for e in events if e.username))
        accepted_sessions = len(accepted)
        
        total_attempts = n_failed_password + accepted_sessions
        success_ratio = accepted_sessions / total_attempts if total_attempts > 0 else 0.0
        
        failed_ports = set()
        for e in failed:
            if hasattr(e, 'src_port') and e.src_port:
                failed_ports.add(e.src_port)
        num_failed_ports = len(failed_ports)
        
        timestamps = np.array([e.timestamp for e in events_sorted])
        if len(timestamps) > 1:
            time_diffs = np.diff(timestamps)
            avg_time_between_attempts = np.mean(time_diffs) if len(time_diffs) > 0 else 0.0
            login_interval_variance = np.var(time_diffs) if len(time_diffs) > 0 else 0.0
        else:
            avg_time_between_attempts = 0.0
            login_interval_variance = 0.0
        
        time_of_day_seconds = np.array([ts % 86400 for ts in timestamps])
        time_of_day_avg = np.mean(time_of_day_seconds) if len(time_of_day_seconds) > 0 else 0.0
        
        usernames = [e.username for e in events if e.username]
        username_entropy = self._compute_entropy(usernames)
        
        num_failed_days = self._get_num_failed_days(ip) if ip else 0.0
        
        features = np.array([
            n_failed_password,
            n_distinct_users,
            avg_time_between_attempts,
            num_failed_ports,
            success_ratio,
            login_interval_variance,
            username_entropy,
            time_of_day_avg,
            num_failed_days
        ], dtype=np.float32)
        
        return features
    
    def prepare_model_input(self, sequence_features: List[np.ndarray]) -> np.ndarray:
        if len(sequence_features) < self.SEQUENCE_LENGTH:
            padding = [np.zeros(self.FEATURE_COUNT, dtype=np.float32)] * (self.SEQUENCE_LENGTH - len(sequence_features))
            sequence_features = padding + sequence_features
        
        sequence_features = sequence_features[-self.SEQUENCE_LENGTH:]
        
        features_array = np.array(sequence_features)
        features_flat = features_array.reshape(-1, self.FEATURE_COUNT)
        features_scaled = self.scaler.transform(features_flat)
        features_reshaped = features_scaled.reshape(1, self.SEQUENCE_LENGTH, self.FEATURE_COUNT)
        
        return features_reshaped
    
    def _update_window_history(self, ip: str, events: List[SSHEvent]):
        if not ip:
            return
        
        self._update_failed_days(ip, events)
        
        hourly_groups = self._group_events_by_hour(events)
        current_time = time.time()
        
        existing_hours = {w['hour_start'] for w in self.ip_window_history[ip]}
        
        for hour_start, hour_events in sorted(hourly_groups.items()):
            if hour_start not in existing_hours:
                window_features = self.calculate_features(hour_events, ip=ip)
                window_data = {
                    'hour_start': hour_start,
                    'features': window_features,
                    'timestamp': current_time
                }
                self.ip_window_history[ip].append(window_data)
            else:
                for w in self.ip_window_history[ip]:
                    if w['hour_start'] == hour_start:
                        w['features'] = self.calculate_features(hour_events, ip=ip)
                        w['timestamp'] = current_time
                        break
        
        cutoff_time = current_time - (self.SEQUENCE_LENGTH * self.window_seconds * 2)
        self.ip_window_history[ip] = [
            w for w in self.ip_window_history[ip] 
            if w['timestamp'] >= cutoff_time
        ]
        
        self.ip_window_history[ip].sort(key=lambda x: x['hour_start'])
    
    def predict(self, events: List[SSHEvent], ip: Optional[str] = None) -> float:
        if not events:
            return 0.0
        
        try:
            if ip:
                self._update_failed_days(ip, events)
                self._update_window_history(ip, events)
            
            if ip and ip in self.ip_window_history:
                window_history = self.ip_window_history[ip]
                if len(window_history) >= self.SEQUENCE_LENGTH:
                    sequence_features = [w['features'] for w in window_history[-self.SEQUENCE_LENGTH:]]
                    model_input = self.prepare_model_input(sequence_features)
                else:
                    return 0.0
            else:
                if ip:
                    self._update_failed_days(ip, events)
                
                # Try hourly windows first
                hourly_groups = self._group_events_by_hour(events)
                if len(hourly_groups) >= self.SEQUENCE_LENGTH:
                    sorted_hours = sorted(hourly_groups.keys())
                    sequence_features = []
                    for hour_start in sorted_hours[-self.SEQUENCE_LENGTH:]:
                        hour_events = hourly_groups[hour_start]
                        features = self.calculate_features(hour_events, ip=ip)
                        sequence_features.append(features)
                    model_input = self.prepare_model_input(sequence_features)
                else:
                    # For rapid attacks, use time-based windows (15-minute windows)
                    # This allows detection even when all events are in the same hour
                    time_groups = self._group_events_by_time_window(events, window_minutes=15)
                    window_size = 15
                    if len(time_groups) < self.SEQUENCE_LENGTH:
                        # If still not enough, try 10-minute windows
                        time_groups = self._group_events_by_time_window(events, window_minutes=10)
                        window_size = 10
                        if len(time_groups) < self.SEQUENCE_LENGTH:
                            # If still not enough, try 5-minute windows
                            time_groups = self._group_events_by_time_window(events, window_minutes=5)
                            window_size = 5
                            if len(time_groups) < self.SEQUENCE_LENGTH:
                                # Last resort: split events into equal chunks to create windows
                                if len(events) >= self.SEQUENCE_LENGTH * 3:  # Need at least 3 events per window
                                    self.logger.debug(f"Using event-based windowing for {len(events)} events")
                                    chunk_size = len(events) // self.SEQUENCE_LENGTH
                                    time_groups = {}
                                    for i in range(self.SEQUENCE_LENGTH):
                                        start_idx = i * chunk_size
                                        end_idx = start_idx + chunk_size if i < self.SEQUENCE_LENGTH - 1 else len(events)
                                        chunk_events = events[start_idx:end_idx]
                                        if chunk_events:
                                            # Use the timestamp of the first event in the chunk as the window start
                                            first_ts = datetime.fromtimestamp(chunk_events[0].timestamp)
                                            time_groups[first_ts] = chunk_events
                                    window_size = 0  # Event-based
                                else:
                                    self.logger.debug(f"Insufficient events ({len(events)}) to create {self.SEQUENCE_LENGTH} windows")
                                    return 0.0
                    
                    sorted_windows = sorted(time_groups.keys())
                    sequence_features = []
                    for window_start in sorted_windows[-self.SEQUENCE_LENGTH:]:
                        window_events = time_groups[window_start]
                        features = self.calculate_features(window_events, ip=ip)
                        sequence_features.append(features)
                    model_input = self.prepare_model_input(sequence_features)
                    if window_size > 0:
                        self.logger.debug(f"Using {window_size}-minute windows for rapid attack detection")
            
            prediction = self.model.predict(model_input, verbose=0)
            probs = prediction[0]
            
            predicted_class_idx = int(np.argmax(probs))
            predicted_label = self.label_decoder[predicted_class_idx]
            
            if predicted_label in ["SLOW_ATTACK", "FAST_ATTACK"]:
                score = float(probs[predicted_class_idx])
            else:
                score = 0.0
            
            return min(max(score, 0.0), 1.0)
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}", exc_info=True)
            return 0.0
    
    def is_attack(self, events: List[SSHEvent], ip: Optional[str] = None) -> tuple[bool, float]:
        score = self.predict(events, ip=ip)
        return score >= self.threshold, score
    
    def analyze_ip(self, ip: str, events: List[SSHEvent]) -> Dict:
        try:
            if not events:
                return {
                    'ip': ip,
                    'is_attack': False,
                    'score': 0.0,
                    'event_count': 0,
                    'event_types': {},
                    'threshold': self.threshold,
                    'predicted_class': 'BENIGN',
                    'class_probs': {}
                }
            
            if ip:
                self._update_failed_days(ip, events)
                self._update_window_history(ip, events)
            
            if ip and ip in self.ip_window_history:
                window_history = self.ip_window_history[ip]
                if len(window_history) >= self.SEQUENCE_LENGTH:
                    sequence_features = [w['features'] for w in window_history[-self.SEQUENCE_LENGTH:]]
                    model_input = self.prepare_model_input(sequence_features)
                else:
                    return {
                        'ip': ip,
                        'is_attack': False,
                        'score': 0.0,
                        'event_count': len(events),
                        'event_types': {},
                        'threshold': self.threshold,
                        'predicted_class': 'BENIGN',
                        'class_probs': {}
                    }
            else:
                if ip:
                    self._update_failed_days(ip, events)
                
                # Try hourly windows first
                hourly_groups = self._group_events_by_hour(events)
                if len(hourly_groups) >= self.SEQUENCE_LENGTH:
                    sorted_hours = sorted(hourly_groups.keys())
                    sequence_features = []
                    for hour_start in sorted_hours[-self.SEQUENCE_LENGTH:]:
                        hour_events = hourly_groups[hour_start]
                        features = self.calculate_features(hour_events, ip=ip)
                        sequence_features.append(features)
                    model_input = self.prepare_model_input(sequence_features)
                else:
                    # For rapid attacks, use time-based windows (15-minute windows)
                    time_groups = self._group_events_by_time_window(events, window_minutes=15)
                    window_size = 15
                    if len(time_groups) < self.SEQUENCE_LENGTH:
                        # If still not enough, try 10-minute windows
                        time_groups = self._group_events_by_time_window(events, window_minutes=10)
                        window_size = 10
                        if len(time_groups) < self.SEQUENCE_LENGTH:
                            # If still not enough, try 5-minute windows
                            time_groups = self._group_events_by_time_window(events, window_minutes=5)
                            window_size = 5
                            if len(time_groups) < self.SEQUENCE_LENGTH:
                                # Last resort: split events into equal chunks to create windows
                                if len(events) >= self.SEQUENCE_LENGTH * 3:  # Need at least 3 events per window
                                    self.logger.debug(f"Using event-based windowing for {len(events)} events")
                                    chunk_size = len(events) // self.SEQUENCE_LENGTH
                                    time_groups = {}
                                    for i in range(self.SEQUENCE_LENGTH):
                                        start_idx = i * chunk_size
                                        end_idx = start_idx + chunk_size if i < self.SEQUENCE_LENGTH - 1 else len(events)
                                        chunk_events = events[start_idx:end_idx]
                                        if chunk_events:
                                            # Use the timestamp of the first event in the chunk as the window start
                                            first_ts = datetime.fromtimestamp(chunk_events[0].timestamp)
                                            time_groups[first_ts] = chunk_events
                                    window_size = 0  # Event-based
                                else:
                                    self.logger.debug(f"Insufficient events ({len(events)}) to create {self.SEQUENCE_LENGTH} windows")
                                    return {
                                        'ip': ip,
                                        'is_attack': False,
                                        'score': 0.0,
                                        'event_count': len(events),
                                        'event_types': {},
                                        'threshold': self.threshold,
                                        'predicted_class': 'BENIGN',
                                        'class_probs': {}
                                    }
                    
                    sorted_windows = sorted(time_groups.keys())
                    sequence_features = []
                    for window_start in sorted_windows[-self.SEQUENCE_LENGTH:]:
                        window_events = time_groups[window_start]
                        features = self.calculate_features(window_events, ip=ip)
                        sequence_features.append(features)
                    model_input = self.prepare_model_input(sequence_features)
                    if window_size > 0:
                        self.logger.debug(f"Using {window_size}-minute windows for rapid attack detection")
            
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
            score = self.predict(events, ip=ip)
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
