"""
ML Anomaly Detection Module
============================
Behavioral anomaly detection using Isolation Forest.
"""

import os
import logging
import pickle
import numpy as np
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("honeypot.ml")


class MLAnomalyDetector:
    def __init__(self, contamination=0.05, model_path="ml_models/anomaly_detector.pkl"):
        self.model_path = model_path
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self._load_model()
        if not self.is_trained:
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
                max_samples="auto",
                n_jobs=-1,
            )

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.model = data["model"]
                    self.scaler = data["scaler"]
                    self.is_trained = True
                logger.info(f"ML model loaded from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")

    def train(self, feature_list):
        if not feature_list:
            return False

        try:
            X = np.array(feature_list)
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)

            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
                max_samples="auto",
                n_jobs=-1,
            )
            self.model.fit(X_scaled)
            self.is_trained = True

            # Save model
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, "wb") as f:
                pickle.dump({"model": self.model, "scaler": self.scaler}, f)

            logger.info(f"ML model trained and saved to {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"ML training failed: {e}")
            return False

    def extract_features(self, session_id):
        from core.models import AttackerSession, AttackEvent

        try:
            session = AttackerSession.objects.get(id=session_id)
        except AttackerSession.DoesNotExist:
            return None

        cutoff_time = timezone.now() - timedelta(minutes=10)
        events = AttackEvent.objects.filter(session=session, timestamp__gte=cutoff_time)

        if events.count() == 0:
            return np.array([0.0] * 6)

        event_count = events.count()
        request_frequency = event_count / 10.0

        payload_lengths = [len(e.body) for e in events if e.body]
        payload_length_avg = np.mean(payload_lengths) if payload_lengths else 0.0
        payload_length_std = np.std(payload_lengths) if payload_lengths else 0.0

        unique_paths = len(set(e.path for e in events))
        error_responses = events.filter(response_status__gte=400).count()
        error_rate = error_responses / event_count if event_count > 0 else 0.0
        suspicious_count = events.exclude(attack_type="none").count()
        suspicious_rate = suspicious_count / event_count if event_count > 0 else 0.0

        return np.array(
            [
                request_frequency,
                payload_length_avg,
                payload_length_std,
                unique_paths,
                error_rate,
                suspicious_rate,
            ]
        )

    def predict_anomaly_score(self, session_id):
        features = self.extract_features(session_id)
        if features is None:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "status": "insufficient_data",
            }

        cache_key = f"ml_anomaly:{session_id}"
        try:
            cached = cache.get(cache_key)
            if cached:
                return cached
        except Exception as e:
            logger.warning(f"Cache get failed for {cache_key}: {e}")

        try:
            if not self.is_trained:
                anomaly_score = self._fallback_scoring(features)
                is_anomaly = anomaly_score > 70
                confidence = 0.6
            else:
                features_scaled = self.scaler.transform(features.reshape(1, -1))
                prediction = self.model.predict(features_scaled)[0]
                decision_score = self.model.decision_function(features_scaled)[0]
                anomaly_score = max(0, min(100, (0.5 - decision_score) * 100))
                is_anomaly = prediction == -1
                confidence = 0.85

            result = {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(anomaly_score, 2),
                "confidence": confidence,
                "features": {
                    "request_frequency": round(features[0], 2),
                    "payload_length_avg": round(features[1], 2),
                    "payload_length_std": round(features[2], 2),
                    "unique_paths": int(features[3]),
                    "error_rate": round(features[4], 3),
                    "suspicious_rate": round(features[5], 3),
                },
                "status": "success",
            }
            try:
                cache.set(cache_key, result, 60)
            except Exception as e:
                logger.warning(f"Cache set failed for {cache_key}: {e}")
            return result
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return {"is_anomaly": False, "anomaly_score": 0.0, "status": "error"}

    def _fallback_scoring(self, features):
        (
            request_freq,
            payload_avg,
            payload_std,
            unique_paths,
            error_rate,
            suspicious_rate,
        ) = features
        score = 0.0
        if request_freq > 20:
            score += 30
        elif request_freq > 10:
            score += 15
        if payload_std > 500:
            score += 20
        elif payload_std > 200:
            score += 10
        if unique_paths > 15:
            score += 25
        elif unique_paths > 8:
            score += 12
        if error_rate > 0.5:
            score += 15
        elif error_rate > 0.3:
            score += 8
        if suspicious_rate > 0.5:
            score += 30
        elif suspicious_rate > 0.2:
            score += 15
        return min(100, score)


ml_detector = MLAnomalyDetector()


def get_ml_score(session_id):
    return ml_detector.predict_anomaly_score(session_id)
