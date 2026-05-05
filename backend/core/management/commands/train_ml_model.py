"""
Management Command: Train ML Model
===================================
Usage: python manage.py train_ml_model
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import AttackerSession
from core.siem.ml_anomaly import ml_detector
import numpy as np

class Command(BaseCommand):
    help = 'Train ML anomaly detection model from historical data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--min-sessions',
            type=int,
            default=100,
            help='Minimum number of sessions needed for training (default: 100)'
        )

    def handle(self, *args, **options):
        min_sessions = options['min_sessions']
        
        self.stdout.write("=" * 60)
        self.stdout.write(self.style.WARNING("ML Model Training"))
        self.stdout.write("=" * 60)
        
        # Get "normal" sessions for training baseline
        normal_sessions = AttackerSession.objects.filter(
            threat_score__lt=30,
            is_blocked=False,
            total_requests__gte=5,
            total_requests__lte=100
        ).order_by('-first_seen')[:1000]
        
        session_count = normal_sessions.count()
        self.stdout.write(f"\nFound {session_count} normal sessions for training")
        
        if session_count < min_sessions:
            self.stdout.write(
                self.style.ERROR(
                    f"\n✗ Insufficient training data ({session_count} < {min_sessions})"
                )
            )
            self.stdout.write("\nTo generate training data:")
            self.stdout.write("1. Run: python manage.py seed_real_users")
            self.stdout.write("2. Generate normal traffic (login as Alice/Bob)")
            self.stdout.write("3. Wait for 100+ sessions")
            return
        
        # Extract features
        self.stdout.write("\nExtracting features...")
        training_data = []
        valid_count = 0
        
        for session in normal_sessions:
            features = ml_detector.extract_features(str(session.id))
            if features is not None and not np.isnan(features).any():
                training_data.append(features)
                valid_count += 1
                if valid_count % 20 == 0:
                    self.stdout.write(f"  Processed {valid_count} sessions...")
        
        self.stdout.write(f"\n✓ Extracted {len(training_data)} valid feature vectors")
        
        if len(training_data) < min_sessions:
            self.stdout.write(
                self.style.ERROR(
                    f"\n✗ Not enough valid features ({len(training_data)} < {min_sessions})"
                )
            )
            return
        
        # Train model
        self.stdout.write("\nTraining Isolation Forest model...")
        success = ml_detector.train(training_data)
        
        if success:
            self.stdout.write(
                self.style.SUCCESS(
                    f"\n✓ ML model trained successfully on {len(training_data)} samples"
                )
            )
            self.stdout.write(f"Model saved to: {ml_detector.model_path}")
            self.stdout.write(f"Contamination: {ml_detector.contamination}")
            self.stdout.write(f"Is Trained: {ml_detector.is_trained}")
            
            # Test prediction
            self.stdout.write("\nTesting model...")
            test_session = normal_sessions.first()
            result = ml_detector.predict_anomaly_score(str(test_session.id))
            self.stdout.write(f"Test Prediction: {result['anomaly_score']} (Anomaly: {result['is_anomaly']})")
            
        else:
            self.stdout.write(self.style.ERROR("\n✗ ML training failed"))
