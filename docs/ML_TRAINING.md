# ML Model Training Guide

## Overview

The honeypot uses Isolation Forest for behavioral anomaly detection.

## How It Works

The ML model analyzes session features:
- Request frequency (requests/minute)
- Payload length average and std deviation
- Unique paths accessed
- Error rate (4xx/5xx responses)
- Suspicious signature rate

## Training the Model

### Manual Training

```bash
docker-compose exec backend python manage.py train_ml_model
```

### Automatic Retraining

The model retrains every 24 hours (configurable via ML_TRAINING_INTERVAL).

## Feature Extraction

Features are collected in `MLTrainingData` model:
- `request_frequency`: Requests per minute
- `payload_length_avg`: Average payload size
- `payload_length_std`: Size standard deviation
- `unique_paths`: Distinct paths accessed
- `error_rate`: Proportion of error responses
- `suspicious_rate`: Attacks detected rate

## Model Evaluation

```bash
# Check model performance
docker-compose exec backend python manage.py shell
>>> from core.siem.ml_anomaly import get_ml_score
>>> get_ml_score('session-id')
{'is_anomaly': True, 'anomaly_score': 85.2}
```

## Hyperparameters

Edit `settings.py` for tuning:
```python
HONEYPOT_CONFIG = {
    'MLcontamination': 0.1,  # Expected anomaly rate
    'MLn_estimators': 100,
    'MLmax_samples': 256,
}
```

## Retraining Schedule

Configure in `.env`:
```bash
ML_TRAINING_INTERVAL=86400  # 24 hours in seconds
```

## Improving Accuracy

1. Collect more attack data
2. Label ground truth in `MLTrainingData.is_malicious`
3. Retrain with labeled data
4. Adjust contamination rate