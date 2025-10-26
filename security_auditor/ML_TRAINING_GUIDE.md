# Email Phishing Detection ML Training Guide

This guide will walk you through training a machine learning model for email phishing detection using your Kaggle dataset.

## Prerequisites

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Prepare Your Kaggle Dataset**
   - Download your email phishing dataset from Kaggle
   - Ensure it has at least two columns:
     - Text content (email body/subject)
     - Labels (0=legitimate, 1=phishing)

## Step-by-Step Training Process

### Step 1: Prepare Your Dataset

Your Kaggle CSV should have this structure:
```csv
text,label
"Urgent: Verify your account immediately",1
"Meeting reminder for tomorrow",0
"Congratulations! You've won $1000",1
"Project update from John",0
```

**Required Columns:**
- `text` (or similar): Email content
- `label` (or similar): 0 for legitimate, 1 for phishing

### Step 2: Train the Model

Run the training script with your dataset:

```bash
# Basic training
python train_email_model.py --data_path path/to/your/dataset.csv

# Advanced training with custom parameters
python train_email_model.py \
    --data_path path/to/your/dataset.csv \
    --text_column "email_content" \
    --label_column "is_phishing" \
    --model_type "random_forest" \
    --model_name "my_phishing_model"
```

**Available Model Types:**
- `random_forest` (default, good balance)
- `gradient_boosting` (often highest accuracy)
- `logistic_regression` (fast, interpretable)
- `svm` (good for high-dimensional data)

### Step 3: Verify Training Results

After training, you'll see:
- Model accuracy score
- Classification report (precision, recall, F1-score)
- Cross-validation scores
- Confusion matrix

### Step 4: Model Files Created

The training creates these files in `security_auditor/ml_engine/models/`:
- `email_phishing_detector.pkl` - Trained model
- `email_phishing_detector_scaler.pkl` - Feature scaler
- `email_phishing_detector_features.pkl` - Feature names

## Features Used for Training

The model extracts 20+ features from each email:

**Text Statistics:**
- Email length, word count, character count
- Uppercase ratio, digit ratio, special character ratio
- Punctuation counts (!, ?, $, %)

**Content Analysis:**
- Suspicious keywords (urgent, verify, suspended, etc.)
- URL count, email count, phone number count
- Suspicious domain detection
- Typo detection

**Phishing Indicators:**
- Urgency words, action words
- Financial terms, prize/lottery mentions
- Link patterns, domain analysis

## Using the Trained Model

Once trained, the email scanner automatically uses your ML model:

```python
from scanners.email_scanner import EmailScanner

# Initialize scanner (automatically loads ML model if available)
scanner = EmailScanner(use_ml=True)

# Scan emails
results = scanner.scan()
print(f"Scanned {results['emails_scanned']} emails")
print(f"Found {results['phishing_emails']} phishing emails")
```

## Model Performance Tips

1. **Dataset Size**: Use at least 1000+ emails for good performance
2. **Balanced Data**: Ensure roughly equal legitimate/phishing samples
3. **Quality Data**: Clean, well-labeled data works best
4. **Feature Engineering**: The trainer automatically extracts comprehensive features
5. **Model Selection**: Try different model types to find the best for your data

## Troubleshooting

**Common Issues:**

1. **"Model files not found"**
   - Ensure training completed successfully
   - Check `security_auditor/ml_engine/models/` directory

2. **"Could not find text and label columns"**
   - Verify your CSV has the correct column names
   - Use `--text_column` and `--label_column` parameters

3. **Low accuracy**
   - Check data quality and balance
   - Try different model types
   - Ensure sufficient training data

4. **Memory errors**
   - Reduce dataset size for initial testing
   - Use `logistic_regression` model (faster, less memory)

## Example Training Commands

```bash
# Quick test with small dataset
python train_email_model.py --data_path test_data.csv --model_type logistic_regression

# Full training with large dataset
python train_email_model.py --data_path full_dataset.csv --model_type gradient_boosting

# Custom column names
python train_email_model.py --data_path data.csv --text_column "email_body" --label_column "phishing_label"
```

## Model Evaluation

The training script provides:
- **Accuracy**: Overall correct predictions
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1-Score**: Harmonic mean of precision and recall
- **Cross-validation**: 5-fold CV to check model stability

A good model should achieve:
- Accuracy > 85%
- F1-Score > 0.8
- Balanced precision/recall

## Next Steps

After successful training:
1. Test the model with new emails
2. Monitor performance in production
3. Retrain periodically with new data
4. Consider ensemble methods for better accuracy
