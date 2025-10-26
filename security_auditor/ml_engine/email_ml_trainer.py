#!/usr/bin/env python3
"""
Email Phishing Detection ML Training Pipeline
Supports training on Kaggle email datasets for phishing detection
"""

import pandas as pd
import numpy as np
import re
import pickle
import os
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
from utils.logger import setup_logger

class EmailMLTrainer:
    def __init__(self, model_save_path="security_auditor/ml_engine/models/"):
        self.logger = setup_logger("EmailMLTrainer")
        self.model_save_path = model_save_path
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = []
        
        # Create models directory if it doesn't exist
        os.makedirs(model_save_path, exist_ok=True)
    
    def load_kaggle_data(self, csv_path, text_column='text', label_column='label'):
        """
        Load email data from Kaggle CSV file
        Expected columns: text (email content), label (0=legitimate, 1=phishing)
        """
        try:
            self.logger.info(f"Loading data from {csv_path}")
            df = pd.read_csv(csv_path)
            
            # Handle different possible column names
            text_col = None
            label_col = None
            
            for col in df.columns:
                if col.lower() in ['text', 'content', 'body', 'message', 'email']:
                    text_col = col
                elif col.lower() in ['label', 'target', 'phishing', 'is_phishing', 'class']:
                    label_col = col
            
            if text_col is None or label_col is None:
                raise ValueError(f"Could not find text and label columns. Available columns: {list(df.columns)}")
            
            self.logger.info(f"Using text column: {text_col}, label column: {label_col}")
            
            # Clean and prepare data
            df = df.dropna(subset=[text_col, label_col])
            df[text_col] = df[text_col].astype(str)
            
            return df[text_col], df[label_col]
            
        except Exception as e:
            self.logger.error(f"Error loading data: {str(e)}")
            raise
    
    def extract_features(self, emails):
        """
        Extract comprehensive features from email text
        """
        features = []
        
        for email in emails:
            email_lower = email.lower()
            
            # Text-based features
            text_features = {
                'length': len(email),
                'word_count': len(email.split()),
                'char_count': len(email.replace(' ', '')),
                'uppercase_ratio': sum(1 for c in email if c.isupper()) / max(len(email), 1),
                'digit_ratio': sum(1 for c in email if c.isdigit()) / max(len(email), 1),
                'special_char_ratio': sum(1 for c in email if not c.isalnum() and not c.isspace()) / max(len(email), 1),
                'exclamation_count': email.count('!'),
                'question_count': email.count('?'),
                'dollar_count': email.count('$'),
                'percent_count': email.count('%'),
                'has_urgent': int('urgent' in email_lower),
                'has_verify': int('verify' in email_lower),
                'has_suspended': int('suspended' in email_lower),
                'has_account': int('account' in email_lower),
                'has_password': int('password' in email_lower),
                'has_click': int('click' in email_lower),
                'has_link': int('http' in email_lower or 'www' in email_lower),
                'has_suspicious_domain': int(self._has_suspicious_domain(email)),
                'has_typos': int(self._has_typos(email_lower)),
                'suspicious_words': self._count_suspicious_words(email_lower),
                'url_count': len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email)),
                'email_count': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email)),
                'phone_count': len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', email)),
            }
            
            features.append(list(text_features.values()))
        
        self.feature_names = list(text_features.keys())
        return np.array(features)
    
    def _has_suspicious_domain(self, email):
        """Check for suspicious domain patterns"""
        suspicious_patterns = [
            r'bit\.ly', r'tinyurl', r'short\.link', r'goo\.gl',
            r'free', r'secure', r'update', r'verify'
        ]
        return any(re.search(pattern, email) for pattern in suspicious_patterns)
    
    def _has_typos(self, email):
        """Simple typo detection"""
        common_typos = ['recieve', 'seperate', 'occured', 'definately', 'accomodate']
        return any(typo in email for typo in common_typos)
    
    def _count_suspicious_words(self, email):
        """Count suspicious words commonly used in phishing"""
        suspicious_words = [
            'urgent', 'immediately', 'verify', 'confirm', 'suspended',
            'expired', 'limited time', 'act now', 'click here', 'free',
            'winner', 'congratulations', 'prize', 'lottery', 'inheritance'
        ]
        return sum(1 for word in suspicious_words if word in email)
    
    def train_model(self, X, y, model_type='random_forest'):
        """
        Train the selected ML model
        """
        self.logger.info(f"Training {model_type} model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Select model
        if model_type == 'random_forest':
            self.model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        elif model_type == 'gradient_boosting':
            self.model = GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=6)
        elif model_type == 'logistic_regression':
            self.model = LogisticRegression(random_state=42, max_iter=1000)
        elif model_type == 'svm':
            self.model = SVC(kernel='rbf', random_state=42, probability=True)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        self.logger.info(f"Model accuracy: {accuracy:.4f}")
        self.logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        self.logger.info(f"Cross-validation scores: {cv_scores}")
        self.logger.info(f"Mean CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        return accuracy, X_test_scaled, y_test, y_pred
    
    def save_model(self, model_name="email_phishing_model"):
        """Save the trained model and preprocessors"""
        model_path = os.path.join(self.model_save_path, f"{model_name}.pkl")
        scaler_path = os.path.join(self.model_save_path, f"{model_name}_scaler.pkl")
        features_path = os.path.join(self.model_save_path, f"{model_name}_features.pkl")
        
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.feature_names, features_path)
        
        self.logger.info(f"Model saved to {model_path}")
        self.logger.info(f"Scaler saved to {scaler_path}")
        self.logger.info(f"Features saved to {features_path}")
    
    def load_model(self, model_name="email_phishing_model"):
        """Load a pre-trained model"""
        model_path = os.path.join(self.model_save_path, f"{model_name}.pkl")
        scaler_path = os.path.join(self.model_save_path, f"{model_name}_scaler.pkl")
        features_path = os.path.join(self.model_save_path, f"{model_name}_features.pkl")
        
        if not all(os.path.exists(p) for p in [model_path, scaler_path, features_path]):
            raise FileNotFoundError("Model files not found. Please train a model first.")
        
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_names = joblib.load(features_path)
        
        self.logger.info(f"Model loaded from {model_path}")
    
    def predict_phishing(self, email_text):
        """Predict if an email is phishing"""
        if self.model is None:
            raise ValueError("Model not loaded. Please load or train a model first.")
        
        # Extract features
        features = self.extract_features([email_text])
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(max(probability)),
            'phishing_probability': float(probability[1]) if len(probability) > 1 else 0.0
        }

def main():
    """Example usage of the EmailMLTrainer"""
    trainer = EmailMLTrainer()
    
    # Example: Load data from Kaggle CSV
    # Replace with your actual Kaggle dataset path
    csv_path = "path/to/your/kaggle_email_dataset.csv"
    
    try:
        # Load data
        emails, labels = trainer.load_kaggle_data(csv_path)
        
        # Extract features
        X = trainer.extract_features(emails)
        y = labels.values
        
        # Train model
        accuracy, X_test, y_test, y_pred = trainer.train_model(X, y, model_type='random_forest')
        
        # Save model
        trainer.save_model("email_phishing_detector")
        
        print(f"Training completed! Model accuracy: {accuracy:.4f}")
        
    except Exception as e:
        print(f"Error during training: {str(e)}")

if __name__ == "__main__":
    main()
