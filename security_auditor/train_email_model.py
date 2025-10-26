#!/usr/bin/env python3
"""
Training script for email phishing detection model
Usage: python train_email_model.py --data_path path/to/kaggle_dataset.csv
"""

import argparse
import os
import sys
from ml_engine.email_ml_trainer import EmailMLTrainer

def main():
    parser = argparse.ArgumentParser(description='Train email phishing detection model')
    parser.add_argument('--data_path', required=True, help='Path to Kaggle CSV dataset')
    parser.add_argument('--text_column', default='text', help='Name of text column in CSV')
    parser.add_argument('--label_column', default='label', help='Name of label column in CSV')
    parser.add_argument('--model_type', default='random_forest', 
                       choices=['random_forest', 'gradient_boosting', 'logistic_regression', 'svm'],
                       help='Type of ML model to train')
    parser.add_argument('--model_name', default='email_phishing_detector', 
                       help='Name to save the model as')
    
    args = parser.parse_args()
    
    # Check if data file exists
    if not os.path.exists(args.data_path):
        print(f"Error: Data file not found at {args.data_path}")
        sys.exit(1)
    
    try:
        # Initialize trainer
        trainer = EmailMLTrainer()
        
        print("Loading data...")
        df, subject_col, label_col = trainer.load_kaggle_data(
            args.data_path, 
            subject_column=args.text_column, 
            label_column=args.label_column
        )
        
        print(f"Loaded {len(df)} rows")
        print(f"Phishing emails: {df[label_col].sum()}")
        print(f"Legitimate emails: {len(df) - df[label_col].sum()}")
        
        print(f"Feature columns: {[col for col in df.columns if col not in [subject_col, label_col]]}")
        
        print(f"Training {args.model_type} model...")
        accuracy, X_test, y_test, y_pred = trainer.train_model(df, label_col, model_type=args.model_type)
        
        print(f"Saving model as '{args.model_name}'...")
        trainer.save_model(args.model_name)
        
        print(f"\nTraining completed successfully!")
        print(f"Model accuracy: {accuracy:.4f}")
        print(f"Model saved to: security_auditor/ml_engine/models/")
        
    except Exception as e:
        print(f"Error during training: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
