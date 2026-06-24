import os
import pandas as pd
from flask import Flask, request, jsonify, render_template
import joblib

import feature_extractor

app = Flask(__name__)

# Global model variables
model_data = None
model = None
feature_names = []

def load_model():
    global model_data, model, feature_names
    model_path = 'phishing_model.joblib'
    if os.path.exists(model_path):
        try:
            model_data = joblib.load(model_path)
            model = model_data['model']
            feature_names = model_data['feature_names']
            print(f"Loaded trained model (Accuracy: {model_data.get('accuracy', 0.0):.4f})")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    else:
        print("Model file 'phishing_model.joblib' not found. Please run 'train_model.py' to train and save the model.")
        return False

# Load model at startup
load_model()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    global model, feature_names
    # Reload model if not loaded yet
    if model is None:
        if not load_model():
            return jsonify({'error': 'Model not trained yet. Please run the training script first.'}), 500

    data = request.get_json() or {}
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Extract features
    features = feature_extractor.get_features(url)
    
    # Prepare input for prediction
    input_df = pd.DataFrame([features])[feature_names]
    
    # Predict probabilities
    try:
        proba = model.predict_proba(input_df)[0]
        risk_score = round(proba[1] * 100, 1)
        prediction = int(model.predict(input_df)[0])
    except Exception as e:
        return jsonify({'error': f'Prediction error: {str(e)}'}), 500
        
    # Get feature analysis explanations
    analysis = feature_extractor.explain_features(url, features)
    
    return jsonify({
        'url': url,
        'prediction': prediction,
        'risk_score': risk_score,
        'features': features,
        'analysis': analysis
    })

@app.route('/api/evaluate_features', methods=['POST'])
def evaluate_features():
    global model, feature_names
    if model is None:
        if not load_model():
            return jsonify({'error': 'Model not trained yet. Please run the training script first.'}), 500

    data = request.get_json() or {}
    
    # Ensure all required features are present
    missing_features = [f for f in feature_names if f not in data]
    if missing_features:
        return jsonify({'error': f"Missing features: {', '.join(missing_features)}"}), 400
        
    try:
        # Construct DataFrame matching the trained feature columns
        input_df = pd.DataFrame([data])[feature_names]
        proba = model.predict_proba(input_df)[0]
        risk_score = round(proba[1] * 100, 1)
        prediction = int(model.predict(input_df)[0])
    except Exception as e:
        return jsonify({'error': f'Evaluation error: {str(e)}'}), 500
        
    return jsonify({
        'prediction': prediction,
        'risk_score': risk_score
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
