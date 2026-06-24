import os
import random
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

import feature_extractor

def generate_balanced_dataset():
    """
    Generates a balanced dataset of legitimate and phishing URLs
    using template expansion and typical patterns.
    """
    print("Generating training dataset...")
    # Base legitimate domains
    legit_domains = [
        'google.com', 'wikipedia.org', 'github.com', 'microsoft.com', 'apple.com',
        'amazon.com', 'netflix.com', 'linkedin.com', 'twitter.com', 'facebook.com',
        'youtube.com', 'nytimes.com', 'cnn.com', 'bbc.co.uk', 'reddit.com',
        'stackoverflow.com', 'medium.com', 'spotify.com', 'dropbox.com', 'zoom.us',
        'adobe.com', 'salesforce.com', 'paypal.com', 'chase.com', 'bankofamerica.com',
        'wellsfargo.com', 'ebay.com', 'walmart.com', 'target.com', 'instagram.com'
    ]
    
    legit_paths = [
        '', 'index.html', 'about', 'contact', 'terms-and-conditions', 'search',
        'wiki/Main_Page', 'trending', 'en-us/windows', 'dp/B07PPDN1G1',
        'section/technology', 'r/all', 'questions/12345/how-to-train-model',
        'profile/user123', 'playlist/my-favorites', 'download/installer.msi',
        'help/faq', 'careers/jobs', 'products/all', 'blog/news/2026/06'
    ]
    
    legit_queries = [
        '', '?q=machine+learning', '?search=true&id=987', '?ref=homepage',
        '?lang=en', '?mode=dark', '?page=2&sort=recent', '?category=electronics'
    ]

    urls = []
    labels = []

    # 1. Generate Legitimate URLs (Safe: Label 0)
    for domain in legit_domains:
        # Increase variety per domain
        for _ in range(30):
            scheme = random.choice(['http://', 'https://', 'http://www.', 'https://www.'])
            path = random.choice(legit_paths)
            query = random.choice(legit_queries)
            url = f"{scheme}{domain}"
            if path:
                url += f"/{path}"
            if query:
                url += query
            urls.append(url)
            labels.append(0)

    # 2. Generate Phishing URLs (Phishing: Label 1)
    # Phishing target brands and spoof patterns
    phish_brands = [
        'paypal', 'paypal-security', 'chase-login', 'wellsfargo-verify', 
        'bankofamerica-update', 'apple-id-verify', 'netflix-billing', 
        'microsoft-outlook-login', 'google-account-verify', 'facebook-login-secure',
        'amazon-giftcard', 'blockchain-wallet', 'metamask-restore', 'binance-support',
        'steam-community-login', 'dropbox-share-file', 'zoom-meeting-join-link'
    ]
    
    phish_tlds = ['.net', '.org', '.xyz', '.cc', '.info', '.top', '.click', '.club', '.support', '.security-update.com']
    phish_keywords = ['login', 'signin', 'signin-webscr', 'secure', 'account', 'verify', 'update', 'billing', 'wallet', 'restore']
    
    # Pattern A: Spoofed domains
    for brand in phish_brands:
        for tld in phish_tlds:
            for kw in phish_keywords:
                scheme = random.choice(['http://', 'https://', 'http://www.', 'https://www.'])
                url = f"{scheme}{brand}-{kw}{tld}"
                urls.append(url)
                labels.append(1)
                
    # Pattern B: Long URLs with IP address or subdomains
    ips = ['192.168.1.102', '10.0.0.15', '172.16.254.1', '88.192.12.44', '103.22.45.98', '216.58.216.164']
    for ip in ips:
        for kw in phish_keywords:
            url = f"http://{ip}/{kw}/index.php?user=verification&id={random.randint(10000, 99999)}"
            urls.append(url)
            labels.append(1)

    # Pattern C: Redirections/Shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'rebrand.ly', 'is.gd', 't.co']
    for sh in shorteners:
        for _ in range(100):
            code = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=7))
            url = f"https://{sh}/{code}"
            urls.append(url)
            labels.append(1)

    # Pattern D: Credential harvesting with @ symbols
    for domain in legit_domains[:15]:
        for phish_domain in ['malicious-site.com', 'secure-server-login.net', 'verification-page.info']:
            url = f"https://{domain}@{phish_domain}/login.html"
            urls.append(url)
            labels.append(1)

    # Combine into DataFrame
    df = pd.DataFrame({'url': urls, 'label': labels})
    
    # Separate and balance
    df_safe = df[df['label'] == 0]
    df_phish = df[df['label'] == 1]
    
    print(f"Generated raw data: Safe = {len(df_safe)}, Phishing = {len(df_phish)}")
    
    n_samples = min(len(df_safe), len(df_phish))
    
    # We want a balanced dataset of at least 800 samples of each type if available
    df_balanced = pd.concat([
        df_safe.sample(n=n_samples, random_state=42),
        df_phish.sample(n=n_samples, random_state=42)
    ]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Balanced dataset: Total = {len(df_balanced)} ({n_samples} safe, {n_samples} phishing)")
    return df_balanced

def main():
    # 1. Generate URLs
    df = generate_balanced_dataset()
    
    # 2. Extract features
    print("Extracting features from URLs...")
    feature_list = []
    for idx, row in df.iterrows():
        feats = feature_extractor.get_features(row['url'])
        feature_list.append(feats)
        
    X = pd.DataFrame(feature_list)
    y = df['label']
    
    print(f"Features DataFrame shape: {X.shape}")
    print("Feature columns: ", list(X.columns))
    
    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train Model (Random Forest Classifier)
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    model.fit(X_train, y_train)
    
    # 5. Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Evaluation:")
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Feature Importances
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    print("Feature rankings:")
    for f in range(X.shape[1]):
        print(f"{f + 1}. feature {X.columns[indices[f]]} ({importances[indices[f]]:.4f})")
        
    # 6. Save model and metadata
    model_data = {
        'model': model,
        'feature_names': list(X.columns),
        'accuracy': accuracy
    }
    
    model_filename = 'phishing_model.joblib'
    print(f"\nSaving model to {model_filename}...")
    joblib.dump(model_data, model_filename)
    print("Model saved successfully!")

if __name__ == '__main__':
    main()
