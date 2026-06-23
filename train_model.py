import sqlite3
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

print("🔌 Connecting to SQL Database to extract live network logs...")

# 1. Fetch data directly from SQLite using SQL query
conn = sqlite3.connect("cyber_logs.db")
query = "SELECT * FROM network_logs"
df = pd.read_sql_query(query, conn)
conn.close()

print(f"📊 Extracted {df.shape[0]} rows successfully. Initializing Feature Split...")

# 2. Separate Features (X) and Target (y)
# Drop non-feature columns safely whether or not an 'id' exists in the table
drop_cols = [col for col in ['id', 'timestamp', 'is_attack'] if col in df.columns]
X = df.drop(columns=drop_cols)
y = df['is_attack']

# 3. The Great Wall: Split into Train and Test sets instantly to prevent Data Leakage
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 4. Group features by type for the ColumnTransformer
numeric_features = ['packet_size_bytes', 'login_attempts']
categorical_features = ['protocol_type']

# 5. Build Sub-Pipelines for Data Cleaning
numeric_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='median')), # Fills missing gaps safely
    ('scaler', StandardScaler())                  # Normalizes scale
])

categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='most_frequent')),
    ('encoder', OneHotEncoder(handle_unknown='ignore')) # Safely bypasses new unseen words in future
])

# 6. Bind them into the Master Preprocessor Engine
preprocessor = ColumnTransformer(transformers=[
    ('num_pipeline', numeric_transformer, numeric_features),
    ('cat_pipeline', categorical_transformer, categorical_features)
])

# 7. Assemble the Final Production Pipeline with the Classifier Brain
full_security_pipeline = Pipeline(steps=[
    ('data_cleaning_engine', preprocessor),
    ('hacker_detector_model', RandomForestClassifier(random_state=42, n_estimators=100))
])

# 🏋️‍♂️ TRAIN THE PIPELINE WITH A SINGLE LINE
print("🏋️‍♂️ Training the automated network security engine...")
full_security_pipeline.fit(X_train, y_train)

# 🔮 EVALUATE THE MODEL USING RECALL SCORE
print("\n🎯 Model Training Complete! Evaluating performance on pure test data...")
y_pred = full_security_pipeline.predict(X_test)

# Print the professional verification report
print("\n" + "="*50)
print("             TECHNICAL CLASSIFICATION REPORT")
print("="*50)
print(classification_report(y_test, y_pred, target_names=['Safe Traffic (0)', 'Hacker Attack (1)']))
print("="*50)

# 💾 SAVE THE MODEL ARTIFACT (Serialization)
# This saves BOTH the preprocessing logic and the trained weights into one file
model_filename = "security_pipeline_model.pkl"
joblib.dump(full_security_pipeline, model_filename)
print(f"\n💾 Success! Saved the production-ready model brain as: '{model_filename}'")