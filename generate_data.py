import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

print("🚀 Initializing Cyber Security Data Generator Engine...")

# 1. Connect to SQLite Database (It will automatically create the file)
conn = sqlite3.connect("cyber_logs.db")
cursor = conn.cursor()

# 2. Create the SQL Table Schema
cursor.execute("""
    CREATE TABLE IF NOT EXISTS network_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        protocol_type TEXT,
        packet_size_bytes INTEGER,
        login_attempts INTEGER,
        is_attack INTEGER
    )
""")
conn.commit()

# 3. Generate Mock Data Arrays using NumPy
np.random.seed(42)
total_rows = 1500

# Base timestamps
start_time = datetime.now()
timestamps = [(start_time - timedelta(minutes=int(i))).strftime('%Y-%m-%d %H:%M:%S') for i in range(total_rows)]

# Generate Normal Traffic (Class 0) -> ~85% of data
protocols = np.random.choice(['HTTP', 'TCP', 'UDP'], size=total_rows, p=[0.6, 0.3, 0.1])
packet_sizes = np.random.normal(loc=500, scale=150, size=total_rows).astype(int) # Small packets
logins = np.random.choice([0, 1], size=total_rows, p=[0.9, 0.1]) # Mostly 0 or 1 attempt
is_attack = np.zeros(total_rows, dtype=int)

# 4. Inject Malicious Attack Signatures (Class 1) -> ~15% of data
# Let's turn 200 random rows into highly suspicious hacker attacks
attack_indices = np.random.choice(total_rows, size=200, replace=False)
for idx in attack_indices:
    is_attack[idx] = 1
    protocols[idx] = np.random.choice(['TCP', 'HTTP']) # Common attack surfaces
    # Randomly make it either a DDoS attack (huge packet) OR a Brute Force attack (many login attempts)
    if np.random.rand() > 0.5:
        packet_sizes[idx] = np.random.randint(8000, 15000) # Massively oversized packets (DDoS)
        logins[idx] = np.random.randint(0, 2)
    else:
        packet_sizes[idx] = np.random.randint(100, 400)
        logins[idx] = np.random.randint(5, 12) # Excessive failed login attempts (Brute Force)

# 5. Pack everything into a DataFrame and write directly to SQL
df = pd.DataFrame({
    'timestamp': timestamps,
    'protocol_type': protocols,
    'packet_size_bytes': packet_sizes,
    'login_attempts': logins,
    'is_attack': is_attack
})

# Make sure no packet sizes went negative during random generation
df['packet_size_bytes'] = df['packet_size_bytes'].clip(lower=64)

# Load the data straight into your SQL table disk space
df.to_sql("network_logs", conn, if_exists="replace", index=False)
conn.close()

print("✅ Success! Database 'cyber_logs.db' generated with 1,500 records.")
print("📊 Data profile saved securely into SQL table: 'network_logs'.")