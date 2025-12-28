import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.spatial import ConvexHull
import sys
import datetime
import os

print("Loading data...")

try:
    # טעינת הנתונים
    df = pd.read_csv('measurements.csv', names=['kernel_time', 'sender_ts', 'ip'], on_bad_lines='skip')
    
    # ניקוי המרות
    df['sender_ts'] = pd.to_numeric(df['sender_ts'], errors='coerce')
    df['kernel_time'] = pd.to_numeric(df['kernel_time'], errors='coerce')
    df = df.dropna()

    if len(df) < 10:
        print("Not enough data points! Run the sniffer longer.")
        sys.exit()

    # שליפת ה-IP לצורך שם הקובץ והכותרת
    target_ip = df['ip'].iloc[0]

    # נרמול הצירים
    x = df['sender_ts'] - df['sender_ts'].iloc[0]
    y = (df['kernel_time'] - df['kernel_time'].iloc[0]) / 1e9

    plt.figure(figsize=(12, 8))

    # 1. ציור הנקודות
    plt.scatter(x, y, s=10, alpha=0.3, label='Raw Packets (Network Jitter)', color='blue')

    # 2. חישוב Convex Hull
    points = np.column_stack((x, y))
    try:
        hull = ConvexHull(points)
        for simplex in hull.simplices:
            plt.plot(points[simplex, 0], points[simplex, 1], 'r-', lw=2)
        print("Convex Hull calculated successfully.")
    except Exception as e:
        print(f"Could not calculate Convex Hull: {e}")

    plt.title(f'Physical Device Fingerprint\nTarget IP: {target_ip}')
    plt.xlabel('Sender Clock Ticks')
    plt.ylabel('Receiver Time (Seconds)')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # --- החלק החדש: יצירת שם קובץ דינמי ---
    # פורמט זמן: YYYYMMDD_HHMMSS (למשל: 20251214_153000)
    current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # יצירת תיקיית פלט אם לא קיימת
    output_dir = "graphs"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Example output: graphs/fingerprint_203.0.113.42_20251214_153000.png
    output_file = f'{output_dir}/fingerprint_{target_ip}_{current_time}.png'
    
    plt.savefig(output_file)
    print(f"\nSUCCESS! Graph saved to: {output_file}")
    print(f"Go to your Windows folder 'Clock Skew/chronos_track/{output_dir}' to see it.")

except FileNotFoundError:
    print("Error: 'measurements.csv' not found. Did you run the sniffer?")
except Exception as e:
    print(f"An error occurred: {e}")