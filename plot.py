import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.spatial import ConvexHull
import sys

print("Loading data...")

try:
    # טעינת הנתונים (הנחה: אין כותרות בקובץ שה-Rust מייצר כרגע)
    # העמודות הן: Kernel Time (nanoseconds), Sender TS (ticks), IP
    df = pd.read_csv('measurements.csv', names=['kernel_time', 'sender_ts', 'ip'], on_bad_lines='skip')
    
    # ניקוי המרות
    df['sender_ts'] = pd.to_numeric(df['sender_ts'], errors='coerce')
    df['kernel_time'] = pd.to_numeric(df['kernel_time'], errors='coerce')
    df = df.dropna()

    if len(df) < 10:
        print("Not enough data points! Run the sniffer longer.")
        sys.exit()

    # נרמול הצירים (כדי שהגרף יתחיל מ-0,0)
    # ציר X: השינוי בשעון השולח
    x = df['sender_ts'] - df['sender_ts'].iloc[0]
    # ציר Y: השינוי בשעון שלנו (בשניות)
    y = (df['kernel_time'] - df['kernel_time'].iloc[0]) / 1e9

    plt.figure(figsize=(12, 8))

    # 1. ציור הנקודות הכחולות (כל הפאקטות שנקלטו)
    plt.scatter(x, y, s=10, alpha=0.3, label='Raw Packets (Network Jitter)', color='blue')

    # 2. חישוב Convex Hull (הקו האדום - האמת הפיזיקלית)
    # אנחנו מחפשים את הגבול התחתון של הגרף
    points = np.column_stack((x, y))
    try:
        hull = ConvexHull(points)
        for simplex in hull.simplices:
            # מצייר קו אדום בין נקודות המעטפת
            plt.plot(points[simplex, 0], points[simplex, 1], 'r-', lw=2)
        print("Convex Hull calculated successfully.")
    except Exception as e:
        print(f"Could not calculate Convex Hull: {e}")

    plt.title(f'Physical Device Fingerprint\nTarget IP: {df["ip"].iloc[0]}')
    plt.xlabel('Sender Clock Ticks')
    plt.ylabel('Receiver Time (Seconds)')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # שמירה לקובץ תמונה
    output_file = 'fingerprint.png'
    plt.savefig(output_file)
    print(f"\nSUCCESS! Graph saved to: {output_file}")
    print("Go to your Windows Desktop folder 'Clock Skew/chronos_track' and open the image.")

except FileNotFoundError:
    print("Error: 'measurements.csv' not found. Did you run the sniffer?")
except Exception as e:
    print(f"An error occurred: {e}")
