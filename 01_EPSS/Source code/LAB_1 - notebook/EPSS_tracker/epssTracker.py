# ===============================
#  EPSS Tracker for Selected CVEs
#  Fully corrected: saves files in script directory
# ===============================

import pandas as pd
import os
import matplotlib.pyplot as plt
from datetime import datetime
import requests
import gzip
from io import BytesIO

# -------------------------------
# 1. Script directory
# -------------------------------
script_dir = os.path.dirname(os.path.abspath(__file__))  # folder of this .py file
HISTORY_FILE = os.path.join(script_dir, 'epss_history.csv')
PLOT_FILE = os.path.join(script_dir, 'epss_plot.png')

# -------------------------------
# 2. Configuration
# -------------------------------
MY_CVES = ['CVE-2025-34185',
            'CVE-2025-52544',
            'CVE-2025-55243',
            'CVE-2025-57147',
            'CVE-2025-8422',
            'CVE-2025-37125',
            'CVE-2025-42944',
            'CVE-2025-41243',
            'CVE-2025-54914',
            'CVE-2025-20339',
           ]  # Your CVEs
EPSS_CSV_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'

# -------------------------------
# 3. Fetch EPSS scores
# -------------------------------
def fetch_epss():
    """
    Fetch the latest EPSS CSV (gzip) and return a DataFrame with 'cve' and 'epss'.
    """
    try:
        response = requests.get(EPSS_CSV_URL)
        response.raise_for_status()
        with gzip.open(BytesIO(response.content), 'rt') as f:
            df = pd.read_csv(f, header=1)  # header row is 1
        df = df[['cve', 'epss']]
        return df
    except Exception as e:
        print(f"Error fetching EPSS CSV: {e}")
        return pd.DataFrame(columns=['cve', 'epss'])

# -------------------------------
# 4. Filter for selected CVEs
# -------------------------------
def get_my_cves_epss():
    """Filter EPSS scores for selected CVEs and add today's date (normalized)."""
    epss_df = fetch_epss()
    filtered = epss_df[epss_df['cve'].isin(MY_CVES)].copy()
    filtered['Date'] = pd.Timestamp.today().normalize()  # one row per CVE per day
    return filtered

# -------------------------------
# 5. Update historical data
# -------------------------------
def update_history():
    """Append new EPSS scores to history CSV, avoiding duplicates."""
    new_data = get_my_cves_epss()
    
    if os.path.exists(HISTORY_FILE):
        df = pd.read_csv(HISTORY_FILE, parse_dates=['Date'])
        # Remove existing rows for the same CVE and Date
        df = df[~df.set_index(['cve', 'Date']).index.isin(new_data.set_index(['cve', 'Date']).index)]
        df = pd.concat([df, new_data], ignore_index=True)
    else:
        df = new_data

    df.to_csv(HISTORY_FILE, index=False)
    print(f"History CSV saved to: {HISTORY_FILE}")
    return df

# -------------------------------
# 6. Plot EPSS over time
# -------------------------------
def plot_epss(df):
    """Plot EPSS scores over time for each CVE and save to PNG."""
    plt.figure(figsize=(10, 6))
    for cve in df['cve'].unique():
        subset = df[df['cve'] == cve]
        plt.plot(subset['Date'], subset['epss'], marker='o', label=cve)
        plt.yscale('log')
    plt.title('EPSS Scores Over Time')
    plt.ylabel('EPSS Score')
    plt.xlabel('Date')
    plt.ylim(0,1)
    plt.xticks(rotation=45)
    plt.legend(title='CVE')
    plt.tight_layout()
    plt.savefig(PLOT_FILE)
    plt.close()
    print(f"Plot PNG saved to: {PLOT_FILE}")

# -------------------------------
# 7. Main execution
# -------------------------------
if __name__ == "__main__":
    df = update_history()
    plot_epss(df)
    print(f"EPSS tracking updated successfully at {datetime.now()}")
