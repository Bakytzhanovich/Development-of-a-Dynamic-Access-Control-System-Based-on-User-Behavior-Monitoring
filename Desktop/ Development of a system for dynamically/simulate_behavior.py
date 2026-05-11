import requests
import time
import random

# Configuration
BASE_URL = "http://localhost:8000"
USERNAME = "admin"
PASSWORD = "admin123"  # Using default from your setup, change if needed

def login():
    """Authenticate and get JWT token"""
    print(f"Logging in as {USERNAME}...")
    # Based on main.py, it takes JSON body for login
    response = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": USERNAME, "password": PASSWORD}
    )
    if response.status_code == 200:
        print("Login successful.")
        return response.json().get("access_token")
    else:
        print(f"Login failed: {response.text}")
        return None

def send_behavior(token, keystrokes, mouse_movements):
    """Send simulated behavior to the analysis endpoint"""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "keystrokes": keystrokes,
        "mouse_movements": mouse_movements
    }
    
    response = requests.post(
        f"{BASE_URL}/api/analyze-behavior",
        headers=headers,
        json=payload
    )
    
    print(f"Status Code: {response.status_code}")
    try:
        data = response.json()
        print(f"Risk Score: {data.get('risk_score')}")
        print(f"Message: {data.get('message')}")
        print(f"Risk Status: {data.get('status')}")
        if 'reasons' in data:
            print(f"Reasons: {data.get('reasons')}")
        if 'baseline_metrics' in data:
            print(f"Baseline: {data.get('baseline_metrics')}")
            print(f"Current: {data.get('current_metrics')}")
    except:
        print(response.text)
    print("-" * 40)

def simulate_normal_behavior(token):
    print("\n--- Scenario 1: Normal Behavior ---")
    print("Simulating normal typing speed and organic mouse movement...")
    
    # 20 keystrokes with ~100ms interval (10 chars/sec)
    keystrokes = []
    base_time = int(time.time() * 1000)
    for i in range(20):
        keystrokes.append({
            "key": chr(97 + i % 26),
            "timestamp": base_time + (i * 100),
            "dwellTime": 50,
            "flightTime": 50
        })
        
    # Organic mouse movement (curves)
    mouse_movements = []
    for i in range(10):
        mouse_movements.append({
            "x": 100 + i * 10 + random.randint(-5, 5),
            "y": 200 + i * 5 + random.randint(-5, 5),
            "timestamp": base_time + (i * 50)
        })
        
    send_behavior(token, keystrokes, mouse_movements)

def simulate_suspicious_behavior(token):
    print("\n--- Scenario 2: Suspicious Behavior (Imposter) ---")
    print("Simulating very slow typing (deviation from baseline)...")
    
    # 20 keystrokes with ~500ms interval (2 chars/sec) - way slower than normal
    keystrokes = []
    base_time = int(time.time() * 1000)
    for i in range(20):
        keystrokes.append({
            "key": chr(97 + i % 26),
            "timestamp": base_time + (i * 500), # 500ms between keys
            "dwellTime": 250,
            "flightTime": 250
        })
        
    send_behavior(token, keystrokes, [])

def simulate_high_risk_behavior(token):
    print("\n--- Scenario 3: High-Risk Behavior (Bot) ---")
    print("Simulating perfectly linear, robotic mouse movement...")
    
    # Perfectly linear mouse movements (no randomness)
    mouse_movements = []
    base_time = int(time.time() * 1000)
    for i in range(10):
        mouse_movements.append({
            "x": 100 + i * 20, # Perfect straight line X
            "y": 100 + i * 20, # Perfect straight line Y
            "timestamp": base_time + (i * 50)
        })
        
    send_behavior(token, [], mouse_movements)

if __name__ == "__main__":
    print("Starting Behavior Simulation Scenarios...")
    token = login()
    if token:
        # We run normal behavior a few times to build the "baseline" profile
        print("Building baseline profile...")
        for _ in range(5):
            simulate_normal_behavior(token)
            time.sleep(1)
            
        # Test scenarios
        simulate_suspicious_behavior(token)
        time.sleep(1)
        
        simulate_high_risk_behavior(token)
