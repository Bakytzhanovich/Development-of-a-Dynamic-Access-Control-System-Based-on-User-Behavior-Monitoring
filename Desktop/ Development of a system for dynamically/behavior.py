"""
Risk Engine - Behavioral Analysis Logic
Compares current user behavior against historical baseline
"""

from sqlalchemy.orm import Session
from models import BehavioralProfile, User
from datetime import datetime, timezone
import statistics


def calculate_typing_speed(keystrokes_data: list) -> float:
    """
    Calculate typing speed from keystroke data
    Returns characters per second
    """
    if not keystrokes_data or len(keystrokes_data) < 2:
        return 0.0
    
    # Calculate total time and character count
    first_key = keystrokes_data[0]
    last_key = keystrokes_data[-1]
    
    total_time_ms = last_key.get("timestamp", 0) - first_key.get("timestamp", 0)
    if total_time_ms <= 0:
        return 0.0
    
    total_time_seconds = total_time_ms / 1000.0
    char_count = len(keystrokes_data)
    
    if total_time_seconds == 0:
        return 0.0
    
    return char_count / total_time_seconds


def calculate_average_dwell_time(keystrokes_data: list) -> float:
    """Calculate average dwell time (time key is held)"""
    dwell_times = [k.get("dwell_time", 0) for k in keystrokes_data if k.get("dwell_time")]
    if not dwell_times:
        return 0.0
    return statistics.mean(dwell_times)


def calculate_average_flight_time(keystrokes_data: list) -> float:
    """Calculate average flight time (time between key presses)"""
    flight_times = [k.get("flight_time", 0) for k in keystrokes_data if k.get("flight_time")]
    if not flight_times:
        return 0.0
    return statistics.mean(flight_times)


def calculate_mouse_velocity(mouse_movements: list) -> float:
    """
    Calculate average mouse velocity (pixels per millisecond)
    """
    if not mouse_movements or len(mouse_movements) < 2:
        return 0.0
    
    velocities = []
    for i in range(1, len(mouse_movements)):
        prev = mouse_movements[i-1]
        curr = mouse_movements[i]
        
        dx = curr.get("x", 0) - prev.get("x", 0)
        dy = curr.get("y", 0) - prev.get("y", 0)
        dt = curr.get("timestamp", 0) - prev.get("timestamp", 0)
        
        if dt > 0:
            distance = (dx**2 + dy**2)**0.5
            velocity = distance / dt
            velocities.append(velocity)
    
    if not velocities:
        return 0.0
    
    return statistics.mean(velocities)


def detect_linear_mouse_movement(mouse_movements: list) -> bool:
    """
    Detect if mouse movement is too linear (suggesting bot behavior)
    Returns True if movement appears bot-like
    """
    if not mouse_movements or len(mouse_movements) < 3:
        print(f"[MOUSE DEBUG] Not enough movements: {len(mouse_movements) if mouse_movements else 0}")
        return False
    
    # Calculate angles between consecutive movements
    angles = []
    for i in range(2, len(mouse_movements)):
        p1 = mouse_movements[i-2]
        p2 = mouse_movements[i-1]
        p3 = mouse_movements[i]
        
        dx1 = p2.get("x", 0) - p1.get("x", 0)
        dy1 = p2.get("y", 0) - p1.get("y", 0)
        dx2 = p3.get("x", 0) - p2.get("x", 0)
        dy2 = p3.get("y", 0) - p2.get("y", 0)
        
        # Calculate angle between vectors
        if dx1 != 0 or dy1 != 0:
            angle1 = (dx1**2 + dy1**2)**0.5
            angle2 = (dx2**2 + dy2**2)**0.5
            if angle1 > 0 and angle2 > 0:
                dot_product = dx1 * dx2 + dy1 * dy2
                cos_angle = dot_product / (angle1 * angle2)
                angles.append(cos_angle)
    
    if not angles:
        print(f"[MOUSE DEBUG] No angles calculated from {len(mouse_movements)} movements")
        return False
    
    # If angles are too consistent (high correlation), might be a bot
    avg_angle_correlation = statistics.mean(angles)
    # Threshold: if correlation > 0.75, movement is suspiciously linear
    # (0.9 was too strict, normal fast straight lines were not detected)
    is_linear = avg_angle_correlation > 0.75
    
    print(f"[MOUSE DEBUG] Movements: {len(mouse_movements)}, Angles: {len(angles)}, Avg correlation: {avg_angle_correlation:.3f}, Linear: {is_linear}")
    
    return is_linear


def update_behavioral_profile(user_id: int, behavior_data: dict, db: Session):
    """Update user's behavioral profile with new data"""
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user_id).first()
    
    keystrokes = behavior_data.get("keystrokes", [])
    mouse_movements = behavior_data.get("mouse_movements", [])
    
    if not profile:
        # Create new profile
        profile = BehavioralProfile(
            user_id=user_id,
            avg_typing_speed=0.0,
            avg_dwell_time=0.0,
            avg_flight_time=0.0,
            avg_mouse_velocity=0.0,
            typing_samples=0,
            mouse_samples=0
        )
        db.add(profile)
    
    # Calculate current metrics
    typing_speed = calculate_typing_speed(keystrokes)
    dwell_time = calculate_average_dwell_time(keystrokes)
    flight_time = calculate_average_flight_time(keystrokes)
    mouse_velocity = calculate_mouse_velocity(mouse_movements)
    
    # Ensure profile values are not None (can happen if previously saved without defaults)
    profile.avg_typing_speed = profile.avg_typing_speed or 0.0
    profile.avg_dwell_time = profile.avg_dwell_time or 0.0
    profile.avg_flight_time = profile.avg_flight_time or 0.0
    profile.avg_mouse_velocity = profile.avg_mouse_velocity or 0.0
    profile.typing_samples = profile.typing_samples or 0
    profile.mouse_samples = profile.mouse_samples or 0
    
    # Update averages using exponential moving average
    alpha = 0.3  # Smoothing factor
    
    if profile.typing_samples > 0 and typing_speed > 0:
        profile.avg_typing_speed = (alpha * typing_speed) + ((1 - alpha) * profile.avg_typing_speed)
    elif typing_speed > 0:
        profile.avg_typing_speed = typing_speed
    
    if profile.typing_samples > 0 and dwell_time > 0:
        profile.avg_dwell_time = (alpha * dwell_time) + ((1 - alpha) * profile.avg_dwell_time)
    elif dwell_time > 0:
        profile.avg_dwell_time = dwell_time
    
    if profile.typing_samples > 0 and flight_time > 0:
        profile.avg_flight_time = (alpha * flight_time) + ((1 - alpha) * profile.avg_flight_time)
    elif flight_time > 0:
        profile.avg_flight_time = flight_time
    
    if profile.mouse_samples > 0 and mouse_velocity > 0:
        profile.avg_mouse_velocity = (alpha * mouse_velocity) + ((1 - alpha) * profile.avg_mouse_velocity)
    elif mouse_velocity > 0:
        profile.avg_mouse_velocity = mouse_velocity
    
    # Update sample counts
    if keystrokes:
        profile.typing_samples += len(keystrokes)
    if mouse_movements:
        profile.mouse_samples += len(mouse_movements)
    
    profile.last_updated = datetime.now(timezone.utc)
    db.commit()


def calculate_risk_score(
    incoming_data: dict,
    user_id: int,
    ip_address: str,
    db: Session
) -> dict:
    """
    Calculate risk score based on behavioral analysis
    
    Risk Scoring Algorithm:
    - Typing speed deviation >30%: +40 points
    - IP address different from last login: +30 points
    - Linear mouse movement (bot-like): +50 points
    - Total score >70: Access denied
    - Total score >50: Step-up authentication required
    """
    risk_score = 0
    reasons = []
    score_breakdown = {
        "Typing Anomaly": 0,
        "Mouse Anomaly": 0,
        "IP Change": 0,
        "Session Anomaly": 0
    }
    
    # Update profile with new data (creates if doesn't exist)
    update_behavioral_profile(user_id, incoming_data, db)
    
    # Get profile from database (after update, it should exist)
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.user_id == user_id).first()
    
    if not profile or (profile.typing_samples < 5 and profile.mouse_samples < 5):
        # Not enough behavioral history yet - keep the score low until we have
        # either keyboard or mouse baseline data.
        return {
            "risk_score": 10,
            "reasons": ["Insufficient behavioral data for analysis"],
            "requires_mfa": False,
            "score_breakdown": score_breakdown
        }
    
    # 1. Check typing speed deviation
    keystrokes = incoming_data.get("keystrokes", [])
    if keystrokes and len(keystrokes) >= 2:
        current_typing_speed = calculate_typing_speed(keystrokes)
        
        avg_typing_speed = profile.avg_typing_speed or 0.0
        if avg_typing_speed > 0:
            deviation = abs(current_typing_speed - avg_typing_speed) / avg_typing_speed
            
            if deviation > 0.30:  # >30% deviation
                risk_score += 55
                score_breakdown["Typing Anomaly"] += 55
                reasons.append(f"Typing speed deviation: {deviation*100:.1f}%")
    
    # 2. Check IP address
    if profile.last_ip_address and profile.last_ip_address != ip_address:
        risk_score += 30
        score_breakdown["IP Change"] += 30
        reasons.append(f"IP address changed from {profile.last_ip_address} to {ip_address}")
    
    # Update last IP address
    profile.last_ip_address = ip_address
    db.commit()
    
    # 3. Check mouse movement linearity
    mouse_movements = incoming_data.get("mouse_movements", [])
    if mouse_movements and len(mouse_movements) >= 3:
        is_linear = detect_linear_mouse_movement(mouse_movements)
        if is_linear:
            risk_score += 80
            score_breakdown["Mouse Anomaly"] += 80
            reasons.append("Mouse movement pattern suggests automated behavior")
        else:
            print(f"[RISK ANALYSIS] Mouse movements analyzed but not linear (normal human behavior)")
    else:
        print(f"[RISK ANALYSIS] Mouse movements too few to analyze: {len(mouse_movements) if mouse_movements else 0}")
            
    # 4. Check session context anomalies
    session_duration = incoming_data.get("session_duration", 0)
    if session_duration > 0 and keystrokes:
        keystrokes_per_sec = len(keystrokes) / session_duration
        if session_duration < 5 and len(keystrokes) > 50:
            # Huge burst of typing instantly after login
            risk_score += 40
            score_breakdown["Session Anomaly"] += 40
            reasons.append("Suspicious burst of activity immediately after login")
    
    return {
        "risk_score": min(risk_score, 100),  # Cap at 100
        "reasons": reasons if reasons else ["No anomalies detected"],
        "requires_mfa": risk_score > 50,
        "score_breakdown": score_breakdown
    }


def analyze_behavior_data(behavior_data: dict) -> dict:
    """Analyze raw behavior data and return metrics"""
    keystrokes = behavior_data.get("keystrokes", [])
    mouse_movements = behavior_data.get("mouse_movements", [])
    
    return {
        "typing_speed": calculate_typing_speed(keystrokes),
        "avg_dwell_time": calculate_average_dwell_time(keystrokes),
        "avg_flight_time": calculate_average_flight_time(keystrokes),
        "mouse_velocity": calculate_mouse_velocity(mouse_movements),
        "keystroke_count": len(keystrokes),
        "mouse_movement_count": len(mouse_movements)
    }
