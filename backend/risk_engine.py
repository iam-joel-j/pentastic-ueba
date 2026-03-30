KNOWN_IPS = ["192.168.1.1", "192.168.1.5", "192.168.1.23", "10.0.0.1"]
REGISTERED_DEVICES = ["Office Laptop", "registered_device", "MacBook Pro", "College Laptop"]
SENSITIVE_FOLDERS = [
    "Sensitive_Files", "sensitive_folder", "HR_Files", "Finance",
    "Exam_Papers", "Faculty_Records", "Student_Results"
]
HONEYFILES = [
    "CS_Final_2026.pdf", "Answer_Key.pdf", "Salary_Slip.xlsx",
    "Performance.docx", "Results_2026.xlsx", "Decoy_Files",
    "Salary_2026.xlsx", "honeyfile"
]

def calculate_risk(login_time, ip_address, device, folder, failed_attempts=0):
    risk = 0
    reasons = []

    # ── Time check ──────────────────────────────────────────────
    try:
        hour = int(str(login_time).split(":")[0])
        # Working hours: 8AM - 3PM (15:00)
        # >= 15 means 3PM and beyond is off-hours
        if hour < 8 or hour >= 15:
            risk += 30
            reasons.append("Off-hours login")
    except:
        risk += 10
        reasons.append("Invalid login time")

    # ── IP check ────────────────────────────────────────────────
    if ip_address not in KNOWN_IPS:
        risk += 25
        reasons.append("Unknown IP address")

    # ── Device check ────────────────────────────────────────────
    if device not in REGISTERED_DEVICES:
        risk += 20
        reasons.append("Unregistered device")

    # ── Brute force check ───────────────────────────────────────
    if failed_attempts >= 3:
        risk += 20
        reasons.append(f"Brute force ({failed_attempts} failed attempts)")

    # ── File/folder check ───────────────────────────────────────
    # Smart logic: honeyfile alone = max 50 (SUSPICIOUS)
    # Honeyfile + other flags = 70+ (DECEPTION)
    if folder in HONEYFILES:
        risk += 50
        reasons.append("Honeyfile accessed")
    elif folder in SENSITIVE_FOLDERS:
        risk += 25
        reasons.append("Sensitive folder access")

    # ── Status assignment ───────────────────────────────────────
    if risk >= 70:
        status = "DECEPTION"
    elif risk >= 40:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return min(risk, 100), status, ", ".join(reasons) if reasons else "Normal activity"