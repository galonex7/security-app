# security-app

🛡️ SHIELD-26: Next-Gen Threat Detection Command Center
SHIELD-26 is a local, AI-augmented cybersecurity tool designed to bridge the gaps found in traditional SIEM (Security Information and Event Management) systems. It focuses on Identity Context, Shadow AI Detection, and Living-off-the-Land (LotL) Analysis.
SHIELD-26 doesn't just find 'bad files.' It finds bad intent. By prioritizing our alerts based on the seniority of the user and the weirdness of the behavior, we spend 80% less time looking at 'false positives' and 100% more time stopping actual breaches before they happen.
🚀 Key Features
Smart Risk Scoring: Prioritizes threats using a $Risk = Likelihood \times Impact$ formula.
Impossible Travel Detection: Flags logins that are geographically impossible within a specific timeframe.
Shadow AI Monitoring: Tracks and alerts on large data transfers to unauthorized AI domains.
SIEM Override: Automatically escalates "Low" severity events involving sensitive system processes like PowerShell.
Interactive Dashboard: Visualizes risk distribution and network traffic with real-time "Isolate User" simulation.

🛠️ Installation & Setup (Local)
1. PrerequisitesEnsure you have Python 3.x installed. During installation, make sure to check the box "Add Python to PATH".
2. Install DependenciesOpen your terminal or command prompt and run: pip install streamlit pandas plotly
3. Run the ApplicationNavigate to the project folder and execute: streamlit run app.py
The app will automatically launch in your default web browser at http://localhost:8501.

📊 How to Use
Ingest Data: Use the sidebar to upload a .csv file containing your security logs.
Review the Feed: The Prioritized Threat Feed automatically sorts the most dangerous events to the top based on their "Smart Score.
"Investigate: Click on an alert to see the "Detection Reasons" and metadata.Take Action: Use the action buttons to simulate account suspension or session revocation.

📁 Required CSV FormatTo ensure the "Smart Engine" works perfectly, your uploaded CSV should contain the following headers:Time: Timestamp of the event.User: Username or Email.Location: Source of the activity.Event: Type of action (Login, Upload, Exec).Data_MB: Size of data transferred (in Megabytes).Destination: Where the data was sent.Process: The system process or binary used.Severity: The original SIEM-assigned severity.

⚖️ Technical Methodology
The engine calculates risk by aggregating points for anomalies:
Unusual Location: +40 pts
Unauthorized AI Transfer: +35 pts
Sensitive Binary (PowerShell/CMD): +20 pts
VIP/Admin Account: +25 pts
