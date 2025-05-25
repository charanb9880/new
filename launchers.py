import subprocess
import webbrowser
import time
import os

# Start the Flask backend server
flask_process = subprocess.Popen(["python", "app.py"])

# Wait a bit to ensure server starts
time.sleep(2)

# Open the HTML frontend
html_file = os.path.abspath("echo_shield_modern_full.html")
webbrowser.open(f"file://{html_file}")
