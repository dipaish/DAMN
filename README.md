# DAMN VULNERABLE WEB APPLICATION 

The Damn Vulnerable Web Application (DVWA) is designed to help students practice and understand some of the most common web vulnerabilities, including SQL Injection, brute force attacks, Cross-Site Scripting (XSS), and more. It provides a controlled environment for students to learn how these attacks work and explore techniques for securing applications against them.

***Warning: DVWA is intentionally insecure! Do not upload or deploy it on any publicly accessible server or web hosting service. If exposed to the internet, it will almost certainly be compromised***

# Setting Up DVWA with Docker

You can set up DVWA (Damn Vulnerable Web Application) by forking this repository to your GitHub account and then cloning it to your local environment. This repository includes a custom `php.ini` file to ensure that all necessary PHP configurations are met for the DVWA environment.

## Prerequisites

- Ensure you have **Docker** installed and running on your device.

## Installation Steps

1. **Fork the Repository**
   - First, go to the DVWA repository on GitHub and fork it to your own GitHub account.

2. **Clone Your Forked Repository**
   - Clone the forked repository to your local device:
     ```bash
     git clone https://github.com/yourusername/dvwa.git
     ```
   - Replace `yourusername` with your GitHub username.

3. **Open the Project Directory**

4. **Start the DVWA Container**
   - Run the following command to start DVWA:
     ```bash
     docker-compose up -d
     ```
   - This will launch the DVWA container with the required environment, including the `php.ini` configuration file included in the repository to meet DVWA’s setup requirements.

5. **Access DVWA in Your Browser**
   - Open your browser and go to `http://localhost:89`.
   - Log in with the following credentials:
     - **Username**: `admin`
     - **Password**: `password`

### Notes

- **PHP Configuration**: The repository includes a custom `php.ini` file that configures essential PHP settings for DVWA. This file ensures compatibility with DVWA requirements.
- **Port Configuration**: If `localhost:89` is already in use, you can update the port in the `docker-compose.yml` file.
- **Security Warning**: DVWA is intentionally vulnerable. **Do not deploy this on any publicly accessible server**.




## Practical Tasks 

### SQL Injection Exercise

This exercise will help you understand how SQL Injection works and explore methods to prevent it.

1. **Access DVWA**:
   - Open your browser and navigate to `http://localhost:89`.

2. **Log In to DVWA**:
   - Use the credentials: **Username**: `admin`, **Password**: `password`.

3. **Set Security Level**:
   - Go to the **DVWA Security** tab and set the security level to **Low**.

4. **Select the SQL Injection Module**:
   - In the left sidebar, select **SQL Injection** from the list of modules.

5. **Perform a Basic SQL Injection**:
   - You will see a field where you can enter a **User ID** to retrieve information from the database.
   - Normally, entering `1` and clicking **Submit** returns information associated with User ID 1.

6. **Inject SQL Payload**:
   - Now, let’s attempt a simple SQL Injection. Instead of entering `1`, try entering:
     ```
     1' OR '1'='1
     ```
   - Click **Submit**.

7. **Analyze the Response**:
   - If the application is vulnerable, you should see multiple rows of user information returned, not just the data for User ID 1.
   - **Explanation**: The SQL query in the backend interprets `1' OR '1'='1` as always being true, causing it to retrieve all records from the database.

#### How to Prevent SQL Injection

After observing this vulnerability, consider how SQL Injection could be mitigated:

- **Prepared Statements**: Use parameterized queries instead of directly concatenating user inputs into SQL commands. This ensures user inputs are treated as data, not executable code.
  
- **Input Validation**: Only allow specific, expected formats (e.g., ensure only integers are allowed for IDs) to prevent malicious input from altering SQL queries.

- **Escaping Special Characters**: Escape special characters like quotes to prevent user inputs from being interpreted as part of the SQL command.

This exercise demonstrates the importance of secure coding practices to protect applications from SQL Injection attacks.


### Brute Force Exercise

This exercise demonstrates how brute force attacks attempt to guess passwords by systematically trying different combinations.

1. **Access DVWA**:
   - Open your browser and navigate to `http://localhost:89`.

2. **Log In to DVWA**:
   - Use the credentials: **Username**: `admin`, **Password**: `password`.

3. **Set Security Level**:
   - Go to the **DVWA Security** tab and set the security level to **Low**.

4. **Select the Brute Force Module**:
   - In the left sidebar, select **Brute Force** from the list of modules.

5. **Prepare a Password List**:
   - Create a file named `passwords.txt` with a few sample passwords:
     ```plaintext
     password
     admin
     123456
     password123
     letmein
     ```

6. **Use Hydra to Perform the Attack**:

Note we need to install hydra 

in Ubuntu/debian run the following command 
sudo apt update
sudo apt install hydra -y

You can also do it in WSL ubuntu 

sudo apt update
sudo apt install hydra -y

Verify Installation

hydra -h

   - Open a terminal and run the following Hydra command to brute force the login:
     ```bash
     hydra -l admin -P passwords.txt localhost http-post-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^:Login failed"
     ```
   - **Explanation**:
     - `-l admin` specifies the username.
     - `-P passwords.txt` specifies the file with password guesses.
     - `localhost` is the DVWA server.
     - `http-post-form` is the method, and `"Login failed"` tells Hydra how to identify a failed attempt.

7. **Review the Results**:
   - Hydra will try each password until it finds the correct one, displaying the successful login credentials.

#### Preventing Brute Force Attacks

Consider these techniques to prevent brute force attacks:
- **Account Lockout**: Temporarily lock accounts after multiple failed attempts.
- **Rate Limiting**: Limit the number of login attempts in a given time period.
- **Strong Password Policies**: Require complex passwords to reduce vulnerability to guessing attacks.

This exercise demonstrates the risk of weak passwords and the importance of enforcing security measures to prevent brute force attacks.

[**Read More**](https://github.com/digininja/DVWA)