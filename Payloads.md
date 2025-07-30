# Payloads for web applications

## XSS
- Level-wise
```bash
"><u>ashok # Check the HTML encoding
<img src=x onerror=alert(1)>
<img src=x onmouseover=alert(1)>

```


## Best Practices
> Resources for Regex [Regular Expressions](https://regex101.com/)
- Here it can allow any website, it matches `In the TEST STRING, Instead of . we can place any single character`
![Regex](/Images/regex1.png)

- Here it should match `^ sign`, `In the TEST STRING, Instead of . we can place any single character`
![Regex](/Images/regex_Secured.png)
