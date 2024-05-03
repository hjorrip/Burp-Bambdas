# Burp-Bambdas
This project contains refactored Bambda queries from https://github.com/PortSwigger/bambdas, with the purpose of having each of them loaded as an extended Column in the HTTP Proxy history.

## URLParam 
Flags requests containing URLs. Useful to identify possible attack surface for SSRF.
```
//Flags requests containing URLs. 
// Useful to identify possible attack surface for SSRF.

HttpRequest request = requestResponse.request();

if (request.hasParameters()){
    for (ParsedHttpParameter parameter : request.parameters()){
        String parameterValue = parameter.value();
        if (parameterValue.contains("http://") ||
            parameterValue.contains(utilities().urlUtils().encode("http://")) ||
            parameterValue.contains("https://") ||
            parameterValue.contains(utilities().urlUtils().encode("https://"))){
            return true;
        }
    }
}

return false;

```

## RedirectToParam
Flags responses which redirect to locations provided as GET parameters. Useful to identify possible attack surface for open redirects. This can be used for phishing, CSP bypasses or OAuth token stealing.
```
// Finds responses which redirect to locations provided as GET parameters. 
// Useful to identify possible attack surface for open redirects. This can be used for phishing, 
// CSP bypasses or OAuth token stealing.

if (!requestResponse.hasResponse()){
    return false;
}

HttpRequest request = requestResponse.request();
HttpResponse response = requestResponse.response();

if (request.hasParameters() && response.isStatusCodeClass(StatusCodeClass.CLASS_3XX_REDIRECTION) && response.hasHeader("Location")){
    for (ParsedHttpParameter parameter : request.parameters()){
        String parameterValue = parameter.value();
        if (response.hasHeader("Location", parameterValue) ||
            response.hasHeader("Location", utilities().urlUtils().encode(parameterValue)) ||
            response.hasHeader("Location", utilities().urlUtils().decode(parameterValue))){
            return true;
        }
    }
}

return false;

```

## Reflected
Flags responses which reflect parameter names and values. Useful to identify possible attack surface for XSS, SSTI, header injection, open redirects or similar.
```
// Finds responses which reflect parameter names and values. 
// Useful to identify possible attack surface for XSS, SSTI, header injection, open redirects or similar.

// Configure to your needs
int minimumParameterNameLength = 2;
int minimumParameterValueLength = 3;
boolean matchCaseSensitive = true;
Set<String> excludedStrings = Set.of("true", "false", "null");
Set<HttpParameterType> excludedParameterTypes = Set.of(HttpParameterType.COOKIE); // e.g. HttpParameterType.COOKIE

if (!requestResponse.hasResponse()){
    return false;
}

HttpRequest request = requestResponse.request();
HttpResponse response = requestResponse.response();

// Check query, b/c parameters without values are not treated as parameters
String query = request.path().replace(request.pathWithoutQuery() + "?", "");
if (query.length() >= minimumParameterValueLength && !excludedStrings.contains(query)){
    if (response.contains(query, matchCaseSensitive) || response.contains(utilities().urlUtils().decode(query), matchCaseSensitive)){
        return true;
    }
}

if (request.hasParameters()){
    for (ParsedHttpParameter parameter : request.parameters()){
        HttpParameterType parameterType = parameter.type();
        if (excludedParameterTypes.contains(parameter.type())){
            continue;
        }

        String parameterName = parameter.name();
        if (parameterName.length() >= minimumParameterNameLength && ! excludedStrings.contains(parameterName) &&
            (response.contains(parameterName, matchCaseSensitive) || response.contains(utilities().urlUtils().decode(parameterName), matchCaseSensitive))){
            return true;
        }

        String parameterValue = parameter.value();
        if (parameterValue.length() >= minimumParameterValueLength && ! excludedStrings.contains(parameterValue) &&
            (response.contains(parameterValue, matchCaseSensitive) || response.contains(utilities().urlUtils().decode(parameterValue), matchCaseSensitive))){
            return true;
        }
    }
}

return false;

```

## Server
Extracts the value of the Server header from the response.
```
// Extracts the value of the Server header from the response

return requestResponse.hasResponse() && requestResponse.response().hasHeader("Server")
  ? requestResponse.response().headerValue("Server")
  : "";
```

## Referer
Extracts Referer request header. Useful to identify sensitive data leakage via Referer header like OIDC authorization codes.
/**
 * Extracts Referer request header.
 *
 * Useful to identify sensitive data leakage via Referer header like
 * OIDC authorization codes.
 *
 * @author emanuelduss
 **/

return requestResponse.request().hasHeader("Referer") ? requestResponse.request().headerValue("Referer") : "";


## Slow
Find slow response requests
```
/**
 * Finds slow responses.
 * @author ps-porpoise
**/
var delta = requestResponse.timingData().timeBetweenRequestSentAndStartOfResponse();
var threshold = Duration.ofSeconds(3);

if(delta != null && delta.toMillis() >= threshold.toMillis()) 
{
	return true;    
} else {
	return false;    
}
```

## SOAPMethod
Extracts the Method and an example value from a SOAP Request.
```
/**
 * Extracts the Method and an example value from a SOAP Request
 * @author Nick Coblentz (https://github.com/ncoblentz)
 *
 * Currently extracts the soap method and the WS-Security Username field's value. 
 * Assumes the body tag's namespace is "s" as in `<s:Body`, customize if your SOAP request tags don't match
 * Customize by adding additional RegEx's to extract more content
 **/

if(requestResponse.request().hasHeader("Content-Type")
    && requestResponse.request().headerValue("Content-Type").contains("soap+xml"))
{
    StringBuilder builder = new StringBuilder();
    if(requestResponse.request().bodyToString().contains("<s:Body"))
    {        
        Matcher m = Pattern.compile("<(?:[a-zA-Z0-9]+:)?Username>([^<]+)</(?:[a-zA-Z0-9]+:)*Username>|<(?:[a-zA-Z0-9]+:)*Body[^>]*><([^ ]+)",Pattern.CASE_INSENSITIVE).matcher(requestResponse.request().bodyToString());
        while(m.find() && m.groupCount()>0) {
            for(int i=1;i<=m.groupCount();i++) {
                if(m.group(i)!=null)
                    builder.append(m.group(i)+" ");
            }
        }
        return builder.toString();
    }
}
return "";
```

## SusFunc
Bambda Script to Detect and Highlight Suspicious JavaScript Functions
```
// Bambda Script to Detect and Highlight Suspicious JavaScript Functions
boolean enableManualAnnotations = true;

// Ensure there is a response
if (!requestResponse.hasResponse()) {
    return false;
}

// Check the Content-Type header for JavaScript
String contentType = requestResponse.response().headerValue("Content-Type");
if (contentType == null || !contentType.toLowerCase().contains("application/javascript")) {
    return false;
}

String responseBody = requestResponse.response().bodyToString();
boolean foundSuspiciousFunction = false;
StringBuilder notesBuilder = new StringBuilder();

// Expanded list of suspicious JavaScript functions
String[] suspiciousFunctions = {
    "eval\\(",                 // Executes a string as code
    "setTimeout\\(",           // Can execute strings as code if used improperly
    "setInterval\\(",          // Similar to setTimeout, can execute strings as code
    "document\\.write\\(",     // Can overwrite entire document
    "innerHTML",               // Can introduce XSS vulnerabilities if used with untrusted content
    "document\\.createElement\\(",  // Safe, but part of dynamic content generation which can be risky
    "document\\.execCommand\\(",   // Deprecated, was used to execute certain commands
    "document\\.domain",       // Altering the document.domain can be risky
    "window\\.location\\.href",    // Can be used for redirects which might be used in phishing
    "document\\.cookie",       // Accessing cookies can be sensitive
    "document\\.URL",          // Can be used to extract URL information
    "document\\.referrer",     // Can be used to check where the request came from
    "window\\.open\\(",        // Opening a new window or tab, potential for misuse
    "document\\.body\\.innerHTML", // Specific case of innerHTML, also risky
    "element\\.setAttribute\\(",   // If used improperly, can set risky attributes like 'onclick'
    "element\\.outerHTML",         // Similar risks to innerHTML
    "XMLHttpRequest\\(",           // Can be used for sending/receiving data, potential for misuse
    "fetch\\(",                    // Modern way to make network requests, potential for misuse
    "navigator\\.sendBeacon\\("    // Used to send analytics and tracking data
};

for (String function : suspiciousFunctions) {
    Pattern pattern = Pattern.compile(function);
    Matcher matcher = pattern.matcher(responseBody);
    if (matcher.find()) {
        foundSuspiciousFunction = true;
        if (enableManualAnnotations) {
            if (notesBuilder.length() > 0) {
                notesBuilder.append(", ");
            }
            notesBuilder.append(function); // Append the complete function signature
        }
    }
}

if (foundSuspiciousFunction && enableManualAnnotations) {
    if (notesBuilder.length() > 0) {
        requestResponse.annotations().setNotes("Suspicious JS functions detected: " + notesBuilder.toString());
        return true;
    }
}

return false;
```


## AbnormalAuth
Marks when an Authorization header is present,  not empty and does not include a traditional bearer token (beginning with "ey")
```
//Marks when an Authorization header is present, 
// not empty and does not include a traditional bearer token (beginning with "ey")

var request = requestResponse.request();
var response = requestResponse.response();


if (!requestResponse.hasResponse() || !response.isStatusCodeClass(StatusCodeClass.CLASS_2XX_SUCCESS)) {
    return false;
}

var hasAuthHeader = request.hasHeader("Authorization");
var authHeaderValue = hasAuthHeader ? String.valueOf(request.headerValue("Authorization")).toLowerCase() : null;

if (!hasAuthHeader || (authHeaderValue == null || authHeaderValue.isEmpty())) {
    return false;
}

var excludeAuthorization =
    authHeaderValue.contains("bearer") &&
    authHeaderValue.contains("ey");


if( !excludeAuthorization){
    return false;
    
};
return true;
```

## OWASPParams
Marks Proxy HTTP history for requests with vulnerable parameters based on the OWASP Top 25
```
//Marks Proxy HTTP history for requests with vulnerable parameters based on the OWASP Top 25

// Define vulnerable parameter group record
record VulnParamGroup(String title, HighlightColor color, String... parameterNames) {}

// Vulnerable Parameter Groups
VulnParamGroup ssrf = new VulnParamGroup("SSRF", HighlightColor.GREEN, "dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir");
VulnParamGroup sql = new VulnParamGroup("SQL", HighlightColor.BLUE, "id", "page", "report", "dir", "search", "category", "file", "class", "url", "news", "item", "menu", "lang", "name", "ref", "title", "view", "topic", "thread", "type", "date", "form", "main", "nav", "region");
VulnParamGroup xss = new VulnParamGroup("XSS", HighlightColor.ORANGE, "q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p", "month", "image", "list_type", "url", "terms", "categoryid", "key", "l", "begindate", "enddate");
VulnParamGroup lfi = new VulnParamGroup("LFI", HighlightColor.YELLOW, "cat", "dir", "action", "board", "date", "detail", "file", "download", "path", "folder", "prefix", "include", "page", "inc", "locate", "show", "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf");
VulnParamGroup or = new VulnParamGroup("OR", HighlightColor.PINK, "next", "url", "target", "rurl", "dest", "destination", "redir", "redirect_uri", "redirect_url", "redirect", "out", "view", "to", "image_url", "go", "return", "returnTo", "return_to", "checkout_url", "continue", "return_path");
VulnParamGroup rce = new VulnParamGroup("RCE", HighlightColor.RED, "cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "feature", "exe", "module", "payload", "run", "print");

// Toggle for highlighting
boolean highlightEnabled = true;

// Set multi vulnerable parameter group colour
HighlightColor multipleVulnColor = HighlightColor.MAGENTA;
VulnParamGroup[] groups = {ssrf, sql, xss, lfi, or, rce};
Set<String> foundParams = new HashSet<>();
Map<HighlightColor, Integer> colorCounts = new HashMap<>();
String combinedNotes = "";

// Get the request object
var request = requestResponse.request();

// Main loop to check for matches
for (VulnParamGroup group : groups) {
    for (String paramName : group.parameterNames()) {
        if (request.hasParameter(paramName, HttpParameterType.URL) ||
            request.hasParameter(paramName, HttpParameterType.BODY)) {
            if (highlightEnabled) {
                foundParams.add(group.title() + ": " + paramName);
                colorCounts.put(group.color(), colorCounts.getOrDefault(group.color(), 0) + 1);
            }
            // Return if only one vulnerability class applies
            if (!highlightEnabled) {
                requestResponse.annotations().setHighlightColor(group.color());
                return true;
            }
        }
    }
}

// If more than one vulnerability class applies set the multi vulnerable parameter colour
if (!foundParams.isEmpty()) {
    HighlightColor highlightColor = multipleVulnColor;
    if (colorCounts.size() == 1) {
        highlightColor = colorCounts.keySet().iterator().next();
    }

    requestResponse.annotations().setHighlightColor(highlightColor);
    combinedNotes = String.join(", ", foundParams);
    requestResponse.annotations().setNotes(combinedNotes);
    return true;
}

return false;
```

## GraphQL
Finds GraphQL endpoints with a 'query' parameter containing a newline.
```
// Finds GraphQL endpoints with a 'query' parameter containing a newline.

var req = requestResponse.request();

if (!req.hasParameters()) {
	return false;
}

var types = new HttpParameterType[] {
    HttpParameterType.JSON, HttpParameterType.BODY, HttpParameterType.URL
};

for (HttpParameterType type : types) {
    if (req.hasParameter("query", type)) {
        var value = req.parameterValue("query", type);
        if (type == HttpParameterType.JSON) {
	        if (value.contains("\\n")) {
                return "X";
            }
        } else {
            if (value.toLowerCase().contains("%0a")) {
                return "X";
            }
        }
    }
}

return "";
```

## DepricatedMethods
Filters and highlights requests using less common or deprecated HTTP methods like TRACE or CONNECT.
```
//Filters and highlights requests using less common or deprecated HTTP methods like TRACE or CONNECT.

// Define the set of deprecated or less common HTTP methods
Set<String> deprecatedMethods = Set.of("TRACE", "CONNECT");

String requestMethod = requestResponse.request().method();

// Check if the request method is in the set of deprecated methods
if (deprecatedMethods.contains(requestMethod)) {
   
     requestResponse.annotations().setNotes("Deprecated method used: " + requestMethod);
return "X";
}

return "";

```

## DevNotes
Flags if response contains a code comment.
```

// Ensure there is a response and it is not null
if (!requestResponse.hasResponse()) {
    return false;
}

// Use mimeType() for content type detection
MimeType responseType = requestResponse.response().mimeType();
boolean isHtml = responseType == MimeType.HTML;
boolean isJavaScript = responseType == MimeType.SCRIPT;

// Process only HTML and JavaScript responses
if (!isHtml && !isJavaScript) {
    return false;
}

boolean foundDeveloperNotes = false;
StringBuilder notesBuilder = new StringBuilder();


String responseBody = requestResponse.response().bodyToString();
String[] commentPatterns = isHtml ? new String[]{"<!--(?!\\[if).*?(?<!\\])-->"} : new String[]{"/\\*\\*(.*?)\\*\\*/"};


for (String pattern : commentPatterns) {
    Pattern regexPattern = Pattern.compile(pattern, Pattern.DOTALL);
    Matcher matcher = regexPattern.matcher(responseBody);

    while (matcher.find()) {
        foundDeveloperNotes = true;
    
        String note = matcher.group();
        // Limit the note length to 250 characters
        if (note.length() > 250) {
            note = note.substring(0, 250) + "...";
        }

        if (notesBuilder.length() > 0) {
            notesBuilder.append("; ");
        }
        notesBuilder.append("Developer note found: ").append(note);
        
    }
}

if (foundDeveloperNotes) {
    if (notesBuilder.length() > 0) {
        requestResponse.annotations().setNotes(notesBuilder.toString());
        return true;
    }
}

return false;

```

## HTTP
Request sent via HTTP (not HTTPS).
```
// Get the request object from the requestResponse
var request = requestResponse.request();

// Extract the URL from the request
var requestUrl = request.url();

// Check if the request URL starts with "http://"
if (requestUrl.startsWith("http://")) {
    // URL is unencrypted, return true to highlight this request
    return true;
}

// URL is encrypted or does not match the criteria, return false
return false;

```


## HostHeaderResponse
Flags responses which contain the hostname. Useful to identify possible attack surface for host header injection and web cache poisioning attacks.
```
// Finds responses which contain the hostname. Useful to identify possible attack surface for host header injection and web cache poisioning attacks.
var hostname = requestResponse.request().headerValue("Host");

return requestResponse.hasResponse() && requestResponse.response().contains(hostname, false);
```

## WrongContentType
Flags JSON responses with wrong Content-Type The content is probably json but the content type is not application/json
```
// Finds JSON responses with wrong Content-Type The content is probably json 
// but the content type is not application/json

var contentType = requestResponse.hasResponse() ? requestResponse.response().headerValue("Content-Type") : null;

if (contentType != null && !contentType.contains("application/json")) {
 String body = requestResponse.response().bodyToString().trim();

 return body.startsWith( "{" ) || body.startsWith( "[" );
}

return false;
```

## JSONP
Flags JSONP for CSP bypass.
https://hurricanelabs.com/blog/bypassing-csp-with-jsonp-endpoints/
```
// https://hurricanelabs.com/blog/bypassing-csp-with-jsonp-endpoints/
// JSONP for CSP bypass.

var req = requestResponse.request();
var res = requestResponse.response();
var paramRegex = Pattern.compile("^[a-zA-Z][.\\w]{4,}$");

if (res == null || res.body().length() == 0) return false;

if (!req.hasParameters()) return false;

var body = res.bodyToString().trim();
var params = req.parameters();

for (var param : params) {
    var value = param.value();
    if (param.type() != HttpParameterType.URL) continue;
    if (paramRegex.matcher(value).find()) {
        var start = "(?:^|[^\\w'\".])";
        var end = "\\s*[(]";
        var callbackRegex = Pattern.compile(start + Pattern.quote(value) + end);

    	if (callbackRegex.matcher(body).find()) return true;
    }
}

return false;
```

## MalHeader
Finds malformed HTTP headers containing spaces within their names.
```
// Finds malformed HTTP headers containing spaces within their names.

if( requestResponse.response().headers().stream()
    .anyMatch(e -> e.name().contains(" ")))
{
    return true;
}
return false;
```

## WrongLength
Flags responses whose body length do not match their stated Content-Length header.
```
// Flags responses whose body length do not match their stated Content-Length header.

if (!requestResponse.hasResponse() || requestResponse.request().method().equals("HEAD") || requestResponse.response().headerValue("Content-Length") == null ) {
    return false;
}

int realContentLength = requestResponse.response().body().length();

int declaredContentLength = Integer.parseInt(requestResponse.response().headerValue("Content-Length"));

return declaredContentLength != realContentLength;
```

## ManyHTMLTags
Flags if there are multiple HTML closing tags in the response. 
```
// Flags if there are multiple HTML closing tags in the response. 
if( requestResponse.hasResponse() &&
       requestResponse.response().statedMimeType() == MimeType.HTML &&
       utilities().byteUtils().countMatches(
       requestResponse.response().body().getBytes(), "</html>".getBytes()) > 1)
{
    return true;
}
return false;
```






































