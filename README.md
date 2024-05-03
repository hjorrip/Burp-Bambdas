# Burp-Bambdas
This project contains refactored Bambda queries from https://github.com/PortSwigger/bambdas, with the purpose of having each of them loaded as an extended Column in the HTTP Proxy history.

## Column: Slow
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
