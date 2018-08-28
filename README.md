# ZapSecurityScannerDotNet
# Introduction
ZapSecurityScanner DotNet facilitates application security testing within existing CI pipelines.  This api provides a simple interface to the ZAP application security scanner. ZAP (Zed Attack Proxy) is an OWASP project providing a free
dynamic application security scanner.  ZAP will automatically find security vulnerabilities in running web applications. [Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)  AIT teams can use the API to incorporate security testing into thier existing tests. 

# Prerequisite for using ZapSecurityScanner
## ZAP instance
ZAP must be running and configured to listen to remote API requests. Example command line: 
```linux cmd
./zap.sh -daemon -config api.key=62o3jhd5gljokoq9ingtbhaqtd -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.addrs.addr=true -host 0.0.0.0 -port 8080
```
## ZAP docker instance
Example below has steps to pull latest stable ZAP docker image and run on command line: 
```linux cmd
sudo docker pull owasp/zap2docker-stable
sudo docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon a -config api.key=62o3jhd5gljokoq9ingtbhaqtd -config api.add.addr.name=.* -config api.addrs.addr.regex=true  -host 0.0.0.0 -port 8080
```

## Proxy Configuration
The test application / framework must set its http(s) proxy.  The proxy value must point to the running ZAP instance.
The example below gets the zapproxy parameter and sets the proxy for HttpURLConnection:
```c#
WebClient client = new WebClient();
WebProxy wp = new WebProxy(zapProxy);
client.Proxy = wp;
```

# Using ZapSecurityScanner
## Create instance
Declare your test class with uppercase first, camelcase, and add '_Tests_'. Example:
```c#
log.Info("ZapTest!");
ZapSecurityScanner zss = new ZapSecurityScanner();
```
## Setup Zap Security Scanner
Call the SetupSecuritScan() method to set the base URL and proxy for the ZAP API
```c#
log.Info("Starting ZAP Test");
zss.SetupSecurityScan(zapProxy, baseURL);
```
## Execute integration test
At this stage you have the proxy directing all traffic to Zap scanner so you should execute your existing integration test.
The traffic will flow through the Zap proxy where the Zap Scanner will compile list of scanning targets (URLs, parameters)

## Call start scan method of Zap Security Scanner
Call the StartSecurityScan() method once testing workflow completes and you wish to start security scanning
```c#
// start scan now that we have URLs and session parameter data captured to test
zss.StartSecurityScan("True");
```

## Get results from Zap Security Scanner
You must call the GetSecurityScanResult() method to poll for scanner to finish and return scan result
```c#
// get results for Medium or higer severity with Medium or higher confidence
string result = zss.GetSecurityScanResult("Medium", "Medium", 10);
```
## Get Reports from Zap Security Scanner
You may wish to retrieve the entire security scanning report.  This is done by calling one of the two methods below after calling getSecurityScanResult() to ensure scan is complete.  The getXMLReport() returns and complete report in XML and getHTMLReport returns HTML formatted report.
```c#
// ================= XML Report ==================
String report = zss.GetXMLReport();

// ================= HTML REPORT =================
String report = zss.GetHTMLReport();
```
