using System;
using System.Net.Http;
using System.Net;
using log4net;
using OpenSSL.X509Certificate2Provider;
using System.Security.Cryptography.X509Certificates;
using OpenQA.Selenium;
using OpenQA.Selenium.Firefox;

using ZapSecurityScan;


namespace ZapTestSuite
{


    class MainClass
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(MainClass));

        public static void Main(string[] args)
        {

            string zapProxy = "http://localhost:8080";
            //string  baseURL = "https://cs.fod.autotrader.com";
            string baseURL = "https://demo1.kbb.com";

            log.Info("ZapTest!");
            ZapSecurityScanner zss = new ZapSecurityScanner();
            log.Info("Starting ZAP Test");
            zss.SetupSecurityScan(zapProxy, baseURL);

            // access urls .. run browser automation
            // this creates Http traffic flow through ZAP 
            GetUrls(zapProxy, baseURL);

            // start scan now that we have URLs and session parameter data captured to test
            zss.StartSecurityScan("True");  // Recurse links found.  False : stay at home

            // get results for Medium or higer severity with Medium or higher confidence
            string result = zss.GetSecurityScanResult("Medium", "Medium", 10);
            Console.WriteLine(result);
            String report = zss.GetXMLReport();
            Console.WriteLine(report);
            // shutdown scanner
        }


	    static void GetUrls(string zapProxy, string baseURL)
	    {

	        // ... Smoke Test Money pages.
	        string page = baseURL;
            string scanProxy = "127.0.0.1:8080";

	        Console.WriteLine("Accessing: " + page);

	        System.Net.ServicePointManager.ServerCertificateValidationCallback +=
	            delegate (object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate,
	                    System.Security.Cryptography.X509Certificates.X509Chain chain,
	                    System.Net.Security.SslPolicyErrors sslPolicyErrors)
	        {
	            return true; // **** Always accept
	        };

	        WebClient client = new WebClient();
	        WebProxy wp = new WebProxy(zapProxy);
	        client.Proxy = wp;
	        
            // home page
            string str = client.DownloadString(baseURL);
            // ICO
            try {
                str = client.DownloadString(baseURL + "/new-cars/");
            } catch (Exception e) {
				log.Error("Exception : " + e.Message);
            } 
            // Dealer Price Quote
            try {
				str = client.DownloadString(baseURL + "/free-dealer-price-quote/");
		    } catch (Exception e) {
                log.Error("Exception : " + e.Message);
            }
	        
            // Selenium testing to created session parameters / attack vectors
            try {
	            FirefoxProfile profile = new FirefoxProfile();
	            String PROXY = scanProxy;
	            OpenQA.Selenium.Proxy proxy = new OpenQA.Selenium.Proxy();
				proxy.HttpProxy = PROXY;
				proxy.FtpProxy = PROXY;
				proxy.SslProxy = PROXY;
				profile.SetProxyPreferences(proxy);
				FirefoxDriver driver = new FirefoxDriver(profile);
	            driver.Navigate().GoToUrl(baseURL);
    		} catch (Exception e) {
                log.Error("Exception : " + e.Message);
            }

        }
    
    }
}
