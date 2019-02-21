using System;
using System.Net.Http;
using System.Net;
using log4net;
using OpenSSL.X509Certificate2Provider;
using System.Security.Cryptography.X509Certificates;
using OpenQA.Selenium;
using OpenQA.Selenium.Firefox;
using ZapSecurityScan;
using System;
using System.Threading;


namespace ZapTestSuite
{


    class MainClass
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(MainClass));

        public static void Main(string[] args)
        {

            string zapProxy = "http://localhost:8088";
           
            string baseURL = "http://localhost:5000";

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
            string result = zss.GetSecurityScanResult("Low", "Low", 10);
            Console.WriteLine(result);
            String report = zss.GetXMLReport();
            
            Console.WriteLine(report);
            // shutdown scanner
            //Console.Read();


        }


	    static void GetUrls(string zapProxy, string baseURL)
	    {

	        // ... Smoke Test Money pages.
	        string page = baseURL;
            string scanProxy = "127.0.0.1:8088";

            Console.WriteLine("GetURLs - zapProxy: " + zapProxy);
            Console.WriteLine("GetURLs - baseURL: " + baseURL);

	        System.Net.ServicePointManager.ServerCertificateValidationCallback +=
	            delegate (object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate,
	                    System.Security.Cryptography.X509Certificates.X509Chain chain,
	                    System.Net.Security.SslPolicyErrors sslPolicyErrors)
	        {
	            return true; // **** Always accept
	        };

            Console.WriteLine("Setup WebClient: ");
            WebClient client = new WebClient();
	        WebProxy wp = new WebProxy(zapProxy);
	        client.Proxy = wp;

            // home page
            Console.WriteLine("webclient Get baseURL: " + baseURL + "/");
            string str = client.DownloadString(baseURL);
            // try delete blog
            try {
                str = client.DownloadString(baseURL + "/");
            } catch (Exception e) {
				log.Error("Exception : " + e.Message);
            }

            // Login page
            Console.WriteLine("webclient Get baseURL: " + baseURL + "/login");
            str = client.DownloadString(baseURL);
            try
            {
				str = client.DownloadString(baseURL + "/login");
		    } catch (Exception e) {
                log.Error("Exception : " + e.Message);
            }

            Console.WriteLine("Selenium testing to created session parameters / attack vectors");
            try {
	            //FirefoxProfile profile = new FirefoxProfile();

                string usernm = "admin";
                string passwd = "admin";
                Proxy proxy = new Proxy();
                FirefoxProfileManager profileManager = new FirefoxProfileManager();

                FirefoxDriverService service = FirefoxDriverService.CreateDefaultService(@"GeckoDriver19", "geckodriver.exe");
                service.FirefoxBinaryPath = @"C:\Program Files\Mozilla Firefox\firefox.exe";

                proxy.SocksProxy = zapProxy;
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                firefoxOptions.Profile = profileManager.GetProfile("Selenium");
                //firefoxOptions.Profile.SetProxyPreferences(proxy);
                //firefoxOptions.SetPreference()
                firefoxOptions.SetPreference("network.proxy.type", 1);
                firefoxOptions.SetPreference("network.proxy.socks", "127.0.0.1");
                firefoxOptions.SetPreference("network.proxy.socks_port", 8088);
                firefoxOptions.SetPreference("network.proxy.http", "127.0.0.1");
                firefoxOptions.SetPreference("network.proxy.http_port", 8088);
                firefoxOptions.SetPreference("network.proxy.ssl", "127.0.0.1");
                firefoxOptions.SetPreference("network.proxy.ssl_port", 8088);


                FirefoxDriver driver = new FirefoxDriver(service, firefoxOptions);

                // LOGIN 
                driver.Navigate().GoToUrl(baseURL + "/login");
                IWebElement uname = driver.FindElement(By.Name("username"));
                IWebElement pword = driver.FindElement(By.Name("password"));
                uname.Clear();
                uname.SendKeys(usernm);
                pword.Clear();
                pword.SendKeys(passwd);
                IWebElement btnId = driver.FindElement(By.XPath("//*[@value='Login']"));
                btnId.Click();
                driver.Manage().Timeouts().ImplicitWait = TimeSpan.FromSeconds(10);

                Thread.Sleep(10000);

                // ENTER BLOG ENTRY
                IWebElement title = driver.FindElement(By.Name("title"));
                IWebElement txt = driver.FindElement(By.Name("text"));
                title.Clear();
                title.SendKeys("Automated blog entry");
                txt.Clear();
                txt.SendKeys("This is an selenium generated blog entry for testing purposes!!!!!!");
                btnId = driver.FindElement(By.XPath("//*[@value='Share']"));
                btnId.Click();
                driver.Manage().Timeouts().ImplicitWait = TimeSpan.FromSeconds(10);

                Thread.Sleep(10000);

                driver.Close();

    		} catch (Exception e) {
                log.Error("Exception : " + e.Message);
            }

        }
    
    }
}
