﻿using OWASPZAPDotNetAPI;
using System.Web;
using log4net;
using log4net.Config;
using System;
using System.Collections.Generic;

using System.Linq;
using System.Text;

namespace ZapSecurityScan
{
    public class ZapSecurityScanner
    {
        private ClientApi zapClientAPI;
        private UriBuilder zapURL, targetURL;
        private string scanid;
        private string contextid;
        private string scanURL;

        private static readonly ILog log = LogManager.GetLogger(typeof(ZapSecurityScanner));
        private static readonly string ZAP_API_KEY = "62o3jhd5gljokoq9ingtbhaqtd"; // Change this if you have set the apikey in ZAP via Options / API


        public ZapSecurityScanner()
        {

            BasicConfigurator.Configure();

            log.Info("Starting Zap Security Scanner Client");

        }

        public bool SetupSecurityScan(String zapProxyURL, String baseURL) {
            
            try
            {
                scanURL = baseURL;
                zapURL = new UriBuilder(zapProxyURL);
                targetURL = new UriBuilder(baseURL);
                log.Info("Setup - Zap Proxy: " + zapURL.Scheme + "://" + zapURL.Host + "   Target URL: " + targetURL.ToString());
                zapClientAPI = new ClientApi(zapURL.Host,8080 , ZAP_API_KEY); 
                log.Info("Enable Passive Scanners");
                zapClientAPI.pscan.enableAllScanners(ZAP_API_KEY);
                log.Info("Generate Root CA");
                zapClientAPI.core.generateRootCA(ZAP_API_KEY);

            }
            catch (Exception e)
            {
                log.Error(e.Message);
                return false;
            }

            try
            {

                log.Info("Create ZAP Context and set scope");
                contextid = zapClientAPI.context.newContext(ZAP_API_KEY, "ZSS").ToString();

            }
            catch (Exception e)
            {
                log.Error(e.Message);
            } finally {
				try
				{
					string httptarget = "http://" + targetURL.Host + targetURL.Path + ".*";
					string httpstarget = "https://" + targetURL.Host + targetURL.Path + ".*";
                    log.Info("Set Zap scope to include: " + httptarget);
                    zapClientAPI.context.includeInContext(ZAP_API_KEY,"ZSS", httptarget);
					log.Info("Set Zap scope to include: " + httpstarget);
                    zapClientAPI.context.includeInContext(ZAP_API_KEY,"ZSS", httpstarget);
				}
				catch (Exception e)
				{
                    log.Error("Exception : " + e.Message);
				}
            }

            return true;
		}

		public string StartSecurityScan(string recursive)
		{
			string recurse;

            if (string.Equals(recursive, "true", StringComparison.OrdinalIgnoreCase))
				recurse = "True";
			else
				recurse = "False";

			try
			{
                log.Info("Actively scanning: " + scanURL);
				log.Info("Recursive: " + recurse);
                /// set XSS attack strength
                /// 
                //log.Info("Context " + zapClientAPI.context.context(ZAP_API_KEY).Name.ToString());

                zapClientAPI.ascan.setScannerAttackStrength(ZAP_API_KEY,"40018", "HIGH", "Default Policy");
                //var response = zapClientAPI.ascan.scan(ZAP_API_KEY,scanURL , recurse, "True", null, null, null,
                //                                       zapClientAPI.context.context(ZAP_API_KEY).Name);
				var response = zapClientAPI.ascan.scan(ZAP_API_KEY, scanURL+"/", recurse, "True", "", "", "","");

 				/// The scan now returns a scan id to support concurrent scanning
				scanid = ((ApiResponseElement)response).Value;
                log.Info("Scan id: " + scanid);
				
			}
			catch (Exception e)
			{
                log.Error("Exception : " + e.Message);
			}

			return scanid;
		}

		public string GetSecurityScanResult(string risk, string confidence, int minutes)
		{
			string result = "SUCCESS";
			int polls = 0;
			int MAX_SCAN_MINUTES = minutes;
			int progress;

			try
			{
                log.Info("Get Scan Result: " + scanURL);
				while (true)
				{
                    progress = int.Parse(((ApiResponseElement)zapClientAPI.ascan.status(scanid)).Value);
					log.Info("Active Scan progress : " + progress + "%");
					if (progress >= 100 || polls++ > MAX_SCAN_MINUTES * 2)
					{
						break;
					}
					System.Threading.Thread.Sleep(30000);
				}

				log.Info("Active Scan complete");
				log.Info("Alerts");



				List<Alert> filtered = new List<Alert>();
                foreach (Alert alert in zapClientAPI.GetAlerts(scanURL, 0, 1000))
				{
                    if (string.Equals(confidence, "medium", StringComparison.OrdinalIgnoreCase))
                        if (alert.Confidence == Alert.ConfidenceLevel.High || alert.Confidence == Alert.ConfidenceLevel.Medium)
                            filtered.Add(alert);
                        else
                        if (alert.Confidence == Alert.ConfidenceLevel.High)
                            filtered.Add(alert);

				}

                foreach (Alert falert in filtered)
				{
                    
                    if ((string.Equals(risk, "medium", StringComparison.OrdinalIgnoreCase) && falert.Risk == Alert.RiskLevel.Medium) || falert.Risk == Alert.RiskLevel.High)
					{
						result = "FAIL";
                        log.Info("Name:     " + falert.AlertMessage);
                        log.Info("Descipt:  " + falert.Description);
                        log.Info("Solution: " + falert.Solution);
						log.Info("--------------");
					}
				}

				// clean up
				//api.context.removeContext("CS");

			}
			catch (Exception e)
			{
                    log.Error("Exception : " + e.Message);
			}

 			log.Info(result);
			return result;
		}



		// called after scan is complete - shutdownZap()
		public void Shutdown()
		{

			try
			{
                  zapClientAPI.core.shutdown(ZAP_API_KEY);
			}
			catch (Exception e)
			{
                  log.Error("Exception : " + e.Message);
			}

		}

		// called after scan is complete - getSecurityScanResult
		// this method returns XML report of issues found
		public string GetXMLReport()
		{
			string xml_report;
			try
			{
                xml_report = System.Text.Encoding.UTF8.GetString(zapClientAPI.core.xmlreport(ZAP_API_KEY));
			}
			catch (Exception e)
			{
				log.Error("Exception : " + e.Message);
				xml_report = e.Message.ToString();
			}
			return xml_report;
		}

		// called after scan is complete - getSecurityScanResult
		// this method returns HTML report of issues found
		public string getHTMLReport()
		{
				string html_report;
				try
				{
                html_report = System.Text.Encoding.UTF8.GetString(zapClientAPI.core.htmlreport(ZAP_API_KEY));
				}
				catch (Exception e)
				{
					log.Error("Exception : " + e.Message);
					html_report = e.Message.ToString();
				}
				return html_report;
		}

        // get certificate
        public byte[] GetZapCertificate() 
        {
            return zapClientAPI.core.rootcert(ZAP_API_KEY);
        }
		

    }



}
