using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Xml;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Security;

namespace Secureworks
{
    class PTAAgentStarter
    {
        
        static void Main(string[] args)
        {
            Console.Clear();
            string certName = null;
            string machineName = null;
            string bootStrap = null;
            int failureReason = 0;
            bool printUsage = false;
            string dumpAgents = "agents.txt";
            X509Certificate certificate = null;
            if (args.Length <= 5)
            {
                foreach(string arg in args)
                {
                    try
                    {
                        string[] values = arg.Split('=');
                        if(values.Length < 2) { printUsage = true; break; }
                        switch (values[0])
                        {
                            case "cert":
                                certName = values[1];
                                if (!File.Exists(certName))
                                {
                                    Console.WriteLine("The given certificate file not found: {0}", certName);

                                    return;
                                }
                                break;
                            case "bootstrap":
                                bootStrap = values[1];
                                if (!File.Exists(bootStrap))
                                {
                                    Console.WriteLine("The given bootstrap file not found: {0}", bootStrap);

                                    return;
                                }
                                Console.WriteLine("Using bootstrap from file: {0}", bootStrap);
                                break;
                            case "name":
                                machineName = values[1];
                                break;
                            case "file":
                                dumpAgents = values[1];
                                if (File.Exists(dumpAgents))
                                {
                                    File.Delete(dumpAgents);
                                }
                                Console.WriteLine("Dumping agents to file: {0}", dumpAgents);
                                break;
                            case "failure":
                                try
                                {
                                    failureReason = int.Parse(values[1]);
                                }
                                catch { printUsage = true; break; }

                                Console.WriteLine("Failing all requests with reason: {0}", failureReason);
                                break;
                            default:
                                printUsage = true; 
                                break;
                        }
                    }
                    catch { printUsage = true; break; }

                    
                }

                if (certName == null)
                {
                    Console.WriteLine("No certificate was provided, trying to load from the current computer.");
                    // Get the ProgramData location
                    string programData = Environment.GetEnvironmentVariable("ProgramData");
                    string configPath = String.Format("{0}\\Microsoft\\Azure AD Connect Authentication Agent\\Config\\TrustSettings.xml", programData);
                    if (File.Exists(configPath))
                    {
                        // Load the configuration
                        System.Xml.XmlDocument xmlTrustSettings = new System.Xml.XmlDocument();
                        System.Xml.XmlReader xmlReader = System.Xml.XmlReader.Create(configPath);

                        xmlTrustSettings.Load(xmlReader);



                        try
                        {
                            string thumbPrint = xmlTrustSettings.GetElementsByTagName("Thumbprint")[0].InnerText;
                            bool isInUserStore = xmlTrustSettings.GetElementsByTagName("IsInUserStore")[0].InnerText.Equals("true");

                            X509Store certStore = null;
                            if (isInUserStore)
                            {
                                Console.WriteLine("Certificate stored in service account personal store, unable to access!");
                                Console.WriteLine("Export certificate using AADInternals: \"Export-AADIntProxyAgentCertificates\"");
                                return;
                            }
                            else
                                certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                                
                            Console.WriteLine("Trying to load certificate {0}", thumbPrint);

                            
                            certStore.Open(OpenFlags.ReadOnly);
                            X509Certificate2Collection certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint,thumbPrint,false);

                            if (certCollection.Count > 0)
                            {
                                certificate = certCollection[0];
                                Console.WriteLine("Certificate succesfully loaded.");
                            }
                            else
                                Console.WriteLine("Could not load the certificate");
                            certStore.Close();
                        }
                        catch
                        {
                            Console.WriteLine("Could not load the certificate");
                        }
                        
                    }
                    else
                        Console.WriteLine("Could not load TrustSettings.xml");




                }
                else
                    certificate = X509Certificate2.CreateFromCertFile(certName);

                if (machineName == null && bootStrap == null)
                {
                    Console.WriteLine("Machine name and bootstrap not provided, getting machine name from the registry.");
                    string computer = (string) Registry.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName","ComputerName",null);
                    string domain = (string)Registry.GetValue("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Domain", null);
                    machineName = String.Format("{0}.{1}",computer,domain);
                    Console.WriteLine("Machine name: {0}", machineName);
                }

                if  (certificate == null)
                    printUsage = true;
            }
            else
                printUsage = true;
            
            if(printUsage)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("PTAAgentDump file=<path to dump file> [cert=<path to certificate>] [name=<machine name>] [bootstrap=<path to bootstrap>]\n");

                return;
            }

            Console.OutputEncoding = System.Text.Encoding.UTF8;


            PTAAgent agent = new PTAAgent(certificate, failureReason, machineName, bootStrap,dumpAgents);

            agent.StartAgent();

            Console.ReadKey();
        }
    }
}
