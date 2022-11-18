using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Net.WebSockets;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Web;
using System.Collections;
using Secureworks.AMQP;
using Newtonsoft.Json;
using System.Linq;
using System.IO;

namespace Secureworks
{
    public class PTAAgent
    {
        // variables
        private string subscriptionId;
        private string connectorId;
        private X509Certificate2 certificate;
        private string machineName; // Doesn't matter..

        private static int failureReason = 0;
        private HttpClient client;
        private string bootStrap = null;

        private static string dumpAgentsFile = null;

        public PTAAgent(X509Certificate Certificate, int failureReason, string machineName, string bootStrap, string dumpAgentsFile)
        {
            // Initialise variables
            this.certificate = new X509Certificate2(Certificate);
            this.machineName = machineName;
            this.bootStrap = bootStrap;
            PTAAgent.failureReason = failureReason;
            PTAAgent.dumpAgentsFile = dumpAgentsFile;
            
            // Get the ids from the certificate
            this.subscriptionId = this.certificate.GetNameInfo(X509NameType.SimpleName, false);
            this.connectorId = new Guid((this.certificate).Extensions["1.3.6.1.4.1.311.82.1"].RawData).ToString();

            // Create the http client with authentication certificate
            HttpClientHandler handler = new HttpClientHandler();
            handler.ClientCertificates.Add(this.certificate);
            this.client = new HttpClient(handler);
        }


        public void StartAgent()
        {
            Console.WriteLine("\nTenant id:    {0}", this.subscriptionId);
            Console.WriteLine("PTA agent id: {0}",this.connectorId);
            Console.WriteLine("Certificate:  {0}\n", this.certificate.Thumbprint);
            string xmlBootstrap = null;

            if(this.bootStrap != null)
            {
                xmlBootstrap = System.IO.File.ReadAllText(this.bootStrap);
            }
            else
            {
                // Get the bootstrap
                var result = GetBootstrapConfiguration();
                xmlBootstrap = result.Result;
            }
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlBootstrap);

            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("a", "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel");
            XmlNodeList endpoints = doc.SelectNodes("//a:SignalingListenerEndpointSettings", nsmgr);

            // Loop through the endpoints
            int n = 1;
            foreach (XmlNode endpoint in endpoints)
            {
                EndpointSettings es = new EndpointSettings();
                es.certificate = this.certificate;

                es.number = n++;
                es.isAvailable = endpoint.SelectSingleNode("a:IsAvailable", nsmgr).InnerText.Equals("true");
                es.name = endpoint.SelectSingleNode("a:Name", nsmgr).InnerText;
                es.domain = endpoint.SelectSingleNode("a:Domain", nsmgr).InnerText;
                es.nameSpace = endpoint.SelectSingleNode("a:Namespace", nsmgr).InnerText;
                es.reliableSessionEnabled = endpoint.SelectSingleNode("a:ReliableSessionEnabled", nsmgr).InnerText.Equals("true");
                es.scheme = endpoint.SelectSingleNode("a:Scheme", nsmgr).InnerText;
                es.servicePath = endpoint.SelectSingleNode("a:ServicePath", nsmgr).InnerText;
                es.sharedAccessKey = endpoint.SelectSingleNode("a:SharedAccessKey", nsmgr).InnerText;
                es.sharedAccessKeyName = endpoint.SelectSingleNode("a:SharedAccessKeyName", nsmgr).InnerText;

                new Thread(StartEndpointListener).Start(es);
            }
        }

        
        // Get the boot strap configuration
        public async Task<string> GetBootstrapConfiguration()
        {
            string body = string.Format(@"
                <BootstrapRequest xmlns=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel"" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"">
	                <AgentSdkVersion>1.5.2482.0</AgentSdkVersion>
	                <AgentVersion>1.5.2482.0</AgentVersion>
	                <BootstrapAddOnRequests i:nil=""true""/>
	                <BootstrapDataModelVersion>1.5.1542.0</BootstrapDataModelVersion>
	                <ConnectorId>{0}</ConnectorId>
	                <ConnectorVersion i:nil=""true""/>
	                <ConsecutiveFailures>0</ConsecutiveFailures>
	                <CurrentProxyPortResponseMode>Primary</CurrentProxyPortResponseMode>
	                <FailedRequestMetrics xmlns:a=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel""/>
	                <InitialBootstrap>true</InitialBootstrap>
	                <IsProxyPortResponseFallbackDisabledFromRegistry>true</IsProxyPortResponseFallbackDisabledFromRegistry>
	                <LatestDotNetVersionInstalled>461814</LatestDotNetVersionInstalled>
	                <MachineName>{1}</MachineName>
	                <OperatingSystemLanguage>1033</OperatingSystemLanguage>
	                <OperatingSystemLocale>040b</OperatingSystemLocale>
	                <OperatingSystemSKU>7</OperatingSystemSKU>
	                <OperatingSystemVersion>10.0.17763</OperatingSystemVersion>
	                <ProxyDataModelVersion>1.5.2482.0</ProxyDataModelVersion>
	                <RequestId>{2}</RequestId>
	                <SubscriptionId>{3}</SubscriptionId>
	                <SuccessRequestMetrics xmlns:a=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.BootstrapDataModel""/>
	                <TriggerErrors/>
	                <UpdaterStatus>Running</UpdaterStatus>
	                <UseServiceBusTcpConnectivityMode>false</UseServiceBusTcpConnectivityMode>
	                <UseSpnegoAuthentication>false</UseSpnegoAuthentication>
                </BootstrapRequest>", this.connectorId, this.machineName, Guid.NewGuid().ToString(),subscriptionId);

            string url = string.Format("https://{0}.bootstrap.msappproxy.net/ConnectorBootstrap", this.subscriptionId);

            HttpContent content = new StringContent(body, Encoding.UTF8, "application/xml");
            HttpResponseMessage response = await client.PostAsync(url, content);

            string responseBody = await response.Content.ReadAsStringAsync();

            return responseBody;
        }
        
        private static Credentials DecodePTACredential(IList<EncryptedData> encryptedData, X509Certificate2 Certificate, string userName, string traceId)
        {

            // Extract the connector Id from the certificate
            string connectorId = new Guid((Certificate).Extensions["1.3.6.1.4.1.311.82.1"].RawData).ToString();
            
            // Find an element encrypted with a correct key (there's one for each PTA agent)
            string keyIdentifier = String.Format("{0}_{1}", connectorId,Certificate.Thumbprint);

            StreamWriter sw = null;
            if (PTAAgent.dumpAgentsFile != null)
            {
                sw = File.CreateText(PTAAgent.dumpAgentsFile);
            }

            // Found agents and number of certs
            Hashtable agents = new Hashtable();

            foreach (EncryptedData element in encryptedData)
            {
                // Just dump agents
				// Split the key identifier (agent guid and cert thumbprint)
				string[] parts = element.KeyIdentifier.Split('_');
				string agent = parts[0];
				int n = 1;
				if(agents.ContainsKey(agent))
				{
					n = (int)agents[agent] + 1;
				}
				agents[agent] = n;

				sw.WriteLine(element.KeyIdentifier);
				sw.Flush();
                
            }

            // Agents dumped, exit.
            Console.WriteLine("╓─────────────────────────────────────────────────────────────────────────╖");
            foreach (DictionaryEntry agent in agents)
                {
                    Console.WriteLine("║ Agent {0} has {1:D2} active certifications ║", agent.Key, agent.Value);
                }
            Console.WriteLine("╙─────────────────────────────────────────────────────────────────────────╜\n");
            Console.WriteLine("Agents dumped to {0}, exiting", PTAAgent.dumpAgentsFile);
                Environment.Exit(0);
           

            // Exits before this
            return null;
        }

        private static string GetSASToken(string url, string key, string keyName)
        {
            // Create the HMAC object
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            HMAC hmac = new HMACSHA256(keyBytes);

            // Convert expiry date to unix time
            var expires = (new DateTime()).AddYears(1);
            string exp = string.Format("{0}", (UInt32)(((DateTimeOffset)expires).ToUniversalTime()).ToUnixTimeSeconds());

            // Form the string to be signed
            string nameSpace = url.Split('/')[2];
            string urlToSign = string.Format("{0}\n{1}",HttpUtility.UrlEncode(url), exp);
            byte[] byteUrl = Encoding.UTF8.GetBytes(urlToSign);

            // Calculate the signature
            byte[] byteHash = hmac.ComputeHash(byteUrl);
            string signature = Convert.ToBase64String(byteHash);

            // Form the token
            string SASToken = string.Format("SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}", HttpUtility.UrlEncode(url), HttpUtility.UrlEncode(signature),exp,keyName);

            return SASToken;
        }


        // Starts the proxy listener
        private static void StartProxyListener(object proxySettings)
        {
            ProxySettings settings = (ProxySettings)proxySettings;

          
            // Build the url
            string url = string.Format("wss://{0}/subscriber/websocketconnect?requestId={1}", settings.url, Guid.NewGuid().ToString());

            if (settings.connectionId == null)
            {
                // Using the "new" protocol, where authRequest was included in the relay message so just send the auth response to the proxy.
                try
                {
                    CreateAndSendClaims(settings.encryptedData, settings.certificate, settings.url, settings.userPrincipalName, settings.requestId, settings.transId);
                }
                catch { }
                finally { }
            }
            else
            {
                // Using the "old" protocol, where authRequest is first received via proxy.
                // Create a socket and connect to it
                ClientWebSocket socket = new ClientWebSocket();

                try
                {
                    socket.Options.ClientCertificates.Add(settings.certificate);

                    socket.Options.SetRequestHeader("x-cwap-dnscachelookup-result", "NotUsed");
                    socket.Options.SetRequestHeader("x-cwap-connector-usesdefaultproxy", "InUse");
                    socket.Options.SetRequestHeader("x-cwap-connector-version", "1.5.1542.0");
                    socket.Options.SetRequestHeader("x-cwap-datamodel-version", "1.5.1542.0");
                    socket.Options.SetRequestHeader("x-cwap-connector-sp-connections", "0");
                    socket.Options.SetRequestHeader("x-cwap-transid", settings.transId);
                    CancellationToken token = new CancellationToken();

                    var connection = socket.ConnectAsync(new Uri(url), token);
                    while (!connection.IsCompleted) { Thread.Sleep(1); };
                    if (connection.IsFaulted.Equals("true"))
                    {
                        Console.WriteLine("ProxyListener failed to connect to {0}", settings.url);
                        return;
                    }

                    Console.WriteLine("ProxyListener connected: {0}", settings.url);

                    // Send the connection id message
                    string connectionIdMessage = string.Format("{{\"ConnectionId\":\"{0}\",\"MessageType\":0}}", settings.connectionId);
                    SendToSocket(socket, token, Encoding.UTF8.GetBytes(connectionIdMessage));


                    // Loop
                    while (socket.State == WebSocketState.Open)
                    {
                        byte[] response = ReadFromSocket(socket, token, 65536);

                        string userName = null;

                        // Parse the json
                        // Parse the the authentication request
                        AuthRequest authRequest = JsonConvert.DeserializeObject<AuthRequest>(Encoding.UTF8.GetString(response));

                        ProtocolContext context = authRequest.TunnelContext.ProtocolContext;
                        IList<EncryptedData> encryptedData = null;

                        switch (context.TrafficProtocol)
                        {
                            case 2:
                                encryptedData = context.EncryptedData;
                                userName = context.UserPrincipalName;
                                break;
                            case 3:
                                string strBody = System.Text.Encoding.UTF8.GetString(context.BodyBytes.ToArray<byte>());
                                AuthRequestContent content = JsonConvert.DeserializeObject<AuthRequestContent>(strBody);
                                encryptedData = content.EncryptedData;
                                userName = content.UserPrincipalName;
                                break;
                            default:
                                throw new Exception(String.Format("Unknown TrafficProtocol {0}", context.TrafficProtocol));
                        }

                        CreateAndSendClaims(encryptedData, settings.certificate, settings.url, userName, authRequest.RequestId, authRequest.TransactionId);
                    }

                    Console.WriteLine("ProxyListener disconnected: {0}", settings.url);
                }
                catch { }
                finally
                {
                    socket.Dispose();
                }
            }
        }

        // Send the authentication response
        private static void CreateAndSendClaims(IList<EncryptedData> encryptedData, X509Certificate2 certificate, string url, string userName, string requestId, string transactionId)
        {
            DecodePTACredential(encryptedData, certificate, userName, requestId);
        }
        
        // Starts the relay listener
        private static void StartRelayListener(object relaySettings)
        {
            RelaySettings settings = (RelaySettings)relaySettings;

            Hashtable proxies = new Hashtable();

            // Build the url
            string url = string.Format("wss://{0}/{1}servicebus/websocket", settings.hostName, '\x0024');

            // Create a socket and connect to it
            ClientWebSocket socket = new ClientWebSocket();

           
            try
            {
                socket.Options.ClientCertificates.Add(settings.certificate);
                socket.Options.AddSubProtocol("wsrelayedconnection");
                CancellationToken token = new CancellationToken();

                var connection = socket.ConnectAsync(new Uri(url), token);
                while (!connection.IsCompleted) { Thread.Sleep(1); };
                if (connection.IsFaulted.Equals("true"))
                {
                    Console.WriteLine("RelayListener failed to connect to {0}", settings.hostName);
                    return;
                }
                settings.socket = socket;
                settings.token = token;

                Console.WriteLine("RelayListener connected: {0} {1}", settings.hostName,settings.relayId);

                // Step 1: Send hello world message
                SendToSocket(socket, token, new RelayInit());

                // Step 2: Send RelayedAccept 
                SendToSocket(socket, token, new RelayedAccept(settings.relayId));

                Guid connectionId = Guid.Empty;
                Guid sequenceId = Guid.Empty;

                // Start the loop
                while (socket.State == WebSocketState.Open)
                {
                    ParsedMessage parsedMessage = AMQPParser.ParseRelayMessage(ReadFromSocket(socket, token, 8192));

                    // Something went wrong :(
                    if (parsedMessage == null)
                        return;

                    // Read the message
                    switch (parsedMessage["Type"].ToString())
                    {
                        case "RelayResponseError": // Something went wrong, bye!
                            return;
                        case "RelaySB":
                            break;
                        case "Disconnect":
                            // Close the socket
                            socket.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, "", token);
                            break;
                        case "CreateSequence":
                            string serviceBus = parsedMessage["To"].ToString();

                            connectionId = Guid.Parse(parsedMessage["MessageID"].ToString().Split(':')[2]);
                            sequenceId = Guid.Parse(parsedMessage["Identifier"].ToString().Split(':')[2]);
          
                            SendToSocket(socket, token, new CreateSequenceResponse(connectionId, Guid.NewGuid(), serviceBus));
                            break;
                        case "AckRequested":
                            Guid ARId = Guid.Parse(parsedMessage["Identifier"].ToString().Split(':')[2]);

                            SendToSocket(socket, token, new SequenceAcknowledgement(ARId));
                            break;
                        case "SignalConnector":
                            string host = parsedMessage["ReturnHost"].ToString();

                            Guid SCrelatesTo = Guid.Parse(parsedMessage["MessageID"].ToString().Split(':')[2]);
                            Guid SCId = Guid.Parse(parsedMessage["Identifier"].ToString().Split(':')[2]);

                            SendToSocket(socket, token, new SequenceAcknowledgement(SCId));
                            SendToSocket(socket, token, new SignalConnectorResponse(SCrelatesTo, sequenceId, Guid.NewGuid()));

                            ProxySettings ps = new ProxySettings();
                            ps.url = host;
                            ps.connectionId = parsedMessage["ConnectionId"].ToString();
                            ps.certificate = settings.certificate;
                            ps.transId = parsedMessage["TransactionId"].ToString();
                            new Thread(StartProxyListener).Start(ps);

                            break;
                        case "PasswordValidation":
                            //Console.WriteLine("Got PasswordValidation message for {0} and don't know what to do with it!!",parsedMessage["UserPrincipalName"]);
                            string PWhost = parsedMessage["ReturnHost"].ToString();

                            Guid PWrelatesTo = Guid.Parse(parsedMessage["MessageID"].ToString().Split(':')[2]);

                            //SendToSocket(socket, token, new SequenceAcknowledgement(SCId));
                            SendToSocket(socket, token, new SignalConnectorResponse(PWrelatesTo, Guid.Empty, Guid.NewGuid()));

                            ProxySettings PWps = new ProxySettings();
                            PWps.url = PWhost;
                            PWps.sessionId = parsedMessage["SessionId"].ToString();
                            PWps.certificate = settings.certificate;
                            PWps.transId = parsedMessage["TransactionId"].ToString();
                            PWps.requestId = parsedMessage["RequestId"].ToString();
                            PWps.encryptedData = (IList <EncryptedData>) parsedMessage["EncryptedData"];
                            PWps.userPrincipalName = parsedMessage["UserPrincipalName"].ToString();
                            new Thread(StartProxyListener).Start(PWps);
                            break;
                        case "RelayedAcceptReply":
                            SendToSocket(socket, token, new byte[] { 0x0B });
                            break;
                        case "RelayResponseOk":
                            break;
                        case "Fault":
                            Console.WriteLine("RelayListener {0} {1} Fault: {2}",settings.hostName,settings.relayId, parsedMessage["Reason"]);
                            break;
                    }

                }

                Console.WriteLine("RelayListener disconnecting: {0} {1}", settings.hostName, settings.relayId);
            }
            finally
            {
                socket.Dispose();
            }

        }

        // Starts the endpoint listener
        public static void StartEndpointListener(object endpointSettings)
        {
            Hashtable relays = new Hashtable();
            EndpointSettings settings = (EndpointSettings)endpointSettings;

            // Build the url
            string url = string.Format("wss://{0}.servicebus.windows.net/{1}servicebus/websocket", settings.nameSpace, '\x0024');

            // Create a socket and connect to it
            ClientWebSocket socket = new ClientWebSocket();
            socket.Options.ClientCertificates.Add(settings.certificate);
            socket.Options.AddSubProtocol("wsrelayedamqp");
            CancellationToken token = new CancellationToken();
            
            
            try{
                var connection = socket.ConnectAsync(new Uri(url), token);
                while (!connection.IsCompleted) { Thread.Sleep(1); };
                if (connection.IsFaulted.Equals("true"))
                {
                    Console.WriteLine("Listener {0}-{1} failed to connect to {2}", settings.number, settings.nameSpace, url);
                    return;
                }

                Console.WriteLine("EndpointListener connected: {0}-{1}", settings.number, url);

                // Define some needed ids
                string relayLinkGuid = Guid.NewGuid().ToString();
                string trackingId = Guid.NewGuid().ToString();
                string connectionId = Guid.NewGuid().ToString();

                /*
                 * SASL conversation
                 */

                ParsedMessage parsedMessage;
                // Send SASL protocol header
                SendToSocket(socket, token, new AMQPProtocolHeader(AMQPProtocol.SASL));
                parsedMessage = AMQPParser.ParseBusMessage(ReadFromSocket(socket, token));

                // Receive SASL mechanisms
                parsedMessage = AMQPParser.ParseBusMessage(ReadFromSocket(socket, token));

                // Step 4: Send SASL Init (external)
                SendToSocket(socket, token, new SASLInit());
                parsedMessage = AMQPParser.ParseBusMessage(ReadFromSocket(socket, token));

                /*
                 * AMQP starts
                 */

                // Send AMQP protocol header
                SendToSocket(socket, token, new AMQPProtocolHeader(AMQPProtocol.AMQP));
                parsedMessage = AMQPParser.ParseBusMessage(ReadFromSocket(socket, token));

                Thread.Sleep(1);

                // AMQP Open
                SendToSocket(socket, token, new AMQPOpen(string.Format("RelayConnection_{0}", connectionId), string.Format("{0}-relay.servicebus.windows.net", settings.nameSpace)));
                parsedMessage = AMQPParser.ParseBusMessage(ReadFromSocket(socket, token));
                string containerId = parsedMessage["ContainerId"].ToString();

                // AMQP Begin
                SendToSocket(socket, token, new AMQPBegin());
                parsedMessage = AMQPParser.ParseBusMessage(ReadFromSocket(socket, token));
           
                byte[] response;

                int handleIn = 0;
                int handleOut = 1;

                // AMQP Attach "out"
                string link = string.Format("RelayLink_{0}:{1}", relayLinkGuid, "out");
                string sbUrl = string.Format("sb://{0}.servicebus.windows.net/{1}/", settings.nameSpace, settings.servicePath);
                string sasUrl = string.Format("http://{0}.servicebus.windows.net/{1}/", settings.nameSpace, settings.servicePath);
                string sas = GetSASToken(sasUrl, settings.sharedAccessKey, settings.sharedAccessKeyName);

                SendToSocket(socket, token, new AMQPAttach(link, sbUrl, sas, trackingId, false, handleIn));
                

                // AMQP Attach "in"
                link = string.Format("RelayLink_{0}:{1}", relayLinkGuid, "in");
                SendToSocket(socket, token, new AMQPAttach(link, sbUrl, sas, trackingId, true, handleOut));
                
                // AMQP Flow "in"
                SendToSocket(socket, token, new AMQPFlow(handleIn));

                // AMQP Flow "out"
                SendToSocket(socket, token, new AMQPFlow(handleOut));

                int onewaySendMessages = 0;

                // Start the loop
                while(socket.State == WebSocketState.Open)
                {
                    // Send empty message to keep connection alive
                    SendToSocket(socket, token, new AMQPEmpty());

                    // Read the message
                    response = ReadFromSocket(socket, token, 1024,true);
                    parsedMessage = AMQPParser.ParseBusMessage(response);

                    if(parsedMessage != null && parsedMessage.ContainsKey("Type"))
                    {
                        switch (parsedMessage["Type"].ToString())
                        {
                            case "AMQP Flow":
                                break;
                            case "AMQP Attach":
                                break;
                            case "AMQP Detach":
                                // Close the socket
                                socket.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, "", token);
                                break;
                            case "AMQP Transfer":
                                // Check the size. If it's bigger than the message,
                                // the content is in the next frame
                                if ((int)parsedMessage["Size"] > parsedMessage.buffer.Length)
                                {
                                    // Read the next frame and parse it
                                    byte[] rawContent = ReadFromSocket(socket, token, 1024);
                                    int pos = 0;
                                    Hashtable content = (Hashtable)AMQPParser.ParseAMQPItem(rawContent, ref pos);

                                    byte onewaySendKey = 0x75;
                                    // Check if we have OnewaySend message
                                    if(content.ContainsKey(onewaySendKey))
                                    {
                                        // Send AMQP disposition message
                                        SendToSocket(socket, token, new AMQPDisposition(true, 0x24, onewaySendMessages++).ToByteArray());

                                        // Parse the message
                                        byte[] binOnewaySend = (byte[]) content[onewaySendKey];
                                        ParsedMessage onewaySend = AMQPParser.ParseRelayBinaryXml(binOnewaySend,0,true);

                                        // Check whether we already have a connection there
                                        string hostName = onewaySend["InstanceDnsAddress"].ToString();
                                        string relayId = onewaySend["Id"].ToString();


                                        bool newConnection = true;
                                        if (relays.ContainsKey(relayId))
                                        {
                                            RelaySettings rs = (RelaySettings)relays[relayId];
                                            if (rs.socket != null)
                                                lock (rs.socket)
                                                {
                                                    if (rs.socket.State == WebSocketState.Open)
                                                    {
                                                        // Send RelayedAccept message to existing connection
                                                        Console.WriteLine("Using existing RelayListener: {0} {1}", hostName,relayId);
                                                        SendToSocket(rs.socket, rs.token, new RelayedAccept(relayId));
                                                        newConnection = false;
                                                    }
                                                    else
                                                    {
                                                        relays.Remove(hostName);
                                                        Console.WriteLine("Removed existing RelayListener: {0}", relayId);
                                                    }
                                                }
                                        }
                                        
                                        if(newConnection)
                                        {
                                            
                                            RelaySettings rs = new RelaySettings(onewaySend, settings.certificate);
                                            relays[relayId] = rs;

                                            // Start a new relay listener thread
                                            new Thread(StartRelayListener).Start(rs);
                                        }

                                    }
                                    
                                }
                                break;
                            default:
                                break;
                        }
                    }

                    
                    
                    
                    Thread.Sleep(1);

                } ;

                Console.WriteLine("EndpointListener disconnected: {0}-{1}", settings.number, url);
            }
            finally
            {
                socket.Dispose();
            }
        }

      

        public static void SendToSocket(ClientWebSocket socket, CancellationToken token, AMQPItem message)
        {
            SendToSocket(socket, token, message.ToByteArray());

        }

        public static void SendToSocket(ClientWebSocket socket, CancellationToken token, byte[] message)
        {
            try
            {
                ArraySegment<byte> bytes = new ArraySegment<byte>(message);
                var connection = socket.SendAsync(bytes, WebSocketMessageType.Binary, true, token);
                while (!connection.IsCompleted) { Thread.Sleep(1); };
            }
            catch { }

            
        }

        public static byte[] ReadFromSocket(ClientWebSocket socket, CancellationToken token, int arraySize = 1024, bool keepAlive = false)
        {
            byte[] retval = null;
            try
            {
                byte[] emptyAMQPHeader = new byte[] { 0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00 };
                DateTime start = new DateTime();

                byte[] bytes = new byte[arraySize];
                ArraySegment<byte> buffer = new ArraySegment<byte>(bytes);

                var connection = socket.ReceiveAsync(buffer, token);
                while (!connection.IsCompleted)
                {
                    // Send the empty AMQP header to keep the connection alive
                    if (keepAlive && (new DateTime()).Subtract(start).Seconds > 30)
                    {
                        SendToSocket(socket, token, emptyAMQPHeader);
                        start = new DateTime();
                    }
                    Thread.Sleep(1);
                };

                retval = new byte[connection.Result.Count];
                Array.Copy(bytes, 0, retval, 0, connection.Result.Count);
            }
            catch { }

            return retval;
        }



    }

    public class EndpointSettings
    {
        public EndpointSettings()
        {

        }
        public int number { get; set; }
        public bool isAvailable { get; set; }
        public string name { get; set; }
        public string domain { get; set; }
        public string nameSpace { get; set; }
        public bool reliableSessionEnabled { get; set; }
        public string scheme { get; set; }
        public string servicePath { get; set; }
        public string sharedAccessKey { get; set; }
        public string sharedAccessKeyName { get; set; }
        public X509Certificate2 certificate { get; set; }
    }

    public class RelaySettings
    {
        public RelaySettings(ParsedMessage message, X509Certificate2 certificate)
        {
            this.hostName = (string) message["InstanceDnsAddress"];
            this.relayId = (string)message["Id"];
            this.certificate = certificate;
        }
        public RelaySettings()
        {}
        public string hostName { get; set; }
        public string relayId { get; set; }
        public X509Certificate2 certificate { get; set; }
        public CancellationToken token { get; set; }

        public ClientWebSocket socket { get; set; }
    }

    public class ProxySettings
    {
        public ProxySettings()
        {

        }
        public string url { get; set; }
        public string transId { get; set; }
        public string connectionId { get; set; }
        public string sessionId { get; set; }
        public X509Certificate2 certificate { get; set; }
        public IList<EncryptedData> encryptedData { get; set; }
        public string userPrincipalName { get; set; }
        public string requestId { get; set; }
    }

    public class Credentials
    {
        public Credentials()
        {
            this.timeStamp = DateTime.Now.ToUniversalTime();
        }
        public string userName { get; set; }
        public string traceId { get; set; }
        public string password { get; set; }

        public DateTime timeStamp { get; set; }

    }

    public class ProtocolContext
    {
        public int TrafficProtocol { get; set; }
        public IList<byte> BodyBytes { get; set; }

        // Only with TrafficProtocol2
        public IList<EncryptedData> EncryptedData { get; set; }
        public string UserPrincipalName { get; set; }
    }

    public class TunnelContext
    {
        public ProtocolContext ProtocolContext { get; set; }
        public string ConfigurationHash { get; set; }
        public string CorrelationId { get; set; }
        public bool HashPayload { get; set; }



    }
    public class AuthRequest
    {
        public TunnelContext TunnelContext { get; set; }
        public string RequestId { get; set; }
        public string SessionId { get; set; }
        public string SubscriptionId { get; set; }

        public string TransactionId { get; set; }
        public bool OverrideServiceHostEnabled { get; set; }
        public string OverridenReturnHost { get; set; }
        public string OverridenReturnPort { get; set; }
        public string ReturnHost { get; set; }
        public int ReturnPort { get; set; }
    }

    public class EncryptedData
    {
        public EncryptedData() { }
        public EncryptedData(string Base64EncryptedData, string KeyIdentifier)
        {
            this.Base64EncryptedData = Base64EncryptedData;
            this.KeyIdentifier = KeyIdentifier;
        }
        public string Base64EncryptedData { get; set; }
        // There's a TYPO here, missing an "i" - took ages to spot this
        public string KeyIdentifer
        {
            get { return KeyIdentifier; }
            set { KeyIdentifier = value; }
        }
        public string KeyIdentifier { get; set; } 
    }

    public class DecryptedPassword
    {
        public string Password { get; set; }
    }

    public class AuthRequestContent
    {
        public int TrafficProtocol { get; set; }
        public string Domain { get; set; }
        public string UserPrincipalName { get; set; }
        public IList<EncryptedData> EncryptedData { get; set; }
    }

}

