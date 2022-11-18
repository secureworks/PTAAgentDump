using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Secureworks.AMQP
{
    public class ParsedMessage : Hashtable 
    {
        public ParsedMessage(byte[] buffer)
        {
            this.buffer = buffer;
        }
        public byte[] buffer;
    }
    public static class AMQPParser
    {
        private static System.Xml.XmlDictionary serviceModelDictionary;

        public static ParsedMessage ParseRelayBinaryXml(byte[] bytes, int pos = 0, bool noSession = false)
        {

            ParsedMessage retVal = new ParsedMessage(bytes);
            retVal.Add("Type", "RelayMessage");

            System.Xml.XmlBinaryReaderSession session = null;
            if (!noSession)
            {
                session = new System.Xml.XmlBinaryReaderSession();
                // Get the size of the session information
                int infoSize = ParseMultiByteInt31(bytes, ref pos);
                int index = 0;
                while(pos < infoSize)
                {
                    int strSize = ParseMultiByteInt31(bytes, ref pos);
                    string str = "";

                    if (strSize > 0)
                    {
                        str = System.Text.Encoding.UTF8.GetString(bytes, pos, strSize);
                    }
                    session.Add(index, str);
                    pos += strSize;
                    index++;
                }
            }

            // Skip to the content
            bytes = bytes.Skip(pos).ToArray();

            // Convert from binary xml
            System.Xml.XmlDocument xmlEnvelope = new System.Xml.XmlDocument();
            System.Xml.XmlDictionaryReader envelopeReader = System.Xml.XmlDictionaryReader.CreateBinaryReader(bytes, 0, bytes.Length, GetDictionary(), System.Xml.XmlDictionaryReaderQuotas.Max, session);

           

            System.Xml.XmlNamespaceManager nsmgr = new System.Xml.XmlNamespaceManager(xmlEnvelope.NameTable);
            nsmgr.AddNamespace("a", "http://www.w3.org/2005/08/addressing");
            nsmgr.AddNamespace("b", "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalingDataModel");
            nsmgr.AddNamespace("netrm", "http://schemas.microsoft.com/ws/2006/05/rm");
            nsmgr.AddNamespace("i", "http://www.w3.org/2001/XMLSchema-instance");
            nsmgr.AddNamespace("r", "http://schemas.xmlsoap.org/ws/2005/02/rm");
            nsmgr.AddNamespace("s", "http://www.w3.org/2003/05/soap-envelope");

            string body="";
            try
            {
                xmlEnvelope.Load(envelopeReader);

                // Extract the header & body
                XmlNode headers = xmlEnvelope.SelectSingleNode("//s:Header", nsmgr);
                foreach (XmlNode header in headers.ChildNodes)
                {
                    retVal.Add(header.LocalName, header.InnerText);
                }
                body = xmlEnvelope.SelectSingleNode("//s:Body", nsmgr).InnerText;
                
                if (retVal.ContainsKey("Action"))
                    retVal["Type"] = retVal["Action"];
            }
            catch(Exception e) {
                // This probably Ping as it always fails do decode :(
                XmlDictionaryString dictString = null;
                session.TryLookup(0, out dictString);
                if (dictString != null && dictString.Value.Equals("Ping"))
                    retVal["Type"] = "Ping";
            }

            switch (retVal["Type"].ToString())
            {
                case "OnewaySend":
                    /*
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	                    <s:Header>
		                    <a:Action s:mustUnderstand="1">OnewaySend</a:Action>
		                    <RelayVia xmlns="http://schemas.microsoft.com/netservices/2009/05/servicebus/connect">sb://his-nam1-scus2.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</RelayVia>
		                    <a:MessageID>655e645f-7e22-4368-bf77-c7a17520f929_G7</a:MessageID>
		                    <a:To s:mustUnderstand="1">sb://his-nam1-scus2.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</a:To>
	                    </s:Header>
	                    <s:Body>VgILAXME[redacted]QBAQE=</s:Body>
                    </s:Envelope>
                     */
                    // Convert body from binary xml
                    byte[] binBody = Convert.FromBase64String(body);
                    System.Xml.XmlDocument xmlBody = new System.Xml.XmlDocument();
                    System.Xml.XmlDictionaryReader bodyReader = System.Xml.XmlDictionaryReader.CreateBinaryReader(binBody, 0, binBody.Length, GetDictionary(), System.Xml.XmlDictionaryReaderQuotas.Max);
                    xmlBody.Load(bodyReader);

                    // Extract parameters
                    /* Decoded body:
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	                    <s:Header>
		                    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/netservices/2009/05/servicebus/relayedconnect/RelayedConnect</a:Action>
		                    <a:To s:mustUnderstand="1">sb://his-nam1-ncus1.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</a:To>
	                    </s:Header>
	                    <s:Body>
		                    <RelayedConnect xmlns="http://schemas.microsoft.com/netservices/2009/05/servicebus/relayedconnect">
			                    <Id>39aadc47-3295-4a41-a886-51ad9e0cca37</Id>
			                    <IpAddress>2748520724</IpAddress>
			                    <IpPort>9352</IpPort>
			                    <HttpAddress>2748520724</HttpAddress>
			                    <HttpPort>80</HttpPort>
			                    <HttpsAddress>2748520724</HttpsAddress>
			                    <HttpsPort>443</HttpsPort>
			                    <InstanceDnsAddress>g17-prod-ch3-006-sb.servicebus.windows.net</InstanceDnsAddress>
		                    </RelayedConnect>
	                    </s:Body>
                    </s:Envelope>
                     */
                    XmlNode bodyNode = xmlBody.SelectSingleNode("//s:Body", nsmgr);
                    if (bodyNode != null)
                    {
                        XmlNode relayedConnect = bodyNode.FirstChild;
                        if (relayedConnect != null)
                        {
                            foreach (XmlNode parameter in relayedConnect.ChildNodes)
                            {
                                string key = parameter.LocalName;
                                string value = parameter.InnerText;
                                if (key.Equals("IpAddress") || key.Equals("HttpAddress") || key.Equals("HttpsAddress"))
                                    value = IntToIp(value);
                                retVal.Add(key, value);
                            }
                        }
                    }
                    break;
                case "RelayedAcceptReply":
                    /*
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
                        <s:Header>
                            <a:Action s:mustUnderstand="1">RelayedAcceptReply</a:Action>
                        </s:Header>
                        <s:Body>
                            <z:anyType xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"/>
                        </s:Body>
                    </s:Envelope>
                     */
                    break;
                case "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence":
                    /*
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	                    <s:Header>
		                    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence</a:Action>
		                    <a:MessageID>urn:uuid:7c4071d7-4bb0-4993-ae33-4d94ac4f844d</a:MessageID>
		                    <a:To s:mustUnderstand="1">sb://his-nam1-wus2.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</a:To>
	                    </s:Header>
	                    <s:Body>
		                    <CreateSequence xmlns="http://schemas.xmlsoap.org/ws/2005/02/rm">
			                    <AcksTo>
				                    <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
			                    </AcksTo>
			                    <Offer>
				                    <Identifier>urn:uuid:da98a5eb-4130-427d-a1a3-09fe238623b4</Identifier>
			                    </Offer>
		                    </CreateSequence>
	                    </s:Body>
                    </s:Envelope>
                     */
                    retVal["Type"] = "CreateSequence";
                    try
                    {
                        retVal.Add("Identifier", xmlEnvelope.GetElementsByTagName("Identifier")[0].InnerText);
                    }
                    catch{};
                    break;

                case "http://tempuri.org/IConnectorSignalingService/SignalConnector":

                    switch (xmlEnvelope.GetElementsByTagName("TrafficProtocol")[0].InnerText)
                    {
                        case "Connect":
                            /*
                            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:r="http://schemas.xmlsoap.org/ws/2005/02/rm" xmlns:a="http://www.w3.org/2005/08/addressing">
                                <s:Header>
                                    <r:AckRequested>
                                        <r:Identifier>urn:uuid:00000000-0000-0000-0000-000000000000</r:Identifier>
                                    </r:AckRequested>
                                    <r:Sequence s:mustUnderstand="1">
                                        <r:Identifier>urn:uuid:00000000-0000-0000-0000-000000000000</r:Identifier>
                                        <r:MessageNumber>1</r:MessageNumber>
                                    </r:Sequence>
                                    <a:Action s:mustUnderstand="1">http://tempuri.org/IConnectorSignalingService/SignalConnector</a:Action>
                                    <a:MessageID>urn:uuid:23f43182-7b11-4bbf-981a-8d0fc078b8c1</a:MessageID>
                                    <a:ReplyTo>
                                        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
                                    </a:ReplyTo>
                                    <a:To s:mustUnderstand="1">sb://his-nam1-wus2.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</a:To>
                                </s:Header>
                                <s:Body>
                                    <SignalConnector xmlns="http://tempuri.org/">
                                        <messageProperties xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalingDataModel" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                                            <RequestId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">2f2ab3af-5e56-45a7-865e-bb3243f06d00</RequestId>
                                            <SessionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">00000000-0000-0000-0000-000000000000</SessionId>
                                            <SubscriptionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">[redacted]</SubscriptionId>
                                            <TransactionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">9c3f0681-e562-4d1d-8f4c-9ef5357ba040</TransactionId>
                                            <b:OverrideServiceHostEnabled>true</b:OverrideServiceHostEnabled>
                                            <b:OverridenReturnHost>vm7-proxy-pta-WUS-SJC01P-3.connector.his.msappproxy.net</b:OverridenReturnHost>
                                            <b:OverridenReturnPort>443</b:OverridenReturnPort>
                                            <b:ReturnHost>vm7-proxy-pta-WUS-SJC01P-3.connector.his.msappproxy.net</b:ReturnHost>
                                            <b:ReturnPort>10100</b:ReturnPort>
                                            <b:TunnelContext>
                                                <ConfigurationHash xmlns="">-139793387</ConfigurationHash>
                                                <CorrelationId xmlns="">9c3f0681-e562-4d1d-8f4c-9ef5357ba040</CorrelationId>
                                                <HasPayload xmlns="">false</HasPayload>
                                                <ProtocolContext i:type="ConnectContext" xmlns="">
                                                    <TrafficProtocol>Connect</TrafficProtocol>
                                                    <ConnectionId>8457828f-e336-44bf-b967-4044b1478cc1</ConnectionId>
                                                </ProtocolContext>
                                            </b:TunnelContext>
                                        </messageProperties>
                                    </SignalConnector>
                                </s:Body>
                            </s:Envelope>
                            */

                            retVal["Type"] = "SignalConnector";
                            try
                            {
                                retVal.Add("Identifier", xmlEnvelope.GetElementsByTagName("r:Identifier")[0].InnerText);
                                retVal.Add("MessageNumber", xmlEnvelope.GetElementsByTagName("r:MessageNumber")[0].InnerText);
                                retVal.Add("RequestId", xmlEnvelope.GetElementsByTagName("RequestId")[0].InnerText);
                                retVal.Add("SessionId", xmlEnvelope.GetElementsByTagName("SessionId")[0].InnerText);
                                retVal.Add("SubscriptionId", xmlEnvelope.GetElementsByTagName("SubscriptionId")[0].InnerText);
                                retVal.Add("TransactionId", xmlEnvelope.GetElementsByTagName("TransactionId")[0].InnerText);
                                retVal.Add("ConnectionId", xmlEnvelope.GetElementsByTagName("ConnectionId")[0].InnerText);
                                retVal.Add("ReturnHost", xmlEnvelope.GetElementsByTagName("b:ReturnHost")[0].InnerText);
                                retVal.Add("ReturnPort", xmlEnvelope.GetElementsByTagName("b:ReturnPort")[0].InnerText);
                            }
                            catch { };
                            break;
                        case "PasswordValidation":
                            /*
                            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	                            <s:Header>
		                            <a:Action s:mustUnderstand="1">http://tempuri.org/IConnectorSignalingService/SignalConnector</a:Action>
		                            <a:MessageID>urn:uuid:5a445862-847b-44f6-a076-3a42ba286999</a:MessageID>
		                            <a:ReplyTo>
			                            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		                            </a:ReplyTo>
		                            <a:To s:mustUnderstand="1">sb://his-nam1-wus2.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7</a:To>
	                            </s:Header>
	                            <s:Body>
		                            <SignalConnector xmlns="http://tempuri.org/">
			                            <messageProperties xmlns:b="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalingDataModel" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
				                            <RequestId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">dff0f331-bb52-4cd0-9b6f-b741343d6d00</RequestId>
				                            <SessionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">00000000-0000-0000-0000-000000000000</SessionId>
				                            <SubscriptionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">[redacted]</SubscriptionId>
				                            <TransactionId xmlns="http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.RequestContexts">41bf611b-36d5-42d3-9151-2be2477279f4</TransactionId>
				                            <b:OverrideServiceHostEnabled>true</b:OverrideServiceHostEnabled>
				                            <b:OverridenReturnHost>vm4-proxy-pta-WUS-SJC01P-3.connector.his.msappproxy.net</b:OverridenReturnHost>
				                            <b:OverridenReturnPort>443</b:OverridenReturnPort>
				                            <b:ReturnHost>vm4-proxy-pta-WUS-SJC01P-3.connector.his.msappproxy.net</b:ReturnHost>
				                            <b:ReturnPort>10100</b:ReturnPort>
				                            <b:TunnelContext>
					                            <ConfigurationHash xmlns="">-139793387</ConfigurationHash>
					                            <CorrelationId xmlns="">41bf611b-36d5-42d3-9151-2be2477279f4</CorrelationId>
					                            <HasPayload xmlns="">false</HasPayload>
					                            <ProtocolContext i:type="PasswordValidationContext" xmlns="">
						                            <TrafficProtocol>PasswordValidation</TrafficProtocol>
						                            <Domain>AADSECURITY</Domain>
						                            <EncryptedData>
							                            <b:EncryptedOnPremValidationData>
								                            <b:Base64EncryptedData>qopI[redacted]K4NFs8fgmzNaA0XL41w==</b:Base64EncryptedData>
								                            <b:KeyIdentifer>[redacted]_44C483C48946CF3BAC85D22018EB134FB4B6460D</b:KeyIdentifer>
							                            </b:EncryptedOnPremValidationData>
							                            <b:EncryptedOnPremValidationData>
								                            <b:Base64EncryptedData>QZdwL[redacted]nP94w4/meAYX0w==</b:Base64EncryptedData>
								                            <b:KeyIdentifer>[redacted]_0CAF09C29EFA51DAFA91528949B253F977ED763D</b:KeyIdentifer>
							                            </b:EncryptedOnPremValidationData>
							                            <b:EncryptedOnPremValidationData>
								                            <b:Base64EncryptedData>flQwZQ[redacted]EtAetg==</b:Base64EncryptedData>
								                            <b:KeyIdentifer>[redacted]_893657AEAE25D4C913BCF37CB138628772BE1B52</b:KeyIdentifer>
							                            </b:EncryptedOnPremValidationData>
						                            </EncryptedData>
						                            <Password/>
						                            <UserPrincipalName>AllanD@[redacted]</UserPrincipalName>
					                            </ProtocolContext>
				                            </b:TunnelContext>
			                            </messageProperties>
		                            </SignalConnector>
	                            </s:Body>
                            </s:Envelope>
                            */

                            retVal["Type"] = "PasswordValidation";
                            try
                            {
                                retVal.Add("RequestId", xmlEnvelope.GetElementsByTagName("RequestId")[0].InnerText);
                                retVal.Add("SessionId", xmlEnvelope.GetElementsByTagName("SessionId")[0].InnerText);
                                retVal.Add("SubscriptionId", xmlEnvelope.GetElementsByTagName("SubscriptionId")[0].InnerText);
                                retVal.Add("TransactionId", xmlEnvelope.GetElementsByTagName("TransactionId")[0].InnerText);
                                retVal.Add("CorrelationId", xmlEnvelope.GetElementsByTagName("CorrelationId")[0].InnerText);
                                retVal.Add("ReturnHost", xmlEnvelope.GetElementsByTagName("b:ReturnHost")[0].InnerText);
                                retVal.Add("ReturnPort", xmlEnvelope.GetElementsByTagName("b:ReturnPort")[0].InnerText);

                                retVal.Add("UserPrincipalName", xmlEnvelope.GetElementsByTagName("UserPrincipalName")[0].InnerText);

                                var encData = xmlEnvelope.GetElementsByTagName("b:Base64EncryptedData");
                                var identifiers = xmlEnvelope.GetElementsByTagName("b:KeyIdentifer");

                                IList<EncryptedData> encryptedData = new List<EncryptedData>();

                                for (int a = 0; a < encData.Count; a++)
                                {
                                    encryptedData.Add(new EncryptedData(encData[a].InnerText, identifiers[a].InnerText));
                                }
                                retVal.Add("EncryptedData", encryptedData);
                            }
                            catch { };
                            break;
                    }
                    break;

                case "http://www.w3.org/2005/08/addressing/soap/fault":
                    /*
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	                    <s:Header>
		                    <a:Action s:mustUnderstand="1">http://www.w3.org/2005/08/addressing/soap/fault</a:Action>
		                    <a:To s:mustUnderstand="1">sb://his-nam1-ncus1.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</a:To>
	                    </s:Header>
	                    <s:Body>
		                    <s:Fault>
			                    <s:Code>
				                    <s:Value>s:Sender</s:Value>
				                    <s:Subcode>
					                    <s:Value xmlns:a="http://schemas.xmlsoap.org/ws/2005/02/rm">a:UnknownSequence</s:Value>
				                    </s:Subcode>
			                    </s:Code>
			                    <s:Reason>
				                    <s:Text xml:lang="en-US">The value of wsrm:Identifier is not a known Sequence identifier.</s:Text>
			                    </s:Reason>
			                    <s:Detail>
				                    <r:Identifier xmlns:r="http://schemas.xmlsoap.org/ws/2005/02/rm">urn:uuid:4213aeec-4fa2-459e-89d4-5fa8e58cf1bb</r:Identifier>
			                    </s:Detail>
		                    </s:Fault>
	                    </s:Body>
                    </s:Envelope>
                     */
                    retVal["Type"] = "Fault";
                    try
                    {
                        retVal.Add("Value", xmlEnvelope.GetElementsByTagName("s:Value")[0].InnerText);
                        retVal.Add("Reason", xmlEnvelope.GetElementsByTagName("s:Text")[0].InnerText);
                    }
                    catch { };
                    break;
                case "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested":
                    /*
                    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:r="http://schemas.xmlsoap.org/ws/2005/02/rm" xmlns:a="http://www.w3.org/2005/08/addressing">
	                    <s:Header>
		                    <r:AckRequested>
			                    <r:Identifier>urn:uuid:bcb65644-d0f1-4a11-adaf-ff844eb5f4ea</r:Identifier>
		                    </r:AckRequested>
		                    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested</a:Action>
		                    <a:To s:mustUnderstand="1">sb://his-nam1-wus2.servicebus.windows.net/[redacted]_17d93d40-1389-4f69-b6f6-dcaedfdc4bb7_reliable</a:To>
	                    </s:Header>
	                    <s:Body/>
                    </s:Envelope>
                     */
                    retVal["Type"] = "AckRequested";
                    try
                    {
                        retVal.Add("Identifier", xmlEnvelope.GetElementsByTagName("r:Identifier")[0].InnerText);
                        retVal.Add("To", xmlEnvelope.GetElementsByTagName("a:To")[0].InnerText);
                    }
                    catch { };
                    break;
            }


            return retVal;
        }


        public static ParsedMessage ParseBusMessage(byte[] bytes)
        {
            if (bytes == null)
                return null;
            else if (Enumerable.SequenceEqual(bytes.Take(2), new byte[2] { 0x41, 0x4d }))
            {
                // This is version negotiation message
                // Construct the message object
                ParsedMessage message = new ParsedMessage(bytes);

                string type = "";
                switch (bytes[4])
                {
                    case 0: type = "AMQP"; break;
                    case 1: type = "AMQP"; break;
                    case 2: type = "TLS"; break;
                    case 3: type = "SASL"; break;
                }
                message.Add("Type", "Protocol " + type);
                message.Add("Protocol", bytes[4]);
                message.Add("Major", bytes[5]);
                message.Add("Minor", bytes[6]);
                message.Add("Revision", bytes[7]);

                return message;
            }
            else
            {
                return ParseAMQPFrame(bytes);
            }
        }

        public static ParsedMessage ParseRelayMessage(byte[] bytes)
        {
            ParsedMessage retVal = null;
            if(bytes != null && bytes.Length > 3)
            {
                switch(bytes[0])
                {
                    case 0x56: // Binary xml without header &session data (Starts with 0x56)
                        retVal = ParseRelayBinaryXml(bytes,0,true);
                        break;
                    case 0x06: // "Normal" relay message
                        int pos = 1;
                        // Extract the size of the message
                        int size = ParseMultiByteInt31(bytes, ref pos);
                        // Parse the binary message
                        retVal = ParseRelayBinaryXml(bytes, pos);
                        break;
                    case 0x07: // Disconnect 
                        retVal.Add("Type", "Disconnect");
                        break;
                    case 0xAA: // Something went wrong
                        retVal = new ParsedMessage(bytes);
                        retVal.Add("Type", "RelayResponseError");
                        break;
                    case 0x98: // Something went okay
                        retVal = new ParsedMessage(bytes);
                        retVal.Add("Type", "RelayResponseOk");
                        break;
                    case 0x00: // Some weirdo message containing SB url
                        /*
                                   00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

                        00000000   00 01 00 01 02 02 7C 73 62 3A 2F 2F 68 69 73 2D  ......|sb://his-
                        00000010   6E 61 6D 31 2D 65 75 73 31 2E 73 65 72 76 69 63  nam1-eus1.servic
                        00000020   65 62 75 73 2E 77 69 6E 64 6F 77 73 2E 6E 65 74  ebus.windows.net
                        00000030   2F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  /[redacted]
                        00000040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  [redacted]
                        00000050   00 00 00 00 00 5F 31 37 64 39 33 64 34 30 2D 31  xxxxx_17d93d40-1
                        00000060   33 38 39 2D 34 66 36 39 2D 62 36 66 36 2D 64 63  389-4f69-b6f6-dc
                        00000070   61 65 64 66 64 63 34 62 62 37 5F 72 65 6C 69 61  aedfdc4bb7_relia
                        00000080   62 6C 65 03 08 0C                                ble... 
                         */
                        retVal = new ParsedMessage(bytes);
                        retVal.Add("Type", "RelaySB");
                        int sbSize = bytes[6];
                        retVal.Add("SB",System.Text.Encoding.UTF8.GetString(bytes, 7, sbSize));
                        break;
                }
            }
            return retVal;
        }

        public static byte[] IntToMultibyteInt32(int value)
        {
            // Get required byte array size
            if (value < 0)
                throw new ArgumentOutOfRangeException("value", value, "ValueMustBeNonNegative");

            int tmpVal = value;
            int size = 1;
            unchecked
            {
                while (((long)tmpVal & (long)((ulong)-128)) != 0L)
                {
                    size++;
                    tmpVal >>= 7;
                }
            }

            byte[] bytes = new byte[size];
            int offset = 0;
            unchecked
            {
                while (((long)value & (long)((ulong)-128)) != 0L)
                {
                    bytes[offset++] = (byte)((value & 127) | 128);
                    value >>= 7;
                }
            }
            bytes[offset] = (byte)value;

            return bytes;
        }
        public static int ParseMultiByteInt31(byte[] bytes, ref int offset)
        {
            int i = 0;
            int retVal = 0;
            int index = 0;
            while (i < bytes.Length)
            {
                int num = (int)bytes[offset];
                retVal |= (num & 127) << (int)(index * 7);

                offset++;
                i++;
                if (index == 4 && (num & 248) != 0)
                    throw new Exception("Invalid size");

                index++;
                if ((num & 128) == 0)
                    break;
            }
            return retVal;
        }

        public static System.Xml.XmlDictionary GetDictionary()
        {

            if (serviceModelDictionary == null)
            {
                serviceModelDictionary = new System.Xml.XmlDictionary();
                lock (serviceModelDictionary)
                {
                    string[] serviceModelStringsVersion1 = { "mustUnderstand", "Envelope", "http://www.w3.org/2003/05/soap-envelope", "http://www.w3.org/2005/08/addressing", "Header", "Action", "To", "Body", "Algorithm", "RelatesTo", "http://www.w3.org/2005/08/addressing/anonymous", "URI", "Reference", "MessageID", "Id", "Identifier", "http://schemas.xmlsoap.org/ws/2005/02/rm", "Transforms", "Transform", "DigestMethod", "DigestValue", "Address", "ReplyTo", "SequenceAcknowledgement", "AcknowledgementRange", "Upper", "Lower", "BufferRemaining", "http://schemas.microsoft.com/ws/2006/05/rm", "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement", "SecurityTokenReference", "Sequence", "MessageNumber", "http://www.w3.org/2000/09/xmldsig#", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "KeyInfo", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "http://www.w3.org/2001/04/xmlenc#", "http://schemas.xmlsoap.org/ws/2005/02/sc", "DerivedKeyToken", "Nonce", "Signature", "SignedInfo", "CanonicalizationMethod", "SignatureMethod", "SignatureValue", "DataReference", "EncryptedData", "EncryptionMethod", "CipherData", "CipherValue", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Security", "Timestamp", "Created", "Expires", "Length", "ReferenceList", "ValueType", "Type", "EncryptedHeader", "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd", "RequestSecurityTokenResponseCollection", "http://schemas.xmlsoap.org/ws/2005/02/trust", "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret", "http://schemas.microsoft.com/ws/2006/02/transactions", "s", "Fault", "MustUnderstand", "role", "relay", "Code", "Reason", "Text", "Node", "Role", "Detail", "Value", "Subcode", "NotUnderstood", "qname", "", "From", "FaultTo", "EndpointReference", "PortType", "ServiceName", "PortName", "ReferenceProperties", "RelationshipType", "Reply", "a", "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity", "Identity", "Spn", "Upn", "Rsa", "Dns", "X509v3Certificate", "http://www.w3.org/2005/08/addressing/fault", "ReferenceParameters", "IsReferenceParameter", "http://www.w3.org/2005/08/addressing/reply", "http://www.w3.org/2005/08/addressing/none", "Metadata", "http://schemas.xmlsoap.org/ws/2004/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous", "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault", "http://schemas.xmlsoap.org/ws/2004/06/addressingex", "RedirectTo", "Via", "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList", "InclusiveNamespaces", "ec", "SecurityContextToken", "Generation", "Label", "Offset", "Properties", "Cookie", "wsc", "http://schemas.xmlsoap.org/ws/2004/04/sc", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT", "RenewNeeded", "BadContextToken", "c", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk", "http://schemas.xmlsoap.org/ws/2005/02/sc/sct", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes128", "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes192", "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes256", "http://www.w3.org/2001/04/xmlenc#des-cbc", "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", "http://www.w3.org/2000/09/xmldsig#hmac-sha1", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1", "http://www.w3.org/2001/04/xmlenc#ripemd160", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#rsa-1_5", "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "http://www.w3.org/2001/04/xmlenc#kw-tripledes", "http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap", "http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap", "http://schemas.microsoft.com/ws/2006/05/security", "dnse", "o", "Password", "PasswordText", "Username", "UsernameToken", "BinarySecurityToken", "EncodingType", "KeyIdentifier", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID", "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion", "http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license", "FailedAuthentication", "InvalidSecurityToken", "InvalidSecurity", "k", "SignatureConfirmation", "TokenType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", "AUTH-HASH", "RequestSecurityTokenResponse", "KeySize", "RequestedTokenReference", "AppliesTo", "Authenticator", "CombinedHash", "BinaryExchange", "Lifetime", "RequestedSecurityToken", "Entropy", "RequestedProofToken", "ComputedKey", "RequestSecurityToken", "RequestType", "Context", "BinarySecret", "http://schemas.xmlsoap.org/ws/2005/02/trust/spnego", " http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego", "wst", "http://schemas.xmlsoap.org/ws/2004/04/trust", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce", "KeyType", "http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey", "Claims", "InvalidRequest", "RequestFailed", "SignWith", "EncryptWith", "EncryptionAlgorithm", "CanonicalizationAlgorithm", "ComputedKeyAlgorithm", "UseKey", "http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego", "http://schemas.microsoft.com/net/2004/07/secext/TLSNego", "t", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce", "RenewTarget", "CancelTarget", "RequestedTokenCancelled", "RequestedAttachedReference", "RequestedUnattachedReference", "IssuedTokens", "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey", "Access", "AccessDecision", "Advice", "AssertionID", "AssertionIDReference", "Attribute", "AttributeName", "AttributeNamespace", "AttributeStatement", "AttributeValue", "Audience", "AudienceRestrictionCondition", "AuthenticationInstant", "AuthenticationMethod", "AuthenticationStatement", "AuthorityBinding", "AuthorityKind", "AuthorizationDecisionStatement", "Binding", "Condition", "Conditions", "Decision", "DoNotCacheCondition", "Evidence", "IssueInstant", "Issuer", "Location", "MajorVersion", "MinorVersion", "NameIdentifier", "Format", "NameQualifier", "Namespace", "NotBefore", "NotOnOrAfter", "saml", "Statement", "Subject", "SubjectConfirmation", "SubjectConfirmationData", "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key", "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches", "SubjectLocality", "DNSAddress", "IPAddress", "SubjectStatement", "urn:oasis:names:tc:SAML:1.0:am:unspecified", "xmlns", "Resource", "UserName", "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", "EmailName", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "u", "ChannelInstance", "http://schemas.microsoft.com/ws/2005/02/duplex", "Encoding", "MimeType", "CarriedKeyName", "Recipient", "EncryptedKey", "KeyReference", "e", "http://www.w3.org/2001/04/xmlenc#Element", "http://www.w3.org/2001/04/xmlenc#Content", "KeyName", "MgmtData", "KeyValue", "RSAKeyValue", "Modulus", "Exponent", "X509Data", "X509IssuerSerial", "X509IssuerName", "X509SerialNumber", "X509Certificate", "AckRequested", "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested", "AcksTo", "Accept", "CreateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence", "CreateSequenceRefused", "CreateSequenceResponse", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse", "FaultCode", "InvalidAcknowledgement", "LastMessage", "http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage", "LastMessageNumberExceeded", "MessageNumberRollover", "Nack", "netrm", "Offer", "r", "SequenceFault", "SequenceTerminated", "TerminateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence", "UnknownSequence", "http://schemas.microsoft.com/ws/2006/02/tx/oletx", "oletx", "OleTxTransaction", "PropagationToken", "http://schemas.xmlsoap.org/ws/2004/10/wscoor", "wscoor", "CreateCoordinationContext", "CreateCoordinationContextResponse", "CoordinationContext", "CurrentContext", "CoordinationType", "RegistrationService", "Register", "RegisterResponse", "ProtocolIdentifier", "CoordinatorProtocolService", "ParticipantProtocolService", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault", "ActivationCoordinatorPortType", "RegistrationCoordinatorPortType", "InvalidState", "InvalidProtocol", "InvalidParameters", "NoActivity", "ContextRefused", "AlreadyRegistered", "http://schemas.xmlsoap.org/ws/2004/10/wsat", "wsat", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC", "Prepare", "Prepared", "ReadOnly", "Commit", "Rollback", "Committed", "Aborted", "Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared", "http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/fault", "CompletionCoordinatorPortType", "CompletionParticipantPortType", "CoordinatorPortType", "ParticipantPortType", "InconsistentInternalState", "mstx", "Enlistment", "protocol", "LocalTransactionId", "IsolationLevel", "IsolationFlags", "Description", "Loopback", "RegisterInfo", "ContextId", "TokenId", "AccessDenied", "InvalidPolicy", "CoordinatorRegistrationFailed", "TooManyEnlistments", "Disabled", "ActivityId", "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1", "http://schemas.xmlsoap.org/ws/2002/12/policy", "FloodMessage", "LinkUtility", "Hops", "http://schemas.microsoft.com/net/2006/05/peer/HopCount", "PeerVia", "http://schemas.microsoft.com/net/2006/05/peer", "PeerFlooder", "PeerTo", "http://schemas.microsoft.com/ws/2005/05/routing", "PacketRoutable", "http://schemas.microsoft.com/ws/2005/05/addressing/none", "http://schemas.microsoft.com/ws/2005/05/envelope/none", "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/2001/XMLSchema", "nil", "type", "char", "boolean", "byte", "unsignedByte", "short", "unsignedShort", "int", "unsignedInt", "long", "unsignedLong", "float", "double", "decimal", "dateTime", "string", "base64Binary", "anyType", "duration", "guid", "anyURI", "QName", "time", "date", "hexBinary", "gYearMonth", "gYear", "gMonthDay", "gDay", "gMonth", "integer", "positiveInteger", "negativeInteger", "nonPositiveInteger", "nonNegativeInteger", "normalizedString", "ConnectionLimitReached", "http://schemas.xmlsoap.org/soap/envelope/", "actor", "faultcode", "faultstring", "faultactor", "detail" };
                    foreach (string word in serviceModelStringsVersion1)
                    {
                        serviceModelDictionary.Add(word);
                    }
                }
            }

            return serviceModelDictionary;
        }

        
        // Tries to convert the given ipaddress integer to proper ip address
        private static string IntToIp(string ipAddress)
        {
            string retVal = ipAddress;

            try
            {
                uint uintAddress;
                uint.TryParse(ipAddress,out uintAddress);
                byte[] bytes = BitConverter.GetBytes(uintAddress);
                Array.Reverse(bytes);
                retVal = new System.Net.IPAddress(bytes).ToString();
            }
            catch { };

            return retVal;
        }

        public static Object ParseAMQPError(Object error)
        {
            Object retVal = error;
            if (error != null)
            {
                IEnumerator e = ((Array)error).GetEnumerator();
                if (e.MoveNext())
                {
                    retVal = ((Array)e.Current).GetValue(0);
                }
            }
            
            return retVal;
        }


        public static ParsedMessage ParseAMQPFrame(byte[] bytes)
        {
            //  Parse the header
            byte[] sizeBytes = bytes.Take(4).ToArray();
            Array.Reverse(sizeBytes);
            int DOff = bytes[4];
            ParsedMessage message = new ParsedMessage(bytes)
            {
                { "Size", BitConverter.ToInt32(sizeBytes, 0) },
                { "DOFF", DOff },
                { "Extended Header", bytes.Skip(8).Take(DOff * 4).ToArray() }
            };

            int pos = DOff * 4 + 2;

            // AQMP Frame
            if (bytes[5] == 0x00)
            {
                message.Add("Type", "AMQP");

                // Channel
                byte[] channelBytes = bytes.Skip(6).Take(2).ToArray();
                Array.Reverse(channelBytes);
                int channel = BitConverter.ToUInt16(channelBytes, 0);
                message.Add("Channel", channel);

                Array content = null;

                switch (bytes[pos++])
                {
                    case 0x10:
                        message["Type"] = "AMQP Open";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("ContainerId", content.GetValue(0));
                        message.Add("HostName", content.GetValue(1));
                        message.Add("MaxFrameSize", content.GetValue(2));
                        message.Add("ChannelMax", content.GetValue(3));
                        message.Add("IdleTimeOut", content.GetValue(4));
                        message.Add("OutgoingLocales", content.GetValue(5));
                        message.Add("IncomingLocales", content.GetValue(6));
                        message.Add("OfferedCapabilities", content.GetValue(7));
                        message.Add("DesiredCapabilities", content.GetValue(8));
                        message.Add("Properties", content.GetValue(9));
                        break;
                    case 0x11:
                        message["Type"] = "AMQP Begin";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("RemoteChannel", content.GetValue(0));
                        message.Add("NextOutgoingId", content.GetValue(1));
                        message.Add("IncomingWindow", content.GetValue(2));
                        message.Add("OutgoingWindow", content.GetValue(3));
                        message.Add("HandleMax", content.GetValue(4));
                        message.Add("OfferedCapabilities", content.GetValue(5));
                        message.Add("DesiredCapabilities", content.GetValue(6));
                        message.Add("Properties", content.GetValue(7));
                        break;
                    case 0x12:
                        message["Type"] = "AMQP Attach";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("Name", content.GetValue(0));
                        message.Add("Handle", content.GetValue(1));

                        // Direction
                        int targetPos = 0;
                        message.Add("Direction", "out");
                        if (content.GetValue(2).ToString().Equals("True"))
                        {
                            message["Direction"] = "in";
                            targetPos = -1;
                        }

                        // Target
                        Hashtable values = (Hashtable)content.GetValue(6 + targetPos);
                        IEnumerator e = values.Values.GetEnumerator();
                        if (e.MoveNext())
                        {
                            message.Add("Target", ((Array)e.Current).GetValue(0));
                        }

                        // Tracking id
                        values = (Hashtable)content.GetValue(13);
                        e = values.Values.GetEnumerator();
                        if (e.MoveNext())
                        {
                            message.Add("TrackingId", e.Current);
                        }
                        break;
                    case 0x13:
                        message["Type"] = "AMQP Flow";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("NextIncomingId", content.GetValue(0));
                        message.Add("IncomingWindow", content.GetValue(1));
                        message.Add("NextOutgoingId", content.GetValue(2));
                        message.Add("OutgoingWindow", content.GetValue(3));
                        message.Add("Handle", content.GetValue(4));
                        message.Add("DeliveryCount", content.GetValue(5));
                        message.Add("LinkCredit", content.GetValue(6));
                        message.Add("Available", content.GetValue(7));
                        message.Add("Drain", content.GetValue(8));
                        message.Add("Echo", content.GetValue(9));
                        message.Add("Properties", content.GetValue(10));
                        break;
                    case 0x14:
                        message["Type"] = "AMQP Transfer";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("Handle", content.GetValue(0));
                        message.Add("DeliveryId", content.GetValue(1));
                        message.Add("DeliveryTag", content.GetValue(2));
                        message.Add("MessageFormat", content.GetValue(3));
                        message.Add("Settled", content.GetValue(4));
                        message.Add("More", content.GetValue(5));
                        message.Add("RcvSettleMode", content.GetValue(6));
                        message.Add("State", content.GetValue(7));
                        message.Add("Resume", content.GetValue(8));
                        message.Add("Aborted", content.GetValue(9));
                        message.Add("Batchable", content.GetValue(10));
                        break;
                    case 0x15:
                        message["Type"] = "AMQP Disposition";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("Role", content.GetValue(0));
                        message.Add("First", content.GetValue(1));
                        message.Add("Last", content.GetValue(2));
                        message.Add("Settled", content.GetValue(3));
                        message.Add("State", content.GetValue(4));
                        message.Add("Batchable", content.GetValue(5));
                        break;
                    case 0x16:
                        message["Type"] = "AMQP Detach";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        message.Add("Handle", content.GetValue(0));
                        message.Add("Closed", content.GetValue(1));
                        if(content.Length > 2)
                            message.Add("Error", content.GetValue(2));
                        break;
                    case 0x17:
                        message["Type"] = "AMQP End";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        if (content != null)
                        {
                            message.Add("Error", ParseAMQPError((byte[])content.GetValue(0)));
                        }
                        else
                        {
                            message.Add("Error", null);
                        }
                        break;
                    case 0x18:
                        message["Type"] = "AMQP Close";
                        content = (Array)ParseAMQPItem(bytes, ref pos);
                        if (content != null)
                        {
                            message.Add("Error", content.GetValue(0));
                        }
                        break;
                }
            }
            else // SASL Frame
            {
                Array content = null;

                switch (bytes[pos++])
                {
                    case 0x40: // sasl-server-mechanisms
                        message.Add("Type", "SASL Mechanisms");
                        message.Add("Content", ParseAMQPList(bytes, ref pos));
                        break;
                    case 0x41: // sasl-server-mechanisms
                        content = ParseAMQPList(bytes, ref pos);
                        message.Add("Type", "SASL Outcome");

                        // Status
                        message.Add("Status", Sasl_outcome.GetValue((int)content.GetValue(0)));

                        // Message
                        message.Add("Message", System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(content.GetValue(1).ToString())));
                        break;
                }
            }
            return message;
        }
        public static Object ParseAMQPItem(byte[] bytes, ref int pos)
        {
            int p = pos;
            Object retVal = null;


            // Check the item type
            switch (bytes[p++])
            {
                // descriptor constructor
                case 0x00:
                    var descriptor = ParseAMQPItem(bytes, ref p);
                    var value = ParseAMQPItem(bytes, ref p);
                    retVal = new Hashtable();
                    ((Hashtable)retVal).Add(descriptor, value);
                    break;

                // null
                case 0x40:
                    pos = p;
                    break;
                //true
                case 0x41:
                    retVal = true;
                    break;
                // false
                case 0x42:
                    retVal = false;
                    break;
                // uint 0
                case 0x43:
                    retVal = 0;
                    break;
                // ulong 0
                case 0x44:
                    retVal = 0;
                    break;
                // empty list
                case 0x45:
                    retVal = Array.Empty<Object>();
                    break;
                // boolean
                case 0x56:
                    byte boolean = bytes[p++];
                    retVal = (boolean == 0x01); // 0x01 = true
                    break;

                // ubyte
                case 0x50:
                    retVal = (byte)bytes[p++];
                    break;

                // byte
                case 0x51:
                    retVal = (byte)bytes[p++];
                    break;
                // smalluint
                case 0x52:
                    retVal = (byte)bytes[p++];
                    break;
                // smallulong
                case 0x53:
                    retVal = (byte)bytes[p++];
                    break;
                // smallint
                case 0x54:
                    retVal = (int)bytes[p++];
                    break;
                // smalllong
                case 0x55:
                    retVal = (long)bytes[p++];
                    break;
                // ushort
                case 0x60:
                    byte[] buffer = bytes.Skip(p).Take(2).ToArray();
                    Array.Reverse(buffer);
                    retVal = BitConverter.ToUInt16(buffer, 0);
                    p += 2;
                    break;
                // short
                case 0x61:
                    byte[] buffer2 = bytes.Skip(p).Take(2).ToArray();
                    Array.Reverse(buffer2);
                    retVal = BitConverter.ToInt16(buffer2, 0);
                    p += 2;
                    break;
                // uint
                case 0x70:
                    byte[] buffer3 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer3);
                    retVal = BitConverter.ToUInt32(buffer3, 0);
                    p += 4;
                    break;

                // int
                case 0x71:
                    byte[] buffer4 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer4);
                    retVal = BitConverter.ToInt32(buffer4, 0);
                    p += 4;
                    break;
                // float
                case 0x72:
                    byte[] buffer5 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer5);
                    retVal = (float)BitConverter.ToInt32(buffer5, 0);
                    p += 4;
                    break;

                // char
                case 0x73:
                    byte[] buffer6 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer6);
                    retVal = System.Text.Encoding.UTF32.GetChars(buffer6);
                    p += 4;
                    break;
                // decimal32
                case 0x74:
                    // Do nothing
                    p += 4;
                    break;
                // ulong
                case 0x80:
                    byte[] buffer7 = bytes.Skip(p).Take(8).ToArray();
                    Array.Reverse(buffer7);
                    retVal = (float)BitConverter.ToUInt64(buffer7, 0);
                    p += 8;
                    break;

                // long
                case 0x81:
                    byte[] buffer8 = bytes.Skip(p).Take(8).ToArray();
                    Array.Reverse(buffer8);
                    retVal = (float)BitConverter.ToInt64(buffer8, 0);
                    p += 8;
                    break;
                // double
                case 0x82:
                    byte[] buffer9 = bytes.Skip(p).Take(8).ToArray();
                    Array.Reverse(buffer9);
                    retVal = (float)BitConverter.ToDouble(buffer9, 0);
                    p += 8;
                    break;
                // timestamp
                case 0x83:
                    byte[] buffer10 = bytes.Skip(p).Take(8).ToArray();
                    Array.Reverse(buffer10);
                    int timeStamp = (int)BitConverter.ToUInt32(buffer10, 0);
                    retVal = (new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddSeconds(timeStamp);
                    p += 8;
                    break;

                // decimal64
                case 0x84:
                    // Do nothing
                    p += 8;
                    break;
                // decimal128
                case 0x94:
                    // Do nothing
                    p += 16;
                    break;

                // UUID
                case 0x98:
                    byte[] buffer11 = bytes.Skip(p).Take(16).ToArray();
                    Array.Reverse(buffer11);
                    retVal = new Guid(buffer11);
                    p += 16;
                    break;


                // Binary
                case 0xa0:
                    int binSize = bytes[p++];
                    byte[] binData = new byte[binSize];
                    Array.Copy(bytes, p, binData, 0, binSize);
                    retVal = binData;// Convert.ToBase64String(bytes.Skip(p).Take(binSize).ToArray());
                    p += binSize;
                    break;
                // String
                case 0xa1:
                    int stringSize = bytes[p++];
                    retVal = System.Text.Encoding.UTF8.GetString(bytes.Skip(p).Take(stringSize).ToArray());
                    p += stringSize;
                    break;

                // symbol
                case 0xa3:
                    int symbolSize = bytes[p++];
                    retVal = System.Text.Encoding.ASCII.GetString(bytes.Skip(p).Take(symbolSize).ToArray());
                    p += symbolSize;
                    break;
                // Binary
                case 0xb0:
                    byte[] buffer12 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer12);
                    int binSize2 = (int)BitConverter.ToUInt32(buffer12, 0);
                    p += 4;
                    byte[] binData2 = new byte[binSize2];
                    Array.Copy(bytes, p, binData2, 0, binSize2);
                    retVal = binData2;// Convert.ToBase64String(bytes.Skip(p).Take(binSize2).ToArray());
                    p += binSize2;
                    break;

                // String
                case 0xb1:
                    byte[] buffer13 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer13);
                    int stringSize2 = (int)BitConverter.ToUInt32(buffer13, 0);
                    p += 4;
                    retVal = System.Text.Encoding.ASCII.GetString(bytes.Skip(p).Take(stringSize2).ToArray());
                    p += stringSize2;
                    break;

                // Symbol
                case 0xb3:
                    byte[] buffer14 = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer14);
                    int symbolSize2 = (int)BitConverter.ToUInt32(buffer14, 0);
                    p += 4;
                    retVal = System.Text.Encoding.ASCII.GetString(bytes.Skip(p).Take(symbolSize2).ToArray());
                    p += symbolSize2;
                    break;

                // List
                case 0xC0:
                    retVal = ParseAMQPList(bytes, ref p);
                    break;
                //  List
                case 0xD0:
                    retVal = ParseAMQPList(bytes, ref p);
                    break;
                // Map
                case 0xC1:
                    retVal = ParseAMQPMap(bytes, ref p);
                    break;
                // Map
                case 0xD1:
                    retVal = ParseAMQPMap(bytes, ref p);
                    break;
                // Array
                case 0xE0:
                    retVal = ParseAMQPArray(bytes, ref p);
                    break;
                //  Array
                case 0xF0:
                    retVal = ParseAMQPArray(bytes, ref p);
                    break;
            }
            pos = p;
            return retVal;
        }
        public static Array ParseAMQPList(byte[] bytes, ref int pos)
        {
            List<Object> retVal = new List<Object>();
            int p = pos;
            p--;

            int size = 0;
            int intSize = 0;
            // Check the list type
            switch (bytes[p++])
            {
                case 0x45: //The empty list
                    break;
                case 0xC0:
                    size = bytes[p++];
                    intSize = 1;
                    break;
                case 0xD0:
                    byte[] buffer = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer);
                    size = (int)BitConverter.ToUInt16(buffer, 0);

                    p += 4;
                    intSize = 4;
                    break;
            }

            int max = p + size;

            //  Next int indicates the number of the items so increase position by the size of the int
            p += intSize;
        
            // Loop through the items

            while (p < max)
            {
                retVal.Add(ParseAMQPItem(bytes, ref p));
            }
            pos = p;

            return retVal.ToArray<Object>();
        }
        public static Array ParseAMQPArray(byte[] bytes, ref int pos)
        {
            List<Object> retVal = new List<Object>();
            int p = pos;

            int size = bytes[p++];
            int elements = bytes[p++];
            byte type = bytes[p++]; // Type or array elements
            
            for(int a = 0; a < elements; a++)
            {
                // Array elements does not have type (except for the first one)
                p--;
                bytes[p] = type;
                retVal.Add(ParseAMQPItem(bytes, ref pos));
            }
            pos = p;

            return retVal.ToArray<Object>();
        }


        public static ParsedMessage ParseAMQPMap(byte[] bytes, ref int pos)
        {
            ParsedMessage retVal = new ParsedMessage(null);
            int p = pos;
            p--;

            int size = 0;
            int intSize = 0;
            // Check the list type
            switch (bytes[p++])
            {
                case 0xC1:
                    size = bytes[p++];
                    intSize = 1;
                    break;
                case 0xD1:
                    byte[] buffer = bytes.Skip(p).Take(4).ToArray();
                    Array.Reverse(buffer);
                    size = (int)BitConverter.ToUInt16(buffer, 0);

                    p += 4;
                    intSize = 4;
                    break;
            }

            int max = p + size;

            //  Next int indicates the number of the items so increase position by the size of the int
            p += intSize;

            // Loop through the items

            while (p < max)
            {
                var key = ParseAMQPItem(bytes, ref p);
                var value = ParseAMQPItem(bytes, ref p);
                retVal.Add(key,value);
            }
            pos = p;

            return retVal;
        }

        private static string[] Sasl_outcome = {
            "ok",
            "auth",
            "sys",
            "sys-perm",
            "sys-temp"
        };

        public static byte[] NewSASLInit(string mechanics = "EXTERNAL")
        {
            // 'EXTERNAL','MSSBCBS','PLAIN','ANONYMOUS'
            byte[] retVal = null;
            byte[] mechBytes = System.Text.Encoding.ASCII.GetBytes(mechanics);
            int totalSize = mechBytes.Length + 19;
            using (StreamWriter m = new StreamWriter(new MemoryStream(mechBytes.Length)))
            {
                // Message length
                byte[] msgLength = BitConverter.GetBytes((UInt32)totalSize - 1);
                Array.Reverse(msgLength);

                // Construct the message
                m.Write(msgLength); // The length of the whole message
                m.Write(0x02); // DOFF = 2
                m.Write(0x01); // Message type = SASL
                m.Write(0x00);   
                m.Write(0x00);   
                m.Write(0x00);   
                m.Write(0x53); // SmallULong
                m.Write(0x41); // SASL Init

                m.Write(0xC0); // Array
                m.Write(mechBytes.Length + 5); // Length of the Array
                m.Write(0x03); // Number of elements
                m.Write(0xA3); // Symbol
                m.Write(mechBytes.Length); // Lenght of the mechanics string
                m.Write(mechBytes); // The mechanics string
                m.Write(0x40); // The initial response (null)
                m.Write(0x40); // The hostname (null)

                retVal = ((MemoryStream)m.BaseStream).ToArray();
            }

            return retVal;
        }

        public static byte[] NewAMQPOpen(string containerId, string hostName)
        {
            byte[] retVal = null;

            // Get the ascii bytes of the strings
            byte[] idByt = System.Text.Encoding.UTF8.GetBytes(containerId);
            int idS = idByt.Length;
            byte[] hostByt = System.Text.Encoding.UTF8.GetBytes(hostName);
            int hostS = hostByt.Length;

            int totalSize = idS + hostS + 19 + 14;

            using (StreamWriter m = new StreamWriter(new MemoryStream(totalSize)))
            {
                // Message length
                byte[] msgLength = BitConverter.GetBytes((UInt32)totalSize - 1);
                Array.Reverse(msgLength);

                // Construct the message
                m.Write(msgLength); // The length of the whole message
                m.Write(0x02); // DOFF = 2
                m.Write(0x00); // Message type = AMQP
                m.Write(0x00);
                m.Write(0x00);
                m.Write(0x00);
                m.Write(0x53); // SmallULong
                m.Write(0x10); // AMQP Open

                m.Write(0xC0); // Array
                m.Write((byte)(idS + hostS + 19)); // Length of the Array
                m.Write(0x0A); // Number of elements
                m.Write(0xA1); // UTF-8
                m.Write((byte)idS); // Lenght of the containerId string
                m.Write(idByt); // The ContainerId string
                m.Write(0xA1); // UTF-8
                m.Write((byte)hostS); // Lenght of the hostName string
                m.Write(hostByt); // The hostName string
                m.Write(0x40); // The initial response (null)
                m.Write(0x40); // The hostname (null)

                retVal = ((MemoryStream)m.BaseStream).ToArray();
            }

            return retVal;
        }

    }

    
 }
    

