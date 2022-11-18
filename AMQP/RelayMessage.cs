using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Secureworks.AMQP
{
    public abstract class RelayMessage : AMQPItem
    {

        protected byte[] GetSessionStringArray(string[] strings)
        {
            if(strings == null)
                return null;

            MemoryStream m = new MemoryStream();
            foreach(string sesStr in strings)
            {
                string value = sesStr;
                if (sesStr == null)
                    value = String.Empty;
                byte[] utf8String = System.Text.Encoding.UTF8.GetBytes(value);
                base.WriteToStream(m, AMQPParser.IntToMultibyteInt32(utf8String.Length));
                base.WriteToStream(m, utf8String);
            }
            byte[] retVal = m.ToArray();
            m.Dispose();
            return retVal;
        }
        
        protected void WriteXml(string xml)
        {
            // This doesn't work actually, XmlDictionaryWriter does NOT use the given dictionary???!?!?
            // Load xml document
            System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
            doc.LoadXml(xml);

            System.Xml.XmlDictionary serviceModelDictionary = new System.Xml.XmlDictionary();
            XmlBinaryWriterSession session = new XmlBinaryWriterSession();

            string[] serviceModelStringsVersion1 = { "mustUnderstand", "Envelope", "http://www.w3.org/2003/05/soap-envelope", "http://www.w3.org/2005/08/addressing", "Header", "Action", "To", "Body", "Algorithm", "RelatesTo", "http://www.w3.org/2005/08/addressing/anonymous", "URI", "Reference", "MessageID", "Id", "Identifier", "http://schemas.xmlsoap.org/ws/2005/02/rm", "Transforms", "Transform", "DigestMethod", "DigestValue", "Address", "ReplyTo", "SequenceAcknowledgement", "AcknowledgementRange", "Upper", "Lower", "BufferRemaining", "http://schemas.microsoft.com/ws/2006/05/rm", "http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement", "SecurityTokenReference", "Sequence", "MessageNumber", "http://www.w3.org/2000/09/xmldsig#", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", "KeyInfo", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "http://www.w3.org/2001/04/xmlenc#", "http://schemas.xmlsoap.org/ws/2005/02/sc", "DerivedKeyToken", "Nonce", "Signature", "SignedInfo", "CanonicalizationMethod", "SignatureMethod", "SignatureValue", "DataReference", "EncryptedData", "EncryptionMethod", "CipherData", "CipherValue", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Security", "Timestamp", "Created", "Expires", "Length", "ReferenceList", "ValueType", "Type", "EncryptedHeader", "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd", "RequestSecurityTokenResponseCollection", "http://schemas.xmlsoap.org/ws/2005/02/trust", "http://schemas.xmlsoap.org/ws/2005/02/trust#BinarySecret", "http://schemas.microsoft.com/ws/2006/02/transactions", "s", "Fault", "MustUnderstand", "role", "relay", "Code", "Reason", "Text", "Node", "Role", "Detail", "Value", "Subcode", "NotUnderstood", "qname", "", "From", "FaultTo", "EndpointReference", "PortType", "ServiceName", "PortName", "ReferenceProperties", "RelationshipType", "Reply", "a", "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity", "Identity", "Spn", "Upn", "Rsa", "Dns", "X509v3Certificate", "http://www.w3.org/2005/08/addressing/fault", "ReferenceParameters", "IsReferenceParameter", "http://www.w3.org/2005/08/addressing/reply", "http://www.w3.org/2005/08/addressing/none", "Metadata", "http://schemas.xmlsoap.org/ws/2004/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous", "http://schemas.xmlsoap.org/ws/2004/08/addressing/fault", "http://schemas.xmlsoap.org/ws/2004/06/addressingex", "RedirectTo", "Via", "http://www.w3.org/2001/10/xml-exc-c14n#", "PrefixList", "InclusiveNamespaces", "ec", "SecurityContextToken", "Generation", "Label", "Offset", "Properties", "Cookie", "wsc", "http://schemas.xmlsoap.org/ws/2004/04/sc", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/dk", "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/SCT", "RenewNeeded", "BadContextToken", "c", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk", "http://schemas.xmlsoap.org/ws/2005/02/sc/sct", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/SCT/Cancel", "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes128", "http://www.w3.org/2001/04/xmlenc#aes192-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes192", "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#kw-aes256", "http://www.w3.org/2001/04/xmlenc#des-cbc", "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments", "http://www.w3.org/2000/09/xmldsig#hmac-sha1", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "http://schemas.xmlsoap.org/ws/2005/02/sc/dk/p_sha1", "http://www.w3.org/2001/04/xmlenc#ripemd160", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmlenc#rsa-1_5", "http://www.w3.org/2000/09/xmldsig#sha1", "http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmlenc#tripledes-cbc", "http://www.w3.org/2001/04/xmlenc#kw-tripledes", "http://schemas.xmlsoap.org/2005/02/trust/tlsnego#TLS_Wrap", "http://schemas.xmlsoap.org/2005/02/trust/spnego#GSS_Wrap", "http://schemas.microsoft.com/ws/2006/05/security", "dnse", "o", "Password", "PasswordText", "Username", "UsernameToken", "BinarySecurityToken", "EncodingType", "KeyIdentifier", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID", "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion", "http://docs.oasis-open.org/wss/oasis-wss-rel-token-profile-1.0.pdf#license", "FailedAuthentication", "InvalidSecurityToken", "InvalidSecurity", "k", "SignatureConfirmation", "TokenType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0", "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID", "AUTH-HASH", "RequestSecurityTokenResponse", "KeySize", "RequestedTokenReference", "AppliesTo", "Authenticator", "CombinedHash", "BinaryExchange", "Lifetime", "RequestedSecurityToken", "Entropy", "RequestedProofToken", "ComputedKey", "RequestSecurityToken", "RequestType", "Context", "BinarySecret", "http://schemas.xmlsoap.org/ws/2005/02/trust/spnego", " http://schemas.xmlsoap.org/ws/2005/02/trust/tlsnego", "wst", "http://schemas.xmlsoap.org/ws/2004/04/trust", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/security/trust/Nonce", "KeyType", "http://schemas.xmlsoap.org/ws/2004/04/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2004/04/trust/PublicKey", "Claims", "InvalidRequest", "RequestFailed", "SignWith", "EncryptWith", "EncryptionAlgorithm", "CanonicalizationAlgorithm", "ComputedKeyAlgorithm", "UseKey", "http://schemas.microsoft.com/net/2004/07/secext/WS-SPNego", "http://schemas.microsoft.com/net/2004/07/secext/TLSNego", "t", "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue", "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey", "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1", "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce", "RenewTarget", "CancelTarget", "RequestedTokenCancelled", "RequestedAttachedReference", "RequestedUnattachedReference", "IssuedTokens", "http://schemas.xmlsoap.org/ws/2005/02/trust/Renew", "http://schemas.xmlsoap.org/ws/2005/02/trust/Cancel", "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey", "Access", "AccessDecision", "Advice", "AssertionID", "AssertionIDReference", "Attribute", "AttributeName", "AttributeNamespace", "AttributeStatement", "AttributeValue", "Audience", "AudienceRestrictionCondition", "AuthenticationInstant", "AuthenticationMethod", "AuthenticationStatement", "AuthorityBinding", "AuthorityKind", "AuthorizationDecisionStatement", "Binding", "Condition", "Conditions", "Decision", "DoNotCacheCondition", "Evidence", "IssueInstant", "Issuer", "Location", "MajorVersion", "MinorVersion", "NameIdentifier", "Format", "NameQualifier", "Namespace", "NotBefore", "NotOnOrAfter", "saml", "Statement", "Subject", "SubjectConfirmation", "SubjectConfirmationData", "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key", "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches", "SubjectLocality", "DNSAddress", "IPAddress", "SubjectStatement", "urn:oasis:names:tc:SAML:1.0:am:unspecified", "xmlns", "Resource", "UserName", "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", "EmailName", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "u", "ChannelInstance", "http://schemas.microsoft.com/ws/2005/02/duplex", "Encoding", "MimeType", "CarriedKeyName", "Recipient", "EncryptedKey", "KeyReference", "e", "http://www.w3.org/2001/04/xmlenc#Element", "http://www.w3.org/2001/04/xmlenc#Content", "KeyName", "MgmtData", "KeyValue", "RSAKeyValue", "Modulus", "Exponent", "X509Data", "X509IssuerSerial", "X509IssuerName", "X509SerialNumber", "X509Certificate", "AckRequested", "http://schemas.xmlsoap.org/ws/2005/02/rm/AckRequested", "AcksTo", "Accept", "CreateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence", "CreateSequenceRefused", "CreateSequenceResponse", "http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse", "FaultCode", "InvalidAcknowledgement", "LastMessage", "http://schemas.xmlsoap.org/ws/2005/02/rm/LastMessage", "LastMessageNumberExceeded", "MessageNumberRollover", "Nack", "netrm", "Offer", "r", "SequenceFault", "SequenceTerminated", "TerminateSequence", "http://schemas.xmlsoap.org/ws/2005/02/rm/TerminateSequence", "UnknownSequence", "http://schemas.microsoft.com/ws/2006/02/tx/oletx", "oletx", "OleTxTransaction", "PropagationToken", "http://schemas.xmlsoap.org/ws/2004/10/wscoor", "wscoor", "CreateCoordinationContext", "CreateCoordinationContextResponse", "CoordinationContext", "CurrentContext", "CoordinationType", "RegistrationService", "Register", "RegisterResponse", "ProtocolIdentifier", "CoordinatorProtocolService", "ParticipantProtocolService", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContext", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/CreateCoordinationContextResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/Register", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/RegisterResponse", "http://schemas.xmlsoap.org/ws/2004/10/wscoor/fault", "ActivationCoordinatorPortType", "RegistrationCoordinatorPortType", "InvalidState", "InvalidProtocol", "InvalidParameters", "NoActivity", "ContextRefused", "AlreadyRegistered", "http://schemas.xmlsoap.org/ws/2004/10/wsat", "wsat", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Completion", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Durable2PC", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Volatile2PC", "Prepare", "Prepared", "ReadOnly", "Commit", "Rollback", "Committed", "Aborted", "Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Commit", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Rollback", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Committed", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Aborted", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepare", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Prepared", "http://schemas.xmlsoap.org/ws/2004/10/wsat/ReadOnly", "http://schemas.xmlsoap.org/ws/2004/10/wsat/Replay", "http://schemas.xmlsoap.org/ws/2004/10/wsat/fault", "CompletionCoordinatorPortType", "CompletionParticipantPortType", "CoordinatorPortType", "ParticipantPortType", "InconsistentInternalState", "mstx", "Enlistment", "protocol", "LocalTransactionId", "IsolationLevel", "IsolationFlags", "Description", "Loopback", "RegisterInfo", "ContextId", "TokenId", "AccessDenied", "InvalidPolicy", "CoordinatorRegistrationFailed", "TooManyEnlistments", "Disabled", "ActivityId", "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics", "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#Kerberosv5APREQSHA1", "http://schemas.xmlsoap.org/ws/2002/12/policy", "FloodMessage", "LinkUtility", "Hops", "http://schemas.microsoft.com/net/2006/05/peer/HopCount", "PeerVia", "http://schemas.microsoft.com/net/2006/05/peer", "PeerFlooder", "PeerTo", "http://schemas.microsoft.com/ws/2005/05/routing", "PacketRoutable", "http://schemas.microsoft.com/ws/2005/05/addressing/none", "http://schemas.microsoft.com/ws/2005/05/envelope/none", "http://www.w3.org/2001/XMLSchema-instance", "http://www.w3.org/2001/XMLSchema", "nil", "type", "char", "boolean", "byte", "unsignedByte", "short", "unsignedShort", "int", "unsignedInt", "long", "unsignedLong", "float", "double", "decimal", "dateTime", "string", "base64Binary", "anyType", "duration", "guid", "anyURI", "QName", "time", "date", "hexBinary", "gYearMonth", "gYear", "gMonthDay", "gDay", "gMonth", "integer", "positiveInteger", "negativeInteger", "nonPositiveInteger", "nonNegativeInteger", "normalizedString", "ConnectionLimitReached", "http://schemas.xmlsoap.org/soap/envelope/", "actor", "faultcode", "faultstring", "faultactor", "detail" };
            int key = 0;
            foreach (string word in serviceModelStringsVersion1)
            {
                 session.TryAdd(serviceModelDictionary.Add(word), out key);
            }

            // Convert to binary
            System.IO.MemoryStream m = new System.IO.MemoryStream();
            
            System.Xml.XmlDictionaryWriter writer = System.Xml.XmlDictionaryWriter.CreateBinaryWriter(m, serviceModelDictionary,session,false);
            doc.WriteContentTo(writer);
            writer.Flush();
            
            // Write to buffer
            base.WriteByteArray(m.ToArray());

            m.Dispose();
        }
    }

    public class RelayInit : RelayMessage
    {
        public RelayInit()
        {
            base.WriteByte(0x1e);
            base.WriteByte(0x01);
            base.WriteByte(0x00);
            base.WriteByte(0x00);
        }
    }

    public class RelayedAccept : RelayMessage
    {
        public RelayedAccept(string Id)
        {
            string xml = string.Format(@"
                <s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
	                <s:Header>
		                <a:Action s:mustUnderstand=""1"">RelayedAccept</a:Action>
		                <a:To s:mustUnderstand=""1"">http://schemas.microsoft.com/2005/12/ServiceModel/Addressing/Anonymous</a:To>
	                </s:Header>
	                <s:Body>
		                <RelayedAccept xmlns=""http://schemas.microsoft.com/netservices/2009/05/servicebus/connect"" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"">
			                <Id>{0}</Id>
		                </RelayedAccept>
	                </s:Body>
                </s:Envelope>", Id);
            //base.WriteXml(xml);
            // XmlDictionary doesn't work, so must do this manually :(
            base.WriteByteArray(new byte[] { 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0x99, 0x0D, 0x52, 0x65, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x44, 0x0C, 0x1E, 0x00, 0x82, 0x99, 0x46, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x32, 0x30, 0x30, 0x35, 0x2F, 0x31, 0x32, 0x2F, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4D, 0x6F, 0x64, 0x65, 0x6C, 0x2F, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x2F, 0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x01, 0x56, 0x0E, 0x40, 0x0D, 0x52, 0x65, 0x6C, 0x61, 0x79, 0x65, 0x64, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x08, 0x43, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x73, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x6E, 0x65, 0x74, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2F, 0x32, 0x30, 0x30, 0x39, 0x2F, 0x30, 0x35, 0x2F, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x75, 0x73, 0x2F, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x09, 0x01, 0x69, 0x29, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x77, 0x33, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x32, 0x30, 0x30, 0x31, 0x2F, 0x58, 0x4D, 0x4C, 0x53, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x2D, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x63, 0x65, 0x40, 0x02, 0x49, 0x64, 0x99, 0x24 });
            base.WriteByteArray(Encoding.UTF8.GetBytes(Id));
            base.WriteByteArray(new byte[] { 0x01, 0x01, 0x01 });
        }
    }

    public class CreateSequenceResponse : RelayMessage
    {
        public CreateSequenceResponse(Guid relatesTo, Guid Id, string serviceBus)
        {
            string xml = string.Format(@"
            <s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
	            <s:Header>
		            <a:Action s:mustUnderstand=""1"">http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequenceResponse</a:Action>
		            <a:RelatesTo>urn:uuid:{0}</a:RelatesTo>
		            <a:To s:mustUnderstand=""1"">http://www.w3.org/2005/08/addressing/anonymous</a:To>
	            </s:Header>
	            <s:Body>
		            <CreateSequenceResponse xmlns=""http://schemas.xmlsoap.org/ws/2005/02/rm"">
			            <Identifier>urn:uuid:{1}</Identifier>
			            <Accept>
				            <AcksTo>
					            <a:Address>{2}</a:Address>
				            </AcksTo>
			            </Accept>
		            </CreateSequenceResponse>
	            </s:Body>
            </s:Envelope>", relatesTo,Id,serviceBus);
            //base.WriteXml(xml);
            // XmlDictionary doesn't work, so must do this manually :(

            byte[] binServiceBus = Encoding.UTF8.GetBytes(serviceBus);

            System.IO.MemoryStream m = new System.IO.MemoryStream();
            // Content
            base.WriteToStream(m, new byte[] { 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0xA0, 0x05, 0x44, 0x12, 0xAD });
            base.WriteToStream(m, relatesTo.ToByteArray());
            base.WriteToStream(m, new byte[] { 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x42, 0x9E, 0x05, 0x0A, 0x20, 0x42, 0x1E, 0xAD });
            base.WriteToStream(m, Id.ToByteArray());
            base.WriteToStream(m, new byte[] { 0x42, 0x96, 0x05, 0x42, 0x94, 0x05, 0x44, 0x2A, 0x99 });
            base.WriteToStream(m, AMQPParser.IntToMultibyteInt32(binServiceBus.Length));
            base.WriteToStream(m, binServiceBus);
            base.WriteToStream(m, new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01 });

            byte[] content = m.ToArray();

            // Message header
            base.WriteByte(0x06); // Message type (I think..)
            base.WriteByteArray(AMQPParser.IntToMultibyteInt32(content.Length+1)); // Message length
            base.WriteByteArray(AMQPParser.IntToMultibyteInt32(0x00)); // SessionStrings length

            base.WriteByteArray(content);

            
        }
    }

    public class SignalConnectorResponse : RelayMessage
    {
        private static string[] strings = {"http://tempuri.org/IConnectorSignalingService/SignalConnectorResponse", "SignalConnectorResponse", "http://tempuri.org/", "SignalConnectorResult", "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalingDataModel", "http://www.w3.org/2001/XMLSchema-instance", "AckLatency", "ConnectorId"};
        
        public SignalConnectorResponse(Guid relatesTo, Guid Id, Guid connectorId)
        {
            string sequence = "";
            if (Id != Guid.Empty)
            {
                sequence = string.Format(@"
                    <r:Sequence s:mustUnderstand=""1"">
			            <r:Identifier>urn:uuid:{0}</r:Identifier>
			            <r:MessageNumber>1</r:MessageNumber>
		            </r:Sequence>", Id);
            }

            string xml = string.Format(@"
            <s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:r=""http://schemas.xmlsoap.org/ws/2005/02/rm"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
	            <s:Header>
		            <r:AckRequested>
			            <r:Identifier>urn:uuid:{0}</r:Identifier>
		            </r:AckRequested>
		            {1}
		            <a:Action s:mustUnderstand=""1"">http://tempuri.org/IConnectorSignalingService/SignalConnectorResponse</a:Action>
		            <a:RelatesTo>urn:uuid:{1}</a:RelatesTo>
		            <a:To s:mustUnderstand=""1"">http://www.w3.org/2005/08/addressing/anonymous</a:To>
	            </s:Header>
	            <s:Body>
		            <SignalConnectorResponse xmlns=""http://tempuri.org/"">
			            <SignalConnectorResult xmlns:b=""http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalingDataModel"" xmlns:i=""http://www.w3.org/2001/XMLSchema-instance"">
				            <b:AckLatency>0</b:AckLatency>
				            <b:ConnectorId>{2}</b:ConnectorId>
			            </SignalConnectorResult>
		            </SignalConnectorResponse>
	            </s:Body>
            </s:Envelope>", relatesTo, sequence, connectorId);
            //base.WriteXml(xml);
            // XmlDictionary doesn't work, so must do this manually :(

            byte[] binConnectorId = System.Text.Encoding.UTF8.GetBytes(connectorId.ToString());

            System.IO.MemoryStream m = new System.IO.MemoryStream();

            // Content
            base.WriteToStream(m, new byte[] { 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x72, 0x20, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x55, 0x90, 0x05, 0x55, 0x1E, 0xAD });
            base.WriteToStream(m, Id.ToByteArray());
            base.WriteToStream(m, new byte[] { 0x01, 0x55, 0x3E, 0x1E, 0x00, 0x82, 0x55, 0x1E, 0xAD });
            base.WriteToStream(m, Id.ToByteArray());
            base.WriteToStream(m, new byte[] { 0x55, 0x40, 0x83, 0x01, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0x01, 0x44, 0x12, 0xAD });
            base.WriteToStream(m, relatesTo.ToByteArray());
            base.WriteToStream(m, new byte[] { 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x42, 0x03, 0x0A, 0x05, 0x42, 0x07, 0x0B, 0x01, 0x62, 0x09, 0x0B, 0x01, 0x69, 0x0B, 0x45, 0x0D, 0x81, 0x45, 0x0F, 0x99 });
            base.WriteToStream(m, AMQPParser.IntToMultibyteInt32(binConnectorId.Length));
            base.WriteToStream(m, binConnectorId);
            base.WriteToStream(m, new byte[] { 0x01, 0x01, 0x01, 0x01});

            byte[] content = m.ToArray();

            // Session strings
            byte[] sessionStrings = base.GetSessionStringArray(strings);
            byte[] sessionStringLen = AMQPParser.IntToMultibyteInt32(sessionStrings.Length);

            // Message header
            base.WriteByte(0x06); // Message type (I think..)
            base.WriteByteArray(AMQPParser.IntToMultibyteInt32(content.Length + sessionStringLen.Length + sessionStrings.Length)); // Message length
            base.WriteByteArray(sessionStringLen); // Session strings length
            base.WriteByteArray(sessionStrings); // Session strings

            base.WriteByteArray(content);


        }
    }
    public class SequenceAcknowledgement : RelayMessage
    {
        public SequenceAcknowledgement(Guid Id)
        {
            string xml = string.Format(@"
            <s:Envelope xmlns:s=""http://www.w3.org/2003/05/soap-envelope"" xmlns:r=""http://schemas.xmlsoap.org/ws/2005/02/rm"" xmlns:a=""http://www.w3.org/2005/08/addressing"">
	            <s:Header>
		            <r:SequenceAcknowledgement>
			            <r:Identifier>urn:uuid:{0}</r:Identifier>
			            <r:AcknowledgementRange Lower=""1"" Upper=""1""/>
			            <netrm:BufferRemaining xmlns:netrm=""http://schemas.microsoft.com/ws/2006/05/rm"">8</netrm:BufferRemaining>
		            </r:SequenceAcknowledgement>
		            <a:Action s:mustUnderstand=""1"">http://schemas.xmlsoap.org/ws/2005/02/rm/SequenceAcknowledgement</a:Action>
		            <a:To s:mustUnderstand=""1"">http://www.w3.org/2005/08/addressing/anonymous</a:To>
	            </s:Header>
	            <s:Body/>
            </s:Envelope>", Id);
            //base.WriteXml(xml);
            // XmlDictionary doesn't work, so must do this manually :(

            System.IO.MemoryStream m = new System.IO.MemoryStream();

            // Content
            base.WriteToStream(m, new byte[] { 0x56, 0x02, 0x0B, 0x01, 0x73, 0x04, 0x0B, 0x01, 0x72, 0x20, 0x0B, 0x01, 0x61, 0x06, 0x56, 0x08, 0x55, 0x2E, 0x55, 0x1E, 0xAD });
            base.WriteToStream(m, Id.ToByteArray());
            base.WriteToStream(m, new byte[] { 0x55, 0x30, 0x06, 0x34, 0x82, 0x06, 0x32, 0x82, 0x01, 0x43, 0x05, 0x6E, 0x65, 0x74, 0x72, 0x6D, 0x36, 0x0B, 0x05, 0x6E, 0x65, 0x74, 0x72, 0x6D, 0x38, 0x89, 0x08, 0x01, 0x44, 0x0A, 0x1E, 0x00, 0x82, 0xAB, 0x3A, 0x44, 0x0C, 0x1E, 0x00, 0x82, 0xAB, 0x14, 0x01, 0x56, 0x0E, 0x01, 0x01 });
            
            byte[] content = m.ToArray();

            // Message header
            base.WriteByte(0x06); // Message type (I think..)
            base.WriteByteArray(AMQPParser.IntToMultibyteInt32(content.Length + 1)); // Message length
            base.WriteByteArray(AMQPParser.IntToMultibyteInt32(0)); // Session strings length

            base.WriteByteArray(content);


        }
    }
}
