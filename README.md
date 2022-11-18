# PTAAgentDump

PTAAgentDump is a tool for checking malicious use of stolen pass-through authentication (PTA) agent certificates. 
The tool shows how many active certificates exists per agent. 

Your organization is likely compromised if both of the following is true:
1. The number of active certificates per agents is greater than one
2. The IP address of the agent with multiple active certificates doesn't contantly change in cycles less than 10 minutes

To check the IP address of the agents, see [Passthrough Authentication](https://portal.azure.com/#view/Microsoft_AAD_IAM/PTAAgentManagement.ReactView) blade in Azure portal.

For more information, see Secureworks Threat Analysis: [Azure Active Directory Pass-Through Authentication Flaws](https://www.secureworks.com/research/azure-active-directory-pass-through-authentication-flaws)

## Installation

Copy **PTAAgentDump.exe** and **Newtonsoft.Json.dll** to server running PTA agent.

**NOTE:** If PTA agent is installed over 6 months ago, the certificate is stored in service account's My store. The certificate must be exported with [AADInternals](https://aadinternals.com/aadinternals/#export-aadintproxyagentcertificates)

To install AADInternals, run the following PowerShell command as Administrator:
```
Install-Module AADInternals
```

## Usage

### If the PTA agent is installed less than 6 months ago
Run the PTAAgentDump.exe:
```
PTAgentDump file=dump.txt
```

The output is similar to this:
```
No certificate was provided, trying to load from the current computer.
Trying to load certificate 07E929D419E244AC63310B97E95F7314595E68CA
Certificate succesfully loaded.
Machine name and bootstrap not provided, getting machine name from the registry.
Machine name: PTA1.contoso.com

Tenant id:    1A0AE5BD-324F-42C8-81AD-3837CD2BEEFF
PTA agent id: 672843e0-8b25-434f-93e2-5d5071139e09
Certificate:  4A90F19C548EE3675C62BB9C5ABCBA93AAA0156A

EndpointListener connected: 5-wss://his-nam1-eus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 1-wss://his-nam1-eus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 6-wss://his-nam1-ncus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 2-wss://his-nam1-ncus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 7-wss://his-nam1-scus2.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 3-wss://his-nam1-scus2.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 4-wss://his-nam1-wus2.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 8-wss://his-nam1-wus2.servicebus.windows.net/$servicebus/websocket
ProxyListener connected: vm12-proxy-pta-NCUS-CHI01P-3.connector.his.msappproxy.net
╓─────────────────────────────────────────────────────────────────────────╖
║ Agent 672843e0-8b25-434f-93e2-5d5071139e09 has 02 active certifications ║
╙─────────────────────────────────────────────────────────────────────────╜

Agents dumped to dump.txt, exiting
```
### If the PTA agent is installed over 6 months ago
Export the certificate using AADInternals:

```
Export-AADIntProxyAgentCertificates
```
The output is similar to this:

```
Certificate saved to: PTA1.contoso.com_1a0ae5bd-324f-42c8-81ad-3837cd2beeff_672843e0-8b25-434f-93e2-5d5071139e09_4A90F19C548EE3675C62BB9C5ABCBA93AAA0156A.pfx
```

Run the PTAAgentDump.exe:
```
PTAgentDump file=dump.txt cert=PTA1.contoso.com_1a0ae5bd-324f-42c8-81ad-3837cd2beeff_672843e0-8b25-434f-93e2-5d5071139e09_4A90F19C548EE3675C62BB9C5ABCBA93AAA0156A
```
The output is similar to this:
```
Dumping agents to file: dump.txt

Tenant id:    1A0AE5BD-324F-42C8-81AD-3837CD2BEEFF
PTA agent id: 672843e0-8b25-434f-93e2-5d5071139e09
Certificate:  4A90F19C548EE3675C62BB9C5ABCBA93AAA0156A

EndpointListener connected: 5-wss://his-nam1-eus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 1-wss://his-nam1-eus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 6-wss://his-nam1-ncus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 2-wss://his-nam1-ncus1.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 3-wss://his-nam1-scus2.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 7-wss://his-nam1-scus2.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 4-wss://his-nam1-wus2.servicebus.windows.net/$servicebus/websocket
EndpointListener connected: 8-wss://his-nam1-wus2.servicebus.windows.net/$servicebus/websocket
RelayListener connected: g5-prod-ch3-006-sb.servicebus.windows.net 933f0892-9509-40a7-a4c4-45c979d2d613
ProxyListener connected: vm12-proxy-pta-NCUS-CHI01P-3.connector.his.msappproxy.net
╓─────────────────────────────────────────────────────────────────────────╖
║ Agent 672843e0-8b25-434f-93e2-5d5071139e09 has 02 active certifications ║
╙─────────────────────────────────────────────────────────────────────────╜

Agents dumped to dump.txt, exiting
```

# Lisence
[Apache 2.0](./LICENSE)
