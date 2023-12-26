<?php
// $wsdlUrl = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService?wsdl';
// $endpoint = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService';
// initialize with input parameters to this API
global $MOH_ID, $username, $password;
$MOH_ID = '621300';
$username = 'confsu+427@gmail.com';
$password = 'Password2!';
global $privatekey;
// load external script which imports $privatekey
include 'loadkeystore.php';
// include 'payload_mike.php';
$uploadFile= 'Claim_File.txt';
// Read the contents of the file
$file_contents = file_get_contents($uploadFile);

// Encode the contents as base64
$base64_encoded = base64_encode($file_contents);
$rawbody = <<<EOT
<soapenv:Body wsu:Id="id-5">
<edt:getTypeList/>
</soapenv:Body>
EOT;
  
function loadbody($base64_encoded) {

$rawbody = <<<EOT
<soapenv:Body wsu:Id="id-5">
<edt:upload>
<upload>
<content>
<inc:Include href="CID:Claim_File.txt" xmlns:inc="http://www.w3.org/2004/08/xop/include"/>
</content>
<description>00123</description>
<resourceType>CL</resourceType>
</upload>
</edt:upload>
</soapenv:Body>
EOT;
    return $rawbody;
  }
function loadtimestamp() {
  // Create the first timestamp
  $firstTimestamp = new DateTime('now', new DateTimeZone('UTC'));
  $firstTimestampStr = $firstTimestamp->format('Y-m-d\TH:i:s.v\Z');

  // Create the second timestamp (10 minutes after the first one)
  $secondTimestamp = clone $firstTimestamp;
  $secondTimestamp->add(new DateInterval('PT10M')); // Add 10 minutes
  $secondTimestampStr = $secondTimestamp->format('Y-m-d\TH:i:s.v\Z');

$timestamp = <<<EOT
<wsu:Timestamp wsu:Id="TS-1">
<wsu:Created>$firstTimestampStr</wsu:Created>
<wsu:Expires>$secondTimestampStr</wsu:Expires>
</wsu:Timestamp>
EOT;
  return $timestamp;
}
function loadEBS() {
// generate uuid without external library because my server doesn't have composer
$uuid = vsprintf( '%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex(random_bytes(16)), 4) );

// hardcode conformance key here, as it will be permanent
$EBS = <<<EOT
<ebs:EBS wsu:Id="id-4">
<SoftwareConformanceKey>da3c7d46-42b9-4cd5-8485-8580e3a39593</SoftwareConformanceKey>
<AuditId>$uuid</AuditId>
</ebs:EBS>
EOT;
  return $EBS;  //what's AuditID???
}
function loadIDP($MOH_ID) {
$IDP = <<<EOT
<idp:IDP wsu:Id="id-3">
<ServiceUserMUID>$MOH_ID</ServiceUserMUID>
</idp:IDP>
EOT;
  return $IDP;
}
function loadUsernameToken($username,$password) {
$usernameToken = <<<EOT
<wsse:UsernameToken wsu:Id="UsernameToken-2">
<wsse:Username>$username</wsse:Username>
<wsse:Password 
Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">$password</wsse:Password>
</wsse:UsernameToken>
EOT;
return $usernameToken;
}
// given xml input, digestxml will canonicalize xml then hash it with SHA256, returning a hash value as digest string
function digestxml($xml) {
  // Create a DOMDocument
  $dom = new DOMDocument(); 
  // echo $xml."\n\n"; //for degug
  // Load the XML content into the DOMDocument
  $dom->loadXML($xml);


  // Canonicalize the document using C14N version 1.0
  $canonicalizedXML = $dom->C14N();

  // Output the canonicalized XML
  // echo $canonicalizedXML."\n\n";

  // Calculate SHA-256 hash, set hash func binary option to true
  $digestvalue = base64_encode(hash('sha256', $canonicalizedXML, true));
  return $digestvalue;
}


function loadxmltemplate() {

$root_namespaces = <<<EOT
 xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:edt="http://edt.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:inc="http://www.w3.org/2004/08/xop/include"
EOT;

// must declare var global to be able to use global var from outside the function
// global $base64_encoded;
// $body = loadbody($base64_encoded);
  $body = $rawbody;
// insert namespace definition from all parent nodes into the xml part to be canonicalized. this is required, otherwise soapenv namespace would be undefined.
$modifiedbody = substr_replace($body, $root_namespaces, strpos($body, '<soapenv:Body') + strlen('<soapenv:Body'), 0);
// echo $body."\n\n"; //for debugging
$digestvalue5 = digestxml($modifiedbody);
// echo $digestvalue5."\n\n"; //for debugging

$timestamp = loadtimestamp();
$modtimestamp = substr_replace($timestamp, $root_namespaces, strpos($timestamp, '<wsu:Timestamp') + strlen('<wsu:Timestamp'), 0);
// echo $modtimestamp."\n\n"; //for debugging
$digestvalue3 = digestxml($modtimestamp);
// echo $digestvalue3."\n\n"; //for debugging

$EBS = loadEBS();
$modifiedEBS = substr_replace($EBS, $root_namespaces, strpos($EBS, '<ebs:EBS') + strlen('<ebs:EBS'), 0);
$digestvalue1 = digestxml($modifiedEBS);

global $MOH_ID;
$IDP = loadIDP($MOH_ID);
$modifiedIDP = substr_replace($IDP, $root_namespaces, strpos($IDP, '<idp:IDP') + strlen('<idp:IDP'), 0);
$digestvalue2 = digestxml($modifiedIDP);

global $username,$password;
$usernameToken = loadUsernameToken($username,$password);
$modusernameToken = substr_replace($usernameToken, $root_namespaces, strpos($usernameToken, '<wsse:UsernameToken') + strlen('<wsse:UsernameToken'), 0);
$digestvalue4 = digestxml($modusernameToken);


$signedInfo = <<<EOT
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:CanonicalizationMethod>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
<ds:Reference URI="#UsernameToken-2">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
<ds:DigestValue>$digestvalue5</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#TS-1">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="wsse ebs edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
<ds:DigestValue>$digestvalue1</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#id-3">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
<ds:DigestValue>$digestvalue2</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#id-4">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
<ds:DigestValue>$digestvalue3</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#id-5">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt idp msa"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
<ds:DigestValue>$digestvalue4</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
EOT;
//insert namespace from all parent nodes before canonicalization
$modsignedInfo = substr_replace($signedInfo, $root_namespaces, strpos($signedInfo, '<ds:SignedInfo') + strlen('<ds:SignedInfo'), 0);

  // Create a DOMDocument to prep for C14N canonicalization
  $dom = new DOMDocument();
  // Load the XML content into the DOMDocument
  $dom->loadXML($modsignedInfo);
  // Canonicalize the document using C14N version 1.0
  $canonicalizedXML = $dom->C14N();
  // Calculate SHA-1 hash of $signedInfo
  // The second parameter 'true' outputs raw binary data
  $digest = sha1($canonicalizedXML, true);

  // Calculate SHA-256 hash of $signedInfo
  // $digest = hash('sha256', $signedInfo, true);

global $privatekey;
// Sign the SHA-1 hash using private key and PKCS1 padding
openssl_sign($digest, $signature, $privatekey, OPENSSL_ALGO_SHA1);
// Signature is now in $signature
$signature=base64_encode($signature);
// echo 'Signature: ', base64_encode($signature), "\n\n"; //for debug

$rawxml = <<<EOT
<soapenv:Envelope
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:msa="http://msa.ebs.health.ontario.ca/"
xmlns:idp="http://idp.ebs.health.ontario.ca/"
xmlns:edt="http://edt.health.ontario.ca/"
xmlns:ebs="http://ebs.health.ontario.ca/"
xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
xmlns:inc="http://www.w3.org/2004/08/xop/include">
<soapenv:Header>
<wsse:Security soapenv:mustUnderstand="1"
xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<wsse:BinarySecurityToken 
EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" 
ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" 
wsu:Id="X509-04FD51796CB607011413612828891871">MIICdTCCAd6gAwIBAgIJAIgq6l1JzkMMMA0GCSqGSIb3DQEBCwUAMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMREwDwYDVQQKEwhsaWdodEVNUjERMA8GA1UECxMIT0hJUCBFQlMxEjAQBgNVBAMTCUxpZ2h0IEVNUjAeFw0yMzExMzAwMzUzNTJaFw00MzExMjUwMzUzNTJaMGsxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMREwDwYDVQQKEwhsaWdodEVNUjERMA8GA1UECxMIT0hJUCBFQlMxEjAQBgNVBAMTCUxpZ2h0IEVNUjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAuTOk0wQTfR5gkaprZ2bk/sIR5UEHV+TQhuUXCnoBgykoM+FOiumHxeZobIYLanFZ7VPxZyXIYB/uPD6NJ5YOd3UhbD7RFgpS7TQiF2Y+Ndu9wwYkXpJSVfd7q+R+xG/zpEVedm8/vJLFLmeHMKELqxKrjmObRyn5BJd0UrhGtzcCAwEAAaMhMB8wHQYDVR0OBBYEFFB8aN77G0N7cC/zkKR9vWrHEycdMA0GCSqGSIb3DQEBCwUAA4GBAKlcecHQkrLz2F033QK3bYn9cJ+Qf3we+VDCr8Wbrp+Bh4wFYs6k57EITm5h/MpAIWO9lc0xaw6wKDlHhrl6fGs7Sxjk/AN7Sm5Bi9hzAyzCSPMhxr3njIDVZr5h0ekzoRnaoPAByM2e4ZKc288DAtE3sirNxmHswrnyZEO7BGa2</wsse:BinarySecurityToken>
<ds:Signature Id="SIG-6" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
$signedInfo
<ds:SignatureValue>
$signature
</ds:SignatureValue>
<ds:KeyInfo Id="KI-04FD51796CB607011413612828892812">
<wsse:SecurityTokenReference wsu:Id="STR-04FD51796CB607011413612828892813">
<wsse:Reference 
URI="#X509-04FD51796CB607011413612828891871" 
ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" />
</wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature>
$usernameToken
$timestamp
</wsse:Security>
</soapenv:Header>
$IDP
$EBS
$body
</soapenv:Envelope>
EOT;
  return $rawxml;
}
$rawxml = loadxmltemplate();
echo $rawxml."\n\n"; //for debugging
// $xml = simplexml_load_string($rawxml);

function sendrequest($xmlPayload) {
  $url = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService';
  $wsdlUrl = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService?wsdl';
  

  // Create a boundary for the multipart request
  // $headers = [
  //     'Content-Type: multipart/related; type="application/xop+xml"; start="mike"; start-info="text/xml"; boundary="----=_Part_1_27925944.1386269341816" MIME-Version: 1.0 User-Agent: Jakarta Commons-HttpClient/3.1 Host:ws.conf.ebs.health.gov.on.ca:1441'. ' Content-Length: ' . strlen($xmlPayload),
  // ];
  $headers = [
      'Content-Type' => 'multipart/related; type="application/xop+xml"; start="<xxx@xxx.org>"; start-info="text/xml"; boundary="----=_Part_1_27925944.1386269341816"',
      'MIME-Version' => '1.0',
      'User-Agent' => 'Jakarta Commons-HttpClient/3.1',
      'Host' => 'ws.conf.ebs.health.gov.on.ca:1441',
      'Content-Length' => strlen($xmlPayload),
      // 'SOAPAction' => '',  // Add your SOAP action if needed
  ];
  // Add SOAP Part Headers
  $headers['SOAPPartHeaders'] = [
      'Content-Type' => 'application/xop+xml; charset=UTF-8; type="text/xml"',
      'Content-Transfer-Encoding' => '8bit',
      'Content-ID' => '<xxx@xxx.org>',
  ];

  // Add additional SOAP headers if needed

  // Use these headers when making your SOAP request
  $options = ['headers' => $headers];

  // Initialize cURL session
  $ch = curl_init($url);

  // Set cURL options
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $xmlPayload);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $options);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  // visit endpoint url in chrome, download certificates from chrome
  // including Certificate Authority G2, intermediate L1K and server certificate
  // open all three in notepad and paste together, save as cacert.pem
  curl_setopt($ch, CURLOPT_CAINFO, 'cacert.pem');
  // set option to track request header in curl_getinfo
  curl_setopt($ch, CURLINFO_HEADER_OUT, true);
  // set option to include response header in $response
  curl_setopt($ch, CURLOPT_HEADER, true);

  // Execute cURL session
  $response = curl_exec($ch);

  // Check for cURL errors
  if (curl_errno($ch)) {
      echo 'Curl error: ' . curl_error($ch);
  }

  // print_r(curl_getinfo($ch)); //for debug
  $serverStatus = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  // request headers

  // Create and open a file for writing verbose output
  $httpLogFile = fopen('httplog.txt', 'a');
  // Delete all contents of the log file
  file_put_contents('httplog.txt', '');
  // Write request headers to the log file
  fwrite($httpLogFile, curl_getinfo($ch, CURLINFO_HEADER_OUT));
  fwrite($httpLogFile, $xmlPayload."\n\n\n");

  // Extract body from the response
  $body = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
  fwrite($httpLogFile, $response);
  // Close the file handle for http log
  fclose($httpLogFile);

  // Close cURL session
  curl_close($ch);

  // Output the response
  return [$serverStatus,$body];
}


$response = sendrequest($rawxml);

// echo out the response to console
echo "\nServerStatus= ".$response[0]."\n\n\n"; //for debugging
echo $response[1]; // for debugging

// if ($response[0] <300) {
//   $decryptedResult = decryptResponse($response[1]);
//   // echo $decryptedResult; //for debugging
//   buildresponseObj($decryptedResult);
// } else {
//   errorhandling($response[0], $response[1]);
// }


