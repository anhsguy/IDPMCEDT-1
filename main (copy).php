<?php
// $wsdlUrl = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService?wsdl';
// $endpoint = 'https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService';
// initialize with input parameters to this API
global $healthcard, $versionCode, $serviceCode; //what attachment??
$healthcard = '9287170261';
$versionCode = 'DK';
$serviceCode = 'A110';
global $MOH_ID, $username, $password;
$MOH_ID = '621300';
$username = 'confsu+427@gmail.com';
$password = 'Password2!';
global $privatekey;
// load external script which imports $privatekey
include 'loadkeystore.php';
// include 'payload_mike.php';

$rawbody = <<<EOT
<soapenv:Body wsu:Id="id-5">
  <edt:getTypeList/>
</soapenv:Body>
EOT;
function loadbody() {

$rawbody = <<<EOT
<soapenv:Body wsu:Id="id-5">
<edt:upload>
<upload>
<content>
<inc:Include href="cid:Claim.File.txt" xmlns:inc="http://www.w3.org/2004/08/xop/include"/>
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
// global $healthcard,$versionCode,$serviceCode;//should be attachment???
// $body = loadbody();
  global $rawbody;
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
<ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv wsu"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:CanonicalizationMethod>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference URI="#UsernameToken-2">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="wsse ebs edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>$digestvalue5</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#TS-1">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt idp msa"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>$digestvalue1</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#id-3">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>$digestvalue2</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#id-4">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>$digestvalue3</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#id-5">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces PrefixList="ebs edt idp msa soapenv"
xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
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
xmlns:ebs="http://ebs.health.ontario.ca/"
xmlns:edt="http://edt.health.ontario.ca/"
xmlns:idp="http://idp.ebs.health.ontario.ca/"
xmlns:msa="http://msa.ebs.health.ontario.ca/"
xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<soapenv:Header>
<wsse:Security
xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="X509-4A6564966742022D8B170319672914254">MIICZTCCAc6gAwIBAgIJAOfnCbp0ZcrkMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAwDgYDVQQHEwdUb3JvbnRvMQ0wCwYDVQQKEwRPSElQMQ0wCwYDVQQLEwRPSElQMRIwEAYDVQQDEwlUZXN0IENlcnQwHhcNMjMxMjIxMjEzOTA5WhcNNDMxMjE2MjEzOTA5WjBjMQswCQYDVQQGEwJDQTEQMA4GA1UECBMHT250YXJpbzEQMA4GA1UEBxMHVG9yb250bzENMAsGA1UEChMET0hJUDENMAsGA1UECxMET0hJUDESMBAGA1UEAxMJVGVzdCBDZXJ0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCW0yRHATronyEOqxrh7y7jN1Va+8jAOfnY/NPMvrLmo6w8cWPfzroTx6+R7sOTiH63TlyDYR3H9POi1rrx5FePU267hZdSFBA8Yz93MTdaCb6eHtm/OqwYVQjq5hOmwInOWzY6GEDQO97MQ4SvXo9zU+TcoKHEL0XZDqD/NbcEYQIDAQABoyEwHzAdBgNVHQ4EFgQUyarNiRTnydza4ifUBwZENxn9m1swDQYJKoZIhvcNAQELBQADgYEAa6sWLouZO3yL+9qZz0h0lnUHODj2Xg6J8j6Rg3Yah+0V90qkrbR4IdnbNFivW1zBkzxSOP12Tj8xiaYQ93lf6NVYcHJI1UXM8p4YTM9QVVy+wXPdoxKD7wCbqw5opDc7uTd7CBqfzqsl6BTqpNVN5DVvVaYkl5fWTLSqvD/YrTU=</wsse:BinarySecurityToken>
$usernameToken
$timestamp
<ds:Signature Id="SIG-6" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
$signedInfo
<ds:SignatureValue>
$signature
</ds:SignatureValue>
<ds:KeyInfo Id="KI-4A6564966742022D8B170319672914255">
<wsse:SecurityTokenReference wsu:Id="STR-4A6564966742022D8B170319672914256">
<wsse:Reference URI="#X509-4A6564966742022D8B170319672914254" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
</wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature>
</wsse:Security>
$IDP
$EBS
</soapenv:Header>
$body
</soapenv:Envelope>
EOT;
  return $rawxml;
}
$rawxml = loadxmltemplate();
// echo $rawxml."\n\n"; //for debugging
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



// // Create a DOMDocument instance and load the XML
// $dom = new DOMDocument;
// $dom->loadXML($response[1]);

// // Find the EncryptedData element
// $encryptedDataElement = $dom->getElementsByTagName('CipherValue')->item(0); // Replace 'EncryptedData' with the actual XML element name
// $x = $dom->documentElement;
// echo $x->nodeName."\n";
// foreach ($x->childNodes AS $item) {
//   echo $item->nodeName . "\n";
// }
// // echo $dom->documentElement->nodeValue;
// if ($encryptedDataElement) {
//     // Get the base64-encoded data from the element
//     $base64EncodedData = $encryptedDataElement->nodeValue;

//     // // Decode the base64-encoded data
//     // $decodedData = base64_decode($base64EncodedData);

//     // // Now $decodedData contains the binary data, and you can proceed with decryption or further processing
//     // echo "\ndecodedData= \n".$decodedData;
//   global $privatekey;
//   openssl_private_decrypt($base64EncodedData , $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
//     echo "\nAES key: ",base64_encode($decryptedAesKey),"\n\n";
//   // Extract the initialization vector required for AES decryption
//   $iv = substr(base64_decode($cipherValues[1]), 0, 16);
//   // Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
//   $decryptedData = openssl_decrypt($cipherValues[1], 'aes-128-cbc', $decryptedAesKey, 0, $iv);
//     $responseXML = substr($decryptedData, 16);
//   echo "\nresponseXML= \n".$responseXML;
//     return $responseXML;
// } else {
//     echo "EncryptedData element not found.";
// }


