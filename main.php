<?php
// initialize with input parameters to this API
include'response_to_file.php';
global $method, $claimfile, $resourceID;
// $method = "getTypeList";
// $method = "list";
// $method = "info";
$method = 'upload';
// $method = "delete";
// $method = "update";
$claimfile = 'Claim_File.txt';
$resourceID = "83351";

global $MOH_ID, $username, $password;
$MOH_ID = '621300';
$username = 'confsu+427@gmail.com';
$password = 'Password2!';

// load $privatekey
global $privatekey;
// Load the PKCS#12 file
$pkcs12 = file_get_contents('teststore.p12');

// Parse the PKCS#12 file to extract private key and certificate
openssl_pkcs12_read($pkcs12, $pkcs12Info, 'changeit');

// load the private key
$privatekey = $pkcs12Info['pkey'];


function loadbody() {
  global $method, $claimfile, $resourceID;
  switch ($method) {
    case 'getTypeList':
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
            <edt:getTypeList/>
         </soapenv:Body>
      EOT;
        break;
    case 'list':
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
            <edt:list>
               <!--Optional:-->
               <resourceType>CL</resourceType>
               <!--Optional:-->
               <status>UPLOADED</status>
               <!--Optional:-->
               <pageNo>1</pageNo>
            </edt:list>
         </soapenv:Body>
      EOT;
        break;
  case 'info':
    $rawbody = <<<EOT
     <soapenv:Body wsu:Id="id-5">
        <edt:info>
           <!--1 to 100 repetitions:-->
           <resourceIDs>$resourceID</resourceIDs>
        </edt:info>
     </soapenv:Body>
    EOT;
      break;
  case 'upload':
    $rawbody = <<<EOT
    <soapenv:Body wsu:Id="id-5">
      <edt:upload>
         <!--1 to 5 repetitions:-->
         <upload>
            <content>
              <inc:Include href="cid:$claimfile" xmlns:inc="http://www.w3.org/2004/08/xop/include" />
            </content>
            <!--Optional:-->
            <description>$claimfile</description>
            <resourceType>CL</resourceType>
         </upload>
      </edt:upload>
    </soapenv:Body>
    EOT;
      break;
  case 'delete':
    $rawbody = <<<EOT
       <soapenv:Body wsu:Id="id-5">
          <edt:delete>
             <!--1 to 100 repetitions:-->
             <resourceIDs>$resourceID</resourceIDs>
          </edt:delete>
       </soapenv:Body>
    EOT;
      break;
    case 'update':
      $rawbody = <<<EOT
         <soapenv:Body wsu:Id="id-5">
          <edt:update>
             <!--1 to 5 repetitions:-->
             <updates>
                <content>
        <inc:Include href="cid:$claimfile" xmlns:inc="http://www.w3.org/2004/08/xop/include" />
                </content>
                <resourceID>$resourceID</resourceID>
             </updates>
          </edt:update>
         </soapenv:Body>
      EOT;
        break;
  default:
      echo "invalid method parameter";
      break;
  }

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
$body = loadbody();
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

  global $method, $claimfile;
  switch ($method) {
    case 'upload':
    case 'update':
      $fileContent = file_get_contents($claimfile);
  
      // Boundary for the multipart message
      // Generate a random boundary string, to avoid collision with msg content
      // $boundary = '----=' . bin2hex(random_bytes(16));
      $boundary = '----=Boundary_' . md5(uniqid(time()));
  
      // Construct the MIME message
      $mimeMessage = "--$boundary\r\n";
      $mimeMessage .= "Content-Type: application/xop+xml; charset=UTF-8; type=\"text/xml\"\r\n";
      $mimeMessage .= "Content-Transfer-Encoding: 8bit\r\n";
      $mimeMessage .= "Content-ID: <rootpart@soapui.org>\r\n\r\n";
      // there must be an extra line break between header and soap envelope
      $mimeMessage .= "$xmlPayload\r\n";
      $mimeMessage .= "--$boundary\r\n";
      // $mimeMessage .= "Content-Type: application/octet-stream;       name=$contentId\r\n";
      // $mimeMessage .= "Content-Transfer-Encoding: binary\r\n";
      $mimeMessage .= "Content-Type: text/plain; charset=us-ascii\r\n";
      $mimeMessage .= "Content-Transfer-Encoding: 7bit\r\n";
      // contentId is just the file name e.g. HL8012345.001
      $mimeMessage .= "Content-ID: <$claimfile>\r\n";
      $mimeMessage .= "Content-Disposition: attachment;   name=\"$claimfile\"\r\n\r\n";
      $mimeMessage .= "$fileContent\r\n";
      $mimeMessage .= "--$boundary--";
  
      $headers = [
        "Content-Type:multipart/related; type=\"application/xop+xml\"; start=\"<rootpart@soapui.org>\"; start-info=\"text/xml\"; boundary=\"$boundary\"",
        'MIME-Version: 1.0',
        // 'User-Agent: Apache-HttpClient/4.5.5 (Java/16.0.2)',
        // 'Connection: Keep-Alive',
        // 'Accept-Encoding: gzip, deflate',
        // 'Authorization: Basic Y29uZnN1KzQyN0BnbWFpbC5jb206UGFzc3dvcmQyIQ==',
        // 'SOAPAction: ""',
        // "Content-Length:".strlen($mimeMessage), //xmlPayload
      ];

      $xmlPayload = $mimeMessage;
      break;
  
    // case 'value3':
    //   // Code to execute if $method equals 'value3'
    //   break;
    
    default:
      $headers = [
          'Content-Type: text/xml;charset=UTF-8',
          // 'Connection: Keep-Alive',
      ];
      break;
  }
  
  
  // Initialize cURL session
  $ch = curl_init($url);

  // Set cURL options
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $xmlPayload);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
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
// echo "\nServerStatus= ".$response[0]."\n\n\n"; //for debugging
// echo $response[1]."\n\n\n"; // for debugging


$decryptedResult = decryptResponse($response[1]);
// echo $decryptedResult; //for debugging
$methodResponse = 'xml_response/'.$method . '_response.xml';
file_put_contents($methodResponse, $decryptedResult);
$txtFilePath= 'xml_response/txt/'.$method . '_response.txt';
response_to_file($methodResponse,$txtFilePath);

function decryptResponse($responseXML) {
  // input encrypted response XML, output decrypted result XML
  // Create SimpleXML object

  $xml = simplexml_load_string($responseXML);

  // Register the 'xenc' namespace
  $xml->registerXPathNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

  // Use XPath to select the CipherValue
  $cipherValues = $xml->xpath('//xenc:CipherValue');

  // Check if CipherValues were found
  if (!empty($cipherValues)) {
      // Decrypt using private key
      global $privatekey;
      openssl_private_decrypt(base64_decode($cipherValues[0]), $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
      // echo "AES key: ",base64_encode($decryptedAesKey),"\n\n";
    // Extract the initialization vector required for AES decryption
    $iv = substr(base64_decode($cipherValues[1]), 0, 16);
    // Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
    $decryptedData = openssl_decrypt($cipherValues[1], 'aes-128-cbc', $decryptedAesKey, 0, $iv);
      $responseXML = substr($decryptedData, 16);
      return $responseXML;
  } else {
      global $responseObj;
      //set error flag to true
      $responseObj->error = true;
      $responseObj->errorMsg = "Ciphervalue not found";
  }
}

