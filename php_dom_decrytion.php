<?php
// load external script which imports $privatekey
include 'loadkeystore.php';
echo $privatekey;
// Sign the SHA-1 hash using private key and PKCS1 padding
$rawbody = <<<EOT
<soapenv:Body wsu:Id="id-5">
  <edt:getTypeList/>
</soapenv:Body>
EOT;
openssl_sign($rawbody, $signature, $privatekey, OPENSSL_ALGO_SHA1);
// Signature is now in $signature
$signature=base64_encode($signature);
echo 'Signature_encode_2: ', base64_encode($signature), "\n\n"; //for debug
echo var_dump($signature);
echo 'Signature: ', $signature, "\n\n"; //for debug
$decodedData = base64_decode($signature);
echo "\ndecoded= " .$decodedData;
// Load the public key
$publicKey = openssl_pkey_get_public(file_get_contents($publicKeyPath));

// Decode the base64-encoded signature
$binarySignature = base64_decode($signature);

// Verify the signature using the public key
$verificationResult = openssl_verify($rawbody, $binarySignature, $publicKey, OPENSSL_ALGO_SHA1);

if ($verificationResult == 1) {
    echo "Signature is valid.\n";
} elseif ($verificationResult == 0) {
    echo "Signature is invalid.\n";
} else {
    echo "Error during verification.\n";
}

// Free the key resource
openssl_free_key($publicKey);
// $dom = new DOMDocument;
// $dom->load("response.xml");
// $xml= $dom->saveXML();
// echo "\nxml_type: \n" . var_dump($xml);
// // Register the 'xenc' namespace
// $xml = simplexml_load_string($dom->saveXML());
// $xml->registerXPathNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

// // Use XPath to select the CipherValue
// $cipherValues = $xml->xpath('//xenc:CipherValue');
// echo "CipherValue: " . $cipherValues[0] . "\n";
// // echo "CipherVa?lue_1: " . $cipherValues[1] . "\n";
// // Check if CipherValues were found
// if (!empty($cipherValues)) {
//     // Decrypt using private key
//     global $privatekey;
//   echo "\nprivatekey= : " .$privatekey;
  //   openssl_private_decrypt(base64_decode($cipherValues[0]), $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
  //   echo "\nDecrypted AES Key: " . $decryptedAesKey . "\n";
  //   echo "\nAES key: ",base64_encode($decryptedAesKey),"\n\n";
  // // Extract the initialization vector required for AES decryption
  // $iv = substr(base64_decode($cipherValues[1]), 0, 16);
  // echo "IV: ",bin2hex($iv),"\n";
  // // Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
  // $decryptedData = openssl_decrypt($cipherValues[1], 'aes-128-cbc', $decryptedAesKey, 0, $iv);
  //   $responseXML = substr($decryptedData, 16);
  //   echo "responseXML: " . $responseXML;
// } 






// $x = $dom->getElementsByTagName("CipherValue");
// echo "\nitem_type= ".var_dump($x->item(0));
// echo "\nnodeValueType= ".$x->item(0)->nodeValue;
// $content=$x->item(0);
// $y=$content=$x->item(0);
// // echo "\ncontent= ".$content;
// // Find the EncryptedData element
// $cipherValues = $content; // Replace 'EncryptedData' with the actual XML element name
// // Check if CipherValues were found
//     // Decrypt using private key
// // Get the base64-encoded data from the element
// $base64EncodedData = $cipherValues->nodeValue;
// global $privatekey;
//     openssl_private_decrypt(base64_decode($base64EncodedData), $decryptedAesKey, $privatekey, OPENSSL_PKCS1_PADDING);
//     echo "\nAES key: ",base64_encode($decryptedAesKey),"\n\n";
//   // Extract the initialization vector required for AES decryption
//   $iv = substr(base64_decode($cipherValues[1]), 0, 16);
//   // Decrypt using AES with CBC mode, PKCS5 padding, and the extracted IV
//   $decryptedData = openssl_decrypt($cipherValues[1], 'aes-128-cbc', $decryptedAesKey, 0, $iv);
//     $responseXML = substr($decryptedData, 16);

// echo "\nDecrypted Data: ",$responseXML;


