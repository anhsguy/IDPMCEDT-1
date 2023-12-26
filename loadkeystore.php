<?php
// Load the PKCS#12 file
$pkcs12 = file_get_contents('teststore.p12');

// Parse the PKCS#12 file to extract private key and certificate
openssl_pkcs12_read($pkcs12, $pkcs12Info, 'changeit');

// load the private key
$privatekey = $pkcs12Info['pkey'];
?>