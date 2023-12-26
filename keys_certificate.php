<?php

$keystorePath = 'teststore.p12';
$keystorePassword = 'changeit';

// Load the keystore
$keystore = file_get_contents($keystorePath);

// Extract private key, public key, and certificate
openssl_pkcs12_read($keystore, $certs, $keystorePassword);

// Get the private key
$privateKey = $certs['pkey'];

// Get the public key
$publicKey = openssl_pkey_get_public($certs['cert']);
// Get details of the public key
$keyDetails = openssl_pkey_get_details($publicKey);

// Extract the public key in PEM format
$publicKeyPEM = $keyDetails['key'];

// Output the public key as a string
echo "Public Key (PEM):\n", $publicKeyPEM, "\n";
// Get the certificate
$certificate = openssl_x509_read($certs['cert']);

// Convert certificate to PEM format
openssl_x509_export($certificate, $certPEM);

// Output results
echo "Private Key:\n", $privateKey, "\n\n";
echo "Public Key:\n", $publicKey, "\n\n";
echo "Certificate:\n", $certPEM, "\n";

// Clean up
openssl_free_key($publicKey);
openssl_free_key($privateKey);

?>
