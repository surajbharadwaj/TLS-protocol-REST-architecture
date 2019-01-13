The certificate and private key are generated using opensssl.

Command to generate X509 certificate:
req -x509 -md5 -nodes -days 365 -newkey rsa:512 -keyout privateKey.key -out Certificate.cer

Command to encrypt in pkc8 format: 
pkcs8 -topk8 -inform PEM -outform DER -in privatekey.key -nocrypt -out privatekey.pkcs8
