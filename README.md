# Payload Cypher
String/Array/Object/JSON asymetric encryption library using PHP OpenSSL RSA.
Supports endless payload length (only limited by memory) by using payload chunking algoritm. 
Good for secure storage of playloads in a database. Supports multiple keys (key rotation) by prefixing the payload output.

### Why RSA?
Rsa was not designed for payload encryption. Processing is rather slow and output will be bulky compared to AES. 
There are some usecases though where the asymetric nature of RSA is favorable. The major advantage is the ability to fully separate encryption from decryption.
In case you only need to encrypt stuff in one application/server, there is no need to distribute the private key to this environment.

### What keylength is appropriate?
Consult the excellent keylength tool [http://www.keylength.com/](http://www.keylength.com/).

## Dependencies
* php 5.4.x+
* php_openssl

## Key creation
Create RSA Key:

### Create private key
    openssl genrsa -out MY001.pem 3072

### Create public key
    openssl rsa -in MY001.pem -outform PEM -pubout -out MY001.pub.pem

## Usage
    $payloadCypher = new PayloadCypher();

    // This public key will be loaded on encryptions
    $payloadCypher->setOnPublicKeyLoad(
        function () {
            $key = file_get_contents('MY001.pub.pem');
            return array($keyName => $key);
        }
    );

    // The private key will be loaded based on the encryption prefix
    // When there is no need to decrypt this callback can be omitted
    $payloadCypher->setOnPrivateKeyLoad(
        function ($keyName) {
            $key = file_get_contents($keyName.'.pem');
            return array($keyName => $key);
        }
    );
    
    // Encryption / Decryption of a string
    $encrypted = $payloadCypher->encryptString('foo bar baz');
    $decrypted = $payloadCypher->decryptString($encrypted);
   
    echo $decrypted.PHP_EOL;
    // ... foo bar baz
    
    // Encryption / Decryption of an array stored as encrypted JSON
    $encrypted = $payloadCypher->arrayToEncryptedJson(array('foo' => 'bar'));
    $decrypted = $payloadCypher->encryptedJsonToArray($encrypted);
   
    var_dump($decrypted);
    // ... array('foo' => 'bar')
        
        