<?php
namespace Dataground;

use Closure;
use ErrorException;
use stdClass;

/**
 * Class PayloadCypher
 *
 * @author Dataground <info@dataground.com>
 */
class PayloadCypher
{
    /**
     * @var string
     */
    private $keyName = 'TMP';

    /**
     * @var string
     */
    private $publicKey = '';

    /**
     * @var string
     */
    private $privateKey = '';

    /**
     * @var string
     */
    private $chunkDelimiter = "_";

    /**
     * @var int
     */
    private $chunkLen = 0;

    /**
     * Replace base64 chars to be "url safe"
     * @var array
     */
    private $replaceChars = array('/' => '.x', '=' => '.y', '+' => '.z');

    /**
     * @var Closure[]
     */
    private $events = array(
        'onPublicKeyLoad' => null,
        'onPrivateKeyLoad' => null
    );

    /**
     * @param Closure $onPrivateKeyLoad
     *
     * function loadPrivateKey($keyName) {
     *      return array('... Name of Key ...' => '... PEM Private Key...');
     * }
     */
    public function setOnPrivateKeyLoad(Closure $onPrivateKeyLoad)
    {
        $this->events['onPrivateKeyLoad'] = $onPrivateKeyLoad;
    }

    /**
     * @param Closure $onPublicKeyLoad
     *
     * function loadPublicKey() {
     *      return array('... Name of key ...' => '... PEM Public Key ...');
     * }
     */
    public function setOnPublicKeyLoad(Closure $onPublicKeyLoad)
    {
        $this->events['onPublicKeyLoad'] = $onPublicKeyLoad;
    }

    /**
     * @param $data
     * @return string
     */
    public function binToArmor($data)
    {
        return str_replace(array_keys($this->replaceChars), $this->replaceChars, base64_encode($data));
    }

    /**
     * @param $data
     * @return string
     */
    public function armorToBin($data)
    {
        return base64_decode(str_replace($this->replaceChars, array_keys($this->replaceChars), $data));
    }

    /**
     * Needed for encryption support
     * @param $publicKey
     * @throws ErrorException
     */
    private function setPublicKey($publicKey)
    {
        $res = openssl_get_publickey($publicKey);

        if ($res === false) {
            throw new ErrorException('Error while opening public key ' . openssl_error_string());
        }

        // RSA is only able to encrypt data to a maximum amount of your key size (2048 bits = 256 bytes) minus padding / header data (11 bytes for PKCS#1 v1.5 padding).
        // https://polarssl.org/kb/cryptography/rsa-encryption-maximum-data-size
        $keyData = openssl_pkey_get_details($res);
        $this->chunkLen = ($keyData['bits'] / 8) - 11;
        $this->publicKey = $publicKey;
    }

    /**
     * Needed for decryption support
     * @param string $privateKey
     */
    private function setPrivateKey($privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * @param string $chunkDelimiter
     */
    public function setChunkDelimiter($chunkDelimiter)
    {
        $this->chunkDelimiter = $chunkDelimiter;
    }

    /**
     * @param string $keyName
     */
    public function setKeyName($keyName)
    {
        $this->keyName = $keyName;
    }

    /**
     * @param $payload
     * @return string
     * @throws ErrorException
     */
    public function encryptString($payload)
    {
        $keyArray = $this->events['onPublicKeyLoad']();
        $keyCrt = reset($keyArray);
        $keyName = key($keyArray);
        $this->setKeyName($keyName);
        $this->setPublicKey($keyCrt);

        // @todo check all prereqs
        $parts = str_split($payload, $this->chunkLen);
        $encryptedParts = array($this->keyName);

        foreach ($parts as $part) {
            $ok = openssl_public_encrypt($part, $encryptedPart, $this->publicKey);

            if ($ok === false) {
                throw new ErrorException('Error while encrypting chunk ' . openssl_error_string());
            }

            $encryptedParts[] = $this->binToArmor($encryptedPart);
        }

        return join($this->chunkDelimiter, $encryptedParts);
    }

    /**
     * @param $cryptedPayload
     * @return string
     * @throws ErrorException
     */
    public function decryptString($cryptedPayload)
    {
        $parts = explode($this->chunkDelimiter, $cryptedPayload);
        $keyName = array_shift($parts);

        $keyArray = $this->events['onPrivateKeyLoad']($keyName);
        $this->setPrivateKey(reset($keyArray));
        $out = '';

        foreach ($parts as $part) {
            $decrypted = '';
            $ok = openssl_private_decrypt($this->armorToBin($part), $decrypted, $this->privateKey);

            if ($ok === false) {
                throw new ErrorException('Error while decrypting chunk: ' . openssl_error_string());
            }

            $out .= $decrypted;
        }

        return $out;
    }

    /**
     * @todo large file encryption/decryption streaming to outfile
     */
//    public function encryptFile($inFile, $outFile) {
//    }

//    public function decryptFile($inFile, $outFile) {
//    }

    /**
     * @param stdClass $data
     * @return string
     */
    public function objectToEncryptedJson(stdClass $data)
    {
        return $this->encryptString(json_encode($data));
    }

    /**
     * @param $encryptedJson
     * @return stdClass $object
     * @throws ErrorException
     */
    public function encryptedJsonToObject($encryptedJson)
    {
        return json_decode($this->decryptString($encryptedJson), false);
    }

    /**
     * @param array $data
     * @return string
     * @throws ErrorException
     */
    public function arrayToEncryptedJson(array $data = array())
    {
        return $this->encryptString(json_encode($data));
    }

    /**
     * @param $encryptedJson
     * @param array $mergeTo
     * @return array
     * @throws ErrorException
     */
    public function encryptedJsonToArray($encryptedJson, array $mergeTo = array())
    {
        $data = json_decode($this->decryptString($encryptedJson), true);
        return array_merge($mergeTo, $data);
    }

    /**
     * @param $encryptedJson
     * @throws ErrorException
     */
    public function encryptedJsonDump($encryptedJson)
    {

        echo '---' . PHP_EOL;
        echo $this->decryptString($encryptedJson) . PHP_EOL;
        echo '---' . PHP_EOL;
    }
}