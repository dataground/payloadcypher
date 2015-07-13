<?php

use Dataground\PayloadCypher;
use ForceUTF8\Encoding;

/**
 * Class PayloadCypherTest
 */
class PayloadCypherTest extends PHPUnit_Framework_TestCase
{
    /**
     * Disabled temporary (test takes a lot of time)
     */
    public function testEncDec()
    {
        $pc = new PayloadCypher();

        $keyDir = __DIR__ . '/../../var/test/keys';
        $dataDir = __DIR__ . '/../../var/test/data';

        // Test different key sizes
        for ($x = 1; $x < 4; $x++) {

            $cmd = 'openssl genrsa -out '  .$keyDir.'/private.pem ' . $x * 1024;
            system($cmd);

            $cmd = 'openssl rsa -in ' .$keyDir. '/private.pem -outform PEM -pubout -out ' . $keyDir.'/public.pem';
            system($cmd);

            $pc->setOnPublicKeyLoad(
                function () use ($keyDir) {
                    return array(rand(1000, 2000) => file_get_contents($keyDir.'/public.pem'));
                }
            );

            $pc->setOnPrivateKeyLoad(
                function ($keyName) use ($keyDir) {
                    return array($keyName => file_get_contents($keyDir.'/private.pem'));
                }
            );

            $utf8Text = file_get_contents($dataDir . '/utf8.txt');

            for ($i = 1; $i < 10; $i++) {
                $payload = $utf8Text . openssl_random_pseudo_bytes(rand(1, 200));
                $cypherText = $pc->encryptString($payload);
                $decrypted = $pc->decryptString($cypherText);
                $this->assertEquals($decrypted, $payload);
            }

            for ($i = 1; $i < 10; $i++) {
                $obj = new stdClass();
                $obj->test0 = 'hallo';
                $obj->test1 = true;
                $obj->test2 = 1.12 * $i;
                $obj->test3 = array(1, 2, 3);
                $obj->utf8 = $utf8Text;

                // Entry to reproduce UTF8 encoding bug like:
                // http://stackoverflow.com/questions/10205722/json-encode-invalid-utf-8-sequence-in-argument
                $obj->invalidUtf8 = Encoding::toUTF8(pack("H*", 'c32e'));

                $cypherText = $pc->objectToEncryptedJson($obj);
                $decrypted = $pc->encryptedJsonToObject($cypherText);

                $this->assertEquals($obj, $decrypted);
            }

            for ($i = 1; $i < 10; $i++) {

                $arr = array(
                    'test1' => 123,
                    'test2' => 10.10,
                    'utf8' => file_get_contents($dataDir . '/utf8.txt')
                );

                $cypherText = $pc->arrayToEncryptedJson($arr);
                $decrypted = $pc->encryptedJsonToArray($cypherText);

                $this->assertEquals($arr, $decrypted);
            }
        }

        unlink($keyDir.'/private.pem');
        unlink($keyDir.'/public.pem');
    }
}