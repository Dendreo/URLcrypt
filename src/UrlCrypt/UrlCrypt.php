<?php

/**
 * URLCrypt
 *
 * PHP library to securely encode and decode short pieces of arbitrary binary data in URLs.
 *
 * (c) Guillermo Gonzalez
 *
 * For the full copyright and license information, please view the COPYING
 * file that was distributed with this source code.
 */

namespace Atrapalo\UrlCrypt;

/**
 * Class UrlCrypt
 * @package dendreo\UrlCrypt
 */
class UrlCrypt
{
    public $table = "1bcd2fgh3jklmn4pqrstAvwxyz567890";
    private $ivSize;
    private $cipher = 'AES-128-CBC';

    public function __construct(string $table = null)
    {
        $this->ivSize = openssl_cipher_iv_length($this->cipher);
        if (!is_null($table) && $table != '') {
            $this->table = $table;
        }
    }

    public static function getInstance(string $table = null): UrlCrypt
    {
        return new self($table);
    }

    public function encode(string $string): string
    {
        $table = str_split($this->table, 1);
        $size = strlen($string) * 8 / 5;
        $stringArray = str_split($string, 1);

        $message = "";
        foreach ($stringArray as $char) {
            $message .= str_pad(decbin(ord($char)), 8, "0", STR_PAD_LEFT);
        }

        $message = str_pad($message, ceil(strlen($message) / 5) * 5, "0", STR_PAD_RIGHT);

        $encodeString = "";
        for ($i = 0; $i < $size; $i++) {
            $encodeString .= $table[bindec(substr($message, $i * 5, 5))];
        }

        return $encodeString;
    }

    public function decode(string $string): string
    {
        $table = str_split($this->table, 1);
        $size = strlen($string) * 5 / 8;
        $stringArray = str_split($string, 1);

        $message = "";
        foreach ($stringArray as $char) {
            $message .= str_pad(decbin(array_search($char, $table)), 5, "0", STR_PAD_LEFT);
        }

        $originalString = '';
        for ($i = 0; $i < floor($size); $i++) {
            $originalString .= chr(bindec(substr($message, $i * 8, 8)));
        }

        return $originalString;
    }

    public function encrypt(string $string, string $key): string
    {
        $key = $this->prepareKey($key);
        $iv = openssl_random_pseudo_bytes($this->ivSize);
        $cipherText = openssl_encrypt($string, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);

        if(false === $cipherText) {
            $this->throwOpensslError();
        }

        return $this->encode(base64_encode($cipherText).'::'.base64_encode($iv));
    }

    public function decrypt(string $string, string $key): string
    {
        $string = $this->decode($string);

        if (strpos($string, '::') === false) {
            return $this->legacyDecrypt($string, $key);
        }

        $key = $this->prepareKey($key);
        list($string, $iv) = explode('::', $string);
        $string = openssl_decrypt(base64_decode($string), $this->cipher, $key, OPENSSL_RAW_DATA, base64_decode($iv));

        return $string;
    }

    private function prepareKey(string $key): string
    {
        if (is_null($key) || $key == "") {
            throw new \Exception('No key provided.');
        }

        return md5($key, true);
    }

    private function isHexString(string $string): string
    {
        return (preg_match('/^[0-9a-f]+$/i', $string) === 1);
    }

    private function throwOpensslError()
    {
        $message = '';
        while ($msg = openssl_error_string()) {
            $message .= "{$msg}. ";
        }

        throw new \RuntimeException(trim($message));
    }

    private function legacyDecrypt(string $string, string $key): string
    {
        $key = $this->legacyPrepareKey($key);
        $iv = substr($string, 0, $this->ivSize);
        $string = substr($string, $this->ivSize);
        $string = openssl_decrypt($string, $this->cipher, $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);

        preg_match_all('#([\\000]+)$#', $string, $matches);
        if (isset($matches[1][0]) && mb_strlen($matches[1][0], '8bit') > 1) {
            $string = rtrim($string, "\0");
        }

        return $string;
    }

    private function legacyPrepareKey(string $key): string
    {
        if (is_null($key) || $key == "") {
            throw new \Exception('No key provided.');
        }

        if (in_array(strlen($key), [32, 48, 64]) && $this->isHexString($key)) {
            return pack('H*', $key);
        } elseif (in_array(strlen($key), [16, 24, 32])) {
            return $key;
        } else {
            return md5($key);
        }
    }
}
