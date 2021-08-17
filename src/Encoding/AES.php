<?php

namespace BPN\Encoding;

/**
 * AES encryption class
 */
class AES
{
    /**
     * Encrypt data
     * 
     * @param string $text - plaintext
     * @param string $key - encryption key
     * 
     * @return string - encrypted data
     */
    public static function encode (string $text, string $key): string
    {
        $key = hash ('sha256', $key, true);
        $iv  = openssl_random_pseudo_bytes(16);

        $ciphertext = openssl_encrypt ($text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        return $iv . hash_hmac ('sha256', $ciphertext . $iv, $key, true) . $ciphertext;
    }

    /**
     * Decrypt data
     * 
     * @param string $text - encrypted data
     * @param string $key - decryption key
     * 
     * @return string|null - returns null if key is not correct or
     * encrypted data is corrupted
     */
    public static function decode (string $text, string $key): ?string
    {
        $iv = substr ($text, 0, 16);
        $key = hash ('sha256', $key, true);
        $ciphertext = substr ($text, 48);

        if (!hash_equals (hash_hmac ('sha256', $ciphertext . $iv, $key, true), substr ($text, 16, 32)))
            return null;

        return openssl_decrypt ($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    }
}
