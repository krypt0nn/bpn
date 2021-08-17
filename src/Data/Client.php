<?php

namespace BPN\Data;

use BPN\Encoding\ECC;

/**
 * Object that represents basic information
 * about remote client
 */
class Client
{
    # UUID hash function
    public static string $hash_function = 'sha1';

    public function __construct (protected string $public_key) {}

    public static function new (...$args): self
    {
        return new self (...$args);
    }

    public function public (): string
    {
        return $this->public_key;
    }

    /**
     * Generate shared secret with this client
     * 
     * @param string $privateKey - your private key
     * 
     * @return string
     */
    public function sharedSecret (string $privateKey): string
    {
        return ECC::generateSharedSecret ($this->public_key, $privateKey);
    }

    /**
     * Calculate client UUID
     * 
     * @return string
     */
    public function uuid (): string
    {
        return hash (self::$hash_function, $this->public_key, true);
    }
}
