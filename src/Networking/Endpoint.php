<?php

namespace BPN\Networking;

use BPN\Networking\DNS\DNS;

/**
 * Remote endpoint
 */
class Endpoint
{
    # Default endpoint port
    public static int $default_port = 53847;

    protected string $ip;
    protected int $port;

    /**
     * Endpoint constructor
     * 
     * @param string $ip
     * [@param int $port = null] - by default will use the.. default port
     */
    public function __construct (string $ip, int $port = null)
    {
        $this->ip = $ip;
        $this->port = $port ?: self::$default_port;

        if (!self::isIp ($this->ip))
            throw new \Exception ('IP address is incorrect');

        if (!self::isPort ($this->port))
            throw new \Exception ('Port is incorrect');
    }

    /**
     * Create endpoint from string
     * 
     * @param string $address (5.10.15.20:2530 / 5.10.15.20)
     * 
     * @return self
     * 
     * @throws \Exception if addres is not correct
     */
    public static function format (string $address): self
    {
        return new self (...explode (':', $address));
    }

    /**
     * Analog of format, but will return null if address
     * is not correct and not throw an exceptions
     * 
     * @param string $address
     * 
     * @return self|null
     */
    public static function formatOrNull (string $address): ?self
    {
        try
        {
            return new self (...explode (':', $address));
        }

        catch (\Exception)
        {
            return null;
        }
    }

    /**
     * Convert endpoint to string
     * 
     * @return string
     */
    public function toString (): string
    {
        return $this->ip .':'. $this->port;
    }

    public function ip (): string
    {
        return $this->ip;
    }

    public function port (): int
    {
        return $this->port;
    }

    public function addressPair (): array
    {
        return [$this->ip, $this->port];
    }

    /**
     * Get list of DNS records with this endpoint
     * 
     * @return array
     */
    public function clients (): array
    {
        return DNS::getClientsByEndpoint ($this);
    }

    public static function isIp (string $ip): bool
    {
        return preg_match ('/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/', $ip);
    }

    public static function isPort (int $port): bool
    {
        return $port > -1 && $port < 65536;
    }

    /**
     * Get local endpoint
     * 
     * [@param int $port = null]
     * 
     * @return self
     */
    public static function local (int $port = null): self
    {
        $socket = socket_create (AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_connect ($socket, '8.8.8.8', 53);
        socket_getsockname ($socket, $address);

        return new self ($address, $port ?: self::$default_port);
    }

    /**
     * Get external endpoint
     * 
     * [@param int $port = null]
     * 
     * @return self
     */
    public static function external (int $port = null): self
    {
        $ip = file_get_contents ('https://api.ipify.org');

        return new self ($ip, $port ?: self::$default_port);
    }
}
