<?php

namespace BPN\Networking\DNS;

use BPN\Data\Client;
use BPN\Networking\Endpoint;
use BPN\Networking\Tunneling\Tunnel;

/**
 * DNS record
 */
class Record
{
    protected Client $client;
    protected Endpoint $endpoint;
    
    protected int $added_at;
    // protected int $last_update;

    /**
     * Construct record
     * 
     * @param Client $client
     * @param Endpoint $endpoint
     */
    public function __construct (Client $client, Endpoint $endpoint)
    {
        $this->client = $client;
        $this->endpoint = $endpoint;

        $this->added_at = time ();
        // $this->last_update = $this->added_at;
    }

    /**
     * Alias of constructor
     */
    public static function new (...$args): self
    {
        return new self (...$args);
    }

    /**
     * Convert record to string
     * 
     * @return string
     */
    public function toString (): string
    {
        return $this->endpoint->toString() .'#'. $this->client->public();
    }

    /**
     * Get record from string
     * 
     * @param string $record
     * 
     * @return Record
     */
    public static function fromString (string $record): Record
    {
        $break = strpos ($record, '#');

        $endpoint = Endpoint::format (substr ($record, 0, $break));
        $client   = Client::new (substr ($record, $break + 1));

        return new self ($client, $endpoint);
    }

    public function client (): Client
    {
        return $this->client;
    }

    public function endpoint (): Endpoint
    {
        return $this->endpoint;
    }

    public function addedAt (): int
    {
        return $this->added_at;
    }

    public function record (): array
    {
        return [$this->client, $this->endpoint];
    }

    /**
     * Get record's uri (endpoint@uuid)
     * 
     * Can be used to get the record from DNS
     * 
     * @return string
     */
    public function uri (): string
    {
        return $this->endpoint->toString() .'@'. $this->client->uuid();
    }

    /**
     * Quickly create protected TCP tunnel with this client
     * 
     * [@param int $wait_milliseconds = 1000] - time to wait before stop trying to create tunnel
     * [@param int $delay_milliseconds = 10] - time to wait between tries to connect to the client
     * 
     * @return Tunnel|null - return Tunnel object or null if we didn't create it
     */
    public function createTunnel (int $wait_milliseconds = 1000, int $delay_milliseconds = 10): ?Tunnel
    {
        return Tunnel::create ($this->endpoint, $wait_milliseconds, $delay_milliseconds);
    }
}
