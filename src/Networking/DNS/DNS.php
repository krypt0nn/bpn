<?php

namespace BPN\Networking\DNS;

use BPN\BPN;

use BPN\Data\{
    Client,
    Packet
};

/**
 * DNS library
 * This class realizes storage for known clients
 * its filtering and another useful stuff
 */
class DNS
{
    # list of known clients
    protected static array $records = [];

    /**
     * Get records by endpoint (ip and port)
     * This method returns a list of records because
     * one client hypotetically can run 2 or more BPNs on one port
     * 
     * @param Endpoint $endpoint
     * 
     * @return array
     */
    public static function getRecordsByEndpoint (Endpoint $endpoint): array
    {
        $endpoint = $endpoint->toString();

        return self::where (function (Record $record) use ($endpoint)
        {
            return $record->endpoint()->toString() == $endpoint;
        });
    }

    /**
     * Get records by UUID (user's public key hash)
     * 
     * @param string $uuid
     * 
     * @return array
     */
    public static function getRecordsByUUID (string $uuid): array
    {
        return self::where (function (Record $record) use ($uuid)
        {
            return $record->client()->uuid() == $uuid;
        });
    }

    /**
     * Execute callable with every DNS record
     * 
     * @param callable $callback - function (Record $record): void
     * 
     * @return void
     */
    public static function foreach (callable $callback): void
    {
        foreach (self::$records as &$record)
            $callback ($record);
    }

    /**
     * Filter DNS records using callable
     * 
     * @param callable $callback - function (Record $record): bool
     * 
     * @return array
     */
    public static function where (callable $callback): array
    {
        $records = [];

        foreach (self::$records as $record)
            if ($callback ($record))
                $records[] = $record;

        return $records;
    }

    /**
     * Add record
     * This method is not looking at if this
     * record already exists
     * 
     * @param Record $record
     * 
     * @return void
     */
    public static function addRecord (Record $record): void
    {
        self::$records[] = $record;
    }

    /**
     * Get records list
     * 
     * @return array
     */
    public static function getRecords (): array
    {
        return self::$records;
    }

    /**
     * Set records list
     * 
     * @param array $records - list of Record objects
     * 
     * @return void
     */
    public static function setRecords (array $records): void
    {
        self::$records = [];

        foreach ($records as $record)
            if ($record instanceof Record)
                self::$records[] = $record;
    }

    /**
     * Initiate DNS SHARING
     * 
     * [@param Endpoint $endpoint = null] - endpoint to share records with
     * By default shares records with every client in DNS
     * 
     * @return void
     */
    public static function shareRecords (Endpoint $endpoint = null): void
    {
        $bpn = BPN::get();

        if ($endpoint !== null)
            $bpn->send ($endpoint, Packet::new (self::$records, Packet::DNS_SHARING_REQUEST));

        else foreach (self::$records as $record)
            $bpn->send ($record->endpoint(), Packet::new (self::$records, Packet::DNS_SHARING_REQUEST));
    }
}
