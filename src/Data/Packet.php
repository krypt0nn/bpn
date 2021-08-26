<?php

namespace BPN\Data;

use BPN\Networking\{
    Endpoint,
    DNS
};

use BPN\Networking\DNS\Record;

/**
 * Representation of a some data
 */
class Packet
{
    /**
     * Packets types
     */
    public const DEFAULT       = 0; // Default packets
    public const INTRODUCING   = 1; // Ask another client to add you to his DNS
    public const PERFORM_EVENT = 2; // Send ... request to perform an event

    /**
     * DNS SHARING
     */
    public const DNS_SHARING_REQUEST  = 3; // Ask ... to get his DNS records that is different from yours
    public const DNS_SHARING_RESPONSE = 4; // Receive ... response about different records

    /**
     * DNS SEARCH
     */
    public const DNS_SEARCH_REQUEST  = 5; // Ask ... about another client record by his uuid
    public const DNS_SEARCH_RESPONSE = 6; // Receive ... response about this client

    public int $type = 0;
    public $data = null;
    
    public ?int $received_at = null;
    public ?int $sent_at = null;

    public ?Endpoint $author_endpoint = null;
    public ?string $author_uuid = null;

    /**
     * Construct packet
     * 
     * [@param array $options = []] - array of options above, like:
     * 
     * [
     *     'type' => Packet::INTRODUCING,
     *     ...
     * ]
     */
    public function __construct (array $options = [])
    {
        foreach ($options as $name => $value)
            $this->$name = $value;
    }

    /**
     * Quickly create new packet
     * 
     * @param mixed $data
     * [@param int $type = 0]
     * 
     * @return self
     */
    public static function new ($data, int $type = 0): self
    {
        return new self ([
            'data' => $data,
            'type' => $type
        ]);
    }

    /**
     * Quickly create PERFORM_EVENT packet
     * 
     * @param string $name - event name
     * @param mixed $data - event data
     * 
     * @return self
     */
    public static function performEvent (string $name, $data): self
    {
        return new self ([
            'data' => [
                'name' => $name,
                'data' => $data
            ],
            'type' => self::PERFORM_EVENT
        ]);
    }

    /**
     * Convert packet to string
     * 
     * [@param Endpoint $author_endpoint = null]
     * 
     * @return string
     */
    public function toString (Endpoint $author_endpoint = null): string
    {
        return implode (':', [
            $this->type,
            ($author_endpoint ?: $this->author_endpoint)?->toString() ?: '-',
            $this->author_uuid ?: '-',
            time(),
            serialize ($this->data)
        ]);
    }

    /**
     * Convert string to the packet
     * 
     * @param string $packet
     * [@param int $received_at = null]
     * 
     * @return self
     */
    public static function fromString (string $packet, int $received_at = null): self
    {
        [$type, $endpoint, $uuid, $sent_at] = explode (':', $packet);

        $data = unserialize (substr ($packet, strlen ($type) + strlen ($endpoint) + strlen ($uuid) + strlen ($sent_at) + 4));

        return new self ([
            'type' => $type,
            'data' => $data,

            'received_at' => $received_at ?: time (),
            'sent_at' => $sent_at,
            
            'author_endpoint' => $endpoint != '-' ?
                Endpoint::formatOrNull ($endpoint) : null,

            'author_uuid' => $uuid != '-' ? $uuid : null
        ]);
    }

    /**
     * Get packet's type
     * 
     * [@param bool $as_string = false] - if true, method will return name of the type
     * 
     * @return int|string
     */
    public function type (bool $as_string = false): int|string
    {
        if (!$as_string)
            return $this->type;

        $type = array_search ($this->type, (new ReflectionClass (self::class))->getConstants ());

        return $type === false ? 0 : $type;
    }

    /**
     * Get time in seconds this packet was alive (received - sent time)
     * 
     * @return int|null
     */
    public function lifetime (): ?int
    {
        return $this->sent_at !== null && $this->received_at !== null ?
            $this->received_at - $this->sent_at : null;
    }

    /**
     * Try to find packet's author in local DNS
     * 
     * @return Record|null
     */
    public function author (): ?Record
    {
        if ($this->author_endpoint === null)
        {
            if ($this->author_uuid === null)
                return null;

            $records = DNS::getRecordsByUUID ($this->author_uuid);

            if (sizeof ($records) == 1)
                return current ($records);

            return null;
        }

        else
        {
            $records = DNS::getRecordsByEndpoint ($this->author_endpoint);

            if (sizeof ($records) == 0)
                return null;

            if ($this->author_uuid === null || sizeof ($records) == 1)
                return current ($records);

            foreach ($records as $record)
                if ($record->client()->uuid() == $this->author_uuid)
                    return $record;

            return null;
        }
    }
}
