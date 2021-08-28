<?php

namespace BPN;

use BPN\Encoding\ECC;

use BPN\Data\{
    Packet,
    Client
};

use BPN\Networking\{
    Endpoint,
    DNS
};

use BPN\Networking\DNS\Record;

/**
 * BPN core class
 * Doing the main stuff
 */
class BPN
{
    public static Endpoint $local_endpoint;
    public static Endpoint $external_endpoint;

    public static ?string $data = null;
    public static ?string $public_key = null;
    public static ?string $private_key = null;

    public static int $unused_stream_lifetime = 120; // in seconds
    public static int $stream_cleanup_delay = 60; // in seconds

    public static int $packets_send_delay = 10 * 1000; // in microseconds, 10 * 1000 = 10 milliseconds or 1 / 100 of second

    /**
     * Strongly unrecommended to change
     */
    public static int $last_streams_cleanup = 0;

    public static $socket = null;
    public static $broadcast = null;
    public static array $streams = [];
    public static array $events = [];
    public static array $search = [];

    public static function get ()
    {
        if (!self::$local_endpoint)
            self::$local_endpoint = Endpoint::local();

        if (!self::$external_endpoint)
            self::$external_endpoint = Endpoint::external();

        if (self::$public_key === null || self::$private_key === null)
            throw new \Exception ('You must initialize public and private keys before');
        
        if (self::$socket === null)
        {
            if (!($socket = socket_create (AF_INET, SOCK_DGRAM, 0)))
                throw new \Exception ('Couldn\'t create socket: '. socket_strerror (socket_last_error ()));

            if (!socket_bind ($socket, self::$local_endpoint->ip(), self::$local_endpoint->port()))
                throw new \Exception ('Couldn\'t bind socket: '. socket_strerror (socket_last_error ()));

            socket_set_nonblock ($socket);

            self::$socket = $socket;
        }

        return new class
        {
            public function update (callable $defaultCallback = null): self
            {
                if (time () - BPN::$last_streams_cleanup > BPN::$stream_cleanup_delay)
                    $this->cleanStreams ();
                
                while (true)
                {
                    $packet_length = socket_recvfrom (BPN::$socket, $packet, 4096, 0, $ip, $port);

                    /*if ($packet_length === false)
                        throw new \Exception ('An error occurred during data reading: '. socket_strerror (socket_last_error ()));*/

                    if (!$packet_length)
                        break;

                    [$part_number, $parts_amount, $stream_id] = explode (':', $packet);

                    BPN::$streams[$stream_id]['parts_amount'] = $parts_amount;
                    BPN::$streams[$stream_id]['last_update'] = time ();

                    // lengths of part number, parts amount + length of stream id (7 digits) + 3 colons
                    BPN::$streams[$stream_id]['parts'][$part_number] = substr ($packet, strlen ($part_number) + strlen ($parts_amount) + 10);

                    // file_put_contents ('stream_'. $stream_id .'.log', print_r (BPN::$streams[$stream_id], true));

                    if (sizeof (BPN::$streams[$stream_id]['parts']) == BPN::$streams[$stream_id]['parts_amount'])
                    {
                        $packet = Packet::fromString (join (BPN::$streams[$stream_id]['parts']));
                        unset (BPN::$streams[$stream_id]);

                        switch ($packet->type)
                        {
                            /**
                             * Introduce client and add him to the DNS
                             */
                            case Packet::INTRODUCING:
                                $already_exists = false;

                                DNS::foreach (function (Record $record) use ($packet, &$already_exists)
                                {
                                    if ($record->endpoint()->toString() == $packet->author_endpoint->toString() &&
                                        $record->client()->uuid() == $packet->author_uuid)

                                        $already_exists = true;
                                });

                                if (!$already_exists)
                                    DNS::addRecord (Record::new (Client::new ($packet->data), $packet->author_endpoint));

                                break;

                            /**
                             * Share your DNS records list with another client
                             * and ask him to send you his different records
                             */
                            case Packet::DNS_SHARING_REQUEST:
                                $shared_records = $packet->data;

                                $diff_dns = DNS::where (function (Record $record) use ($shared_records)
                                {
                                    foreach ($shared_records as $shared_record)
                                        if ($record->uri() == $shared_record->uri())
                                                return false;

                                    return true;
                                });

                                foreach ($shared_records as $shared_record)
                                {
                                    $addRecord = true;

                                    foreach (DNS::getRecords () as $record)
                                        if ($record->uri() == $shared_record->uri())
                                        {
                                            $addRecord = false;

                                            break;
                                        }

                                    if ($addRecord)
                                        DNS::addRecord ($shared_record);
                                }

                                $this->send ($packet->author_endpoint, Packet::new ($diff_dns, Packet::DNS_SHARING_RESPONSE));

                                break;

                            /**
                             * Add new DNS records from remote client
                             */
                            case Packet::DNS_SHARING_RESPONSE:
                                foreach ($packet->data as $shared_record)
                                {
                                    $addRecord = true;

                                    foreach (DNS::getRecords () as $record)
                                        if ($record->uri() == $shared_record->uri())
                                        {
                                            $addRecord = false;

                                            break;
                                        }

                                    if ($addRecord)
                                        DNS::addRecord ($shared_record);
                                }

                                break;

                            /**
                             * DNS Search request
                             */
                            case Packet::DNS_SEARCH_REQUEST:
                                $ttl = min (ord ($packet->data[0]), 36) - 1;

                                if ($ttl > -1)
                                {
                                    $delimiter1 = strpos ($packet->data, '/');
                                    $uuid = substr ($packet->data, 1, $delimiter1 - 1);

                                    $delimiter2 = strpos ($packet->data, '/', $delimiter1 + 1);
                                    $backtrace = substr ($packet->data, $delimiter1 + 1, $delimiter2 - $delimiter1 - 1);
                                    $backtrace = Endpoint::format ($backtrace);

                                    $blacklist = explode (',', substr ($packet->data, $delimiter2 + 1));
                                    $blacklist[] = $packet->author_endpoint->toString();

                                    $records = DNS::where (fn ($record) => !in_array ($record->endpoint()->toString(), $blacklist));

                                    $blacklist = array_unique (array_merge ($blacklist, array_map (function ($record)
                                    {
                                        return $record->endpoint()->toString();
                                    }, $records)));

                                    $new_packet = chr ($ttl) . $uuid . '/' . implode (',', $blacklist);

                                    foreach ($records as $record)
                                    {
                                        // we shouldn't stop here because this client
                                        // may have another endpoint saved in someone's DNS
                                        // and our record can be incorrect
                                        if ($record->client()->uuid() == $uuid)
                                            $this->send ($backtrace, Packet::new ($record->toString(), Packet::DNS_SEARCH_RESPONSE));

                                        if ($ttl > 0)
                                            $this->send ($record->endpoint(), Packet::new ($new_packet, Packet::DNS_SEARCH_REQUEST));
                                    }
                                }

                                break;

                            /**
                             * DNS Search response
                             */
                            case Packet::DNS_SEARCH_RESPONSE:
                                $record = Record::fromString ($packet->data);

                                if (isset (self::$search[$uuid = $record->client()->uuid()]))
                                    if (self::$search[$uuid] ($record, $packet) === false)
                                        unset (self::$search[$uuid]);

                                break;

                            /**
                             * Receive and share broadcast packet
                             */
                            case Packet::BROADCAST:
                                $ttl = min (ord ($packet->data[0]), 36) - 1;

                                if ($ttl > -1)
                                {
                                    $delimiter = strpos ($packet->data, '/');

                                    $blacklist = explode (',', substr ($packet->data, 1, $delimiter - 1));
                                    $blacklist[] = $packet->author_endpoint->toString();

                                    $records = DNS::where (fn ($record) => !in_array ($record->endpoint()->toString(), $blacklist));

                                    $blacklist = array_unique (array_merge ($blacklist, array_map (function ($record)
                                    {
                                        return $record->endpoint()->toString();
                                    }, $records)));

                                    $data = substr ($packet->data, $delimiter + 1);

                                    if (is_callable (self::$broadcast))
                                        self::$broadcast (unserialize ($data), $packet);

                                    $new_packet = Packet::new (chr ($ttl) . implode (',', $blacklist) .'/'. $data, Packet::BROADCAST);

                                    if ($ttl > 0)
                                        foreach ($records as $record)
                                            $this->send ($record->endpoint(), $new_packet);
                                }

                                break;

                            /**
                             * Perform registered event
                             */
                            case Packet::PERFORM_EVENT:
                                BPN::perform ($packet->data['name'], $packet);

                                break;

                            /**
                             * Default packet (type = 0)
                             */
                            default:
                                if ($defaultCallback !== null)
                                    $defaultCallback ($packet);

                                break;
                        }
                    }
                }

                return $this;
            }

            public function send (Endpoint $endpoint, Packet $packet): self
            {
                $packet->author_endpoint = BPN::$external_endpoint;
                $packet->author_uuid = Client::new(BPN::$public_key)->uuid();

                $packet = $packet->toString();
                $length = strlen ($packet);

                $parts  = ceil ($length / 4000);
                $stream = rand (1000000, 9999999);

                for ($i = 0, $j = 0; $i < $parts; ++$i, $j += 4000)
                {
                    $packet_part = "$i:$parts:$stream:". substr ($packet, $j, min ($length - $j, 4000));

                    socket_sendto (BPN::$socket, $packet_part, 4096, 0, $endpoint->ip(), $endpoint->port());

                    usleep (BPN::$packets_send_delay);
                }

                return $this;
            }

            public function broadcast ($data, int $ttl = 8): self
            {
                $packet = chr (max (1, min ($ttl, 36))) .
                    implode (',', array_unique (array_map (fn ($record) => $record->endpoint()->toString(), DNS::getRecords()))) .'/'.
                    serialize ($data);

                $packet = Packet::new ($packet, Packet::BROADCAST);

                foreach (DNS::getRecords() as $record)
                    $this->send ($record->endpoint(), $packet);

                return $this;
            }

            public function cleanStreams (): self
            {
                $current = time ();

                foreach (BPN::$streams as $id => $stream)
                    if ($current - $stream['last_update'] > BPN::$unused_stream_lifetime)
                        unset (BPN::$streams[$id]);

                BPN::$last_streams_cleanup = $current;

                return $this;
            }
        };
    }

    public static function configure (array $settings): void
    {
        foreach ($settings as $name => $value)
            self::$$name = $value;
    }

    public static function on (string $name, callable $callback = null): void
    {
        if ($callback === null)
            unset (self::$events[$name]);

        else self::$events[$name] = $callback;
    }

    public static function onBroadcast (callable $callback = null): void
    {
        self::$broadcast = $callback;
    }

    public static function perform (string $name, Packet $packet): void
    {
        if (isset (BPN::$events[$name]))
            BPN::$events[$name] ($packet);
    }

    public static function closeSocket (): void
    {
        socket_close (self::$socket);
        self::$socket = null;
    }
}
