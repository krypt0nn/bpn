<?php

namespace BPN\Networking\Tunneling;

use BPN\Encoding\{
    AES,
    ECC,
    Enclosure
};

use BPN\Networking\Endpoint;
use BPN\BPN;

class Tunnel
{
    protected string $buffer = '';

    protected static $listener_socket = null;

    public function __construct (protected string $encryptionKey, protected $socket) {}

    public function send ($data): self
    {
        $data = AES::encode (serialize ($data), $this->encryptionKey);

        socket_write ($this->socket, strlen ($data) . chr (255) . $data);

        return $this;
    }

    public function update (callable $callback): self
    {
        if ($data = socket_read ($this->socket, 4096))
        {
            $data = $this->buffer . $data;
            
            $delimiter_pos = strpos ($data, chr (255));
            $packet_length = substr ($data, 0, $delimiter_pos);

            $packet = substr ($data, $delimiter_pos + 1);
            
            if (strlen ($packet) >= $packet_length)
            {
                $packet_data = substr ($packet, 0, $packet_length);
                $callback (unserialize (AES::decode ($packet_data, $this->encryptionKey)));

                $data = substr ($packet, $packet_length);
            }

            $this->buffer = $data;
        }

        return $this;
    }

    public function close (): void
    {
        socket_close ($this->socket);
    }

    public static function create (Endpoint $endpoint, int $wait_milliseconds = 1000, int $delay_milliseconds = 10): ?self
    {
        if (!($socket = socket_create (AF_INET, SOCK_STREAM, SOL_TCP)))
            throw new \Exception ('Couldn\'t create socket: '. socket_strerror (socket_last_error ()));

        if (!socket_connect ($socket, $endpoint->ip(), $endpoint->port()))
            return null;

        socket_write ($socket, 'bpn-tunnel:'. BPN::$public_key, 256);

        for ($i = 0, $n = $wait_milliseconds / $delay_milliseconds; $i < $n; ++$i)
        {
            usleep ($delay_milliseconds * 1000);

            if (($data = socket_read ($socket, 256)) && substr ($data, 0, 11) == 'bpn-tunnel:')
                return new self (ECC::generateSharedSecret (substr ($data, 11), BPN::$private_key), $socket);
        }

        return null;
    }

    public static function listen (Endpoint $localEndpoint = null, int $wait_milliseconds = 1000, int $delay_milliseconds = 10): ?self
    {
        if (self::$listener_socket === null)
        {
            $localEndpoint ??= BPN::$local_endpoint;

            if (!($socket = socket_create (AF_INET, SOCK_STREAM, SOL_TCP)))
                throw new \Exception ('Couldn\'t create socket: '. socket_strerror (socket_last_error ()));

            if (!socket_bind ($socket, $localEndpoint->ip(), $localEndpoint->port()))
                throw new \Exception ('Couldn\'t bind socket: '. socket_strerror (socket_last_error ()));

            socket_set_nonblock ($socket);
            socket_listen ($socket);

            self::$listener_socket = $socket;
        }

        if ($socket = socket_accept (self::$listener_socket))
        {
            for ($i = 0, $n = $wait_milliseconds / $delay_milliseconds; $i < $n; ++$i)
            {
                usleep ($delay_milliseconds * 1000);

                if (($data = socket_read ($socket, 256)) && substr ($data, 0, 11) == 'bpn-tunnel:')
                {
                    socket_write ($socket, 'bpn-tunnel:'. BPN::$public_key, 256);

                    return new self (ECC::generateSharedSecret (substr ($data, 11), BPN::$private_key), $socket);
                }
            }
        }

        return null;
    }

    public function __destruct ()
    {
        socket_close ($this->socket);
    }
}
