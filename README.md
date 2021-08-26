<p align="center"><img src="bpn.png" width="384px"></p>

<p align="center">
    <a href="https://packagist.org/packages/krypt0nn/bpn"><img src="https://poser.pugx.org/krypt0nn/bpn/v"></a>
    <a href="https://packagist.org/packages/krypt0nn/bpn"><img src="https://poser.pugx.org/krypt0nn/bpn/downloads"></a>
    <a href="/LICENSE"><img src="https://poser.pugx.org/krypt0nn/bpn/license"></a>
</p>

<p align="center">
    🚀 <b>BPN</b> is a huge library which allows you to create your own decentralized network on PHP 8+ <br>
    and provides various communication tools
</p>

## Installation

```
composer require krypt0nn/bpn
```

## Usage example

### Communication through events with unprotected UDP packets

client.php

```php
<?php

require 'vendor/autoload.php';

use BPN\BPN;
use BPN\Networking\Endpoint;
use BPN\Encoding\ECC;
use BPN\Data\Packet;

$keypair = ECC::generateKeyPair();

BPN::configure ([
    'public_key'  => $keypair['public'],
    'private_key' => $keypair['private']
]);

BPN::get()->send (
    Endpoint::format('server address'),
    Packet::performEvent('hello-world', 'Hello, World!')
);
```

server.php

```php
<?php

require 'vendor/autoload.php';

use BPN\BPN;
use BPN\Networking\Endpoint;
use BPN\Encoding\ECC;

$keypair = ECC::generateKeyPair();

BPN::configure ([
    'public_key'  => $keypair['public'],
    'private_key' => $keypair['private']
]);

BPN::on('hello-world', fn (Packet $packet) => echo $packet->data['data'] . PHP_EOL);

while (true)
    BPN::get()->update();
```

### Direct connection through protected TCP tunnel

client.php

```php
<?php

require 'vendor/autoload.php';

use BPN\BPN;
use BPN\Networking\Endpoint;
use BPN\Networking\Tunneling\Tunnel;
use BPN\Encoding\ECC;

$keypair = ECC::generateKeyPair();

BPN::configure ([
    'public_key'  => $keypair['public'],
    'private_key' => $keypair['private']
]);

$tunnel = Tunnel::create(Endpoint::format('server address'));

if ($tunnel === null)
    die ('Tunnel creation error');

else while (true)
{
    $message = readline ('> ');

    $tunnel->send ($message);
}
```

server.php

```php
<?php

require 'vendor/autoload.php';

use BPN\BPN;
use BPN\Networking\Endpoint;
use BPN\Networking\Tunneling\Tunnel;

$keypair = ECC::generateKeyPair();

BPN::configure ([
    'public_key'  => $keypair['public'],
    'private_key' => $keypair['private']
]);

while (!($tunnel = Tunnel::listen(Endpoint::local())));

while (true)
{
    $tunnel->update (function ($data)
    {
        echo $data . PHP_EOL;
    });
}
```

### Search client through BPN network by his UUID

```php
<?php

require 'vendor/autoload.php';

use BPN\Networking\DNS;
use BPN\Networking\DNS\Record;
use BPN\Data\Packet;

DNS::searchRecords ('client uuid', function (Record $record, Packet $packet)
{
    echo 'Client with endpoint '. $packet->author_endpoint->toString() .
         ' found client we wanted to find'.
         ' and his endpoint is '. $record->endpoint()->toString() . PHP_EOL;

    // if you want to not to receive another records
    // you can return false from this callback
    // return false;
});
```

## Documentation

Documentation will be added in future

<br>

Author: [Nikita Podvirnyy](https://vk.com/technomindlp)
