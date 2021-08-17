<?php

namespace BPN\Encoding;

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\Serializer\PrivateKey\DerPrivateKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use Mdanter\Ecc\Util\NumberSize;

/**
 * Elliptic curves
 */
class ECC
{
    # Hashing algorithm
    public static string $hash = 'sha256';

    /**
     * Generate private and public elliptic curves keys
     * 
     * @return array ['private' => (string) ..., 'public' => (string) ...]
     */
    public static function generateKeyPair (): array
    {
        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator384();

        $private = $generator->createPrivateKey();
        $public = $private->getPublicKey();

        $privateSerializer = new DerPrivateKeySerializer($adapter);
        $derPrivate = $privateSerializer->serialize ($private);

        $publicSerializer = new DerPublicKeySerializer($adapter);
        $derPublic = $publicSerializer->serialize ($public);

        return [
            'public'  => base64_encode ($derPublic),
            'private' => base64_encode ($derPrivate)
        ];
    }

    /**
     * Sign some data with private key
     * 
     * @param string $data
     * @param string $private
     * 
     * @return string - return signed data
     */
    public static function sign (string $data, string $private): string
    {
        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator384();

        $privateSerializer = new DerPrivateKeySerializer($adapter);
        $private = $privateSerializer->parse (base64_decode ($private));

        $hasher = new SignHasher (self::$hash, $adapter);
        $hash = $hasher->makeHash ($data, $generator);

        $random = RandomGeneratorFactory::getHmacRandomGenerator ($private, $hash, self::$hash);
        $randomK = $random->generate ($generator->getOrder ());

        $signature = (new Signer ($adapter))
            ->sign ($private, $hash, $randomK);

        $serializer = new DerSignatureSerializer;
        $serializedSig = $serializer->serialize ($signature);

        return base64_encode ($serializedSig);
    }

    /**
     * Verify signed data
     * 
     * @param string $sign - signed data
     * @param string $data - original data
     * @param string $public - public key
     * 
     * @return bool
     */
    public static function verify (string $sign, string $data, string $public): bool
    {
        try
        {
            $adapter = EccFactory::getAdapter();
            $generator = EccFactory::getNistCurves()->generator384();

            $sigSerializer = new DerSignatureSerializer;
            $sig = $sigSerializer->parse (base64_decode ($sign));

            $derSerializer = new DerPublicKeySerializer ($adapter);
            $public = $derSerializer->parse (base64_decode ($public));

            $hasher = new SignHasher (self::$hash);
            $hash = $hasher->makeHash ($data, $generator);

            return (new Signer ($adapter))
                ->verify ($public, $sig, $hash);
        }

        catch (\Throwable)
        {
            return false;
        }
    }

    /**
     * Generate shared secret with another client
     * 
     * @param string $publicKey - client's public key
     * @param string $privateKey - your private key
     * 
     * @return string
     */
    public static function generateSharedSecret (string $publicKey, string $privateKey): string
    {
        $adapter = EccFactory::getAdapter();
        $generator = EccFactory::getNistCurves()->generator384();

        $privateSerializer = new DerPrivateKeySerializer($adapter);
        $publicSerializer = new DerPublicKeySerializer($adapter);

        $privateKey = $privateSerializer->parse (base64_decode ($privateKey));
        $publicKey = $publicSerializer->parse (base64_decode ($publicKey));

        $exchange = $privateKey->createExchange ($publicKey);
        $shared = $exchange->calculateSharedKey();

        $adapter = $generator->getAdapter();

        $binary = $adapter->intToFixedSizeString (
            $shared,
            NumberSize::bnNumBytes ($adapter, $generator->getOrder())
        );

        return unpack ("H*", hash ('sha256', $binary, true))[1];
    }
}
