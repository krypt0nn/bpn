<?php

namespace BPN\Encoding;

class Convert
{
    public static function convert (int|string $data, int $from = 10, array $chars = null): string
    {
        $chars ??= array_merge (range (0, 9), range ('a', 'z'), range ('A', 'Z'), ['-', '_']);
        $chars_size = sizeof ($chars);

        $data = gmp_init ($data, $from);
        $converted = '';

        while ($data > 0)
        {
            $converted .= $chars[gmp_intval (gmp_mod ($data, $chars_size))];

            $data = gmp_div ($data, $chars_size);
        }

        return $converted;
    }

    /**
     * TODO: fix this methods
     */
    public static function encode (string $data, array $chars = null): string
    {
        $chars ??= array_merge (range (0, 9), range ('a', 'z'), range ('A', 'Z'), ['-', '_']);
        $chars_size = sizeof ($chars);

        $data = self::str2gmp ($data);
        $converted = '';

        while ($data > 0)
        {
            $converted .= $chars[gmp_intval (gmp_mod ($data, $chars_size))];

            $data = gmp_div ($data, $chars_size);
        }

        return $converted;
    }

    public static function decode (string $data, array $chars = null): string
    {
        $chars ??= array_merge (range (0, 9), range ('a', 'z'), range ('A', 'Z'), ['-', '_']);
        $chars = array_flip ($chars);
        $chars_size = sizeof ($chars);

        $data_gmp = gmp_init (0);

        for ($i = strlen ($data) - 1, $j = 0; $i >= 0; --$i, ++$j)
            $data_gmp = gmp_add ($data_gmp, gmp_mul ($chars[$data[$i]], gmp_pow ($chars_size, $j)));

        return self::gmp2str ($data_gmp);
    }

    public static function str2gmp (string $str): \GMP
    {
        $gmp = gmp_init (0);

        for ($i = strlen ($str) - 1, $j = 0; $i >= 0; --$i, ++$j)
            $gmp = gmp_add ($gmp, gmp_mul (ord ($str[$i]), gmp_pow (256, $j)));

        return $gmp;
    }

    public static function gmp2str (\GMP $gmp): string
    {
        $str = '';

        while ($gmp > 0)
        {
            $str .= chr (gmp_intval (gmp_mod ($gmp, 256)));

            $gmp = gmp_div ($gmp, 256);
        }

        return $str;
    }
}
