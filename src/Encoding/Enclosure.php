<?php

namespace BPN\Encoding;

class Enclosure
{
    public static string $enclosure = "\0";

    public static function encode (string $text): string
    {
        return str_replace (self::$enclosure, self::$enclosure . self::$enclosure, $text);
    }

    public static function decode (string $text): string
    {
        $text_len = strlen ($text);
        $enc_len  = strlen (self::$enclosure);

        if ($text_len < $enc_len * 2)
            return $text;
        
        $clean_text = '';

        for ($i = 0, $l = $text_len - $enc_len; $i < $l; ++$i)
            if (($t = substr ($text, $i, $enc_len)) == substr ($text, $i + $enc_len, $enc_len))
            {
                $clean_text .= $t;

                $i += $enc_len * 2 - 1;
            }

            else $clean_text .= $text[$i];

        if ($i < $text_len)
            $clean_text .= substr ($text, $i);

        return $clean_text;
    }
}
