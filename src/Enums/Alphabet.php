<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Enums;

use function preg_replace;

enum Alphabet: string
{
    public const DEFAULT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public const SCRAMBLED = '234567QWERTYUIOPASDFGHJKLZXCVBNM';

    public static function removeInvalidCharacters(string $value): ?string
    {
        return preg_replace(
            '/[^' . self::DEFAULT . ']/',
            '',
            $value
        );
    }

    public static function isValidCharacters(string $value): bool
    {
        return self::removeInvalidCharacters($value) === $value;
    }
}
