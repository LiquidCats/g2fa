<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Enums;

enum Algorithm: string
{
    case SHA1 = 'sha1';

    case SHA256 = 'sha256';

    case SHA512 = 'sha512';
}
