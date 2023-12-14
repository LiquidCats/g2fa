<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Exceptions;

class SecretKeyTooShortException extends G2FAException
{
    protected $message = 'Secret key is too short. Must be at least 16 base32 characters';
}
