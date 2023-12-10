<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Exceptions;

class InvalidCharactersException extends G2FAException
{
    protected $message = 'Invalid characters in the base32 string.';
}