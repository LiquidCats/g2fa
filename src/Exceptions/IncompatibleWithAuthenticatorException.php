<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Exceptions;

class IncompatibleWithAuthenticatorException extends G2FAException
{
    protected $message = 'This secret key is not compatible with Google Authenticator.';
}