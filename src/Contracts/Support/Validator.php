<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Contracts\Support;

use SensitiveParameter;

interface Validator
{
    public function validate(#[SensitiveParameter]string $secret);
}