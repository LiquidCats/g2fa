<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Contracts\Support;

use SensitiveParameter;

interface Generator
{
    public function secretKey(int $length = 16, #[SensitiveParameter] string $prefix = ''): string;
}