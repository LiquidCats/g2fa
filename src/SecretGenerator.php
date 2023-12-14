<?php

declare(strict_types=1);

namespace LiquidCats\G2FA;

use LiquidCats\G2FA\Contracts\Support\Validator;
use LiquidCats\G2FA\Enums\Alphabet;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use LiquidCats\G2FA\Support\SecretValidator;
use ParagonIE\ConstantTime\Base32;
use Random\RandomException;
use SensitiveParameter;

use function random_int;
use function str_replace;

readonly class SecretGenerator
{
    public function __construct(private Validator $validator = new SecretValidator())
    {
    }

    /**
     * @param int    $length
     * @param string $prefix
     *
     * @return string
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     * @throws RandomException
     */
    public function secretKey(int $length = 16, #[SensitiveParameter] string $prefix = ''): string
    {
        $secret = Base32::encodeUpper($prefix);

        $secret = str_replace('=', '', $secret);

        $secret = $this->strPadBase32($secret, $length);

        $this->validator->validate($secret);

        return $secret;
    }

    /**
     * Pad string with random base 32 chars.
     *
     * @param string $string
     * @param int    $length
     *
     * @return string
     * @throws RandomException
     */
    private function strPadBase32(#[SensitiveParameter] string $string, int $length): string
    {
        for ($i = 0; $i < $length; $i++) {
            $charIndex = random_int(0, 31);
            $string .= Alphabet::SCRAMBLED[$charIndex];
        }

        return $string;
    }
}
