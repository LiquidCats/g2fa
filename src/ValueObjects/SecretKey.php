<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\ValueObjects;

use LiquidCats\G2FA\Enums\Alphabet;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use ParagonIE\ConstantTime\Base32;
use Random\RandomException;
use SensitiveParameter;

use function random_bytes;
use function strlen;

readonly class SecretKey
{
    /**
     * @param string $value
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function __construct(#[SensitiveParameter] public string $value)
    {
        $this->checkIsBigEnough($this->value);
        $this->checkForValidCharacters($this->value);
        $this->checkGoogleAuthenticatorCompatibility($this->value);
    }

    public function decode(): string
    {
        return Base32::decodeUpper($this->value);
    }


    /**
     * Calculate char count bits.
     *
     * @param string $secret
     *
     * @return int
     */
    private function charCountBits(#[SensitiveParameter] string $secret): int
    {
        return strlen($secret) * 8;
    }

    /**
     * Check if the string length is power of two.
     *
     * @param string $secret
     *
     * @return bool
     */
    private function isCharCountNotAPowerOfTwo(#[SensitiveParameter] string $secret): bool
    {
        return (strlen($secret) & (strlen($secret) - 1)) !== 0;
    }

    /**
     * Check if the secret key is compatible with Google Authenticator.
     *
     * @param string $secret
     *
     * @throws IncompatibleWithAuthenticatorException
     */
    private function checkGoogleAuthenticatorCompatibility(#[SensitiveParameter] string $secret): void
    {
        // Google Authenticator requires it to be a power of 2 base32 length string
        if ($this->isCharCountNotAPowerOfTwo($secret)) {
            throw new IncompatibleWithAuthenticatorException();
        }
    }

    /**
     * Check if all secret key characters are valid.
     *
     * @param string $secret
     *
     * @throws InvalidCharactersException
     */
    private function checkForValidCharacters(#[SensitiveParameter] string $secret): void
    {
        if (!Alphabet::isValidCharacters($secret)) {
            throw new InvalidCharactersException();
        }
    }

    /**
     * Check if secret key length is big enough.
     *
     * @param string $secret
     *
     * @throws SecretKeyTooShortException
     */
    private function checkIsBigEnough(#[SensitiveParameter] string $secret): void
    {
        // Minimum = 128 bits
        // Recommended = 160 bits
        // Compatible with Google Authenticator = 256 bits

        if ($this->charCountBits($secret) < 128) {
            throw new SecretKeyTooShortException();
        }
    }

    /**
     * @param int $length
     *
     * @return static
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws RandomException
     * @throws SecretKeyTooShortException
     */
    public static function generate(int $length = 16): static
    {
        $key = Base32::decodeUpper(random_bytes($length));

        return new static($key);
    }
}