<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Support;

use LiquidCats\G2FA\Contracts\Support\Validator;
use LiquidCats\G2FA\Enums\Alphabet;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use SensitiveParameter;
use function strlen;

readonly class SecretValidator implements Validator
{
    /**
     * @param string $secret
     *
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function validate(#[SensitiveParameter] string $secret): void
    {
        $this->checkForValidCharacters($secret);

        $this->checkGoogleAuthenticatorCompatibility($secret);

        $this->checkIsBigEnough($secret);
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
}