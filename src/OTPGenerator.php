<?php

declare(strict_types=1);

namespace LiquidCats\G2FA;

use LiquidCats\G2FA\Contracts\Support\Validator;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use LiquidCats\G2FA\Support\SecretValidator;
use ParagonIE\ConstantTime\Base32;
use SensitiveParameter;

use function hash_hmac;
use function ord;
use function pack;
use function str_pad;
use function strlen;
use function strtoupper;
use function substr;
use function unpack;

use const STR_PAD_LEFT;

readonly class OTPGenerator
{
    public function __construct(
        private Validator $validator = new SecretValidator(),
        private Algorithm $algorithm = Algorithm::SHA512,
        private int $oneTimePasswordLength = 6,
    ) {
    }

    /**
     * @param string $secret
     * @param int    $counter
     *
     * @return string
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function generate(#[SensitiveParameter] string $secret, int $counter): string
    {
        if (strlen($secret) < 8) {
            throw new SecretKeyTooShortException();
        }

        $secret = $this->decodeSecret($secret);

        return str_pad(
            $this->oathTruncate($this->generateHotp($secret, $counter)),
            $this->oneTimePasswordLength,
            '0',
            STR_PAD_LEFT
        );
    }

    /**
     * Decodes a secret.
     *
     * @param string $secret The secret to be decoded. (SensitiveParameter)
     *
     * @return string The decoded secret.
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    private function decodeSecret(#[SensitiveParameter] string $secret): string
    {
        $secret = strtoupper($secret);

        $this->validator->validate($secret);

        return Base32::decodeUpper($secret);
    }

    /**
     * Extracts the OTP from the SHA1 hash.
     *
     * @param string $hash
     *
     * @return string
     **/
    private function oathTruncate(#[SensitiveParameter] string $hash): string
    {
        $offset = ord($hash[strlen($hash) - 1]) & 0xF;

        $temp = unpack('N', substr($hash, $offset, 4));

        $temp = $temp[1] & 0x7FFFFFFF;

        return substr(
            (string) $temp,
            -$this->oneTimePasswordLength
        );
    }

    /**
     * Generate the HMAC OTP.
     *
     * @param string $secret
     * @param int    $counter
     *
     * @return string
     */
    private function generateHotp(#[SensitiveParameter] string $secret, int $counter): string
    {
        return hash_hmac(
            $this->algorithm->value,
            pack('N*', 0, $counter), // Counter must be 64-bit int
            $secret,
            true
        );
    }
}
