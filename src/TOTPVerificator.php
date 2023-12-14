<?php

declare(strict_types=1);

namespace LiquidCats\G2FA;

use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use SensitiveParameter;

use function floor;
use function hash_equals;
use function max;
use function microtime;

readonly class TOTPVerificator
{
    public function __construct(
        private OTPGenerator $generator = new OTPGenerator(),
        public int $keyRegeneration = 30,
        public int $window = 1,
    ) {
    }

    /**
     * Verifies a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string   $key User specified key
     * @param string   $secret
     * @param int|null $timestamp
     * @param int|null $oldTimestamp
     *
     * @return bool|int
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function verify(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $secret,
        ?int $timestamp = null,
        ?int $oldTimestamp = null
    ): bool|int {
        $timestamp ??= $this->getTimestamp();
        $startingTimestamp = $this->makeStartingTimestamp($timestamp, $oldTimestamp);

        for (;
            $startingTimestamp <= $timestamp + $this->window;
            $startingTimestamp++
        ) {
            $totp = $this->generator->generate($secret, $startingTimestamp);
            if (hash_equals($totp, $key)) {
                return $oldTimestamp === null
                    ? true
                    : $startingTimestamp;
            }
        }

        return false;
    }

    /**
     * Make a window based starting timestamp.
     *
     * @param int      $timestamp
     * @param int|null $oldTimestamp
     *
     * @return int
     */
    private function makeStartingTimestamp(int $timestamp, ?int $oldTimestamp = null): int
    {
        return $oldTimestamp === null
            ? $timestamp - $this->window
            : max($timestamp - $this->window, $oldTimestamp + 1);
    }

    /**
     * Returns the current Unix Timestamp divided by the $keyRegeneration
     * period.
     *
     * @return int
     **/
    private function getTimestamp(): int
    {
        return (int) floor(microtime(true) / $this->keyRegeneration);
    }
}
