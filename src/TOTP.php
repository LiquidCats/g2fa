<?php

declare(strict_types=1);

namespace LiquidCats\G2FA;

use DateTimeImmutable;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\Exceptions\G2FAException;
use LiquidCats\G2FA\ValueObjects\SecretKey;
use SensitiveParameter;

use function array_reverse;
use function array_values;
use function chr;
use function count;
use function floor;
use function hash_equals;
use function hash_hmac;
use function implode;
use function str_pad;
use function unpack;

use const STR_PAD_LEFT;

readonly class TOTP
{
    public function __construct(
        private Algorithm $algorithm = Algorithm::SHA512,
        private int $length = 6,
        public int $epoch = 30,
        public int $period = 1,
    ) {
    }

    /**
     * @param SecretKey $secret
     * @param int       $input
     *
     * @return string
     * @throws G2FAException
     */
    public function at(#[SensitiveParameter] SecretKey $secret, int $input): string
    {
        return $this->generate($secret, $this->timecode($input));
    }

    /**
     * @param SecretKey $secret
     *
     * @return string
     * @throws G2FAException
     */
    public function now(#[SensitiveParameter] SecretKey $secret): string
    {
        return $this->at($secret, (new DateTimeImmutable())->getTimestamp());
    }

    /**
     * @param SecretKey $secret
     * @param int       $counter
     *
     * @return string
     *
     * @throws G2FAException
     */
    public function generate(#[SensitiveParameter] SecretKey $secret, int $counter): string
    {
        $hash = hash_hmac($this->algorithm->value, $this->intToByteString($counter), $secret->decode(), true);
        $unpacked = unpack('C*', $hash);
        if ($unpacked === false) {
            throw new G2FAException('Invalid data.');
        }
        $hmac = array_values($unpacked);

        $offset = ($hmac[count($hmac) - 1] & 0xF);
        $code = ($hmac[$offset] & 0x7F) << 24 | ($hmac[$offset + 1] & 0xFF) << 16 | ($hmac[$offset + 2] & 0xFF) << 8 | ($hmac[$offset + 3] & 0xFF);
        $otp = $code % (10 ** $this->length);

        return str_pad((string) $otp, $this->length, '0', STR_PAD_LEFT);
    }

    /**
     * If no timestamp is provided, the OTP is verified at the actual timestamp. When used, the leeway parameter will
     * allow time drift. The passed value is in seconds.
     *
     * @throws G2FAException
     */
    public function verify(
        #[SensitiveParameter] SecretKey $secret,
        string $otp,
        null|int $timestamp = null,
        null|int $leeway = null
    ): bool {
        $timestamp ??= (new DateTimeImmutable())->getTimestamp();

        if ($timestamp < 0) {
            throw new G2FAException('Timestamp must be at least 0.');
        }

        if ($leeway === null) {
            return $this->compare($this->at($secret, $timestamp), $otp);
        }

        $leeway = (int) abs($leeway);
        if ($leeway >= $this->period) {
            throw new G2FAException('The leeway must be lower than the TOTP period');
        }

        return $this->compare($this->at($secret, $timestamp - $leeway), $otp)
            || $this->compare($this->at($secret, $timestamp), $otp)
            || $this->compare($this->at($secret, $timestamp + $leeway), $otp);
    }

        /**
     * @param non-empty-string $safe
     * @param non-empty-string $user
     */
    protected function compare(string $safe, string $user): bool
    {
        return hash_equals($safe, $user);
    }

    /**
     * Returns the current Unix Timestamp divided by the $keyRegeneration
     * period.
     *
     * @param int $timestamp
     *
     * @return int
     *
     * @throws G2FAException
     */
    private function timecode(int $timestamp): int
    {
        $timecode = (int) floor(($timestamp - $this->epoch) / $this->period);
        if ($timecode < 0) {
            throw new G2FAException('Timestamp must be at least 0.');
        }

        return $timecode;
    }

    /**
     * @param int $int
     *
     * @return string
     */
    private function intToByteString(int $int): string
    {
        $result = [];
        while ($int !== 0) {
            $result[] = chr($int & 0xFF);
            $int >>= 8;
        }

        return str_pad(implode('', array_reverse($result)), 8, "\000", STR_PAD_LEFT);
    }
}
