<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Tests;

use PHPUnit\Framework\TestCase;
use LiquidCats\G2FA\TOTP;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\Exceptions\G2FAException;
use LiquidCats\G2FA\ValueObjects\SecretKey;

class TOTPTest extends TestCase
{
    private TOTP $totp;

    protected function setUp(): void
    {
        $this->totp = new TOTP(Algorithm::SHA512, 6, 30, 1);
    }

    public function testGenerateOTP(): void
    {
        $secretKey = new SecretKey('ADUMJO5634NPDEKW');
        $counter = 123456;

        $otp = $this->totp->generate($secretKey, $counter);

        $this->assertIsString($otp);
        $this->assertEquals(6, strlen($otp));
    }

    public function testNowGeneratesValidOTP(): void
    {
        $secretKey = new SecretKey('ADUMJO5634NPDEKW');
        $otp = $this->totp->now($secretKey);

        $this->assertIsString($otp);
        $this->assertEquals(6, strlen($otp));
    }

    public function testAtGeneratesValidOTP(): void
    {
        $secretKey = new SecretKey('ADUMJO5634NPDEKW');
        $timestamp = time();

        $otp = $this->totp->at($secretKey, $timestamp);

        $this->assertIsString($otp);
        $this->assertEquals(6, strlen($otp));
    }

    public function testVerifyReturnsTrueForCorrectOTP(): void
    {
        $secretKey = new SecretKey('ADUMJO5634NPDEKW');
        $timestamp = time();
        $otp = $this->totp->at($secretKey, $timestamp);

        $result = $this->totp->verify($secretKey, $otp, $timestamp);

        $this->assertTrue($result);
    }

    public function testVerifyReturnsFalseForIncorrectOTP(): void
    {
        $secretKey = new SecretKey('ADUMJO5634NPDEKW');
        $timestamp = time();
        $invalidOtp = '123456';

        $result = $this->totp->verify($secretKey, $invalidOtp, $timestamp);

        $this->assertFalse($result);
    }

    public function testTimecodeThrowsExceptionForNegativeTimestamp(): void
    {
        $this->expectException(G2FAException::class);

        $secretKey = new SecretKey('valid-secret');
        $this->totp->at($secretKey, -1);
    }
}
