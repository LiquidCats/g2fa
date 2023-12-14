<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Tests;

use PHPUnit\Framework\TestCase;
use LiquidCats\G2FA\TOTPVerificator;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;

class TOTPVerificatorTest extends TestCase
{
    private TOTPVerificator $verificator;

    protected function setUp(): void
    {
        $this->verificator = new TOTPVerificator(window: 2);
    }

    public function testVerifyReturnsTrueForCorrectKey(): void
    {
        $secret = 'ADUMJO5634NPDEKW';
        $timestamp = 26213400;
        $totp = '424074'; // Assuming this is the correct TOTP

        $result = $this->verificator->verify($totp, $secret, $timestamp);

        $this->assertTrue($result);
    }

    public function testVerifyReturnsFalseForIncorrectKey(): void
    {
        $secret = 'ADUMJO5634NPDEKW';
        $timestamp = 26213400;
        $invalidTotp = '237162'; // Incorrect TOTP

        $result = $this->verificator->verify($invalidTotp, $secret, $timestamp);

        $this->assertFalse($result);
    }

    public function testVerifyThrowsInvalidCharactersException(): void
    {
        $this->expectException(InvalidCharactersException::class);

        $this->verificator->verify('424074', 'DUMJO5634NPDEKX@', 26213400);
    }

    public function testVerifyThrowsIncompatibleWithAuthenticatorException(): void
    {
        $this->expectException(IncompatibleWithAuthenticatorException::class);

        $this->verificator->verify('424074', 'ADUMJO5634NPDEK', 26213400);
    }

    public function testVerifyThrowsSecretKeyTooShortException(): void
    {
        $this->expectException(SecretKeyTooShortException::class);

        $this->verificator->verify('424074', 'ADUMJO5', 26213400);
    }
}