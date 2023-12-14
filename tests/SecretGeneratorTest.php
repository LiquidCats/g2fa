<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Tests;

use PHPUnit\Framework\TestCase;
use LiquidCats\G2FA\SecretGenerator;
use LiquidCats\G2FA\Contracts\Support\Validator;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use Random\RandomException;

class SecretGeneratorTest extends TestCase
{
    private Validator $validator;
    private SecretGenerator $secretGenerator;

    protected function setUp(): void
    {
        $this->validator = $this->createMock(Validator::class);
        $this->secretGenerator = new SecretGenerator($this->validator);
    }

    /**
     * @throws IncompatibleWithAuthenticatorException
     * @throws RandomException
     * @throws SecretKeyTooShortException
     * @throws InvalidCharactersException
     */
    public function testSecretKeyGeneratesCorrectLength(): void
    {
        $length = 16;
        $secret = $this->secretGenerator->secretKey($length);
        $this->assertEquals($length, strlen($secret));
    }

    /**
     * @throws IncompatibleWithAuthenticatorException
     * @throws RandomException
     * @throws SecretKeyTooShortException
     * @throws InvalidCharactersException
     */
    public function testSecretKeyWithPrefix(): void
    {
        $length = 16;
        $prefix = 'MB';
        $secret = $this->secretGenerator->secretKey($length, $prefix);
        $this->assertEquals(20, strlen($secret));
    }

    /**
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws RandomException
     */
    public function testSecretKeyThrowsSecretKeyTooShortException(): void
    {
        $this->validator->method('validate')
            ->will($this->throwException(new SecretKeyTooShortException()));

        $this->expectException(SecretKeyTooShortException::class);
        $this->secretGenerator->secretKey(6);
    }

    /**
     * @throws RandomException
     * @throws IncompatibleWithAuthenticatorException
     * @throws SecretKeyTooShortException
     */
    public function testSecretKeyThrowsInvalidCharactersException(): void
    {
        $this->validator->method('validate')
            ->will($this->throwException(new InvalidCharactersException()));

        $this->expectException(InvalidCharactersException::class);
        $this->secretGenerator->secretKey(16);
    }

    /**
     * @throws InvalidCharactersException
     * @throws RandomException
     * @throws SecretKeyTooShortException
     */
    public function testSecretKeyThrowsIncompatibleWithAuthenticatorException(): void
    {
        $this->validator->method('validate')
            ->will($this->throwException(new IncompatibleWithAuthenticatorException()));

        $this->expectException(IncompatibleWithAuthenticatorException::class);
        $this->secretGenerator->secretKey();
    }
}