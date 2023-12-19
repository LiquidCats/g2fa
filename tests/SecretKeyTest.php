<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Tests;

use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\TestCase;
use LiquidCats\G2FA\ValueObjects\SecretKey;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use Random\RandomException;
use function strlen;

class SecretKeyTest extends TestCase
{
    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testCanBeInstantiatedWithValidSecret(): void
    {
        $validSecret = 'ADUMJO5634NPDEKW';
        $secretKey = new SecretKey($validSecret);
        $this->assertInstanceOf(SecretKey::class, $secretKey);
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     * @throws RandomException
     */
    public function testCanGenerateSecretKey(): void
    {
        $key = SecretKey::generate()->value;

        $this->assertEquals(16, strlen($key));

        $key = SecretKey::generate(20)->value;

        $this->assertEquals(32, strlen($key));
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testDecodeReturnsExpectedResult(): void
    {
        $base32EncodedSecret = 'ADUMJO5634NPDEKW';
        $secretKey = new SecretKey($base32EncodedSecret);
        $decoded = $secretKey->decode();

        $expected = Base32::decodeUpper($base32EncodedSecret);

        $this->assertEquals($expected, $decoded);
    }

    public function testConstructorThrowsExceptionForInvalidCharacters(): void
    {
        $this->expectException(InvalidCharactersException::class);
        new SecretKey('DUMJO5634NPDEKX@');
    }

    public function testConstructorThrowsExceptionForIncompatibleKey(): void
    {
        $this->expectException(IncompatibleWithAuthenticatorException::class);
        new SecretKey('ADUMJO5634NPDEKXX');
    }

    public function testConstructorThrowsExceptionForShortKey(): void
    {
        $this->expectException(SecretKeyTooShortException::class);
        new SecretKey('ADUMJO5');
    }
}