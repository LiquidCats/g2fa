<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Tests\Support;

use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use LiquidCats\G2FA\Support\SecretValidator;
use PHPUnit\Framework\TestCase;

class SecretValidatorTest extends TestCase
{
    /**
     * @return void
     *
     * @throws InvalidCharactersException
     * @throws IncompatibleWithAuthenticatorException
     * @throws SecretKeyTooShortException
     */
    public function test_throw_exception_when_invalid_character(): void
    {
        $this->expectException(InvalidCharactersException::class);

        $validator = new SecretValidator();

        $validator->validate('DUMJO5634NPDEKX@');
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function test_throw_exception_when_not_compatible_with_authenticator(): void
    {
        $this->expectException(IncompatibleWithAuthenticatorException::class);

        $validator = new SecretValidator();

        $validator->validate('ADUMJO5');
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function test_throw_exception_when_secret_not_big_enough(): void
    {
        $this->expectException(SecretKeyTooShortException::class);

        $validator = new SecretValidator();

        $validator->validate('ADMD');
    }
}