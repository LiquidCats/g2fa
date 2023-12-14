<?php

declare(strict_types=1);

namespace LiquidCats\G2FA\Tests;

use LiquidCats\G2FA\Contracts\Support\Validator;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\Exceptions\IncompatibleWithAuthenticatorException;
use LiquidCats\G2FA\Exceptions\InvalidCharactersException;
use LiquidCats\G2FA\Exceptions\SecretKeyTooShortException;
use LiquidCats\G2FA\OTPGenerator;
use PHPUnit\Framework\TestCase;

class OTPGeneratorTest extends TestCase
{
    private OTPGenerator $totpGenerator;

    protected function setUp(): void
    {
        $this->totpGenerator = new OTPGenerator(algorithm: Algorithm::SHA512);
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testGenerateWithValidInput(): void
    {
        $secret = 'ADUMJO5634NPDEKW';
        $counter = 123456;

        // Assuming the known output for the provided secret and counter
        $expectedOutput = '485723'; // Replace with actual expected output

        $output = $this->totpGenerator->generate($secret, $counter);

        $this->assertEquals($expectedOutput, $output);
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testGenerateThrowsSecretKeyTooShortException(): void
    {
        $this->expectException(SecretKeyTooShortException::class);

        $this->totpGenerator->generate('ADUMJO5', 123456);
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testGenerateThrowsInvalidCharactersException(): void
    {
        $this->expectException(InvalidCharactersException::class);
        $this->totpGenerator->generate('DUMJO5634NPDEKX@', 123456);
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testGenerateThrowsIncompatibleWithAuthenticatorException(): void
    {
        $this->expectException(IncompatibleWithAuthenticatorException::class);
        $this->totpGenerator->generate('ADUMJO5634NPDEK', 123456);
    }

    /**
     * @return void
     *
     * @throws IncompatibleWithAuthenticatorException
     * @throws InvalidCharactersException
     * @throws SecretKeyTooShortException
     */
    public function testGeneratesPasswordsInManyDifferentSizes(): void
    {
        $otp = (new OTPGenerator(oneTimePasswordLength: 6))
            ->generate('ADUMJO5634NPDEKW', 26213400);

        $this->assertEquals('752139', $otp);

        $otp = (new OTPGenerator(oneTimePasswordLength: 7))
            ->generate('ADUMJO5634NPDEKW', 26213400);

        $this->assertEquals('0752139', $otp);
    }
}
