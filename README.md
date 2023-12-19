# PHP Google 2FA and TOTP

This repository was inspired by https://github.com/antonioribeiro/google2fa
This library provides PHP classes for generating and verifying Time-Based One-Time Passwords (TOTP) as per the G2FA (Google Two Factor Authentication) standards. It includes TOTP and SecretKey classes designed to work together to offer a robust solution for two-factor authentication.

## Installation

```shell
composer require liquid-cats/g2fa 
```

## 1. TOTP
This class is responsible for generating and verifying TOTPs based on a secret key and time.

### Features

Generates TOTPs for a given timestamp.
Verifies TOTPs against the current or provided timestamp.
Customizable algorithm, length, epoch, and period.
Usage

```php
Copy code
use LiquidCats\G2FA\TOTP;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\ValueObjects\SecretKey;

$totp = new TOTP(Algorithm::SHA512, 6, 30, 1);
$secretKey = new SecretKey('YOUR_SECRET_KEY');
$otp = $totp->now($secretKey);

// To verify OTP
$isValid = $totp->verify($secretKey, $otp);
```

## 2. SecretKey

The SecretKey class is used to handle secret keys required for generating TOTPs.

### Features

Validates secret keys for format and size.
Decodes secret keys from Base32 encoding.
Static method for generating new secret keys.

### Usage

```php
Copy code
use LiquidCats\G2FA\ValueObjects\SecretKey;

// Creating a SecretKey
$secretKey = new SecretKey('YOUR_SECRET_KEY');

// Decoding a SecretKey
$decodedKey = $secretKey->decode();

// Generating a new SecretKey
$newSecretKey = SecretKey::generate();
```

## Contributing

I welcome contributions and improvements to this library. Please submit pull requests or open issues for any bugs, feature requests, or enhancements.

## License

This project is open-sourced under the MIT License. See the LICENSE file for more details.