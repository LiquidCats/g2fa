# PHP Google 2FA and TOTP

This repository was inspired by https://github.com/antonioribeiro/google2fa

It contains three PHP classes designed for generating and verifying Time-Based One-Time Passwords (TOTP) according to the RFC 6238 standard. These classes are part of the LiquidCats\G2FA namespace and offer functionality for secret key generation, TOTP generation, and TOTP verification.


## Installation

```shell
composer require liquid-cats/g2fa 
```

## Usage

### SecretGenerator
The SecretGenerator class is responsible for generating a base32-encoded secret key, which is used in the TOTP process.

##### Features:

Generates a random secret key.
Validates the secret key for compatibility and character set.
Usage:

```php
use LiquidCats\G2FA\SecretGenerator;

$secretGenerator = new SecretGenerator();
$secret = $secretGenerator->secretKey(16); // Generate a 16-character secret key
```

### TOTPGenerator
The TOTPGenerator class generates a TOTP using a secret key and a counter value, typically based on the current time.

##### Features:

Generates a TOTP based on the provided secret and counter.
Supports different hashing algorithms like SHA512.
Usage:

```php
use LiquidCats\G2FA\OTPGenerator;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\Support\SecretValidator;

$validator = new SecretValidator();
$totpGenerator = new OTPGenerator($validator, Algorithm::SHA512, oneTimePasswordLength: 7);
$totp = $totpGenerator->generate($secret, $counter); // will generate 7 digit one time password
```

### TOTPVerificator
The TOTPVerificator class verifies a given TOTP against the expected value, based on the secret key and the current time.

##### Features:

Verifies user inputted TOTP.
Considers a time window for TOTP validation.
Usage:

```php
use LiquidCats\G2FA\OTPGenerator;
use LiquidCats\G2FA\Enums\Algorithm;
use LiquidCats\G2FA\Support\SecretValidator;
use LiquidCats\G2FA\TOTPVerificator;

$validator = new SecretValidator();
$totpGenerator = new OTPGenerator($validator, Algorithm::SHA512, oneTimePasswordLength: 7);
$verificator = new TOTPVerificator(keyRegeneration: 30, window: 1);
$isValid = $verificator->verify($userInputTOTP, $secret);
```

## Contributing

Contributions to improve these classes are welcome. Please submit pull requests or open issues to propose changes or report bugs.

## License

This project is licensed under the MIT License - see the LICENSE file for details.