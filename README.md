[![Build Status](https://travis-ci.org/iAchilles/pjwt.svg?branch=master)](https://travis-ci.org/iAchilles/pjwt)
[![AGPL v3](http://www.gnu.org/graphics/agplv3-88x31.png)](http://www.gnu.org/licenses/agpl-3.0.html)

pJWT
===

PHP implementation of [JSON Web Token](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31) (JWT). It provides a simple way to create, sign and verify JWT.

The following features are supported:
   - Built-in validation for the JWT claims (iat, nbf, exp, jti).
   - Symmetric and asymmetric algorithms for protecting integrity:

   | Symmetric | Asymmetric
   | --------- | ---------
   | HS256     | RS256
   | HS384     | RS384
   | HS512     | RS512


Requirements
------------
PHP 5.4.0 or above.


Installation
------------
Use [composer](https://getcomposer.org/) to install pJWT:

```
composer require iAchilles/pjwt
```

Code examples
-------------

1. Creating JWT
  - by using symmetric algorithm HS256:

  ```php
  $claims = ['iat' => time(), 'nbf' => time(), 'exp' => strtotime('+1 day'), 'iss' => 'domain.com', 'uid' => 1];
  $headers = ['alg' => 'HS256', 'typ' => 'JWT'];
  $jws = new Jws($headers, $claims);
  $jws->privateKey = 'YoUr_SeCrEt';
  $jws->sign(); //Returns URL-safe string representation of the digitally signed JWT. This encoded JWT can be sent to a user.
  ```

  - by using asymmetric algorithm RS256:

   ```php
  $claims = ['iat' => time(), 'nbf' => time(), 'exp' => strtotime('+1 day'), 'iss' => 'domain.com', 'uid' => 1];
  $headers = ['alg' => 'RS256', 'typ' => 'JWT'];
  $jws = new Jws($headers, $claims);
  $jws->privateKey = 'file:///path/to/private/key.pem'; //Path to the PEM encoded private key.
  $jws->sign(); //Returns URL-safe string representation of the digitally signed JWT. This encoded JWT can be sent to a user.
  ```
   If the private key is encrypted with a password, you can use the following format:

   ```php
  $jws->privateKey = ['file:///path/to/private/key.pem', 'pAsSwOrd'];
   ```

  - with protection from replay attacks.
    In order to protect from replay attacks, you can set 'jti' claim to TRUE during creation JWT.

   ```php
  $claims = ['jti' => true, 'iat' => time(), 'nbf' => time(), 'exp' => strtotime('+1 day')];
  $headers = ['alg' => 'RS256', 'typ' => 'JWT'];
  $jws = new Jws($headers, $claims);
  ```

1. Decoding and verifying JWT

   ```php
$encodedJwt = 'abcdef.ghijklm.nopqrstuvw';
$jws = Jws::parse($encodedJwt);
$jws->getPayload()->issuedAt; //Access to the registered JWT claims
$jws->getPayload()->getCustomClaim('user_id'); //Access to the custom claims.
$jws->getHeader()->getAlgorithm(); //Access to the JOSE header parameters.
```
   Verifying signature

   ```php
   $encodedJwt = 'abcdef.ghijklm.nopqrstuvw';
   $jws = Jws::parse($encodedJwt);
   //For symmetric algorithm:
   $jws->privateKey = 'YoUr_SeCrEt';
   //For asymmetric algorithm:
   $jws->certificate = 'file:///path/to/certificate.pem'; //Path to the PEM encoded X.509 certificate.
   $jws->verify(); //TRUE if the signature is valid.
   ```
   If the signature is valid, you have to validate the JWT claims.

   ```php
   $jws->getPayload()->verify(); //Returns TRUE if the JWT is valid, otherwise it returns a string that contains an error message.
   ```

   To validate "jti" you need create two anonymous functions, and pass them as arguments to the verify method.
   ```php
   $setJti = function($jti)
   {
        //Writes "jti" value into storage. (E.g. Redis Db)
   };
   //This function must return TRUE if the given value exists in storage, false otherwise.
   $getJti = function($jti)
   {
       //...
   };
   $jws->getPayload()->verify($setJti, $getJti);
   ```
