<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
 
namespace iAchilles\pjwt;

/**
 * Jwt class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class Jwt 
{
    /**
     * @var integer Timestamp of the expiration time for the JWT.
     * @link https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.4
     */
    public $expires;

    /**
     * @var integer Timestamp of the time before which the JWT must not be accepted for processing.
     * @link https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.5
     */
    public $notBefore;

    /**
     * @var integer Timestamp of the creation of the JWT.
     * @link https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.6
     */
    public $issuedAt;

    /**
     * @var string
     * @link https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-31#section-4.1.1
     */
    public $issuer;

    /**
     * @var string
     * @link https://tools.ietf.org/html/draft-jones-json-web-token-10#section-4.1.3
     */
    public $audience;

    /**
     * @var string
     * @link https://tools.ietf.org/html/draft-jones-json-web-token-10#section-4.1.7
     */
    public $jwtId;

    /**
     * @var string
     * @link https://tools.ietf.org/html/draft-jones-json-web-token-10#section-4.1.8
     */
    public $subject;

    /**
     * @var array Custom claims.
     */
    private $customClaims = [];


    /**
     * Returns registered claim names.
     * @return array List of the registered claim names.
     */
    public static function getRegisteredClaimNames()
    {
        return ['iss', 'iat', 'nbf', 'exp', 'sub', 'aud', 'jti'];
    }

    /**
     * Parses an array of claims and returns an instance of the class Jwt.
     * @param array $payload An array of claims.
     * @return Jwt Instance of the class Jwt.
     */
    public static function parseFromArray(array $payload)
    {
        $instance = new self();
        !isset ($payload['iss']) ?: $instance->issuer = utf8_encode($payload['iss']);
        !isset ($payload['iat']) ?: $instance->issuedAt =  (int)$payload['iat'];
        !isset ($payload['nbf']) ?: $instance->notBefore = (int)$payload['nbf'];
        !isset ($payload['exp']) ?: $instance->expires =(int)$payload['exp'];
        !isset ($payload['sub']) ?: $instance->subject = utf8_encode($payload['sub']);
        !isset ($payload['aud']) ?: $instance->audience = utf8_encode($payload['aud']);
        $customClaims = array_diff(array_keys($payload), self::getRegisteredClaimNames());
        foreach ($customClaims as $claim) {
            $instance->customClaims[$claim] = $payload[$claim];
        }
        if (isset($payload['jti'])) {
            $instance->jwtId = $payload['jti'] === true ? $instance->createJwtId() : $payload['jti'];
        }
        return $instance;
    }

    /**
     * Returns JSON string representation of the JWT.
     * @return string JSON string representation of the JWT.
     */
    public function toJSON()
    {
        $json = [];
        is_null($this->issuer)    ?: $json['iss'] = utf8_encode($this->issuer);
        is_null($this->issuedAt)  ?: $json['iat'] = (int) $this->issuedAt;
        is_null($this->notBefore) ?: $json['nbf'] = (int) $this->notBefore;
        is_null($this->expires)   ?: $json['exp'] = (int) $this->expires;
        is_null($this->subject)   ?: $json['sub'] = utf8_encode($this->subject);
        is_null($this->audience)  ?: $json['aud'] = utf8_encode($this->audience);
        is_null($this->jwtId)     ?: $json['jti'] = utf8_encode($this->jwtId);
        if (!empty($this->customClaims)) {
            $json = array_merge($json, $this->customClaims);
        }
        return json_encode($json, JSON_UNESCAPED_SLASHES);
    }


    /**
     * Returns a value of the given claim.
     * @param string $name The name of a custom claim.
     * @return mixed Value of the given claim.
     * @throws \DomainException If the specified claim is not defined.
     */
    public function getCustomClaim($name)
    {
        if (isset($this->customClaims[$name])) {
            return $this->customClaims[$name];
        } else {
            throw new \DomainException("The {$name} claim is not defined.");
        }
    }

    /**
     * Creates jti value.
     * @return string
     */
    public function createJwtId()
    {
        $random = openssl_random_pseudo_bytes(32);
        $jti = hash('sha256', $this->toJSON() . $random);
        return $jti;
    }


    /**
     * Verifies if JWT is valid.
     * @param null $setJwtId
     * @param null $getJwtId
     * @return mixed true if verification success, otherwise it returns a string containing the error message.
     * @throws \UnexpectedValueException
     */
    public function verify($setJwtId = null, $getJwtId = null)
    {
        if (isset($this->jwtId)) {
            if (!is_callable($setJwtId) || !is_callable($getJwtId)) {
                throw new \UnexpectedValueException('First and second arguments must be an anonymous function.');
            }
            if (!$getJwtId($this->jwtId)) {
                $setJwtId($this->jwtId);
            } else {
                return 'Token has already been used.';
            }
        }
        if (isset($this->notBefore) && $this->notBefore > time()) {
            return 'Token cannot be accepted for processing prior to ' . date(\DateTime::ISO8601, $this->notBefore);
        }
        if (isset($this->issuedAt) && $this->issuedAt > time()) {
            return 'Token cannot be accepted for processing prior to ' . date(\DateTime::ISO8601, $this->notBefore);
        }
        if (isset($this->expires) && $this->expires <= time()) {
            return 'Token has been expired.';
        }

        return true;
    }
}