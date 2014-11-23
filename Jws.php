<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */

namespace iAchilles\pjwt;

/**
 * Jws class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class Jws 
{
    /**
     * @var string|array Secret or a string having the format file://path/to/file.pem (the named file must contain a PEM
     * encoded private key, or a PEM formatted private key. Also it can be an array with two elements. The second element
     * is a string that represent a password for the encrypted private key.
     */
    public $privateKey;

    /**
     * @var string It can be either a string having the format file://path/to/file.pem (the named file must
     * contain a PEM encoded certificate) or PEM formatted certificate.
     */
    public $certificate;

    /**
     * @var JoseHeader Instance of the class JoseHeader.
     */
    private $header;

    /**
     * @var Jwt Instance of the class Jwt.
     */
    private $payload;

    /**
     * @var string BASE64URL encoded string representation of the JOSE header.
     */
    private $encodedHeader;

    /**
     * @var string BASE64URL encoded string representation of the JWT.
     */
    private $encodedPayload;

    /**
     * @var string BASE64URL encoded string representation of the digital signature.
     */
    private $encodedSignature;


    /**
     * Constructor.
     * @param array $header
     * @param array $payload
     */
    public function __construct(array $header, array $payload)
    {
        $this->header = JoseHeader::parseFromArray($header);
        $this->payload = Jwt::parseFromArray($payload);
    }

    /**
     * Returns an instance of the class JoseHeader.
     * @return JoseHeader Instance of the class JoseHeader.
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Returns an instance of the class Jwt.
     * @return Jwt Instance of the class Jwt.
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Parses an encoded string representation of the JWS.
     * @param string $jws Encoded string representation of the JWS.
     * @return Jws Instance of the class Jws.
     * @throws \DomainException If string representation of the JWS is invalid or JWS contains invalid data.
     */
    public static function parse($jws)
    {
        $jws = preg_split('/\./', $jws, -1, PREG_SPLIT_NO_EMPTY);
        if (count($jws) == 3) {
            $header = json_decode(self::base64UrlDecode($jws[0]), true, 512, JSON_BIGINT_AS_STRING);
            if (json_last_error() != JSON_ERROR_NONE) {
                throw new \UnexpectedValueException('JSON parse error: JOSE header encoding is invalid.');
            }
            $payload = json_decode(self::base64UrlDecode($jws[1]), true, 512, JSON_BIGINT_AS_STRING);
            if (json_last_error() != JSON_ERROR_NONE) {
                throw new \UnexpectedValueException('JSON parse error: JWT encoding is invalid.');
            }
            $instance = new self($header, $payload);
            $instance->encodedHeader = $jws[0];
            $instance->encodedPayload = $jws[1];
            $instance->encodedSignature = $jws[2];
            return $instance;
        } else {
            throw new \UnexpectedValueException('String representation of the JWS is invalid.');
        }
    }

    /**
     * Returns the complete JWS representation using the JWS Compact Serialization.
     * @return string Encoded string representation of the JWS.
     */
    public function sing()
    {
        $this->encodedHeader = self::base64UrlEncode($this->header->toJSON());
        $this->encodedPayload = self::base64UrlEncode($this->payload->toJSON());
        $input = "{$this->encodedHeader}.{$this->encodedPayload}";
        $alg = Jwa::getAlgorithmInstance($this->header, $this->privateKey);
        $sign = $alg->sign($input);
        $this->encodedSignature = self::base64UrlEncode($sign);
        return "{$this->encodedHeader}.{$this->encodedPayload}.{$this->encodedSignature}";
    }

    /**
     * Verifies if a digital signature is valid.
     * @return boolean whether a digital signature is valid, false otherwise.
     */
    public function verify()
    {
        switch ($this->header->getAlgorithm()) {
            case 'HS256' :
            case 'HS384' :
            case 'HS512' :
                $alg = Jwa::getAlgorithmInstance($this->header, $this->privateKey);
                $input = "{$this->encodedHeader}.{$this->encodedPayload}";
                $sign = $alg->sign($input);
                return self::base64UrlDecode($this->encodedSignature) === $sign;
            break;

            case 'RS256' :
            case 'RS384' :
            case 'RS512' :
                $alg = Jwa::getAlgorithmInstance($this->header);
                $input = "{$this->encodedHeader}.{$this->encodedPayload}";
                $sign = self::base64UrlDecode($this->encodedSignature);
                return $alg->verify($input, $sign, $this->certificate);
            break;
        }

        return null;
    }

    /**
     * Encodes data with MIME base64. It provides an url-safe base64 string encoding.
     * @param string $data The data to encode.
     * @return string The encoded data, as a string.
     */
    public static function base64UrlEncode($data)
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }

    /**
     * Decodes data with MIME base64. It provides an url-safe base64 string decoding.
     * @param string $data The encoded data.
     * @return string Returns the original data or false on failure.
     */
    public static function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}