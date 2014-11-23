<?php
/**
 * @link https://github.com/iAchilles/pjwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
 
namespace iAchilles\pjwt;

/**
 * JoseHeader class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class JoseHeader
{
    /**
     * @var string Header Parameter Name "alg".
     */
    private $algorithm;

    /**
     * @var string Header Parameter Name "jku".
     */
    private $jwkSetUrl;

    /**
     * @var array Header Parameter Name "jwk".
     */
    private $jsonWebKey;

    /**
     * @var string Header Parameter Name "kid".
     */
    private $keyId;

    /**
     * @var string Header Parameter Name "x5u".
     */
    private $x509Url;

    /**
     * @var string Header Parameter Name "x5c".
     */
    private $x509CertificateChain;

    /**
     * @var string Header Parameter Name "x5t".
     */
    private $x509CertificateSHA1Thumbprint;

    /**
     * @var string Header Parameter Name "x5t#S256".
     */
    private $x509CertificateSHA256Thumbprint;

    /**
     * @var string Header Parameter Name "typ".
     */
    private $type;

    /**
     * @var string Header Parameter Name "cty".
     */
    private $contentType;

    /**
     * @var array  Header Parameter Name "crit".
     */
    private $critical;


    /**
     * Constructor.
     * @param string $algorithm
     * @throws \DomainException If the specified algorithm is not supported.
     */
    public function __construct($algorithm)
    {
        if (!isset(Jwa::getSupportedAlgorithms()[$algorithm])) {
            throw new \DomainException('Specified algorithm is not supported.');
        } else {
            $this->algorithm = $algorithm;
        }
    }

    /**
     * Returns registered header parameter names.
     * @return array Registered header parameter names.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1
     */
    public static function getRegisteredHeaderParameterNames()
    {
        return ['alg', 'jku', 'jwk', 'kid', 'x5u', 'x5c', 'x5t', 'x5t#S256', 'typ', 'cty', 'crit'];
    }

    /**
     * Parses an array of header parameters and returns an instance of the class JoseHeader.
     * @param array $header An array of header parameters.
     * @return JoseHeader Instance of the class JoseHeader.
     * @throws \DomainException If input array contains invalid elements.
     */
    public static function parseFromArray(array $header)
    {
        if (!isset($header['alg'])) {
            throw new \DomainException('Missing required parameter "alg".');
        } else {
            $instance = new self($header['alg']);
            if (isset($header['crit'])) {
                if (!is_array($header['crit'])) {
                    throw new \DomainException('Parameter "crit" must be an array.');
                } else if (array_intersect(self::getRegisteredHeaderParameterNames(), $header['crit']) != []) {
                    throw new \DomainException('Registered header parameter names must not be used in the "crit" list.');
                } else {
                    foreach ($header['crit'] as $name) {
                        if (!isset($header[$name])) {
                            throw new \DomainException('Header parameter with name "' . $name . '" not exists.');
                        } else {
                            $instance->critical[$name] = $header[$name];
                            unset($header[$name]);
                        }
                    }
                }
            }
            if (isset ($header['jku'])) {
                if (filter_var($header['jku'], FILTER_VALIDATE_URL) === false) {
                    throw new \DomainException('The value of the "jku" header parameter is not a valid URL.');
                } else {
                    if (preg_match('/^https/', $header['jku'])) {
                        $instance->jwkSetUrl = $header['jku'];
                    } else {
                        throw new \DomainException('JSON Web Key URL must be HTTPS.');
                    }
                }
            }
            if (isset ($header['x5u'])) {
                if (filter_var($header['x5u'], FILTER_VALIDATE_URL) === false) {
                    throw new \DomainException('The value of the "x5u" header parameter is not a valid URL.');
                } else {
                    if (preg_match('/^https/', $header['x5u'])) {
                        $instance->x509Url = $header['x5u'];
                    } else {
                        throw new \DomainException('X.509 URL must be HTTPS.');
                    }
                }
            }
            if (isset ($header['jwk'])) {
                if (!is_array($header['jwk'])) {
                    throw new \DomainException('Parameter "jwk" must be an array.');
                } else {
                    $instance->jsonWebKey = $header['jwk'];
                }
            }
            !isset ($header['kid'])      ?: $instance->keyId = $header['kid'];
            !isset ($header['x5c'])      ?: $instance->x509CertificateChain = $header['x5c'];
            !isset ($header['x5t'])      ?: $instance->x509CertificateSHA1Thumbprint = $header['x5t'];
            !isset ($header['x5t#S256']) ?: $instance->x509CertificateSHA256Thumbprint = $header['x5t#S256'];
            !isset ($header['typ'])      ?: $instance->type = $header['typ'];
            !isset ($header['cty'])      ?: $instance->contentType = $header['cty'];

            return $instance;
        }
    }

    /**
     * Returns an array representation of the JOSE header.
     * @return array An array representation of the JOSE header.
     */
    public function toArray()
    {
        $header['alg'] = $this->algorithm;
        is_null($this->jwkSetUrl)                      ?: $header['jku'] = $this->jwkSetUrl;
        is_null($this->jsonWebKey)                     ?: $header['jwk'] = $this->jsonWebKey;
        is_null($this->keyId)                          ?: $header['kid'] = $this->keyId;
        is_null($this->x509Url)                        ?: $header['x5u'] = $this->x509Url;
        is_null($this->type)                           ?: $header['typ'] = $this->type;
        is_null($this->contentType)                    ?: $header['cty'] = $this->contentType;
        is_null($this->critical)                       ?: $header['crit'] = array_keys($this->critical);
        is_null($this->x509CertificateChain)           ?: $header['x5c'] = $this->x509CertificateChain;
        is_null($this->x509CertificateSHA1Thumbprint)  ?: $header['x5t'] = $this->x509CertificateSHA1Thumbprint;
        is_null($this->x509CertificateSHA256Thumbprint)?: $header['x5t#S256'] = $this->x509CertificateSHA256Thumbprint;
        if (is_array($this->critical)) {
            foreach ($this->critical as $name => $value) {
                $header[$name] = $value;
            }
        }

        return $header;
    }

    /**
     * Returns JSON string representation of the JOSE header.
     * @return string JSON string representation of the JOSE header.
     */
    public function toJSON()
    {
        return json_encode($this->toArray(), JSON_UNESCAPED_SLASHES);
    }

    /**
     * Returns the value of the "alg" header parameter.
     * @return string Algorithm.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.1
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * Returns the value of the "jku" header parameter.
     * @return string URL.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.2
     */
    public function getJwkUrl()
    {
        return $this->jwkSetUrl;
    }

    /**
     * Returns the value of the "jwk" header parameter.
     * @return array Jwk JSON web key.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.3
     */
    public function getJsonWebKey()
    {
        return $this->jsonWebKey;
    }

    /**
     * Returns the value of the "kid" header parameter.
     * @return string Key id.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.4
     */
    public function getKeyId()
    {
        return $this->keyId;
    }

    /**
     * Returns the value of the "x5u" header parameter.
     * @return string URL.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.5
     */
    public function getX509Url()
    {
        return $this->x509Url;
    }

    /**
     * Returns the value of the "x5c" header parameter.
     * @return string  X.509 public key certificate or certificate chain.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.6
     */
    public function getX509CertificateChain()
    {
        return $this->x509CertificateChain;
    }

    /**
     * Returns the value of the "x5t" header parameter.
     * @return string Certificate thumbprint.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.7
     */
    public function getX509CertificateSHA1Thumbprint()
    {
        return $this->x509CertificateSHA1Thumbprint;
    }

    /**
     * Returns the value of the "x5t#S256"  header parameter.
     * @return string Certificate thumbprint.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.8
     */
    public function getX509CertificateSHA256Thumbprint()
    {
        return $this->x509CertificateSHA256Thumbprint;
    }

    /**
     * Returns the value of the "typ" header parameter.
     * @return string MIME Media Type of the complete JWS object.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.9
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Returns the value of the "cty" header parameter.
     * @return string MIME Media Type of the the payload.
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.10
     */
    public function getContentType()
    {
        return $this->contentType;
    }

    /**
     * Returns the value of "crit" header parameter.
     * @return array $critical
     * @link https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-36#section-4.1.11
     */
    public function getCritical()
    {
        return $this->critical;
    }
} 