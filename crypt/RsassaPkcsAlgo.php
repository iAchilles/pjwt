<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
 
namespace iAchilles\pjwt\crypt;

/**
 * RsassaPkcsAlgo class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class RsassaPkcsAlgo
{
    /**
     * Constant can be used to specify the fingerprint algorithm.
     */
    const ALGO_SHA1 = 'sha1';

    /**
     * Constant can be used to specify the fingerprint algorithm.
     */
    const ALGO_SHA256 = 'sha256';

    /**
     * @var resource A positive key resource identifier.
     */
    private $key;

    /**
     * @var string Algorithm.
     */
    private $algorithm;


    /**
     * Constructor.
     * @param integer $algorithm OPENSSL_ALGO_SHA256, OPENSSL_ALGO_SHA384 or OPENSSL_ALGO_SHA512.
     * @param string|array $key It can be either a string having the format file://path/to/file.pem. The named file must
     * contain a PEM encoded certificate/private key (it may contain both), or a PEM formatted private key. Also it can
     * be an array with two elements. The second element is a string that represent a password for the encrypted private key.
     * @throws \DomainException If the private key invalid or not found.
     */
    public function __construct($algorithm, $key = null)
    {
        $this->algorithm = $algorithm;
        if (!is_null($key)) {
            $password = is_array($key) ? $key[1] : null;
            $key = is_array($key) ? $key[0] : $key;
            $this->key = openssl_pkey_get_private($key, $password);
            if (!$this->key) {
                throw new \DomainException('Private key invalid or not found.');
            }
        }
    }

    /**
     * Generates a digital signature for the specified data.
     * @param string $data The first two parts of the JWS.
     * @return string Digital signature.
     * @throws \DomainException If unable to generate a digital signature.
     */
    public function sign($data)
    {
        $signature = '';
        $result = openssl_sign($data, $signature, $this->key, $this->algorithm);
        if ($result) {
            return $signature;
        }
        throw new \DomainException('Unable to generate a digital signature.');
    }

    /**
     * Verifies if a digital signature is valid.
     * @param string $data The first two parts of the JWS.
     * @param string $signature BASE64URL decoded string, that represents the digital signature.
     * @param string $certificate It can be either a string having the format file://path/to/file.pem (the named file must
     * contain a PEM encoded certificate) or PEM formatted certificate.
     * @return boolean whether a digital signature is valid, false otherwise.
     */
    public function verify($data, $signature, $certificate)
    {
        $publicKey = openssl_pkey_get_public($certificate);
        if ($publicKey === false)
        {
            return false;
        }
        if (openssl_verify($data, $signature, $publicKey, $this->algorithm) === 1)
        {
            return true;
        }

        return false;
    }

    /**
     * Returns X.509 Certificate fingerprint.
     * @param string $certificate A string that contains the X.509 certificate in PEM format.
     * @param string $algorithm Fingerprint algorithm, either "sha1" or "sha256".
     * @return string X.509 Certificate fingerprint.
     */
    public static function getFingerprint($certificate, $algorithm = self::ALGO_SHA1)
    {
        $certificate = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/', '', $certificate);
        return hash($algorithm, base64_decode($certificate));
    }

}