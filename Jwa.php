<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
 
namespace iAchilles\pjwt;
use iAchilles\pjwt\crypt\HmacAlgo;
use iAchilles\pjwt\crypt\RsassaPkcsAlgo;

/**
 * Jwa class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class Jwa
{
    /**
     * Returns supported algorithms.
     * @return array Supported algorithms.
     */
    public static function getSupportedAlgorithms()
    {
        return ['HS256' => 'sha256', 'HS384' => 'sha384', 'HS512' => 'sha512', 'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384, 'RS512' => OPENSSL_ALGO_SHA512];
    }

    /**
     * Returns an instance of the algorithm class that will be used for sign.
     * @param JoseHeader $header
     * @param mixed $key
     * @return mixed
     */
    public static function getAlgorithmInstance(JoseHeader $header, $key = null)
    {
        switch ($header->getAlgorithm()) {
            case 'HS256' :
            case 'HS384' :
            case 'HS512' :
                return new HmacAlgo(self::getSupportedAlgorithms()[$header->getAlgorithm()], $key);
            break;

            case 'RS256' :
            case 'RS384' :
            case 'RS512' :
                return new RsassaPkcsAlgo(self::getSupportedAlgorithms()[$header->getAlgorithm()], $key);
            break;
        }
    }
} 