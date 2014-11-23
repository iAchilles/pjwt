<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
 
namespace iAchilles\pjwt\crypt;

/**
 * HmacAlgo class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class HmacAlgo
{
    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var string
     */
    private $key;


    /**
     * Constructor.
     * @param string $algorithm
     * @param string $key
     */
    public function __construct($algorithm, $key)
    {
        $this->algorithm = $algorithm;
        $this->key = $key;
    }


    /**
     * @param string $data
     * @return string Digital signature.
     */
    public function sign($data)
    {
        return hash_hmac($this->algorithm, $data, $this->key);
    }
} 