<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */
use iAchilles\pjwt\JoseHeader;
use iAchilles\pjwt\Jwa;

/**
 * JwaTest class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class JwaTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers Jwa::getAlgorithmInstance
     */
    public function testGetAlgorithmInstance()
    {
        $this->assertInstanceOf('iAchilles\pjwt\crypt\HmacAlgo', Jwa::getAlgorithmInstance(JoseHeader::parseFromArray(['alg' => 'HS256'])));
        $this->assertInstanceOf('iAchilles\pjwt\crypt\HmacAlgo', Jwa::getAlgorithmInstance(JoseHeader::parseFromArray(['alg' => 'HS384'])));
        $this->assertInstanceOf('iAchilles\pjwt\crypt\HmacAlgo', Jwa::getAlgorithmInstance(JoseHeader::parseFromArray(['alg' => 'HS512'])));
        $this->assertInstanceOf('iAchilles\pjwt\crypt\RsassaPkcsAlgo', Jwa::getAlgorithmInstance(JoseHeader::parseFromArray(['alg' => 'RS256'])));
        $this->assertInstanceOf('iAchilles\pjwt\crypt\RsassaPkcsAlgo', Jwa::getAlgorithmInstance(JoseHeader::parseFromArray(['alg' => 'RS384'])));
        $this->assertInstanceOf('iAchilles\pjwt\crypt\RsassaPkcsAlgo', Jwa::getAlgorithmInstance(JoseHeader::parseFromArray(['alg' => 'RS512'])));
    }
} 