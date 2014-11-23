<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */


use iAchilles\pjwt\JoseHeader;

/**
 * JoseHeaderTest class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class JoseHeaderTest extends PHPUnit_Framework_TestCase
{

    /**
     * @covers JoseHeader::parseFromArray
     */
    public function testParseFromArray()
    {
        $headers = ['alg' => 'HS256', 'jku' => 'https://localhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'https://localhost',
                     'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['a'], 'a' => 'b'];
        $header = JoseHeader::parseFromArray($headers);
        $this->assertEquals('HS256', $header->getAlgorithm());
        $this->assertEquals('https://localhost', $header->getJwkUrl());
        $this->assertEquals([], $header->getJsonWebKey());
        $this->assertEquals('a', $header->getKeyId());
        $this->assertEquals('https://localhost', $header->getX509Url());
        $this->assertEquals('a', $header->getX509CertificateChain());
        $this->assertEquals('a', $header->getX509CertificateSHA1Thumbprint());
        $this->assertEquals('a', $header->getX509CertificateSHA256Thumbprint());
        $this->assertEquals('a', $header->getType());
        $this->assertEquals('a', $header->getContentType());
        $this->assertEquals(['a' => 'b'], $header->getCritical());

        $headers = ['alg' => 'S256fhf', 'jku' => 'https://localhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'https://localhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['a'], 'a' => 'b'];
        $exception = false;
        try {
            JoseHeader::parseFromArray($headers);
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);

        $headers = ['alg' => 'HS256', 'jku' => 'httlocalhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'https://localhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['a'], 'a' => 'b'];
        $exception = false;
        try {
            JoseHeader::parseFromArray($headers);
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);

        $headers = ['alg' => 'HS256', 'jku' => 'https://localhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'htlocalhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['a'], 'a' => 'b'];
        $exception = false;
        try {
            JoseHeader::parseFromArray($headers);
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);

        $headers = ['alg' => 'HS256', 'jku' => 'https://localhost', 'jwk' => 'a', 'kid' => 'a', 'x5u' => 'https://localhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['a'], 'a' => 'b'];
        $exception = false;
        try {
            JoseHeader::parseFromArray($headers);
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);

        $headers = ['alg' => 'HS256', 'jku' => 'https://localhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'https://localhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['c'], 'a' => 'b'];
        $exception = false;
        try {
            JoseHeader::parseFromArray($headers);
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);

        $headers = ['alg' => 'HS256', 'jku' => 'https://localhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'https://localhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => 'c', 'a' => 'b'];
        $exception = false;
        try {
            JoseHeader::parseFromArray($headers);
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);
    }

    /**
     * @covers JoseHeader::toArray
     */
    public function testToArray()
    {
        $headers = ['alg' => 'HS256', 'jku' => 'https://localhost', 'jwk' => [], 'kid' => 'a', 'x5u' => 'https://localhost',
                    'x5c' => 'a', 'x5t' => 'a', 'x5t#S256' => 'a', 'typ' => 'a', 'cty' => 'a', 'crit' => ['a'], 'a' => 'b'];
        $header = JoseHeader::parseFromArray($headers);
        $this->assertEquals($headers, $header->toArray());
    }

}