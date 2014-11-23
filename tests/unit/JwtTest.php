<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */

use iAchilles\pjwt\Jwt;
 
/**
 * JwtTest class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class JwtTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers Jwt::parseFromArray
     */
    public function testParseFromArray()
    {
        $claims = ['iss' => 'a', 'iat' => 123, 'nbf' => 123, 'exp' => 123, 'sub' => 'a', 'aud' => 'a', 'jti' => 'a', 'cus' => 'b'];
        $class = Jwt::parseFromArray($claims);
        $this->assertEquals('a', $class->issuer);
        $this->assertEquals('a', $class->subject);
        $this->assertEquals('a', $class->audience);
        $this->assertEquals('a', $class->jwtId);
        $this->assertEquals(123, $class->issuedAt);
        $this->assertEquals(123, $class->notBefore);
        $this->assertEquals(123, $class->expires);
        $this->assertEquals('b', $class->getCustomClaim('cus'));
        $this->assertTrue(is_string(Jwt::parseFromArray(['jti' => true])->jwtId));
        $this->assertTrue(is_integer(Jwt::parseFromArray(['jti' => 546465])->jwtId));
    }

    /**
     * @covers Jwt::toJSON
     */
    public function testToJSON()
    {
        $claims = ['iss' => 'a', 'iat' => 123, 'nbf' => 123, 'exp' => 123, 'sub' => 'a', 'aud' => 'a', 'jti' => 'a', 'cus' => 'b'];
        $j1 = json_encode($claims, JSON_UNESCAPED_SLASHES);
        $j2 = Jwt::parseFromArray($claims)->toJSON();
        $this->assertEquals($j1, $j2);
    }

    /**
     * @covers Jwt::getCustomClaim
     */
    public function testGetCustomClaim()
    {
        $claims = ['iss' => 'a', 'iat' => 123, 'nbf' => 123, 'exp' => 123, 'sub' => 'a', 'aud' => 'a', 'jti' => 'a', 'cus' => 'b'];
        $this->assertEquals('b', Jwt::parseFromArray($claims)->getCustomClaim('cus'));
        $exception = false;
        try {
            Jwt::parseFromArray($claims)->getCustomClaim('cuse');
        } catch (\DomainException $ex) {
            $exception = true;
        }
        $this->assertTrue($exception);
    }

    /**
     * @covers Jwt::verify
     */
    public function testVerify()
    {
        $past = strtotime('-1 day');
        $future = strtotime('+1 day');
        $claims = ['iat' => $past, 'nbf' => $past, 'exp' => $future];
        $jwt = Jwt::parseFromArray($claims);
        $this->assertTrue($jwt->verify());
        $claims = ['iat' => $future, 'nbf' => $future, 'exp' => $future];
        $jwt = Jwt::parseFromArray($claims);
        $this->assertTrue($jwt->verify() !== true);
        $this->assertTrue(Jwt::parseFromArray(['exp' => $past])->verify() !== true);
        $this->assertTrue(Jwt::parseFromArray(['iat' => $future])->verify() !== true);
        $this->assertTrue(Jwt::parseFromArray(['iat' => $past])->verify());
        $this->assertTrue(Jwt::parseFromArray(['exp' => $future])->verify());
        $this->assertTrue(Jwt::parseFromArray(['nbf' => $past])->verify());
        $this->assertTrue(Jwt::parseFromArray(['nbf' => $future])->verify() !== true);
        $claims = ['iat' => $past, 'nbf' => $past, 'exp' => $future, 'jti' => true];
        $get = function($jti){return true;};
        $set = function($jti){};
        $jwt = Jwt::parseFromArray($claims);
        $this->assertTrue($jwt->verify($set, $get) !== true);
        $get = function($jti){return false;};
        $this->assertTrue($jwt->verify($set, $get));
    }
} 