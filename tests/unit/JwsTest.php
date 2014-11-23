<?php
/**
 * @link https://github.com/iAchilles/jwt
 * @copyright Copyright (c) 2014, Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 * @license AGPL License 3.0 (http://www.gnu.org/licenses/agpl-3.0.html)
 */

use iAchilles\pjwt\Jws;

/**
 * JwsTest class
 *
 * @author Igor Manturov Jr. <igor.manturov.jr@gmail.com>
 */
class JwsTest extends PHPUnit_Framework_TestCase
{
    private $cert = '-----BEGIN CERTIFICATE-----
MIIECTCCAvGgAwIBAgIJAISrEwI3LqNLMA0GCSqGSIb3DQEBBQUAMIGaMQswCQYD
VQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTESMBAGA1UEBwwJV2hpdGVmaXNoMRIw
EAYDVQQKDAlpQWNoaWxsZXMxEjAQBgNVBAsMCWlBY2hpbGxlczESMBAGA1UEAwwJ
aUFjaGlsbGVzMSkwJwYJKoZIhvcNAQkBFhppZ29yLm1hbnR1cm92LmpyQGdtYWls
LmNvbTAeFw0xNDExMjMxNTQyMzdaFw0xNDEyMjMxNTQyMzdaMIGaMQswCQYDVQQG
EwJVUzEQMA4GA1UECAwHTW9udGFuYTESMBAGA1UEBwwJV2hpdGVmaXNoMRIwEAYD
VQQKDAlpQWNoaWxsZXMxEjAQBgNVBAsMCWlBY2hpbGxlczESMBAGA1UEAwwJaUFj
aGlsbGVzMSkwJwYJKoZIhvcNAQkBFhppZ29yLm1hbnR1cm92LmpyQGdtYWlsLmNv
bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKi4PgBAM4aHJgIKc8tv
j5SmwqBuUJISbIfm5XExMkHXSTCPzh+4rkrG627QS0GCbcWvGbqXP7oDMsB0HBNb
xZeK4wzdvzx7ga4T5AqQKKosAOVW8QBfl2t0Z8Hgr0FVsdpFnxvz3iHKWtTRaASK
eRUjgtHO7uAUceW+vleHnATlEu15FxsQbNlc1oQSBbm1TKqjVd2JMETH3K6kCO2W
+hG0ahBBCOxo1uFTnVGvzEveD7rHUkpgoeb1jGZyiqxqjFAv1mQmT6tljsy5V6Uo
WC6KxbrRWr6VwjCL4zJQR97bw+l/TyIkqLLUsIBiJye8hZ68GQricYOVNkoXnVI9
qLMCAwEAAaNQME4wHQYDVR0OBBYEFCu1XNHHZGVBsWkuMiAyqq0FDABxMB8GA1Ud
IwQYMBaAFCu1XNHHZGVBsWkuMiAyqq0FDABxMAwGA1UdEwQFMAMBAf8wDQYJKoZI
hvcNAQEFBQADggEBAIQfwwav+ZpjftJ9hzX7NQuqZf6wgH80rxSD5L4SAmFB0DZA
eYojXReQ/BwB7ic1S6G6NwxntYC9A0MOaTe+vgFp5GsfqK7cvMH8PGx7EBpWVSQX
CsdYytgy+KMMsEG8LMpQzrVmv8/u5huq7GmO8cPKz6RQ7K9ZfAtMNkDj8L+2fm1I
qvTxnyDbObclfg18fAlLUjlw77od+3TkQSNsFLz4TM6AkzvhbAtvY7ApF+DDMU4i
Zj38c8XpzVWtuRNKryxAvbKCoAbu1zRZrcZQvidvNJb2oQVGmdvaGffHeFgJ7jci
pgo9GCoYAoqMwhP5aTaIIIx51fO/S8tpEVIbzqg=
-----END CERTIFICATE-----';
    private  $key = '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCouD4AQDOGhyYC
CnPLb4+UpsKgblCSEmyH5uVxMTJB10kwj84fuK5Kxutu0EtBgm3Frxm6lz+6AzLA
dBwTW8WXiuMM3b88e4GuE+QKkCiqLADlVvEAX5drdGfB4K9BVbHaRZ8b894hylrU
0WgEinkVI4LRzu7gFHHlvr5Xh5wE5RLteRcbEGzZXNaEEgW5tUyqo1XdiTBEx9yu
pAjtlvoRtGoQQQjsaNbhU51Rr8xL3g+6x1JKYKHm9YxmcoqsaoxQL9ZkJk+rZY7M
uVelKFguisW60Vq+lcIwi+MyUEfe28Ppf08iJKiy1LCAYicnvIWevBkK4nGDlTZK
F51SPaizAgMBAAECggEAd8r5Gqx66RWkQuaw+MypIV6V6drpkg1KyeODHS9VA7Kb
4ML6E0PJXIaIOxHhnQ3Caw28MuOY97W1nzfRh10tmj+enlADrCn1FWhCDc31UX4U
1ME6NI2qsTzhPqMNTFJQCS5Nnkc0fMF0ZI6aUD8RYZTpGZbXvHpHtFwOQY+jk0T7
IBP+BU52DpSh0n175kagkAmymXmzsbz0fKVw5yW4qoHIaq1V4KKnIMFDSM0lQZ/V
PUZgpHxVZChmCIStbu6RuHjux1xgfyGCYs9jeqNcvASnIjydlqh1VuLDutiv0dbQ
u7+P9W4RAhmyjPEQBDv7HTgehsFlqIEOhSgp1eAwQQKBgQDYh4XV1jKrGYSR/U6x
a5aC8ZlENLZD5oaRLjV8BW/4ewm0oxvdQ3JpssLB68TvWO3DqB5Wrm1+nQRZ03sj
a6XyTY/auMAjg6wUZ2VdcgF8uArWlW7vqUMp3uCajkpKi9ly3qQvgfSoZpHoOkxz
tKbdBFvIOPF/mQ9j0LIhGSEVKQKBgQDHeaaYYpJ6AL+vMjJFsbqqWV2AqgK29jo3
+SXrwEMs5VN7PS8GvpeJTy1YEyYuUDIUlrjtSg8IFhXZHPm0CQxAL4DZI9KTnBrp
91/exMvXqMEwDITFbGP6451cgOvD6vLPWEXP3oU36DR/IdIGsUZL1vEkFlwA750A
DyguWnZOewKBgQCasyC8qX+j3ORphWf+vJZZUZGmOF7sXjxQZ4pQ5HWeOxGxHEPh
LroEqHIbKH6YXpnpCyk51v9l0Xr1TnIQ2W1Dk4SuyQaFmSKNpV23iKdlWvxrWXJc
CjtxI8qmwfh0EDy4pDb7tkZ9NmMSXuyWUkBRcja882ofNtTXBJjvqsuHGQKBgFFx
g+mX5YJWp+zaK9h01mgTELAlufIF2oNcAHWfDE5aW5lnw7mXO7veTf814lLqf2gU
mfCYWkbM7aK1x+YQA6Z5PrxpeeK2y+5XCBemdivZRPdfRR5uQOwA3xETui9F0FmE
CwzyJ6ZJ8pUts9jzrGXunopDbtEbBBkwFxHF8aPdAoGBAK+ajpGwAaaC4HY/0TuK
AXsHEA7VfGkwoqeVefQWlVGImhA+DugBMpD+YuBgn3ProUkKkLHq0o6a20rMxlxz
84xC6zkQfxTwti/He45vfjbOW6SoOb2L872Iq+DCDOhIeqZLmJZePN8jaeC1z8fw
29oipZ1SJBldaSGpcBkk0Vdo
-----END PRIVATE KEY-----';
    private $secret = 'dafwf588w7fwefq5q4f6AS3';


    /**
     * @covers Jws::__construct
     */
    public function testConstructor()
    {
        $payload = ['iss' => 'domain.com'];
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        $jws = new Jws($header, $payload);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
    }

    /**
     * @covers Jws::sign
     */
    public function testSign()
    {
        $payload = ['iss' => 'a', 'iat' => 123, 'nbf' => 123, 'exp' => 123, 'sub' => 'a', 'aud' => 'a', 'jti' => 'a', 'cus' => 'b'];
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        $jws = new Jws($header, $payload);
        $jws->privateKey = $this->secret;
        $hs256 = $jws->sing();
        $jws = new Jws(['alg' => 'HS384', 'typ' => 'JWT'], $payload);
        $jws->privateKey = $this->secret;
        $hs384 = $jws->sing();
        $jws = new Jws(['alg' => 'HS512', 'typ' => 'JWT'], $payload);
        $jws->privateKey = $this->secret;
        $hs512 = $jws->sing();
        $jws = new Jws(['alg' => 'RS256', 'typ' => 'JWT'], $payload);
        $jws->privateKey = $this->key;
        $jws->certificate = $this->cert;
        $rs256 = $jws->sing();
        $jws = new Jws(['alg' => 'RS384', 'typ' => 'JWT'], $payload);
        $jws->privateKey = $this->key;
        $jws->certificate = $this->cert;
        $rs384 = $jws->sing();
        $jws = new Jws(['alg' => 'RS512', 'typ' => 'JWT'], $payload);
        $jws->privateKey = $this->key;
        $jws->certificate = $this->cert;
        $rs512 = $jws->sing();
        return [$hs256, $hs384, $hs512, $rs256, $rs384, $rs512];
    }

    /**
     * @covers Jws::parse
     * @depends testSign
     */
    public function testParse(array $sign)
    {
        $jws = Jws::parse($sign[0]);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
        $this->assertEquals('HS256', $jws->getHeader()->getAlgorithm());
        $jws = Jws::parse($sign[1]);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
        $this->assertEquals('HS384', $jws->getHeader()->getAlgorithm());
        $jws = Jws::parse($sign[2]);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
        $this->assertEquals('HS512', $jws->getHeader()->getAlgorithm());
        $jws = Jws::parse($sign[3]);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
        $this->assertEquals('RS256', $jws->getHeader()->getAlgorithm());
        $jws = Jws::parse($sign[4]);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
        $this->assertEquals('RS384', $jws->getHeader()->getAlgorithm());
        $jws = Jws::parse($sign[5]);
        $this->assertInstanceOf('iAchilles\pjwt\JoseHeader', $jws->getHeader());
        $this->assertInstanceOf('iAchilles\pjwt\Jwt', $jws->getPayload());
        $this->assertEquals('RS512', $jws->getHeader()->getAlgorithm());
    }

    /**
     * @covers Jws::verify
     * @depends testSign
     */
    public function testVerify(array $sign)
    {
        $jws = Jws::parse($sign[0]);
        $jws->privateKey = $this->secret;
        $this->assertTrue($jws->verify());
        $jws = Jws::parse($sign[1]);
        $jws->privateKey = $this->secret;
        $this->assertTrue($jws->verify());
        $jws = Jws::parse($sign[2]);
        $jws->privateKey = $this->secret;
        $this->assertTrue($jws->verify());
        $jws = Jws::parse($sign[3]);
        $jws->certificate = $this->cert;
        $this->assertTrue($jws->verify());
        $jws = Jws::parse($sign[4]);
        $jws->certificate = $this->cert;
        $this->assertTrue($jws->verify());
        $jws = Jws::parse($sign[5]);
        $jws->certificate = $this->cert;
        $this->assertTrue($jws->verify());
    }
} 