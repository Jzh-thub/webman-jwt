<?php


namespace Jzh\Jwt;


use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Jzh\Jwt\Adapter\JwtInterface;
use Jzh\Jwt\Exception\JwtException;

class JwtToken implements JwtInterface
{
    /**
     * access_token
     */
    const ACCESS_TOKEN = 1;

    /**
     * refresh_token.
     */
    const REFRESH_TOKEN = 2;

    protected $guard = 'user';

    protected $config = [];

    /**
     * JwtToken constructor.
     */
    public function __construct()
    {
        $_config = config('plugin.jzh.jwt.app');
        if (empty($_config)) {
            throw new JwtException('The configuration file is abnormal or does not exist');
        } else if (!isset($_config['jwt'])) {
            throw new JwtException('jwt配置文件不存在');
        } else if (!isset($_config['guard'])) {
            throw new JwtException('guard配置文件不存在');
        }
        $this->config = $_config;
    }

    /**
     * 设置角色
     * @param string $guard
     * @return $this
     */
    public function guard(string $guard = 'user'): JwtToken
    {
        $this->guard = $guard;
        return $this;
    }

    /**
     * 退出登入
     */
    public function logout($all = false)
    {
        $token        = self::getTokenFromHeaders();
        $tokenPayload = self::verifyToken($token, self::ACCESS_TOKEN);
        //获取主键
        $idKey = $this->config['guard'][$this->guard]['key'];
        $id    = $tokenPayload['extend'][$idKey];
        RedisHandler::logout($token, $this->config['jwt']['redis_pre'], $this->guard, $id, $all);
    }


    /**
     * 生成令牌
     * @param array $extend 扩展内容
     * @return array
     */
    public function generateToken(array $extend): array
    {
        $payload   = self::generatePayload($extend);
        $secretKey = self::getPrivateKey();
        $token     = [
            'token_type'           => 'Bearer',
            'access_token_in'      => $this->config['jwt']['access_exp'],
            'access_token_expires' => bcadd((string)$this->config['jwt']['access_exp'], (string)time(), 0),
            'access_token'         => self::makeToken($payload['accessPayload'], $secretKey)
        ];
        if (!isset($this->config['jwt']['refresh_disable']) || (isset($this->config['jwt']['refresh_disable']) && $this->config['jwt']['refresh_disable'] === false)) {
            $refreshSecretKey               = self::getPrivateKey(self::REFRESH_TOKEN);
            $token['refresh_token']         = self::makeToken($payload['refreshPayload'], $refreshSecretKey);
            $token['refresh_token_in']      = $this->config['jwt']['refresh_exp'];
            $token['refresh_token_expires'] = bcadd((string)$this->config['jwt']['refresh_exp'], (string)time(), 0);

        }
        //获取主键
        $idKey = $this->config['guard'][$this->guard]['key'];
        RedisHandler::generateToken($extend[$idKey], $this->guard, $this->config['jwt']['redis_pre'], $this->config['guard'][$this->guard]['limit'], $this->config['jwt']['refresh_disable'], $token['access_token'], $token['access_token_in'], $token['refresh_token'] ?? null, $token['refresh_token_in'] ?? null);
        return $token;
    }


    /**
     * 刷新令牌
     * @return array
     */
    public function refreshToken(): array
    {
        $refreshToken        = self::getTokenFromHeaders();
        $tokenPayload        = self::verifyToken($refreshToken, self::REFRESH_TOKEN);
        $tokenPayload['exp'] = time() + $this->config['jwt']['access_exp'];
        $secretKey           = self::getPrivateKey();
        $token               = self::makeToken($tokenPayload, $secretKey);
        //获取主键
        $idKey = $this->config['guard'][$this->guard]['key'];
        RedisHandler::setAccessToken($tokenPayload['extend'][$idKey], $this->guard, $this->config['jwt']['redis_pre'], $refreshToken, $token, $tokenPayload['exp']);
        return ['access_token' => $token, 'access_token_expires' => $tokenPayload['exp']];
    }

    /**
     * 验证令牌
     * @param int         $tokenType token类型:self::ACCESS_TOKEN,self::REFRESH_TOKEN
     * @param string|null $token token
     * @return array
     */
    public function verify(int $tokenType = self::ACCESS_TOKEN, string $token = null): array
    {
        $token = $token ?? self::getTokenFromHeaders();
        return $this->verifyToken($token, $tokenType);
    }

    /**
     * @desc: 获令牌有效期剩余时长.
     * @param int $tokenType token类型:self::ACCESS_TOKEN,self::REFRESH_TOKEN
     * @return int
     */
    public function getTokenExp(int $tokenType = self::ACCESS_TOKEN): int
    {
        return (int)self::verify($tokenType)['exp'] - time();
    }

    /**
     * 获取当前用户登录ID
     * @return int|mixed|string
     */
    public function getCurrentId()
    {
        $key = $this->config['guard'][$this->guard]['key'];
        return self::getExtendVal($key) ?? 0;
    }

    /**
     * 获取会员信息
     * @param false $cache 是否从数据库读取
     * @return array
     * @throws JwtException
     */
    public function user(bool $cache = false): array
    {
        $key    = $this->config['guard'][$this->guard]['key'];
        $extend = self::getExtend();
        if (isset($extend) && !empty($extend) && isset($extend[$key])) {
            if ($cache) {
                return $extend;
            } else {
                return $this->getUser();
            }

        }
        throw new JwtException('配置信息异常', 401);

    }

    /**
     * 获取当前用户信息
     * @return array
     */
    private function getUser(): array
    {
        $guardConfig = $this->config['guard'][$this->guard];
        if (is_callable($guardConfig['model'])) {
            return $guardConfig['model'](self::getCurrentId()) ?? [];
        }
        return [];
    }

    /**
     *  获取指定令牌扩展内容字段的值
     * @param string $val
     * @return mixed|string
     */
    public function getExtendVal(string $val)
    {
        return self::getTokenExtend()[$val] ?? '';
    }

    /**
     * @desc 获取所有字段
     * @return array
     */
    public function getExtend(): array
    {
        return self::getTokenExtend();
    }

    /**
     * 获取扩展字段
     * @return array
     */
    private function getTokenExtend(): array
    {
        return (array)self::verify()['extend'];
    }


    /**
     * 生成令牌
     * @param array  $payload 载荷信息
     * @param string $secretKey 签名key
     * @return string
     */
    private function makeToken(array $payload, string $secretKey): string
    {
        $algorithms = $this->config['jwt']['algorithms'];
        return \Firebase\JWT\JWT::encode($payload, $secretKey, $algorithms);
    }

    /**
     * @param array $extend
     * @return array
     */
    private function generatePayload(array $extend): array
    {
        $basePayload = [
            'iss'    => $this->config['jwt']['iss'],
            'iat'    => time(),
            'exp'    => time() + $this->config['jwt']['access_exp'],
            'extend' => $extend,
            'guard'  => $this->guard,
        ];

        $resPayLoad['accessPayload']  = $basePayload;
        $basePayload['exp']           = time() + $this->config['jwt']['refresh_exp'];
        $resPayLoad['refreshPayload'] = $basePayload;
        return $resPayLoad;
    }

    /**
     * 根据签名算法获取 【公钥】 签名值
     * @param string $algorithm 算法
     * @param int    $tokenType 类型
     * @return mixed
     */
    protected function getPublicKey(string $algorithm, int $tokenType = self::ACCESS_TOKEN)
    {
        switch ($algorithm) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $this->config['jwt']['access_secret_key'] : $this->config['jwt']['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::REFRESH_TOKEN == $tokenType ? $this->config['jwt']['access_public_key'] : $this->config['jwt']['refresh_public_key'];
                break;
            default:
                $key = $this->config['jwt']['access_secret_key'];
        }

        return $key;
    }

    /**
     * 根据签名算法获取【私钥】签名值
     * @param int $tokenType 令牌类型
     * @return mixed
     */
    protected function getPrivateKey(int $tokenType = self::ACCESS_TOKEN)
    {
        switch ($this->config['jwt']['algorithms']) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $this->config['jwt']['access_secret_key'] : $this->config['jwt']['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $this->config['jwt']['access_private_key'] : $this->config['jwt']['refresh_private_key'];
                break;
            default:
                $key = $this->config['jwt']['access_secret_key'];
        }

        return $key;

    }


    /**
     * 获取Header头部authorization令牌
     * @return string
     */
    private static function getTokenFromHeaders(): string
    {
        $authorization = request()->header('authorization');
        if (!$authorization || 'undefined' == $authorization) {
            throw new JwtException('请求未携带authorization信息');
        }

        if (self::REFRESH_TOKEN != substr_count($authorization, '.')) {
            throw new JwtException('非法的authorization信息');
        }

        if (2 != count(explode(' ', $authorization))) {
            throw new JwtException('Bearer验证中的凭证格式有误，中间必须有个空格');
        }

        [$type, $token] = explode(' ', $authorization);
        if ('Bearer' !== $type) {
            throw new JwtException('接口认证方式需为Bearer');
        }
        if (!$token || 'undefined' === $token) {
            throw new JwtException('尝试获取的Authorization信息不存在');
        }
        return $token;
    }

    /**
     * 校验令牌
     * @param string $token
     * @param int    $tokenType
     * @return array
     * @throws JwtException
     */
    private function verifyToken(string $token, int $tokenType): array
    {
        $publicKey                 = self::ACCESS_TOKEN == $tokenType ? self::getPublicKey($this->config['jwt']['algorithms']) : self::getPublicKey($this->config['jwt']['algorithms'], self::REFRESH_TOKEN);
        \Firebase\JWT\JWT::$leeway = 60;
        try {
            $decoded      = \Firebase\JWT\JWT::decode($token, new Key($publicKey, $this->config['jwt']['algorithms']));
            $tokenPayload = json_decode(json_encode($decoded), true);
            if ($tokenPayload['guard'] != $this->guard) {
                throw new SignatureInvalidException('无效令牌');
            }
            //获取主键
            $idKey = $this->config['guard'][$this->guard]['key'];
            RedisHandler::verifyToken($tokenPayload['extend'][$idKey], $this->guard, $this->config['jwt']['redis_pre'], $token, $tokenType);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtException('身份验证令牌无效', 401);
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtException('身份验证令牌尚未生效', 403);
        } catch (ExpiredException $expiredException) {
            throw new JwtException('身份验证会话已过期，请重新登录！', 402);
        } catch (\UnexpectedValueException $unexpectedValueException) {
            throw new JwtException('获取扩展字段不正确', 401);
        } catch (JwtException | \Exception $exception) {
            throw new JwtException($exception->getMessage(), 401);
        }
        return $tokenPayload;
    }
}
