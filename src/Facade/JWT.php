<?php

declare (strict_types=1);

namespace Jzh\Jwt\Facade;

use Jzh\Jwt\Adapter\JwtInterface;
use Jzh\Jwt\JwtToken;

/**
 * Class Auth
 * @package Jzh\Jwt\Facade
 * @see JwtToken
 * @mixin JwtToken
 * @method static JwtInterface guard($guard = 'user')  设置角色
 * @method static array generateToken(array $extend)  生成令牌
 * @method static array refreshToken()  刷新令牌
 * @method static array verify(int $tokenType = self::ACCESS_TOKEN, string $token = null)  验证token
 * @method static int getTokenExp(int $tokenType = self::ACCESS_TOKEN)  获令牌有效期剩余时长.
 * @method static int|mixed|string getCurrentId()  获取当前用户登录ID
 * @method static array user(bool $cache = false)  获取会员信息
 * @method static mixed|string getExtendVal(string $val)  获取指定令牌扩展内容字段的值
 * @method static array getExtend()  获取所有字段
 * @method static logout($all = false)  退出
 *
 */
class JWT
{
    protected static $_instance = null;


    /**
     * @return JwtToken
     */
    public static function instance(): JwtToken
    {
        if (!static::$_instance) {
            static::$_instance = new JwtToken();
        }
        return static::$_instance;
    }

    /**
     * @param $name
     * @param $arguments
     * @return mixed
     */
    public static function __callStatic($name, $arguments)
    {
        return static::instance()->{$name}(... $arguments);
    }
}
