<?php


namespace Jzh\Jwt\Adapter;


use Jzh\Jwt\Exception\JwtException;
use Jzh\Jwt\JwtToken;

interface JwtInterface
{
    /**
     * 退出登录
     * @param bool $all 是否清除所有缓存
     */
    public function logout(bool $all = false);

    /**
     * 生成令牌
     * @param array $extend 扩展内容
     * @return array
     */
    public function generateToken(array $extend): array;


    /**
     * 刷新令牌
     * @return array
     */
    public function refreshToken(): array;


    /**
     * 验证令牌
     * @param int         $tokenType token类型:
     * @param string|null $token token
     * @return array
     */
    public function verify(int $tokenType = JwtToken::ACCESS_TOKEN, string $token = null): array;


    /**
     * @desc: 获令牌有效期剩余时长.
     * @param int $tokenType token类型:
     * @return int
     */
    public function getTokenExp(int $tokenType = JwtToken::ACCESS_TOKEN): int;

    /**
     * 获取当前用户登录ID
     * @return int|mixed|string
     */
    public function getCurrentId();

    /**
     * 获取会员信息
     * @param false $cache 是否从数据库读取
     * @return array
     * @throws JwtException
     */
    public function user(bool $cache = false): array;

    /**
     * 获取指定令牌扩展内容字段的值
     * @param string $val
     * @return mixed|string
     */
    public function getExtendVal(string $val);

    /**
     * @desc 获取指定令牌扩展内容
     * @return array
     */
    public function getExtend(): array;
}
