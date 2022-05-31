<?php


declare(strict_types=1);

namespace Jzh\Jwt;


use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use support\Redis;

class RedisHandler
{


    /**
     * 生成缓存令牌
     * @param int  $id
     * @param      $guard
     * @param      $redis_pre
     * @param      $maxLimit
     * @param      $refresh_disable
     * @param      $access_token
     * @param      $access_token_expires
     * @param null $refresh_token
     * @param null $refresh_token_expires
     */
    public static function generateToken(int $id, $guard, $redis_pre, $maxLimit, $refresh_disable, $access_token, $access_token_expires, $refresh_token = null, $refresh_token_expires = null): void
    {
        $cacheKey    = $redis_pre . '_' . $guard . '_' . $id;
        $clientType  = request()->input('client_type', 'web');
        $defaultList = [
            'accessToken'     => $access_token,
            'accessExp'       => $access_token_expires,
            'clientType'      => $clientType,
            'accessTime'      => time(),
            'refresh_disable' => $refresh_disable
        ];
        if (!$refresh_disable) {
            $defaultList['refreshToken'] = $refresh_token;
            $defaultList['refreshExp']   = $refresh_token_expires;
            $defaultList['refreshTime']  = time();
        }
        $redisList = Redis::get($cacheKey);
        if ($redisList != null) {
            $tokenList = json_decode($redisList, true);

            if ($maxLimit === -1) {//不限制
                $tokenList[] = $defaultList;
                Redis::set($cacheKey, json_encode($tokenList));
            } elseif ($maxLimit === 0) {//只允许一个终端
                Redis::set($cacheKey, json_encode([$defaultList]));
            } elseif ($maxLimit > 0) {// 限制同一终端使用个数
                $clientTypeNum = 0;
                $index         = 0;
                foreach ($tokenList as $key => $value) {
                    if ($value['clientType'] == $clientType) {
                        $clientTypeNum++;
                        $index = $key;
                    }
                }

                if ($maxLimit <= $clientTypeNum) {
                    unset($tokenList[$index]);
                }
                $tokenList   = array_values($tokenList);
                $tokenList[] = $defaultList;
                Redis::set($cacheKey, json_encode($tokenList));
            }

            //清理过期token
            self::clearExpRedis($cacheKey);
        } else {

            Redis::set($cacheKey, json_encode([$defaultList]));
        }


    }

    /**
     * redis 验证token
     * @param int    $id
     * @param        $guard
     * @param        $redis_pre
     * @param string $token
     * @param int    $tokenType
     */
    public static function verifyToken(int $id, $guard, $redis_pre, string $token, int $tokenType = JwtToken::ACCESS_TOKEN)
    {
        $cacheKey = $redis_pre . '_' . $guard . '_' . $id;
        $list     = Redis::get($cacheKey);
        if ($list != null) {
            $tokenList  = json_decode($list, true);
            $checkToken = false;
            foreach ($tokenList as $key => $value) {
                if (!$value['refresh_disable'] && $tokenType == JwtToken::REFRESH_TOKEN && $value['refreshToken'] == $token) {
                    if (bcadd((string)$value['refreshTime'], (string)$value['refreshExp'], 0) < time()) {
                        unset($tokenList[$key]);
                    } else {
                        $checkToken = true;
                    }
                }
                if ($tokenType == JwtToken::ACCESS_TOKEN && $value['accessToken'] == $token) {
                    if (bcadd((string)$value['accessTime'], (string)$value['accessExp'], 0) < time()) {
                        unset($tokenList[$key]);
                    } else {
                        $checkToken = true;
                    }
                }
            }
            $tokenList = array_values($tokenList);
            if (count($tokenList) == 0) {
                Redis::del([$cacheKey]);
            } else {
                Redis::set($cacheKey, json_encode($tokenList));
            }
            if (!$checkToken) {
                if ($tokenType == JwtToken::ACCESS_TOKEN) {
                    throw new SignatureInvalidException('无效');
                } else {
                    throw new ExpiredException('无效');
                }
            }
        } else {
            if ($tokenType == JwtToken::ACCESS_TOKEN) {
                throw new SignatureInvalidException('无效');
            } else {
                throw new ExpiredException('无效');
            }
        }
    }

    /**
     * 清除过期的令牌
     * @param $cacheKey
     */
    public static function clearExpRedis($cacheKey)
    {
        $redisList = Redis::get($cacheKey);
        if ($redisList) {
            $redisList = json_decode($redisList, true);
            $refresh   = false;
            foreach ($redisList as $key => $value) {
                if (!$value['refresh_disable'] && ($value['refreshTime'] + $value['refreshExp']) < time()) {
                    unset($redisList[$key]);
                    $refresh = true;
                }
                if (($value['accessTime'] + $value['accessExp']) < time()) {
                    $redisList[$key]['accessToken'] = '';
                    $refresh                        = true;
                }
            }
            $redisList = array_values($redisList);
            if (count($redisList) == 0) {
                Redis::del([$cacheKey]);
            } else {
                if ($refresh) {
                    Redis::set($cacheKey, json_encode($redisList));
                }
            }
        }
    }

    /**
     * 刷新令牌后设置新token
     * @param int    $id
     * @param        $guard
     * @param        $redis_pre
     * @param string $refresh_token
     * @param string $access_token
     * @param        $expires_in
     */
    public static function setAccessToken(int $id, $guard, $redis_pre, string $refresh_token, string $access_token, $expires_in)
    {
        $cacheKey = $redis_pre . '_' . $guard . '_' . $id;
        $list     = Redis::get($cacheKey);
        if ($list != null) {
            $tokenList  = json_decode($list, true);
            $checkToken = false;
            foreach ($tokenList as $key => $value) {
                if (!$value['refresh_disable']) {
                    if ($value['refreshToken'] == $refresh_token) {
                        $tokenList[$key]['accessToken'] = $access_token;
                        $tokenList[$key]['accessExp']   = $expires_in;
                        $tokenList[$key]['accessTime']  = time();
                    }
                    if (bcadd((string)$value['refreshTime'], (string)$value['refreshExp'], 0) < time()) {
                        unset($tokenList[$key]);
                    } else {
                        $checkToken = true;
                    }
                }
            }
            $tokenList = array_values($tokenList);
            if (count($tokenList) == 0) {
                Redis::del([$cacheKey]);
            } else {
                Redis::set($cacheKey, json_encode($tokenList));
            }
            if (!$checkToken) {
                throw new ExpiredException('无效');
            }
        } else {
            throw new ExpiredException('无效');
        }
    }

    /**
     * 登出 清除token
     * @param       $token
     * @param       $redis_pre
     * @param       $guard
     * @param       $id
     * @param false $all
     */
    public static function logout($token, $redis_pre, $guard, $id, bool $all = false)
    {
        $cacheKey = $redis_pre . '_' . $guard . '_' . $id;
        if ($all) {
            Redis::del([$cacheKey]);
        } else {
            $list = Redis::get($cacheKey);
            if ($list) {
                $redisList = json_decode($list, true);
                foreach ($redisList as $key => $value) {
                    if ($value['accessToken'] == $token) {
                        unset($redisList[$key]);
                    }
                }
                $redisList = array_values($redisList);
                if (count($redisList) == 0) {
                    Redis::del([$cacheKey]);
                } else {
                    Redis::set($cacheKey, json_encode($redisList));
                }
            }
        }
    }
}
