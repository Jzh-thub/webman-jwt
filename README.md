# webman JWT 插件


## 安装

```php
composer require jzh/jwt
```

## 配置文件
```php
// guard 角色配置
// jwt jwt参数配置

// 配置示例（根据自己真实情况 user一定要存在 因为默认就是user）
    'guard'  => [
        'user' => [
            'key'   => 'uid',    //对应表主键
            'limit' => 1,       //-1为不限制终端数量 0为只支持一个终端在线 大于0为同一账号同终端支持数量 建议设置为1 则同一账号同终端在线1个
            'model' => function ($uid) {
                // ThinkORM
                return \think\facade\Db::table('core_user')
                    ->field('uid,account,create_time')
                    ->where('uid', $uid)
                    ->find();

                // LaravelORM
                // return \support\Db::table('resty_user')
                //    ->where('id', $uid)
                //    ->select('id','email','mobile','create_time')
                //    ->first();
            }
        ],
        'admin'=>[
            'key'   => 'id',    //对应表主键
            'limit' => -1,       //-1为不限制终端数量 0为只支持一个终端在线 大于0为同一账号同终端支持数量 建议设置为1 则同一账号同终端在线1个
            'model' => function ($id) {
                // ThinkORM
                return \think\facade\Db::table('admin')
                    ->field('id,account,create_time')
                    ->where('id', $id)
                    ->find();

                // LaravelORM
                // return \support\Db::table('resty_user')
                //    ->where('id', $uid)
                //    ->select('id','email','mobile','create_time')
                //    ->first();
            }
        ]       
    ],
    'jwt'    => [
        // 算法类型 ES256、HS256、HS384、HS512、RS256、RS384、RS512
        'algorithms'          => 'HS256',
        // access令牌秘钥
        'access_secret_key'   => '',
        // access令牌过期时间，单位秒。默认 2 小时
        'access_exp'          => 7200,
        // refresh令牌秘钥
        'refresh_secret_key'  => '',
        // refresh令牌过期时间，单位秒。默认 7 天
        'refresh_exp'         => 604800,
        // refresh 令牌是否禁用,默认不禁用
        'refresh_disable'     => false,
        // 缓存令牌前缀
        'redis_pre'           => 'JZH:JWT:TOKEN:',
        // 令牌签发者
        'iss'                 => 'webman',
        /**
         * access令牌 RS256 私钥
         * 生成RSA私钥(Linux系统)：openssl genrsa -out access_private_key.key 1024 (2048)
         */
        'access_private_key'  => '',
        /**
         * access令牌 RS256 公钥
         * 生成RSA公钥(Linux系统)：openssl rsa -in access_private_key.key -pubout -out access_public_key.key
         */
        'access_public_key'   => '',

        /**
         * refresh令牌 RS256 私钥
         * 生成RSA私钥(Linux系统)：openssl genrsa -out refresh_private_key.key 1024 (2048)
         */
        'refresh_private_key' => '',
        /**
         * refresh令牌 RS256 公钥
         * 生成RSA公钥(Linux系统)：openssl rsa -in refresh_private_key.key -pubout -out refresh_public_key.key
         */
        'refresh_public_key'  => '',
    ]
```
## 异常类

> 失败，抛出`JwtException`异常


## 使用

## 指定角色
```php
$guard = 'admin'; // 默认user 
\Jzh\Jwt\Facade\JWT::guard('admin');
```

## 生成令牌

```php
$user = [
    'id'  => id, // 这里必须是一个全局抽象唯一id
    'xx'  => 'xx',
    'xx1' => 'xx1'
];
$token = \Jzh\Jwt\Facade\JWT::generateToken($user);
var_dump(json_encode($token));

// guard 指定 角色;比如 user 用户,admin 用户
$token = \Jzh\Jwt\Facade\JWT::guard('admin')->generateToken($user);
```
**输出（json格式）**
```json
{
    "token_type": "Bearer",
    "expires_in": 36000,
    "access_token": "eyJ0eXAiOiJAUR-Gqtnk9LUPO8IDrLK7tjCwQZ7CI...",
    "refresh_expires_in":78000,
    "refresh_token": "eyJ0eXAiOiJIEGkKprvcccccQvsTJaOyNy8yweZc...",
}
```

**响应参数**

| 参数|类型|描述示|例值|
|:---|:---|:---|:---|
|token_type | string| Token 类型 | Bearer |
|expires_in | int| Token凭证有效时间，单位：秒 | 36000 |
|access_token | string| 访问凭证 | webman |
|refresh_expires_in | int| 刷新Token凭证有效时间，单位：秒 | 720000 |
|refresh_token | string| 刷新访问凭证 | webman |

### 退出登录
```php
$all = false; //false 退出当前用户;true 退出所有当前用户终端;默认 false
\Jzh\Jwt\Facade\JWT::logout($all);
\Jzh\Jwt\Facade\JWT::guard('admin')->logout(); //管理员退出
```

### 支持函数列表

> 1、获取当前`uid`
```php
// 获取user用户
$uid = \Jzh\Jwt\Facade\JWT::getCurrentId();

// 获取admin用户
$uid = \Jzh\Jwt\Facade\JWT::guard('admin')->getCurrentId();
```

> 2、获取获取会员信息
```php
$cache = false; //false 获取缓存中的数据  true 获取数据库中的数据
$userInfo = \Jzh\Jwt\Facade\JWT::user($cache);

// 获取admin用户
$userInfo = \Jzh\Jwt\Facade\JWT::guard('admin')->user($cache);
```

> 3、获取指定令牌扩展内容

```php
$info = \Jzh\Jwt\Facade\JWT::getExtend();

// 获取admin用户
$info = \Jzh\Jwt\Facade\JWT::guard('admin')->getExtend();
```

> 4、获取自定义字段

```php
$uid = \Jzh\Jwt\Facade\JWT::getExtendVal('uid');

// 获取admin用户
$uid = \Jzh\Jwt\Facade\JWT::guard('admin')->getExtendVal('uid');
```

> 4、刷新令牌（通过刷新令牌获取访问令牌）

```php
$info = \Jzh\Jwt\Facade\JWT::refreshToken();
{
    "expires_in": 36000,
    "access_token": "eyJ0eXAiOiJAUR-Gqtnk9LUPO8IDrLK7tjCwQZ7CI...",
}

// 获取admin用户
$info = \Jzh\Jwt\Facade\JWT::guard('admin')->refreshToken();
```

> 5、获令牌有效期剩余时长

```php
$exp = \Jzh\Jwt\Facade\JWT::getTokenExp();

// 获取admin用户
$exp = \Jzh\Jwt\Facade\JWT::guard('admin')->getTokenExp();
```

> 6、验证令牌

```php
// 返回 jwt 解密的信息
$info = \Jzh\Jwt\Facade\JWT::verify();

// 获取admin用户
$info = \Jzh\Jwt\Facade\JWT::guard('admin')->verify();
```


