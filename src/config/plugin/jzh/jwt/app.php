<?php

return [
    'enable' => true,
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
        ]
    ],
    'jwt'    => [
        // 算法类型 ES256、HS256、HS384、HS512、RS256、RS384、RS512
        'algorithms'          => 'HS256',
        // access令牌秘钥
        'access_secret_key'   => 'w5LgNx5luRRjmamZFSqz3cPHOp9KuQPExlvgi18DN4SdnSI9obcVEhiZVE0NIIC7',
        // access令牌过期时间，单位秒。默认 2 小时
        'access_exp'          => 7200,
        // refresh令牌秘钥
        'refresh_secret_key'  => 'w5LgNx5luRRjmamZFSqz3cPHOp9KuQPExlvgi18DN4SdnSI9obcVEhiZVE0NIIC7',
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
        'access_private_key'  => <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCpo7306MlR0720SISBfB/Qt1TfxrMJ+MCmplEK5+YGEeRetpCg
TPkhxZY4CylLZFvlpo1Gk1z1cZLDOZHgo9olXViRyC+376xZPF7ySwvzv/cU2Ux3
/BKOmRuDCxGhQYsCoiip8F40GhlJ+IgGCJWQXCMz8NbpO7jmRPGjCZDNGwIDAQAB
AoGAHnf9d06UUjEgwo+/1O3xXPCAuwyaPbFDEOuQZNAP/YkbJnPN+Cy7FnjBqWE/
0n29D7thZoqzSJZUkOH3NIzZck+1TqJK53rrmGAheGFSRNhLJF4b34dNxh+U/LNG
VKePD+9TtCYvzP8czxZ7N52qDgwsjwB/BXmkrxAIGVAQSoECQQDWR58aM9l1sWxb
HFh4exf5MQIdw6qzaydxaUc25xzTiovlZ5G1DkOjMgVUnMfQVPmeBzjSOAPvoj3Q
9xc2LkLBAkEAyqsdW86M5vWn4Nms9zKehVVLJHF5SatlNjMyA7qlL2T5WXsZGqAk
ryYd1bzfmF2QXYiLgXz9mPGa7ob3x/Qy2wJAbHPfkRGBFNJx90NHe+NBZPxrB8mK
0jh/xCT2yFD9BAxxdfCPjMXlcenVTNf1QfpgRJ1/Itb7FwRUqTkGZIPRgQJAWD7Z
sbfmMkqUppshbSFlVLkm1t9x6Fnw4AC6rlT+x/w3dnbbH3TLhFgcdYyf70AONCvY
UrGR2p6Yz3OFQFNcMQJAaSF+lLxgJkRb9Fy/XD6t/kjqudlsj2JBo5MPJiU2eUt4
yyGkqdE5V/6kLFiUlsNgzHfDxXo/DOVpCfJVzblZPA==
-----END RSA PRIVATE KEY-----
EOD,
        /**
         * access令牌 RS256 公钥
         * 生成RSA公钥(Linux系统)：openssl rsa -in access_private_key.key -pubout -out access_public_key.key
         */
        'access_public_key'   => <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCpo7306MlR0720SISBfB/Qt1Tf
xrMJ+MCmplEK5+YGEeRetpCgTPkhxZY4CylLZFvlpo1Gk1z1cZLDOZHgo9olXViR
yC+376xZPF7ySwvzv/cU2Ux3/BKOmRuDCxGhQYsCoiip8F40GhlJ+IgGCJWQXCMz
8NbpO7jmRPGjCZDNGwIDAQAB
-----END PUBLIC KEY-----
EOD,

        /**
         * refresh令牌 RS256 私钥
         * 生成RSA私钥(Linux系统)：openssl genrsa -out refresh_private_key.key 1024 (2048)
         */
        'refresh_private_key' => <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC9l3+FNVsGr9ILWF513Ub2y6Wzyt+zBRZLCaFceFfmkUwNnx5X
KOn2k7bT4z2j7SjjhpWT99VKCTiyMmC6r0kaayWpzA5nSRHudPsHIdgQQScnR/g8
HG1xWdqU0wg+b/vVdRXeqpxEW6Zdx3EB4VbMV7uunlcjJcamWec1Bwc8aQIDAQAB
AoGABCstmZ83tijthGRYB11rLwgBR7fBPW1yNQosKx1WSXKOaopCH4Z9xncvAO+x
LkaLrJ0L8unzHaKgRYLID7LE9673vA4DnkIGWFFBniXWCqsn8W4GR65W65zrOga8
9yaUWaRQnTWDkGJIb/RzJEbAN4NGVpAv8E/b0UtFL9yJgpECQQD7Tcn/tUSWoCs3
wor/VKdlNCMe+1ojC5CQLAqYfk42U5JMbGfed02tBcDfoO3eIsN3KJj9ZkYEtuDG
410ZPVudAkEAwSJ8LcLKpNXmIVclttIy0S5tKNyaF3oMKf+83c3/8I1lruxYwEgo
RmBCf94pWaIiMcoCK8cGvHx4GfJo8aGIPQJBANv5yMMb0jEjfREvKuq8GFd/Xurk
zI72tZFt68x2a1Ikr2BUWEulFQpKif126iDTP1ST5e+SUeIYjwOpzDmmuwUCQQCD
1oeQMVVlekIy5itvhkN8OcX4S8bAWebt0I5bluCsk8kixGG9OESN7e3XHY96iUvw
UuZyfdUiW5EcnTZ4I309AkBYhEVrEUMhMNYcbotxNGEI7f39q0KPLfXQ8AP4XLWk
gp1Z71kvPqnNP2bkG3xZQsU8ZoV96z0wHIwdbFdsOFev
-----END RSA PRIVATE KEY-----
EOD,
        /**
         * refresh令牌 RS256 公钥
         * 生成RSA公钥(Linux系统)：openssl rsa -in refresh_private_key.key -pubout -out refresh_public_key.key
         */
        'refresh_public_key'  => <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9l3+FNVsGr9ILWF513Ub2y6Wz
yt+zBRZLCaFceFfmkUwNnx5XKOn2k7bT4z2j7SjjhpWT99VKCTiyMmC6r0kaayWp
zA5nSRHudPsHIdgQQScnR/g8HG1xWdqU0wg+b/vVdRXeqpxEW6Zdx3EB4VbMV7uu
nlcjJcamWec1Bwc8aQIDAQAB
-----END PUBLIC KEY-----
EOD,
    ],
];
