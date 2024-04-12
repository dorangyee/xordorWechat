<?php

namespace Xordor\Wechat;

use support\Cache;
use support\Log;

enum CacheKey: string
{
    case wxAccessToken = 'WX:ACCESS_TOKEN';
    case wxSessionKey = 'WX:SESSION_KEY:';
}

enum WxErrorEnum: int
{
    case CacheError = 10000;
    case WxLoginError = 20000;
    case WxNoAppIdOrSecret = 20001;
    case WxCanNotFindSessionKey = 20002;
    case WxCanNotFindAccessToken = 20003;
    case WxCanNotFindPhoneNumber = 20004;
    case WxMsgSecCheckError = 20005;
    case OK = 0;
    case IllegalAesKey = -41001;
    case IllegalIv = -41002;
    case IllegalBuffer = -41003;
    case DecodeBase64Error = -41004;
}

class WechatService
{
    /**
     * code换session
     *
     * @param string $jscode
     * @return array
     */
    public static function code2Session(string $jscode): array
    {
        $response = (new \GuzzleHttp\Client())->request('GET', 'https://api.weixin.qq.com/sns/jscode2session', [
            'query' => [
                'appid' => config('plugin.xordor.wechat.env.wx.appId'),
                'secret' => config('plugin.xordor.wechat.env.wx.appSecret'),
                'js_code' => $jscode,
                'grant_type' => 'authorization_code'
            ]
        ]);

        $res = json_decode($response->getBody(), true);

        if (isset($res['errcode']) && $res['errcode'] != 0) {
            Log::error($response->getBody());
            throw new \Exception(WxErrorEnum::WxLoginError->name, WxErrorEnum::WxLoginError->value);
        }

        // 保存sessionKey
        self::saveSessionKey($res['openid'], $res['session_key']);

        return $res;
    }

    /**
     * 请求签名
     *
     * @param array $data
     * @param string $sessionKey
     * @return string
     */
    private static function signature(array $data, string $openid): string
    {
        $sessionKey = self::getSessionKey($openid);
        $s = empty($data) ? "" : json_encode($data);
        return hash_hmac('sha256', $s, $sessionKey);
    }

    /**
     * 请求签名后的数据
     *
     * @param array $data
     * @param string $openid
     * @return array
     */
    private static function sign(array &$data, string $openid): array
    {
        $data['signature'] = self::signature($data, $openid);
        $data['sig_method'] = 'hmac_sha256';
        $data['access_token'] = self::getAccessToken();
        $data['openid'] = $openid;
        // 水印
        $data['watermark'] = [
            'appid' => config('plugin.xordor.wechat.env.wx.appId'),
            'timestamp' => time()
        ];
        return $data;
    }

    /**
     * 读取sessionKey
     *
     * @param string $openid
     * @return string
     */
    public static function getSessionKey(string $openid): string
    {
        if (Cache::has(CacheKey::wxSessionKey->value . $openid)) {
            return Cache::get(CacheKey::wxSessionKey->value . $openid);
        }

        throw new \Exception(WxErrorEnum::WxCanNotFindSessionKey->name, WxErrorEnum::WxCanNotFindSessionKey->value);
    }

    /**
     * 保存sessionKey
     *
     * @param string $openid
     * @param string $sessionKey
     * @return void
     */
    public static function saveSessionKey(string $openid, string $sessionKey): void
    {
        if (Cache::set(CacheKey::wxSessionKey->value . $openid, $sessionKey, 7100) !== true) {
            Log::error("微信session_key保存异常");
            throw new \Exception(WxErrorEnum::CacheError->name, WxErrorEnum::CacheError->value);
        }
    }

    /**
     * 检查签名:true有效false无效
     *
     * @param string $accessToken
     * @param string $openid
     * @return bool
     */
    public static function checkSessionKey(string $openid): bool
    {
        $data = [];

        self::sign($data, $openid);

        $response = (new \GuzzleHttp\Client())->request('GET', 'https://api.weixin.qq.com/wxa/checksession', [
            'queyr' => $data
        ]);

        $res = json_decode($response->getBody(), true);

        if (isset($res['errcode']) && $res['errcode'] != 0) {
            Log::error($response->getBody());
            return false;
        }

        return true;
    }

    /**
     * 微信登陆时，先验证openid是否合法
     */
    public static function checkOpenid(string $openid): bool
    {
        if (Cache::has(CacheKey::wxSessionKey->value . $openid)) {
            return true;
        }

        return false;
    }

    /**
     * 获取微信accessToken
     *
     * @return string
     */
    public static function getAccessToken(): string
    {
        if (Cache::has(CacheKey::wxAccessToken)) {
            return Cache::get(CacheKey::wxAccessToken);
        }

        $response = (new \GuzzleHttp\Client())->request('GET', 'https://api.weixin.qq.com/cgi-bin/token', [
            'query' => [
                'appid' => config('plugin.xordor.wechat.env.wx.appId'),
                'secret' => config('plugin.xordor.wechat.env.wx.appSecret'),
                'grant_type' => 'client_credential'
            ]
        ]);

        $res = json_decode($response->getBody(), true);

        if (isset($res['errcode']) && $res['errcode'] != 0) {
            Log::error($response->getBody());
            throw new \Exception(WxErrorEnum::WxCanNotFindAccessToken->name, WxErrorEnum::WxCanNotFindAccessToken->value);
        }

        // 保存
        Cache::set(CacheKey::wxAccessToken, $res['access_token'], 7100);

        return $res['access_token'];
    }

    /**
     * 获取手机号
     *
     * @param string $code 前端获取到的微信code
     * @return array 手机号相关信息
     */
    public static function getPhoneNumber(string $code): array
    {
        $data = [
            'code' => $code
        ];

        $response = (new \GuzzleHttp\Client())->request('POST', 'https://api.weixin.qq.com/wxa/business/getuserphonenumber?access_token=' . self::getAccessToken(), [
            'form_params' => $data
        ]);

        $res = json_decode($response->getBody(), true);

        if ($res['errcode'] != 0) {
            Log::error($response->getBody());
            throw new \Exception(WxErrorEnum::WxCanNotFindPhoneNumber->name, WxErrorEnum::WxCanNotFindPhoneNumber->value);
        }

        return $res['phone_info'];
    }

    /**
     * 验证消息推送的签名信息
     *
     * @param string $signature
     * @param string $timestamp
     * @param string $nonce
     * @return boolean
     */
    public static function checkSignature(string $signature, string $timestamp, string $nonce): bool
    {
        $tmpArr = array(config('plugin.xordor.wechat.env.wx.apiSecret'), $timestamp, $nonce);
        sort($tmpArr, SORT_STRING);
        $tmpStr = implode($tmpArr);
        $tmpStr = sha1($tmpStr);

        if ($tmpStr == $signature) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 文本安全检查
     *
     * @param string $openid
     * @param string $content
     * @param integer $scene
     * @return boolean
     */
    public static function msgSecCheck(string $openid, string $content, string $title = '', int $scene = 4): bool
    {
        $data = [
            // 'access_token' => $this->getAccessToken(),
            'content' => $content,
            'version' => 2,
            'scene' => $scene,
            'openid' => $openid,
            'title' => $title,
        ];

        Log::error($data);

        $response = (new \GuzzleHttp\Client())->request('POST', 'https://api.weixin.qq.com/wxa/msg_sec_check?access_token=' . self::getAccessToken(), [
            'form_params' => $data
        ]);

        $res = json_decode($response->getBody(), true);

        Log::error($response);

        if ($res['errcode'] != 0) {
            Log::error($response->getBody());
            throw new \Exception(WxErrorEnum::WxMsgSecCheckError->name, WxErrorEnum::WxMsgSecCheckError->value);
            // return false;
        }

        if ($res['result']['suggest'] == 'pass') {
            return true;
        }

        return false;
    }

    /**
     * 异步检查多媒体文件
     *
     * @param string $openid
     * @param string $mediaUrl
     * @param integer $mediaType
     * @param integer $scene
     * @return string
     */
    public static function mediaCheckAsync(string $openid, string $mediaUrl, int $mediaType = 2, int $scene = 4): string
    {
        $data = [
            // 'access_token' => $this->getAccessToken(),
            'media_url' => $mediaUrl,
            'media_type' => $mediaType,
            'version' => 2,
            'scene' => $scene,
            'openid' => $openid
        ];

        $response = (new \GuzzleHttp\Client())->request('POST', 'https://api.weixin.qq.com/wxa/media_check_async?access_token=' . self::getAccessToken(), [
            'form_params' => $data
        ]);

        $res = json_decode($response->getBody(), true);

        Log::error($response);

        if ($res['errcode'] != 0) {
            Log::error($response->getBody());
            throw new \Exception(WxErrorEnum::WxMsgSecCheckError->name, WxErrorEnum::WxMsgSecCheckError->value);
        }

        Log::error($res);

        return $res['trace_id'];
    }

    /**
     * 检验数据的真实性，并且获取解密后的明文
     *
     * @param string $encryptedData
     * @param string $iv
     * @param string $data
     * @param string $openid
     * @return integer
     */
    private function decryptData(string $encryptedData, string $iv, string &$data, string $openid): int
    {
        $sessionKey = $this->getSessionKey($openid);

        if (strlen($sessionKey) != 24) {
            return WxErrorEnum::IllegalAesKey->value;
        }
        $aesKey = base64_decode($sessionKey);


        if (strlen($iv) != 24) {
            return WxErrorEnum::IllegalIv->value;
        }
        $aesIV = base64_decode($iv);

        $aesCipher = base64_decode($encryptedData);

        $result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);

        $dataObj = json_decode($result);
        if ($dataObj  == NULL) {
            return WxErrorEnum::IllegalBuffer->value;
        }
        if ($dataObj->watermark->appid != config('plugin.xordor.wechat.env.wx.appId')) {
            return WxErrorEnum::IllegalBuffer->value;
        }
        $data = $result;
        return WxErrorEnum::OK->value;
    }
}
