import asyncio, sys
import json
import random
import time
import requests

from curl_cffi.requests import AsyncSession

from web3 import AsyncWeb3
from loguru import logger
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <level>{message}</level>")

tokens = []
new_tokens = []
success_num = 0
success_code = []


def get_proxy():
    # 代理方法根据自己实际情况进行填写
    proxies = "http://user:123456@127.0.0.1:8888"
    return proxies


class Twitter:
    def __init__(self, auth_token):
        self.auth_token = auth_token
        bearer_token = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
        defaulf_headers = {
            "authority": "x.com",
            "origin": "https://x.com",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "authorization": bearer_token,
        }
        defaulf_cookies = {"auth_token": auth_token}
        self.Twitter = AsyncSession(headers=defaulf_headers, cookies=defaulf_cookies, timeout=120)
        self.auth_code = None

    async def get_auth_code(self, client_id, state, code_challenge):
        try:
            params = {
                'code_challenge': code_challenge,
                'code_challenge_method': 'plain',
                'client_id': client_id,
                'redirect_uri': 'https://app.jameswoof.com/login',
                'response_type': 'code',
                'scope': 'tweet.read tweet.write offline.access users.read follows.read follows.write',
                'state': state
            }
            response = await self.Twitter.get('https://twitter.com/i/api/2/oauth2/authorize', params=params)
            if "code" in response.json() and response.json()["code"] == 353:
                self.Twitter.headers.update({"x-csrf-token": response.cookies["ct0"]})
                return await self.get_auth_code(client_id, state, code_challenge)
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.get_auth_code(client_id, state, code_challenge)
            elif 'auth_code' in response.json():
                self.auth_code = response.json()['auth_code']
                return True
            logger.error(f'{self.auth_token} 获取auth_code失败')
            if self.auth_token in tokens:
                logger.success(f'{self.auth_token}  剔除Token')
                index = tokens.index(self.auth_token)
                del tokens[index]
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self, client_id, state, code_challenge):
        try:
            if not await self.get_auth_code(client_id, state, code_challenge):
                return False
            data = {
                'approval': 'true',
                'code': self.auth_code,
            }
            response = await self.Twitter.post('https://twitter.com/i/api/2/oauth2/authorize', data=data)
            if 'redirect_uri' in response.text:
                return True
            elif response.status_code == 429:
                await asyncio.sleep(5)
                return self.twitter_authorize(client_id, state, code_challenge)
            logger.error(f'{self.auth_token}  推特授权失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特授权异常：{e}')
            return False

    async def follow(self):
        try:
            data = {
                'include_profile_interstitial_type': 1,
                'include_blocking': 1,
                'include_blocked_by': 1,
                'include_followed_by': 1,
                'include_want_retweets': 1,
                'include_mute_edge': 1,
                'include_can_dm': 1,
                'include_can_media_tag': 1,
                'include_ext_is_blue_verified': 1,
                'include_ext_verified_type': 1,
                'include_ext_profile_image_shape': 1,
                'skip_status': 1,
                'user_id': 1747452081911504896
            }
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            res = await self.Twitter.post('https://x.com/i/api/1.1/friendships/create.json', data=data, headers=headers)
            if res.status_code == 200:
                return True
            logger.error(f'{self.auth_token}  推特关注失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特关注异常：{e}')
            return False


class Jwf:
    def __init__(self, auth_token, invite_code):
        RPC_list = [
            'https://arbitrum.llamarpc.com', 'https://arb1.arbitrum.io/rpc', 'https://rpc.ankr.com/arbitrum',
            'https://1rpc.io/arb', 'https://arb-pokt.nodies.app', 'https://arbitrum.blockpi.network/v1/rpc/public',
            'https://arbitrum-one.public.blastapi.io', 'https://arb-mainnet-public.unifra.io',
            'https://arbitrum-one-rpc.publicnode.com', 'https://arbitrum.meowrpc.com', 'https://arbitrum.drpc.org'
        ]
        self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(random.choice(RPC_list)))
        headers = {
            "Authorization": "Bearer 6bb61e3b7bce0931da574d19d1d82c88-e217f33bcdec2d2e829b035d4547cd97-65d24e754bd9530508177829bf96b62b",
            "Origin": "https://app.jameswoof.com",
            "Referer": "https://app.jameswoof.com/"
        }
        proxies = get_proxy()
        if proxies == "":
            return
        # self.client = AsyncSession(timeout=120, headers=headers, impersonate="chrome120", proxy=proxies)  有代理的配置
        self.client = AsyncSession(timeout=120, headers=headers, impersonate="chrome120")
        self.Twitter = Twitter(auth_token)
        self.auth_token, self.invite_code = auth_token, invite_code

    async def test_proxy(self):  # 测试代理的接口
        res = await self.client.post("http://ip-api.com/json/?lang=zh-CN")
        logger.info(res.json())

    def encode(self, info):
        encodeKey = self.client.headers.get('Authorization').split('-')[0].replace('Bearer ', '')[:16]
        key = encodeKey.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, key)
        padded_text = pad(info.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted).decode('utf-8')

    def decode(self, info):
        decodeKey = self.client.headers.get('Authorization').split('-')[2][:16]
        key = decodeKey.encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, key)
        decrypted = unpad(cipher.decrypt(binascii.unhexlify(info)), AES.block_size)
        return decrypted.decode('utf-8')

    async def get_auth_code(self):
        try:
            # await self.test_proxy()   #测试代理是否配置成功的入口
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.get(f'https://api.jameswoof.com/login/app/twitter_url?sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                clientId = resdata['clientId']
                state = resdata['url'].split('state=')[1].split('&')[0]
                code_challenge = resdata['url'].split('code_challenge=')[1].split('&')[0]
                if await self.Twitter.twitter_authorize(clientId, state, code_challenge):
                    logger.success(f'{self.auth_token}  推特授权成功')
                    return await self.login(uuid, clientId, state)
            logger.error(f'{self.auth_token}  推特授权失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  推特授权异常：{e}')
            return False

    async def login(self, uuid, clientId, state):
        try:
            info = {
                "state": state,
                "code": self.Twitter.auth_code,
                "clientId": clientId,
                "inviteCode": self.invite_code,
                "uuid": uuid
            }
            info = json.dumps(info, separators=(',', ':'))
            res = await self.client.post('https://api.jameswoof.com/login/app/sign_in',
                                         data=f'sign={self.encode(info)}')
            if len(res.text) > 200:
                resdata = json.loads(self.decode(res.text))
                if 'token' in resdata:
                    self.client.headers.update({"Authorization": f"Bearer {resdata['token']}"})
                    await self.pet_claim()
                    await self.wake()
                    return await self.check()
            logger.error(f'{self.auth_token}  登录失败')
            return False
        except Exception as e:
            logger.error(f'{self.auth_token}  登录异常：{e}')
            return False

    async def pet_claim(self):
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))
            pet_claim_post = await self.client.post("https://api.jameswoof.com/pet/claim",
                                                    data=f'sign={self.encode(info)}')
            if pet_claim_post.status_code == 200:
                logger.info("pet_claim success")
        except Exception as e:
            logger.error(f'{self.auth_token}  登检测积分异常：{e}')
            return False

    async def wake(self):
        try:
            uuid = int(time.time() * 1000)
            info = {
                "petId": 463089,
                "uuid": uuid
            }
            info = json.dumps(info, separators=(',', ':'))
            wake_post = await self.client.post("https://api.jameswoof.com/pet/wakeup", data=f'sign={self.encode(info)}')
            if wake_post.status_code == 200:
                logger.info("wake success")
        except Exception as e:
            logger.error(f'{self.auth_token}  登检测积分异常：{e}')
            return False

    async def check(self):
        global success_num
        try:
            uuid = int(time.time() * 1000)
            info = {"uuid": uuid}
            info = json.dumps(info, separators=(',', ':'))

            res = await self.client.get(f'https://api.jameswoof.com/account?sign={self.encode(info)}')
            resdata = json.loads(self.decode(res.text))
            # logger.info(resdata)
            score = resdata['coinList'][0]['quantity']
            logger.success(f'{self.auth_token}  积分 {score}')
            if self.auth_token in tokens:
                logger.success(f'{self.auth_token}  剔除Token')
                index = tokens.index(self.auth_token)
                del tokens[index]
                success_num += 1
                logger.success(f'邀请成功：{success_num}/{len(tokens)}')
                return True
        except Exception as e:
            logger.error(f'{self.auth_token}  登检测积分异常：{e}')
            return False


async def do(invite_code, auth_token):
    if await Jwf(auth_token, invite_code).get_auth_code():
        time.sleep(2)


async def main(invite_code):
    for account_line in tokens:
        await do(invite_code, account_line)


def run(invite_code):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main(invite_code))
    logger.success("下列token刷邀请失败，正在重新运行。")
    logger.success(f"剩余{len(tokens)}个账号")
    for j in tokens:
        print(j)


if __name__ == '__main__':
    _filePath = input("请输入文件路径：").strip()
    _invite_code = input("请输入大号邀请码：").strip()
    with open(_filePath, 'r') as f:
        for line in f:
            line = line.strip()
            tokens.append(line)
    while True:
        try:
            run(_invite_code)
            if len(tokens) == 0:
                logger.success(f"运行完成，共刷 {success_num} 个邀请")
                break
            time.sleep(5)
        except Exception as e:
            logger.error(f"运行异常：{e}")
            time.sleep(5)
        logger.success(f"本轮完成,已刷取{success_num}个邀请")
