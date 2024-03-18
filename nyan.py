import asyncio
import sys
import time
from datetime import datetime
import base58
import httpx
from loguru import logger
from urllib.parse import urlparse, parse_qs
from solathon import Keypair

g_success, g_fail = 0, 0

logger.remove()
logger.add(sys.stdout, colorize=True,
           format="<w>{time:HH:mm:ss:SSS}</w> | <r>{extra[fail]}</r>-<g>{extra[success]}</g> | <level>{message}</level>")
logger = logger.patch(lambda record: record["extra"].update(fail=g_fail, success=g_success))


proxies = {
    'http://': 'http://127.0.0.1:7890',
    'https://': 'http://127.0.0.1:7890',
}


class Nyan:
    def __init__(self, auth_token, referral):
        self.http = httpx.AsyncClient(proxies=proxies, verify=False)
        self.http.headers = {
            'Accept-Language': 'en-US,en;q=0.8',
            'Authority': 'twitter.com',
            'Origin': 'https://twitter.com',
            'Referer': 'https://twitter.com/',
            'Sec-Ch-Ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/'
        }

        self.Twitter = httpx.AsyncClient(proxies=proxies, verify=False)
        self.Twitter.headers = {
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept': 'application/json, text/plain, */*',
            'Origin': 'https://missions.nyanheroes.com',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0'
        }
        self.Twitter.cookies.update({'auth_token': auth_token})
        self.oauth_token, self.authenticity_token, self.oauth_verifier, self.token = None, None, None, None
        self.referral = referral
        self.auth_token = auth_token

    async def get_twitter(self):
        try:
            response = await self.http.get(
                'https://api.nyanheroes.com/Login/Authorize?callbackUrl=https://missions.nyanheroes.com/')
            if 'oauth_token' in response.text:
                parsed_url = urlparse(response.text)
                query_params = parse_qs(parsed_url.query)
                self.oauth_token = query_params.get('oauth_token', [None])[0]
                return True
            logger.error(f'{self.auth_token} 获取oauth_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def get_twitter_token(self):
        try:
            if not await self.get_twitter():
                return False
            response = await self.Twitter.get(f'https://api.twitter.com/oauth/authorize?oauth_token={self.oauth_token}')
            if 'authenticity_token' in response.text:
                self.authenticity_token = response.text.split('authenticity_token" value="')[1].split('"')[0]
                return True
            logger.error(f'{self.auth_token} 获取authenticity_token失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_authorize(self):
        try:
            if not await self.get_twitter_token():
                return False
            data = {
                'authenticity_token': self.authenticity_token,
                'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={self.oauth_token}',
                'oauth_token': self.oauth_token
            }
            response = await self.Twitter.post('https://api.twitter.com/oauth/authorize', data=data)
            if 'oauth_verifier' in response.text:
                self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
                return True
            logger.error(f'{self.auth_token} 获取oauth_verifier失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def twitter_login(self):
        try:
            if not await self.twitter_authorize():
                return False
            data = {
                'oauthToken': self.oauth_token,
                'callbackUrl': 'https://missions.nyanheroes.com/',
                'oauthVerifier': self.oauth_verifier
            }
            response = await self.http.get(f'https://api.nyanheroes.com/Login/Authorize', params=data)
            if response.json()['user']['twitterUsername'] is not None:
                self.token = response.json()['token']
                self.http.headers['Authorization'] = 'Bearer ' + self.token
                return True
            logger.error(f'{self.auth_token} 登录失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def set_referral(self):
        try:
            response = await self.http.post('https://api.nyanheroes.com/User/addReferral?referralCode=' + self.referral)
            if response.json()['result']:
                return True
            logger.error(f'{self.auth_token} 设置邀请人失败')
            return False
        except Exception as e:
            logger.error(e)
            return False

    async def compete_task(self,sol_wallet):
        try:
            task_id = [5, 6, 7, 8, 3, 31, 1, 4, 32, 65, 2]
            for i in task_id:
                time.sleep(1)
                try:
                    if i != 2:
                        response = await self.http.post('https://api.nyanheroes.com/Quest/setQuest', json={'Id': i})
                        if not response.json()['result']:
                            logger.error(f'{self.auth_token} 完成任务{i}失败')
                            continue
                    else:
                        now = datetime.utcnow()
                        iso_format_time = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:23] + 'Z'
                        message = f'Please sign in to prove the ownership : {str(sol_wallet.public_key)} , Timestamp: {iso_format_time}'
                        signature = sol_wallet.sign(message)[:64]
                        signature = base58.b58encode(signature).decode('utf-8')
                        data = {
                            'QuestId': 2,
                            'WalletAddress': str(sol_wallet.public_key),
                            'Signature':signature,
                            'Message':message,
                        }
                        response = await self.http.post('https://api.nyanheroes.com/Quest/verifyMessage', json=data)
                        if not response.json()['result']:
                            logger.error(f'{self.auth_token} 完成任务{i}失败')
                            continue
                except Exception as e:
                    logger.error(e)
                    continue
            return True
        except Exception as e:
            logger.error(e)
            return False


async def main(referral_code, file_name,task=False):
    global g_fail, g_success
    with open(file_name, 'r', encoding='UTF-8') as f, open('nyan-success.txt', 'a') as s, open('nyan-error.txt',
                                                                                               'a') as e:  # eth----auth_token
        lines = f.readlines()
        for k, v in enumerate(lines):
            try:
                auth_token = v.strip()
                mini = Nyan(auth_token, referral_code)
                if await mini.twitter_login() and await mini.set_referral():
                    sol_private = ''
                    if task:
                        sol_wallet = Keypair()
                        sol_private = str(sol_wallet.private_key)
                        await mini.compete_task(sol_wallet)
                    g_success += 1
                    logger.success(f'{auth_token} 成功')
                    s.write(f'{auth_token}----{sol_private}\n')
                else:
                    g_fail += 1
                    logger.error(f'{auth_token} 失败')
                    e.write(f'{auth_token}----{sol_private}\n')
            except Exception as ex:
                g_fail += 1
                logger.error(f'{auth_token} 失败')
                e.write(f'{auth_token}----{auth_token}\n')
                continue


if __name__ == '__main__':
    rel_code = '' #替换为你的邀请码
    file_name = 'tw_token.txt'
    asyncio.run(main(rel_code, file_name,task=True))
