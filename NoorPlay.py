from time import time
from defusedxml.minidom import parseString
from requests import Session
from os import path
from json import loads, dumps
import atexit
from pywidevine.decrypt.wvdecrypt import WvDecrypt
from base64 import b64encode
from m3u8 import loads as m3U8_loads

class NoorPlay:
    SESSION_PATH = path.dirname(__file__) + path.sep + "session.txt"

    def __init__(self):
        self.session = Session()
        self.session_dict = {
            "status": {},
            "session_vars": {}
        }
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
            "origin": "https://www.noorplay.com",
            "referer": "https://www.noorplay.com/"
        })

        atexit.register(self.clean)

    def update_session_headers(self):
        print("[+] updating session.")
        self.session.headers.update({
            "authorization": f"Bearer {self.session_dict['session_vars']['session_key']}",
        })
        print("[+] session has been updated successfully.")
                
    def set_session(self, hash=None, token=None):
        print('[+] setting session.')
        
        hash = str(hash or '').strip()
        token = str(token or '').strip()
        login = False 
        
        if path.exists(self.SESSION_PATH) and not all([hash, token]):
            print('[+] reading session file.')
            with open(self.SESSION_PATH, 'r+') as reader:
                try:
                    self.session_dict = loads(reader.read().strip("\n"))
                            
                    try:
                        self.update_session_headers()
                        resp = self.session.get(f"https://vsms.mobiotics.com/prodv3/subscriberv2/v1/subscription", headers={
                            'x-session': self.session_dict['session_vars']['verify']['access_token']
                        })
                        if resp.status_code == 200:
                            if not all([hash, token]):
                                hash = self.session_dict['status']['hash']
                                token = self.session_dict['status']['token']
                            if time() - self.session_dict['session_vars']['verify']['expire_date'] < 3600:
                                print('[+] setting session done successfully.')
                            return True
                        elif resp.status_code == 400:
                            login = True    
                        print('[-] session expired.')
                    except Exception as e:
                        print(f"[+] an error occurred while setting up the session.\n\terror:{e}")
                        return None
                    
                   
                except:
                    print('[-] invalid session file given.')
                    
                    
        print('[+] trying to set a new session.')
        if not all([hash, token]):
            print("[-] can't set session using Null.")
            return False
        
        self.session_dict['status']['hash'] = hash
        self.session_dict['status']['token'] = token
        self.session_dict['session_vars']['session_key'] = self.get_session_key(hash, token)
        
        self.session_dict['session_vars']['verify'] = None
        if self.session_dict['session_vars'].get("session_key") is None:
            print("[-] Please change hash, token.")
            return False
        
        self.login() if login else ''
        
        print('[+] setting session done successfully.')
        return True

    def get_session_key(self, hash, token):
        print('[+] getting new session key.')
        hash = str(hash or '').strip()
        token = str(token or '').strip()

        if not all([hash, token]):
            print("[-] couldn't retrive session key using Null.")
            return None

        try:
            url = "https://vsms.mobiotics.com/prodv3/subscriberv2/v1/device/register/noorplay?hash="
            resp = self.session.post(url+hash, token, headers={
                                       'Content-Type': "text/plain;charset=UTF-8"})
            if resp.status_code == 200:
                resp = loads(resp.text)
                print('[+] session key has been retrived successfully.')
                return resp['success']
            else:
                print(f'[-] couldnot get session keys.\n\tresponse:{resp.text}')
        except Exception as e:
            print(f"[-] an error occurred while getting session keys.\n\terror: {e}")
        
        return None

    def clean(self):
        print('[+] saving session info to session file.')
        if self.session_dict['status'] and self.session_dict['session_vars']:
            with open(self.SESSION_PATH, 'w+') as writer:
                writer.write(dumps(self.session_dict))
        print('[+] session file has been created successfully.')

    def login(self, email=None, password=None):
        print('[+] trying to login to the website.')
        try:
            if self.session_dict['session_vars'].get("verify") is not None:
                self.session.headers.update({
                    'x-session': self.session_dict['session_vars']['verify']['access_token']
                })
                print("[+] logged in successfully using session file.")
                return True

            email = str(email or '').strip()
            password = str(password or '').strip()

            if not all([email, password]):
                try: 
                    email = self.session_dict['session_vars']['email']
                    password = self.session_dict['session_vars']['password']
                except:
                    print("[-] can't login to the requested server using Null.")
                    return False
            
            print(f"trying to login to the website using credentials -> email: {email}, password: {'*' * len(password)}.")
            
            resp = self.session.get(
                f"https://vsms.mobiotics.com/prodv3/subscriberv2/v1/login?email={email}&password={password}&devicetype=PC&deviceos=LINUX&country=PE")
            if resp.status_code == 200:
                resp = loads(resp.text)
                self.session_dict['session_vars']['verify'] = {
                    'access_token': resp['success'],
                    'logged': True,
                    'expire_date': time() + 3600
                }
                self.session.headers.update({
                    'x-session': resp['success'],
                })
                self.session_dict['session_vars']['email'] = email
                self.session_dict['session_vars']['password'] = password
                print("[+] logged in successfully.")
                return True
            else:
                print(
                    f"[-] invalid email or password.\n\tresponse: {resp.text}")
        except Exception as e:
            print(
                f'[-] an error occurred will authentication.\n\terror: {e}')

        return False

    def get_availability_set(self):
        availability_set = []
        print("[+] trying to get availability set.")
        try:
            resp = self.session.get("https://vsms.mobiotics.com/prodv3/subscriberv2/v1/subscription")
            if resp.status_code == 200:
                resp = loads(resp.text)
                print('[+] availability set has been retrived successfully.')
                for user in resp['data']:
                    availability_set += user['availabilityset']
            else:
                print(f"[-] couldn't retrive availability set.\n\tresponse: {resp.text}")
        except Exception as e:
            print(f"[-] an error occurred while retriving availability set.\n\terror: {e}")
        return availability_set
        
    def get_package_info_video(self, video_id):
        print('[+] getting package info.')
        if self.session_dict['session_vars']['verify'] is None:
            print("[-] Please login to get the requested package info.")
            return None

        video_id = str(video_id or '').strip()
        if not video_id:
            print("[-] couldn't retrive package info using Null.")
            return None

        try:
            resp = self.session.get(f"https://vcms.mobiotics.com/prodv3/subscriber/v1/content/{video_id}?displaylanguage=eng", headers={
                'Content-Type': 'application/x-www-form-urlencoded'
            })

            if resp.status_code == 200:
                resp = loads(resp.text)
                print('[+] package info has been retrived successfully.')
                content_details_selected = None
                
                for content in resp['contentdetails']:
                    if 'WIDEVINE' in content['drmscheme']:
                        if not content_details_selected:
                            content_details_selected = content
                        elif len(content_details_selected['subtitlelang']) < len(content['subtitlelang']):
                            content_details_selected = content   
                                         
                if content_details_selected is None:
                    print("[-] couldn't retrive WIDEVINE token.")
                else:
                    print('[+] package info has been retrived successfully.')
                    return {
                        'package_id': content_details_selected['packageid'],
                        'availability_id': content_details_selected['availabilityset'][0],
                        'foldername': resp['title'].replace(" ", "_").replace(" ", "_").replace(":", "").replace(path.sep, ""),
                        'filename': resp['title'].replace(" ", "_").replace(":", "").replace(path.sep, "")
                    }
            else:
                print(
                    f"[-] couldn't retrive package info of this video.\n\tresponse: {resp.text}")
                if "jwt" in resp.text:
                        self.set_session()
        except Exception as e:
            print(
                f"[-] an error occurred while getting package info.\n\terror: {e}")

        return None

    def get_package_info_series(self, series_id, season, episode):
        print('[+] getting package info.')
        if self.session_dict['session_vars']['verify'] is None:
            print("[-] Please login to get the requested package info.")
            return None

        series_id = str(series_id or '').strip()
        episode = str(episode or '').strip()
        season = str(season or '').strip()
        page = 1

        if not all([series_id, episode.isdigit(), season.isdigit()]):
            print("[-] couldn't retrive package info using Null.")
            return None

        while True:
            try:
                resp = self.session.get(f"https://vcms.mobiotics.com/prodv3/subscriber/v1/content?objecttype=CONTENT&seriesid={series_id}&seasonnum={season}&pagesize=100&page={page}&displaylanguage=eng", headers={
                    'Content-Type': 'application/x-www-form-urlencoded'
                })

                if resp.status_code == 200:
                    resp = loads(resp.text)
                    try:
                        episode_contents = resp['data'][int(episode)-1]
                        content_details = episode_contents['contentdetails']
                        content_details_selected = None
                        for content in content_details:
                            if 'WIDEVINE' in content['drmscheme']:
                                if not content_details_selected:
                                    content_details_selected = content
                                elif len(content_details_selected['subtitlelang']) < len(content['subtitlelang']):
                                    content_details_selected = content
                        print('[+] package info has been retrived successfully.')
                        return {
                            'package_id': content_details_selected['packageid'],
                            'availability_id': content_details_selected['availabilityset'][0],
                            'video_id': episode_contents['objectid'],
                            'foldername': episode_contents['seriesname'].replace(" ", "_").replace(":", "").replace(path.sep, ""),
                            'filename': episode_contents['poster'][0]['title'].replace(" ", "_").replace(":", "").replace(path.sep, "")
                        }
                    except Exception as e:
                        page += 1
                        continue
                else:
                    print(
                        f"[-] couldn't retrive package info of this video.\n\tresponse: {resp.text}")
                    if "jwt" in resp.text:
                        return False
                    break
            except Exception as e:
                print(
                    f"[-] an error occurred while getting package info.\n\terror: {e}")
                break

        return None
    
    def get_mpd_file(self, video_id, package_id, availability_id):
        print('[+] trying to get mpd file.')
        if self.session_dict['session_vars']['verify'] is None:
            print("[-] Please login to get the requested mpd file.")
            return None

        video_id = str(video_id or '').strip()
        package_id = str(package_id or '').strip()
        availability_id = str(availability_id or '').strip()
        
        if not all([video_id, package_id, availability_id]):
            print("[-] couldn't retrive mpd file url using Null.")
            return None
        
        try:
            resp = self.session.post(f"https://vcms.mobiotics.com/prodv3/subscriber/v1/content/package/{video_id}", {
                                    'availabilityid': availability_id,
                                    'packageid': package_id
                                    })
            if resp.status_code == 200:
                print('[+] mpd file url has been retrived successfully.')
                resp = loads(resp.text)
                return resp['streamfilename']
            else:
                print(f"[-] couldn't retrive mpd file url.\n\tresponse: {resp.text}")
                print(f"[+] trying get mpd file url using availability set.")
            availability_set = self.get_availability_set()
            for availability_id in availability_set:
                resp = self.session.post(f"https://vcms.mobiotics.com/prodv3/subscriber/v1/content/package/{video_id}", {
                                        'availabilityid': availability_id,
                                        'packageid': package_id
                                        })
                if resp.status_code == 200:
                    print('[+] mpd file url has been retrived successfully.')
                    resp = loads(resp.text)
                    return resp['streamfilename']
                else:
                    print(f"[-] couldn't retrive mpd file url using availability id: {availability_id}.\n\tresponse: {resp.text}")
            print("[-] couldn't retrive the mpd file of this video.")
        except Exception as e:
            print(
                f'[-] an error occurred while getting mpd file url.\n\terror: {e}')

        return None

    def mpd_file_reader(self, mpd_file_content, url):
        try:
            result = {
                'subtitle': {
                    'cenc': [],
                    'links': []},
                'audio': {'cenc': [],
                            'links': []},
                'video': {'cenc': [],
                            'links': []}
            }
            
            def get_content_protection(adaptive_set):
                result = {
                    'KID': None,
                    'SCHEMEIDURI': None,
                    'PSSH': None
                }

                try:
                    for content_protection in adaptive_set.getElementsByTagName('ContentProtection'):
                        if content_protection.hasAttribute('cenc:default_KID'):
                            result['KID'] = content_protection.getAttribute(
                                'cenc:default_KID').replace('-', "")
                        elif content_protection.hasAttribute('schemeIdUri'):
                            result['SCHEMEIDURI'] = content_protection.getAttribute(
                                'schemeIdUri')
                            result['PSSH'] = content_protection.childNodes[1].firstChild.nodeValue
                except:
                    return result

                return result

            def get_representation(adaptive_set, url):
                results = []
                try:
                    for representation in adaptive_set.getElementsByTagName('Representation'):
                        for base_url in representation.getElementsByTagName('BaseURL'):
                            results.append(url+base_url.firstChild.nodeValue)
                except:
                    return results
                return results

            xml_document = parseString(mpd_file_content)

            for adaptive_set in xml_document.getElementsByTagName('AdaptationSet'):
                content_type = adaptive_set.getAttribute(
                    'contentType').lower()
                if content_type == "text":
                    result['subtitle']['cenc'].append(get_content_protection(
                        adaptive_set))
                    result['subtitle']['links'].append(get_representation(
                        adaptive_set, url))
                elif content_type == 'audio':
                    result['audio']['cenc'].append(get_content_protection(
                        adaptive_set))
                    result['audio']['links'].append(get_representation(
                        adaptive_set, url))
                elif content_type == 'video':
                    result['video']['cenc'].append(get_content_protection(
                        adaptive_set))
                    result['video']['links'].append(get_representation(
                        adaptive_set, url))
        except:
            return None
        
        return result

    def m3u8_file_reader(self, m3u8_content, url):
        result = {
            'subtitle': {
                'cenc': [],
                'links': []},
            'audio': {'cenc': [],
                      'links': []},
            'video': {'cenc': [],
                      'links': []}
        }
        try:
            print(m3u8_content)
            content = m3U8_loads(m3u8_content)
            for video in content.playlists:
                print(video.uri)
        except:
            return None
        
        return result
            
    
    def get_mpd_file_content(self, mpd_file_url):
        result = None
        resp = None
        
        print(f'[+] reading {mpd_file_url} content.')
        if self.session_dict['session_vars']['verify'] is None:
            print("[-] Please login to get the requested mpd file content.")
            return None

        mpd_file_url = str(mpd_file_url or '').strip()

        if not mpd_file_url:
            print("[-] couldn't retrive content using Null.")
            return None
        
        try:
            
            url = mpd_file_url[:mpd_file_url.index("/", 10)+1]
            resp = self.session.get(mpd_file_url)
            file_type = path.splitext(mpd_file_url)[1] 
            if resp.status_code == 200:
                if file_type == ".mpd":
                    result = self.mpd_file_reader(resp.text, url)
                elif file_type == '.m3u8':
                    result = self.m3u8_file_reader(resp.text, url)
        except Exception as e:
            print(
                f'[-] an error occurred while getting mpd file content.\n\terror: {e}')
            
        if result:
            print('[+] mpd file content has been retrived successfully.')
        else:
            print(f"[-] couldn't retrive mpd file content.\n\tresponse:{resp.txt}")
        return result
    
    def get_drm_token(self, package_id, video_id, availability_id):
        print('[+] trying to get drm token.')
        if self.session_dict['session_vars']['verify'] is None:
            print("[-] Please login to get the requested mpd file content.")
            return None

        package_id = str(package_id or '').strip()
        video_id = str(video_id or '').strip()
        availability_id = str(availability_id or '').strip()

        if not all([package_id, video_id, availability_id]):
            print("[-] couldn't retrive drm token using Null.")
            return None

        try:
            resp = self.session.post('https://vcms.mobiotics.com/prodv3/subscriber/v1/content/drmtoken', {
                'contentid': video_id,
                'packageid': package_id,
                'availabilityid': availability_id,
                'drmscheme': 'WIDEVINE',
                'seclevel': "SW"
            })

            if resp.status_code == 200:
                resp = loads(resp.text)
                print('[+] drm token has been reterived successfully.')
                return resp['success']
            else:
                print(f"[-] couldn't retrive drm token.\n\tresponse: {resp.text}")
        except Exception as e:
            print(
                f'[-] an error occurred while getting drm token.\n\terror: {e}')

    def get_drm_keys(self, pssh, video_id, package_id, drm_token):
        print('[+] trying to retrive widevine keys.')
        
        if self.session_dict['session_vars']['verify'] is None:
            print("[-] Please login to get the requested mpd file content.")
            return None

        pssh = str(pssh or '').strip()
        video_id = str(video_id or '').strip()
        package_id = str(package_id or '').strip()
        drm_token = str(drm_token or '').strip()
        
        if not all([pssh, video_id, package_id, drm_token]):
            print("[-] can't retrive keys using Null.")
            return None
        
        try:
            license_url = "https://vdrm.mobiotics.com/prod/proxy/v1/license"
            decryptor = WvDecrypt(pssh)
            challenge = decryptor.get_challenge()
            
            request = b64encode(challenge)
            resp = self.session.post(license_url, json={
                'contentid': video_id,
                'customdata': {
                    'packageid': package_id,
                    'drmtoken': drm_token
                },
                'drmscheme': "WIDEVINE",
                'payload': request.decode(),
                'providerid': 'noorplay'
            }, allow_redirects=True, headers={
                'content-type': 'application/json',
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
                "x-session": self.session_dict['session_vars']['verify']['access_token'],
                'origin': 'https://www.noorplay.com',
                "referer": "https://www.noorplay.com/"
            })
            
            if resp.status_code == 200:
                resp = loads(resp.text)
                license = resp['body']                
                decryptor.update_license(license)
                keys = decryptor.start_process()
                if keys[0]:
                    print('[+] drm keys retrived successfully.')
                    return keys
                print(f'[-] unable to retrive the drm keys.\n\tresponse: {resp.text}')
            else:
                print(f"[-] couldn't obtain drm keys from the server.\n\tresponse:{resp.text}")
        except Exception as e:
            print(f"[-] an error occurred while extracting widevine keys.\n\terror: {e}")
            
        return None
    

