from NoorPlay import NoorPlay
from getpass import getpass
from os import path, getcwd, mkdir, rename, scandir, unlink
import youtube_dl
from platform import system
from ffmpy import FFmpeg
from subprocess import Popen, PIPE

class Runner:
    DOWNLOADS_PATH = getcwd() + path.sep + "Downloads"
    MP4DECRYPTOR_PATH = path.dirname(__file__) + path.sep + "mp4Decrypt"
    def __init__(self):
        self.make_downloads_dir()
        self.get_decryptor_executable()
        self.player = NoorPlay()
        self.set_session()
        self.player.update_session_headers()
        self.login()
        mpd_dict = self.get_mpd_content()
        if mpd_dict and self.decryptor(mpd_dict) and self.merge(mpd_dict['foldername'], mpd_dict['filename'], mpd_dict['filename']+"_video_decrypted.mp4", mpd_dict['filename'] + "_audio_decrypted.mp4", mpd_dict['filename'] + "_subtitle.vtt"):
            self.clean(self.DOWNLOADS_PATH + path.sep + mpd_dict['foldername'])       
        
        
    def make_downloads_dir(self, dir=None):
        print("[+] trying to create downloads directory.")
        dir = self.DOWNLOADS_PATH + path.sep + dir if dir else dir
        if path.exists(self.DOWNLOADS_PATH):
            try:
                mkdir(dir) if dir and not path.exists(dir) else ''
                print("[+] downloads directory has been created successfully.")
                return True
            except Exception as e:
                print(f'[-] an error occurred while creating the directory.\n\terror: {e}')
        else:
            try:
                mkdir(self.DOWNLOADS_PATH)
                mkdir(dir) if dir and not path.exists(dir) else ''
                print("[+] downloads directory has been created successfully.")
                return True
            except Exception as e:
                print(f'[-] an error occurred while creating the directory.\n\terror: {e}')
        return False
                
    def set_session(self, update=False):
        session = self.player.set_session() if not update else None
        while not session:
            hash = input("-> Please enter hash from website: ").strip()
            token = input("-> Please enter the token from website: ").strip()
            if not all([hash, token]):
                print('[-] either auth url or token is empty.')
                continue
            session = self.player.set_session(hash, token)
    
    def login(self):
        logged = self.player.login()
        while not logged:
            email = input('-> Please enter email: ').strip()
            password = getpass('-> Please enter password: ').strip()
            if not all([email, password]):
                print('[-] either email or password is empty')
                continue
            logged = self.player.login(email, password)
            
    @staticmethod
    def calculate_index(array, i):
        sum = 0
        last_sum = 0
        for index, length in enumerate(array):
            sum += length
            if i <= sum:
                return index, i - last_sum - 1
            last_sum = sum
        return -1, -1
                
    def get_mpd_content(self):
        while True:
            type = ''
            while not type.isdigit() or not (0 <= int(type) <= 1):
                type = input("-> Please enter 0 for film or 1 for series: ").strip()
                
            if int(type) == 0:
                video_id = None
                while not video_id:
                    video_id = input("-> Please enter the required video id: ").strip()
                package_info = self.player.get_package_info_video(video_id)
                if package_info is False:
                    self.set_session(True)
                    continue
                if package_info is None:
                    continue
            else:
                series_id = None
                while not series_id:
                    series_id = None
                    while not series_id:
                        series_id = input("-> Please enter the required series id: ").strip()
                        
                    season = None
                    while not season or not season.isdigit():
                        season = input("-> Please enter season number: ").strip()
                    
                    episode = None
                    while not episode or not episode.isdigit():
                        episode = input("-> Please enter episode number: ")
                
                    package_info = self.player.get_package_info_series(series_id, season, episode)
                    if package_info is False:
                        self.set_session(True)
                        series_id = None
                        continue
                  
                    if package_info is None:
                        series_id = None
                        return None
                    video_id = package_info['video_id']

            mpd_file_url = self.player.get_mpd_file(video_id, package_info['package_id'], package_info['availability_id'])
            if mpd_file_url is None:
                video_id = None
                series_id = None
                continue
            break
                
        mpd_file_contents = self.player.get_mpd_file_content(mpd_file_url)
        
        if mpd_file_contents is None:
            print(f"[-] unable to read the required file.\n\tfile: {mpd_file_url}")
            return None
        
        selected = {
            'subtitle': None,
            'audio': None,
            'video': None,
            'pssh': None,
            'video_id': video_id,
            'foldername': package_info['foldername'],
            'filename': package_info['filename']
        }
        
        links = []
        
        drm_token = self.player.get_drm_token(package_info['package_id'], video_id, package_info['availability_id'])
        if not drm_token:
            return None
                
        for name, content in mpd_file_contents.items():
            print(f'[+] {name.capitalize()}:')
            id = 0
            sub_arrays_length = [0]
            if content['links']:
                for link_list in content['links']:
                    for link in link_list:
                        id += 1
                        print(f"    [{id}] -> {link.split(name.upper() + '_')[-1].replace('enc_', '')}")
                    sub_arrays_length.append(id - sub_arrays_length[-1])
                sub_arrays_length = sub_arrays_length[1:]
                    
                selection = None
                    
                while not selection or not selection.isdigit() or int(selection) > id:
                    selection = input("-> Please choose the required file to download: ")
                
                index, sub_index = Runner.calculate_index(sub_arrays_length, int(selection))

                selected[name] = [content['cenc'][index]['KID'], content['links'][index][sub_index]]
                selected['pssh'] = content['cenc'][index]['PSSH']
                links.append(selected[name][1])
            else:
                print(f'[+] No {name} found in this file.')
            
        keys = self.player.get_drm_keys(selected['pssh'], video_id, package_info['package_id'], drm_token)[1]

        if keys is None or not keys[0]:
            print("[-] couldn't get the drm_keys from the website please change the blob file.")
            return None
        
        for key in keys:
            for name in list(selected.keys())[:-4]:
                if selected[name] and str(selected[name][0]) in key:
                    selected[name][0] = f"{key}"
                
        if self.make_downloads_dir(package_info['foldername']):  
            file_path = f"{self.DOWNLOADS_PATH}{path.sep}{package_info['foldername']}"
            
            downloader = youtube_dl.YoutubeDL({'no_warnings': True, 'force_generic_extractor': True, 'fixup': 'never', 'outtmpl': f"{file_path}{path.sep}%(title)s.%(ext)s"})
            downloader.download(links)
            
            try:
                for file in scandir(file_path):
                    file_name = file.name.lower()
                    if "audio" in file_name:
                        name = f"audio"
                    elif 'video' in file_name:
                        name = f"video"
                    else:
                        name = f"subtitle"
                    name = f"{name}.{file_name.split('.')[-1]}"
                    try:
                        rename(file.path, file.path.replace(file.name, f"{package_info['filename']}_{name}"))
                    except:
                        pass
            except Exception as e:
                print(f'[-] an error occurred while reading.\n\terror:{file_path}')
            
        else:
            print("[-] the requested files cannot be downloaded.\n\terror: unable to create downloads folder.")
        
        return selected
    
    def decryptor(self, mpd_dict):
        folder = self.DOWNLOADS_PATH + path.sep + mpd_dict['foldername']
        try:
            if not path.exists(folder):
                print(f"[-] unable to find the required media directory {folder}.")
                return False
            for filename, media_file_info in list(mpd_dict.items())[:-4]:
                if not media_file_info or media_file_info[0] is None:
                    continue
                print(f"[+] trying to decrypt {mpd_dict['filename']}_{filename}.")
                process = Popen(f"{self.MP4DECRYPTOR_PATH} {folder}{path.sep}{mpd_dict['filename']}_{filename}.mp4 {folder}{path.sep}{mpd_dict['filename']}_{filename}_decrypted.mp4 --key {media_file_info[0]} --show-progress".split(), stdout=PIPE, stderr=PIPE)
                output, error = process.communicate()
                if not error:
                    print(f"[+] {filename} file has been decrypted successfully.")
                else:
                    print(f"[-] failed to decrypt {filename}.\n\terror: {process.stderr.read()}")
        except Exception as e:
            print(f"[-] an error occurred while trying to decrypt the media.\n\terror: {e}")
            return False
        return True
        
    def merge(self, output_dir, output_filename, video_file, audio_file, subtitles_file):
        print("[+] trying to merge media files")
        output_folder = f'{self.DOWNLOADS_PATH}{path.sep}{output_dir}{path.sep}'
        if not path.exists(output_folder):
            print('[-] couldn\'t find the required files.')
            return False
        inputs = {}
        outputs = []
        if video_file and path.exists(output_folder + video_file):
            video_file = output_folder + video_file
            inputs.update({video_file: None})
            outputs += ['-c:v', 'copy']
        
        if audio_file and path.exists(output_folder + audio_file):
            audio_file = output_folder + audio_file
            inputs.update({audio_file: None})
            outputs += ['-c:a', 'copy']
        
        if subtitles_file and path.exists(output_folder + subtitles_file):
            subtitles_file = output_folder + subtitles_file
            inputs.update({subtitles_file: None})
            outputs += ['-c:s', 'mov_text']
            
        try:
            if outputs.__len__() >= 2:
                ffmpeg = FFmpeg(
                global_options=['-loglevel', 'quiet'],
                outputs={f'{output_folder}{output_filename}.mp4': outputs},
                inputs=inputs)
                ffmpeg.run()
                print('[+] media file has been merged successfully.')
                return True
            else:
                print('[-] unable to merge this mpd media file.')
        except Exception as e:
            print(f'[-] an error occurred while merging media files.')
        return False
        
    def clean(self, output_dir):
        print("[+] trying to clean resources.")
        try:
            for file in scandir(output_dir):
                if 'audio' in file.name.lower() or 'video' in file.name.lower():
                    unlink(file.path)
            print("[+] resources has been clean successfully.")
        except Exception as e:
            print(f"[-] an error occurred while cleaning resources.\n\terror: {e}")
                
                
    def get_decryptor_executable(self):
        print("[+] Setting up decrytor path.")
        os = system().replace("Darwin", "Mac")
        if os == "Windows":
            executable = "mp4decrypt_win.exe"
        elif os == "Linux":
            executable = "mp4decrypt_linux"
        elif os == "Mac":
            executable = "mp4decrypt_mac"
        
        self.MP4DECRYPTOR_PATH += path.sep + executable
        
        if not path.exists(self.MP4DECRYPTOR_PATH):
            print("[-] There's no decryptor exists. script will exit.")
            exit(0)
        print("[+] decryptor path has been updated successfully.")

        
if __name__ == "__main__":
    runner = Runner()
    
# hash = "https://vsms.mobiotics.com/prodv3/subscriberv2/v1/device/register/noorplay?hash=c909e75f8a1405988c73e9ebcba907b71dd30881"
# token = "G/ZDNyFXQmSbbDX6lXOh4u+1/42h+NoNbMdRehgmc9o8cbVno9hNoarQYBpea3Z3q4fsXkmo3NR/z0Jw0+zDYW5DhV7o7CO2CGjFs8pwQTrDk5OmbyjQuW8KZCfsk2kO"
# username = "as1185442@gmail.com"
# password = "Th3@Professional"
# video_id = "6ZPoBmSSpck5"

# player = NoorPlay(hash, token)
# player.login(username, password)
# package_info = player.get_package_info(video_id)
# mpd_file_url = player.get_mpd_file(
#     video_id, package_info['package_id'], package_info['availability_id'])
# mpd_file_contents = player.get_mpd_file_content(mpd_file_url)
# drm_token = player.get_drm_token(
#     package_info['package_id'], video_id, package_info['availability_id'])

# print(mpd_file_contents)
# print(player.get_drm_keys(mpd_file_contents['video']['cenc']
#                     ['PSSH'], video_id, package_info['package_id'], drm_token))
