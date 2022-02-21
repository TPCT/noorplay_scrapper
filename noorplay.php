<?php
ini_set("display_errors", true);
session_start();
$username = "as1185442@gmail.com";
$password = "A0118017795a";
$auth_url = "https://vsms.mobiotics.com/prodv3/subscriberv2/v1/device/register/noorplay?hash=2cac4c2b48c46697c95e25c57875f7cc8f80f6b6";
$token = "lsuH+ivrqFLTidIuEn6/lpfbHoazcw80XTJAbdzqe448cbVno9hNoarQYBpea3Z3q4fsXkmo3NR/z0Jw0+zDYW5DhV7o7CO2CGjFs8pwQTrDk5OmbyjQuW8KZCfsk2kO";
$video_id = "6ZPoBmSSpck5";

if (!isset($_SESSION['logged']) || time() > $_SESSION['expire_time'])
    __set_session();
else
    echo "logged in successfully <br/>";

extract(__get_package_info($video_id));
$mpd_url = __get_mpd_file($video_id, $package_id, $availability_id);
var_dump(__get_drm_token($package_id, $video_id, $availability_id));

function __set_session(){
    global $username, $password;
    $access_token = __login($username, $password);
    if ($access_token){
        $_SESSION['logged'] = True;
        $_SESSION['access_token'] = $access_token;
        $_SESSION['expire_time'] = strtotime("+1 hour");
        echo "logged in successfully </br>";
    }else{
        session_destroy();
        echo 'Please change ($auth_url, $token) using the noorplay <br/>';
        exit(0);
    }
}

function __get_access_token($auth_url, $token)
{
    $handler = curl_init($auth_url);
    curl_setopt($handler, CURLOPT_POST, true);
    curl_setopt($handler, CURLOPT_POSTFIELDS, $token);
    curl_setopt($handler, CURLOPT_HTTPHEADER, [
        'Content-Type: text/plain;charset=UTF-8',
    ]);
    curl_setopt($handler, CURLOPT_RETURNTRANSFER, true);
    $resp = curl_exec($handler);
    try {
        return json_decode($resp)->success;
    } catch (Exception $e) {
    }
    return null;
}

function __login(String $email, String $password)
{
    global $auth_url, $token;
    $access_token = __get_access_token($auth_url, $token);
    $email = urlencode($email);
    $password = urlencode($password);
    $login_url = "https://vsms.mobiotics.com/prodv3/subscriberv2/v1/login?email={$email}&password={$password}&devicetype=PC&deviceos=LINUX&country=EG";
    $handler = curl_init($login_url);
    curl_setopt($handler, CURLOPT_RETURNTRANSFER, True);
    curl_setopt($handler, CURLOPT_HTTPHEADER, [
        "authorization: Bearer {$access_token}",
        'user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36'
    ]);
    $content = curl_exec($handler);
    $status_code = curl_getinfo($handler, CURLINFO_HTTP_CODE);
    if ($status_code == 200)
        return json_decode($content)->success;
    else
        return Null;
}

function __get_package_info($video_id){
    $package_url = "https://vcms.mobiotics.com/prodv3/subscriber/v1/content/{$video_id}?displaylanguage=eng";
    $handler = curl_init($package_url);
    curl_setopt($handler, CURLOPT_HTTPHEADER, [
        "x-session: {$_SESSION['access_token']}",
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
    ]);
    curl_setopt($handler, CURLOPT_RETURNTRANSFER, true);
    $content = curl_exec($handler);
    $status_code = curl_getinfo($handler, CURLINFO_HTTP_CODE);
    if ($status_code == 200){
        $data = json_decode($content, true);
        return [
            'package_id' => $data['contentdetails'][0]['packageid'],
            'availability_id' => $data['contentdetails'][0]['availabilityset'][0]
        ];
    }
    else
        return Null;
}

function __get_mpd_file($video_id, $package_id, $availability_id){
    $object_url = "https://vcms.mobiotics.com/prodv3/subscriber/v1/content/package/{$video_id}";
    $handler = curl_init($object_url);
    curl_setopt($handler, CURLOPT_POST, true);
    curl_setopt($handler, CURLOPT_HTTPHEADER, [
        "x-session: {$_SESSION['access_token']}",
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
    ]);
    curl_setopt($handler, CURLOPT_POSTFIELDS, http_build_query([
        'availabilityid' => $availability_id,
        'packageid' => $package_id
    ]));
    curl_setopt($handler, CURLOPT_RETURNTRANSFER, true);
    $content = curl_exec($handler);
    $status_code = curl_getinfo($handler, CURLINFO_HTTP_CODE);
    if ($status_code == 200){
        return json_decode($content)->streamfilename;
    }
    return Null;
}

function __get_encrypted_videos($mpd_url){
    $audio_files = [];
    $video_files = [];
    $handler = curl_init($mpd_url);
    curl_setopt($handler, CURLOPT_HTTPHEADER, [
        "x-session: {$_SESSION['access_token']}",
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
    ]);

    curl_setopt($handler, CURLOPT_RETURNTRANSFER, true);
    $content = curl_exec($handler);
    $status_code = curl_getinfo($handler, CURLINFO_HTTP_CODE);
    
    $re = '/(\.net\/)(.*\.mpd)/isu';
    $mpd_url = preg_replace($re, "$1", $mpd_url);

    if ($status_code == 200){
        $xml_documet = new DOMDocument();
        $xml_documet->loadXML($content);
        foreach($xml_documet->getElementsByTagName("AdaptationSet") as $adaptive_set){
                if ($adaptive_set->getAttribute('contentType') == 'audio'){
                    foreach($adaptive_set->getElementsByTagName("ContentProtection") as $content_protection){
                        if ($kid = $content_protection->getAttribute('cenc:default_KID')){
                            $audio_files['KID'] = $kid;
                        }

                        if ($schemeUri = $content_protection->getAttribute('schemeIdUri')){
                            $audio_files['schemeIdUri'] = @end(explode(":", $schemeUri));
                            $audio_files['PSSH'] = $content_protection->textContent;
                        }
                    }
                    $audio_files['links'] = [];

                    foreach($adaptive_set->getElementsByTagName('Representation') as $representation){
                        $audio_files['links'][] = [
                            'type' => $representation->getAttribute('mimeType'),
                            'url' => $mpd_url . $representation->getElementsByTagName('BaseURL')->item(0)->textContent
                        ];
                    }
                }elseif ($adaptive_set->getAttribute('contentType') == 'video'){
                    foreach($adaptive_set->getElementsByTagName("ContentProtection") as $content_protection){
                        if ($kid = $content_protection->getAttribute('cenc:default_KID')){
                            $video_files['KID'] = $kid;
                        }

                        if ($schemeUri = $content_protection->getAttribute('schemeIdUri')){
                            $video_files['schemeIdUri'] = $schemeUri;
                            $video_files['PSSH'] = $content_protection->textContent;
                        }
                    }
                    $video_files['links'] = [];

                    foreach($adaptive_set->getElementsByTagName('Representation') as $representation){
                        $video_files['links'][] = [
                            'type' => $representation->getAttribute('mimeType'),
                            'url' => $mpd_url . $representation->getElementsByTagName('BaseURL')->item(0)->textContent
                        ];
                    }
                }
        }
    }
    return[
        'audio' => $audio_files,
        'video' => $video_files
    ];
}

function __get_drm_token($package_id, $content_id, $availability_id){
    $drm_token_url = "https://vcms.mobiotics.com/prodv3/subscriber/v1/content/drmtoken";
    $handler = curl_init($drm_token_url);
    curl_setopt($handler, CURLOPT_POST, true);
    curl_setopt($handler, CURLOPT_RETURNTRANSFER, true);

    curl_setopt($handler, CURLOPT_HTTPHEADER, [
        "x-session: {$_SESSION['access_token']}",
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36"
    ]);

    curl_setopt($handler, CURLOPT_POSTFIELDS, http_build_query([
        "contentid" => $content_id,
        "packageid" => $package_id,
        "drmscheme" => "WIDEVINE",
        "availabilityid" => $availability_id,
        "seclevel" => "SW"
    ]));

    $content = curl_exec($handler);

    $status_code = curl_getinfo($handler, CURLINFO_HTTP_CODE);
    if ($status_code == 200){
        return json_decode($content)->success;
    }
    return Null;
}

function __get_widevine($content_id, $package_id, $drm_token){

}
