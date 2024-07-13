import requests , random , uuid , secrets , json , re , string , socks , socket , urllib.request , urllib.parse , hashlib
from hashlib import md5
from time import time
from urllib.parse import urlencode
import urllib.request
import urllib.parse
from user_agent import generate_user_agent
from secrets import token_hex
from curl2pyreqs.ulti import parseCurlString 
r = requests.Session()
#L7N
# All Instagram methods
class Instagram:
	@staticmethod
	def CheckEmail(email):
		Choice = random.choice("1234")
		if Choice == "1":
		      files=[
        
  ]
		      headers = {
  }
		      data = {
            'enc_password': '#PWD_INSTAGRAM_BROWSER:0:'+str(time()).split('.')[0]+':maybe-jay-z',
            'optIntoOneTap': 'false',
            'queryParams': '{}',
            'trustedDeviceRecords': '{}',
            'username': email,
        }
		      try:
		          response = requests.post('https://www.instagram.com/api/v1/web/accounts/login/ajax/', headers=headers, data=data,files=files)
		      except Exception as e:
		          return e
		      try:		          
		          csrf= md5(str(time()).encode()).hexdigest()
		          mid=response.cookies["mid"]
		          ig_did=response.cookies["ig_did"]
		          ig_nrcb=response.cookies["ig_nrcb"]
		          app=''.join(random.choice('1234567890')for i in range(15))
		      except:
		          csrf = "9y3N5kLqzialQA7z96AMiyAKLMBWpqVj"
		          mid = "ZVfGvgABAAGoQqa7AY3mgoYBV1nP"
		          ig_did = ""
		          ig_nrcb = ""
		      headers = {
  'User-Agent': "Mozilla/5.0 (Linux; U; Android 12; ar-ae; SM-M317F Build/SP1A.210812.016) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36 PHX/15.8",
  'content-type': "application/x-www-form-urlencoded;charset=UTF-8",
  'x-csrftoken': csrf,
  'x-ig-app-id': app,
  'Cookie': f"csrftoken={csrf}; mid={mid}; ig_did={ig_did}; ig_nrcb={ig_nrcb};"}
		      try:
		          response2 = requests.post('https://www.instagram.com/api/v1/web/accounts/login/ajax/', headers=headers, data=data,files=files)
		      except:
		          return False
		      if 'showAccountRecoveryModal' in response2.text:
		          return True
		      else:
		          return False
	
		elif Choice == "2":
		    csrf = md5(str(time()).encode()).hexdigest()
		    url = 'https://b.i.instagram.com/api/v1/accounts/login/'
		    headers = {
'User-Agent': "Instagram 136.0.0.34.124 Android (24/7.0; 640dpi; 1440x2560; HUAWEI; LON-L29; HWLON; hi3660; en_US; 208061712)",
"Content-Type": "application/x-www-form-urlencoded",
"X-CSRFToken": str(csrf),
        }
		    data = {
'username': email,
'password': "Topython",
'device_id': f"android-{secrets.token_hex(8)}",
'_csrftoken' : csrf,
'phone_id': str(uuid.uuid4()),
'guid': str(uuid.uuid4()),

        }
		    try:
		        response = requests.post(url, headers=headers, data=data).text
		        if '"message":"The password you entered is incorrect. Please try again."' in response:
		            return True
		        elif '"error_type":"invalid_user"' in response:
		            return 
		        else:
		            return False		            
		    except Exception as e:
		        return e
		elif Choice == "3":
		    rnd=str(random.randint(150, 999))
		    user_agent = "Instagram 311.0.0.32.118 Android (" + ["23/6.0", "24/7.0", "25/7.1.1", "26/8.0", "27/8.1", "28/9.0"][random.randint(0, 5)] + "; " + str(random.randint(100, 1300)) + "dpi; " + str(random.randint(200, 2000)) + "x" + str(random.randint(200, 2000)) + "; " + ["SAMSUNG", "HUAWEI", "LGE/lge", "HTC", "ASUS", "ZTE", "ONEPLUS", "XIAOMI", "OPPO", "VIVO", "SONY", "REALME"][random.randint(0, 11)] + "; SM-T" + rnd + "; SM-T" + rnd + "; qcom; en_US; 545986"+str(random.randint(111,999))+")"
		    url = 'https://www.instagram.com/api/v1/web/accounts/check_email/'
		    head= {	
			 'Host': 'www.instagram.com',
			 'origin': 'https://www.instagram.com',
			 'referer': 'https://www.instagram.com/accounts/signup/email/',	
			 'sec-ch-ua-full-version-list': '"Android WebView";v="119.0.6045.163", "Chromium";v="119.0.6045.163", "Not?A_Brand";v="24.0.0.0"',
			 'user-agent': user_agent}
		    data = {
		'email':email
		}
		    try:
		        response = requests.post(url,headers=head,data=data)
		        if 'email_is_taken' in response.text:
		            return True
		        else:
		         return False
		    except Exception as e:
		     return e
		elif Choice == "4":
		    try:
		        responses = requests.get('https://www.instagram.com/api/graphql')
		        mid = responses.cookies.get_dict().get('mid')
		    except:
		        mid  = "Zo8bBAAEAAF27Fed1oBbtK7tGgwj"
		    url='https://i.instagram.com/api/v1/accounts/create/'
		    headers={'Host': 'i.instagram.com',
'cookie': f'mid={mid}',
'x-ig-capabilities': 'AQ==',
'cookie2': '$Version=1',
'x-ig-connection-type': 'WIFI',
'user-agent': "Instagram 136.0.0.34.124 Android (24/7.0; 640dpi; 1440x2560; HUAWEI; LON-L29; HWLON; hi3660; en_US; 208061712)",
'content-type': 'application/x-www-form-urlencoded',
'content-length': '159',}
		    data={
'password':'Topython',
'device_id':str(uuid.uuid4()),
'guid':str(uuid.uuid4()),
'email': email,
'username':'topython8786969_586',}
		    try:
		        response = requests.post(url,headers=headers,data=data)
		        if "Another account is using the same email" in response.text:
		            return True
		        else:
		            return False
		    except Exception as e:
		        return e
		
	@staticmethod
	def CheckUsers(username):
	   try:
	       files=[
        
  ]
	       headers = {
  }
	       data = {
            'enc_password': '#PWD_INSTAGRAM_BROWSER:0:'+str(time()).split('.')[0]+':maybe-jay-z',
            'optIntoOneTap': 'false',
            'queryParams': '{}',
            'trustedDeviceRecords': '{}',
            'username': username,
        }
	       response = requests.post('https://www.instagram.com/api/v1/web/accounts/login/ajax/', headers=headers, data=data,files=files)
	       try:
		          csrf=response.cookies["csrftoken"]
		          mid=response.cookies["mid"]
		          ig_did=response.cookies["ig_did"]
		          ig_nrcb=response.cookies["ig_nrcb"]
	       except:
		          csrf = "9y3N5kLqzialQA7z96AMiyAKLMBWpqVj"
		          mid = "ZVfGvgABAAGoQqa7AY3mgoYBV1nP"
		          ig_did = ""
		          ig_nrcb = ""
	       url = "https://www.instagram.com/accounts/web_create_ajax/attempt/"
	       headers = {
        'Host': 'www.instagram.com',
        'content-length': '85',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="101"',
        'x-ig-app-id': '936619743392459',
        'x-ig-www-claim': '0',
        'sec-ch-ua-mobile': '?0',
        'x-instagram-ajax': '81f3a3c9dfe2',
        'content-type': 'application/x-www-form-urlencoded',
        'accept': '/',
        'x-requested-with': 'XMLHttpRequest',
        'x-asbd-id': '198387',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.40 Safari/537.36',
        'x-csrftoken': 'jzhjt4G11O37lW1aDFyFmy1K0yIEN9Qv',
        'sec-ch-ua-platform': '"Linux"',
        'origin': 'https://www.instagram.com',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.instagram.com/accounts/emailsignup/',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-IQ,en;q=0.9',
        'cookie': 'csrftoken=jzhjt4G11O37lW1aDFyFmy1K0yIEN9Qv; mid=YtsQ1gABAAEszHB5wT9VqccwQIUL; ig_did=227CCCC2-3675-4A04-8DA5-BA3195B46425; ig_nrcb=1'
    }
	       data = f'email=l7ntopython%40gmail.com&username={username}&first_name=&opt_into_one_tap=false'
	       response = requests.post(url=url, headers=headers, data=data)	       
	       
	       if '{"message":"feedback_required","spam":true,"feedback_title":"Try Again Later","feedback_message":"We limit how often you can do certain things on Instagram to protect our community. Tell us if you think we made a mistake.","feedback_url":"repute/report_problem/scraping/","feedback_appeal_label":"Tell us","feedback_ignore_label":"OK","feedback_action":"report_problem","status":"fail"}' in response.text:
	           return False
	       elif '"errors": {"username":' in response.text or '"code": "username_is_taken"' in response.text:
	           return False
	       elif response.status_code == 200:
	           return True
	       elif response.status_code == 429:
	           return "ban"  
	   except:
	       return None         

	@staticmethod
	def information(username):	    
		    try:
		        info=requests.get('https://anonyig.com/api/ig/userInfoByUsername/'+username).json()
		    except :
		        info = False
		    try:
		        Id =info['result']['user']['pk_id']
		    except :
		        Id = None
		        
		    try:
		        followers = info['result']['user']['follower_count']
		    except :
		        followers = None
		    try:
		        following = info['result']['user']['following_count']
		    except :
		        following = None
		    try:
		        post = info['result']['user']['media_count']
		    except :
		        post = None
		    try:
		        name = info['result']['user']['full_name']
		    except :
		        name = None
		    try:
		        is_verified = info['result']['user']["is_verified"]
		    except:
		        is_verified = None
		    try:
		         is_private= info['result']['user']['is_private']
		    except:
		        is_private = None
		    try:
		        biography = info['result']['user']['biography']
		    except:
		        biography = None
		    try:
		        
		        if int(Id) >1 and int(Id)<1279000:
		            date =  "2010"
		        elif int(Id)>1279001 and int(Id)<17750000:
		            date =  "2011"
		        elif int(Id) > 17750001 and int(Id)<279760000:
		            date =  "2012"
		        elif int(Id)>279760001 and int(Id)<900990000:
		            date =  "2013"
		        elif int(Id)>900990001 and int(Id)< 1629010000:
		            date =  "2014"
		        elif int(Id)>1900000000 and int(Id)<2500000000:
		            date =  "2015"
		        elif int(Id)>2500000000 and int(Id)<3713668786:
		            date =  "2016"
		        elif int(Id)>3713668786 and int(Id)<5699785217:
		            date =  "2017"
		        elif int(Id)>5699785217 and int(Id)<8507940634:
		            date =  "2018"
		        elif int(Id)>8507940634 and int(Id)<21254029834:
		            date =  "2019"	         
		        else:
		            return "2020-2023"
		    except :
		        return None
		    return {
		    "name" : name ,
		    "username" : username ,
		    "followers" : followers , 
		    "following" : following ,
		    "date" : date ,
		    "id" : Id ,
		    "post" : post , 
		    "bio" : biography , 
		    "is_verified" : is_verified , 
		    'is_private' : is_private , 		    
		    }	    

	@staticmethod
	def sessionid(username,password):
	    url = 'https://www.instagram.com/accounts/login/ajax/'
	    data = {'username': f'{username}',
        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1589682409:{password}',
        'queryParams': '{}',
        'optIntoOneTap': 'false'}
	    headers = {'accept': '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'content-length': '275',
    'content-type': 'application/x-www-form-urlencoded',
    'cookie': 'csrftoken=DqBQgbH1p7xEAaettRA0nmApvVJTi1mR; ig_did=C3F0FA00-E82D-41C4-99E9-19345C41EEF2; mid=X8DW0gALAAEmlgpqxmIc4sSTEXE3; ig_nrcb=1',
    'origin': 'https://www.instagram.com',
    'referer': 'https://www.instagram.com/',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36',
    'x-csrftoken': 'DqBQgbH1p7xEAaettRA0nmApvVJTi1mR',
    'x-ig-app-id': '936619743392459',
    'x-ig-www-claim': '0',
    'x-instagram-ajax': 'bc3d5af829ea',
    'x-requested-with': 'XMLHttpRequest'}  
	    try:
	        response = requests.post(url,headers=headers,data=data)
	        if 'authenticated":true' in response.text or 'userId' in response.text:
	            try:
	                sessionid = response.cookies['sessionid']
	            except:
	                sessionid = None
	            return {
	            'sessionid': sessionid,
	            'BY': '@g_4_q'
	            }
	    except:
	        False	            
	@staticmethod
	def Rests(username):
	    try:
	        headers = {
    'X-Pigeon-Session-Id': '50cc6861-7036-43b4-802e-fb4282799c60',
    'X-Pigeon-Rawclienttime': '1700251574.982',
    'X-IG-Connection-Speed': '-1kbps',
    'X-IG-Bandwidth-Speed-KBPS': '-1.000',
    'X-IG-Bandwidth-TotalBytes-B': '0',
    'X-IG-Bandwidth-TotalTime-MS': '0',
    'X-Bloks-Version-Id': '009f03b18280bb343b0862d663f31ac80c5fb30dfae9e273e43c63f13a9f31c0',
    'X-IG-Connection-Type': 'WIFI',
    'X-IG-Capabilities': '3brTvw==',
    'X-IG-App-ID': '567067343352427',
    'User-Agent': 'Instagram 100.0.0.17.129 Android (29/10; 420dpi; 1080x2129; samsung; SM-M205F; m20lte; exynos7904; en_GB; 161478664)',
    'Accept-Language': 'en-GB, en-US',
     'Cookie': 'mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Accept-Encoding': 'gzip, deflate',
    'Host': 'i.instagram.com',
    'X-FB-HTTP-Engine': 'Liger',
    'Connection': 'keep-alive',
    'Content-Length': '356',
}
	        data = {
    'signed_body': '0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.{"_csrftoken":"9y3N5kLqzialQA7z96AMiyAKLMBWpqVj","adid":"0dfaf820-2748-4634-9365-c3d8c8011256","guid":"1f784431-2663-4db9-b624-86bd9ce1d084","device_id":"android-b93ddb37e983481c","query":"'+username+'"}',
    'ig_sig_key_version': '4',
}	
	        try:
	            response = requests.post('https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/',headers=headers,data=data)
	            return response.json()['email']
	        except :
	            rest = False
	            return rest
	    except :
	        return False	    

	@staticmethod
	def GenUsers(date):
	       if date == 2010:
	           iD = str(random.randrange(1,1279000)) 	           	  
	       elif date == 2011:
	           iD = str(random.randrange(1279001, 17750000))   
	       elif date == 2012:
	           iD = str(random.randrange(17750000, 279760000)) 
	       elif date == 2013:
	           iD = str(random.randrange(279760000, 900990000))
	       elif date == 2014:
	           iD = str(random.randrange(900990000, 1629010000))   
	       elif date == 2015:
	           iD = str(random.randrange(1629010000, 2500000000))
	       elif date == 2016:
	           iD = str(random.randrange(2500000000,3713668786))
	       elif date == 2017:
	           iD = str(random.randrange(3713668786, 5699785217))
	       elif date == 2018:
	           iD = str(random.randrange(5699785217, 8507940634))
	       elif date == 2019:
	           iD = str(random.randrange(8507940634, 21254029834))
	       elif date == 2020 or 2021 or 2022 or 2023 or 2024:
	           iD = str(random.randrange(21254029834, 21954029834))
	       else:
	           return None   
	       rnd=str(random.randint(150, 999))
	       user_agent = "Instagram 311.0.0.32.118 Android (" + ["23/6.0", "24/7.0", "25/7.1.1", "26/8.0", "27/8.1", "28/9.0"][random.randint(0, 5)] + "; " + str(random.randint(100, 1300)) + "dpi; " + str(random.randint(200, 2000)) + "x" + str(random.randint(200, 2000)) + "; " + ["SAMSUNG", "HUAWEI", "LGE/lge", "HTC", "ASUS", "ZTE", "ONEPLUS", "XIAOMI", "OPPO", "VIVO", "SONY", "REALME"][random.randint(0, 11)] + "; SM-T" + rnd + "; SM-T" + rnd + "; qcom; en_US; 545986"+str(random.randint(111,999))+")"
	       lsd=''.join(random.choice('azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN1234567890') for _ in range(32))
	       headers = {
    'accept': '*/*',
    'accept-language': 'en,en-US;q=0.9',
    'content-type': 'application/x-www-form-urlencoded',
    'dnt': '1',
    'origin': 'https://www.instagram.com',
    'priority': 'u=1, i',
    'referer': 'https://www.instagram.com/cristiano/following/',
    'user-agent': user_agent,
    'x-fb-friendly-name': 'PolarisUserHoverCardContentV2Query',
    'x-fb-lsd': lsd,
}
	       data = {
    'lsd': lsd,
    'fb_api_caller_class': 'RelayModern',
    'fb_api_req_friendly_name': 'PolarisUserHoverCardContentV2Query',
    'variables': '{"userID":"'+str(iD)+'","username":"cristiano"}',
    'server_timestamps': 'true',
    'doc_id': '7717269488336001',
}
	       try:
	           response = requests.post('https://www.instagram.com/api/graphql', headers=headers, data=data)
	           username =response.json()['data']['user']['username'] 
	           return username
	       except :
	           try:             
	               variables = json.dumps({"id": iD, "render_surface": "PROFILE"})
	               data = {"lsd": lsd, "variables": variables, "doc_id": "25618261841150840"}
	               response = requests.post("https://www.instagram.com/api/graphql", headers={"X-FB-LSD": lsd}, data=data)
	               username = response.json()['data']['user']['username']    
	               return username
	           except :
	               return None
	@staticmethod
	def token():
	           try:
	               files=[        
  ]
	               headers = {
  }
	               data = {
            'enc_password': '#PWD_INSTAGRAM_BROWSER:0:'+str(time()).split('.')[0]+':maybe-jay-z',
            'optIntoOneTap': 'false',
            'queryParams': '{}',
            'trustedDeviceRecords': '{}',
            'username': "topython",
        }
	               response = requests.post('https://www.instagram.com/api/v1/web/accounts/login/ajax/', headers=headers, data=data,files=files)
	               try:
	                   csrf=response.cookies["csrftoken"]
	                   mid= GetMid()
	                   ig_did=response.cookies["ig_did"]
	                   ig_nrcb=response.cookies["ig_nrcb"]
	                   IgFamilyDeviceId,AndroidID,PigeonSession,App,Blockversion,IgDeviceId,user_agent = coockie()
	               except:
	                   IgFamilyDeviceId,AndroidID,PigeonSession,App,Blockversion,IgDeviceId,user_agent = None , None , None , None , None , None
	                   csrf = None
	                   mid = None
	                   ig_did = None
	                   ig_nrcb = None
	               return {
            "csrf": csrf ,
            "mid": mid ,
            "ig_did": ig_did,
            "ig_nrcb": ig_nrcb,
            "IgFamilyDeviceId": IgFamilyDeviceId,
            "AndroidID": AndroidID,
            "PigeonSession": PigeonSession,
            "Blockversion": Blockversion,
            "IgDeviceId": IgDeviceId,
            }
	           except:
	               return False 
def GetMid():
        IgFamilyDeviceId,AndroidID,PigeonSession,App,Blockversion,IgDeviceId,user_agent = coockie()		
        data = urlencode({
            'device_id': str(AndroidID),
            'token_hash': '',
            'custom_device_id': str(IgDeviceId),
            'fetch_reason': 'token_expired',
        })
        headers = {
            'Host': 'b.i.instagram.com',
            'X-Ig-App-Locale': 'en_US',
            'X-Ig-Device-Locale': 'en_US',
            'X-Ig-Mapped-Locale': 'en_US',
            'X-Pigeon-Session-Id': str(PigeonSession),
            'X-Pigeon-Rawclienttime': str(round(time(), 3)),
            'X-Ig-Bandwidth-Speed-Kbps': f'{random.randint(1000, 9999)}.000',
            'X-Ig-Bandwidth-Totalbytes-B': f'{random.randint(10000000, 99999999)}',
            'X-Ig-Bandwidth-Totaltime-Ms': f'{random.randint(10000, 99999)}',
            'X-Bloks-Version-Id': str(Blockversion),
            'X-Ig-Www-Claim': '0',
            'X-Bloks-Is-Layout-Rtl': 'false',
            'X-Ig-Device-Id': str(IgDeviceId),
            'X-Ig-Android-Id': str(AndroidID),
            'X-Ig-Timezone-Offset': '-21600',
            'X-Fb-Connection-Type': 'MOBILE.LTE',
            'X-Ig-Connection-Type': 'MOBILE(LTE)',
            'X-Ig-Capabilities': '3brTv10=',
            'X-Ig-App-Id': '567067343352427',
            'Priority': 'u=3',
            'User-Agent': str(user_agent),
            'Accept-Language': 'en-US',
            'Ig-Intended-User-Id': '0',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Content-Length': str(len(data)),
            'Accept-Encoding': 'gzip, deflate',
            'X-Fb-Http-Engine': 'Liger',
            'X-Fb-Client-Ip': 'True',
            'X-Fb-Server-Cluster': 'True',
            'Connection': 'close',
        }
        requests.post('https://b.i.instagram.com/api/v1/zr/tokens/', headers=headers, data=data)
        headers.update({'X-Ig-Family-Device-Id': str(IgFamilyDeviceId)})
        requests.post('https://b.i.instagram.com/api/v1/zr/tokens/', headers=headers, data=data)
        data = f'signed_body=SIGNATURE.%7B%22phone_id%22%3A%22{IgFamilyDeviceId}%22%2C%22usage%22%3A%22prefill%22%7D'
        updict = {"Content-Length": str(len(data))}
        headers = {key: updict.get(key, headers[key]) for key in headers}
        requests.post(
            'https://b.i.instagram.com/api/v1/accounts/contact_point_prefill/',
            headers=headers,
            data=data
            )
        data = urlencode({
            'signed_body': 'SIGNATURE.{"bool_opt_policy":"0","mobileconfigsessionless":"","api_version":"3","unit_type":"1","query_hash":"1fe1eeee83cc518f2c8b41f7deae1808ffe23a2fed74f1686f0ab95bbda55a0b","device_id":"'+str(IgDeviceId)+'","fetch_type":"ASYNC_FULL","family_device_id":"'+str(IgFamilyDeviceId).upper()+'"}',
        })
        updict = {"Content-Length": str(len(data))}
        headers = {key: updict.get(key, headers[key]) for key in headers}
        return requests.post('https://b.i.instagram.com/api/v1/launcher/mobileconfig/', headers=headers, data=data).headers['ig-set-x-mid']

def coockie():
	rnd=str(random.randint(150, 999))
	user_agent = "Instagram 311.0.0.32.118 Android (" + ["23/6.0", "24/7.0", "25/7.1.1", "26/8.0", "27/8.1", "28/9.0"][random.randint(0, 5)] + "; " + str(random.randint(100, 1300)) + "dpi; " + str(random.randint(200, 2000)) + "x" + str(random.randint(200, 2000)) + "; " + ["SAMSUNG", "HUAWEI", "LGE/lge", "HTC", "ASUS", "ZTE", "ONEPLUS", "XIAOMI", "OPPO", "VIVO", "SONY", "REALME"][random.randint(0, 11)] + "; SM-T" + rnd + "; SM-T" + rnd + "; qcom; en_US; 545986"+str(random.randint(111,999))+")"
	IgFamilyDeviceId = uuid.uuid4()
	AndroidID = f'android-{secrets.token_hex(8)}'
	IgDeviceId = uuid.uuid4()
	PigeonSession = f'UFS-{str(uuid.uuid4())}-0'
	App=''.join(random.choice('1234567890')for i in range(15))
	Blockversion = '8c9c28282f690772f23fcf9061954c93eeec8c673d2ec49d860dabf5dea4ca27'
	return  IgFamilyDeviceId,AndroidID,PigeonSession,App,Blockversion,IgDeviceId,user_agent

def get_country_info(country_code):
    url = f"https://restcountries.com/v3.1/alpha/{country_code}"
    response = requests.get(url)
    if response.status_code == 200:
        country_data = response.json()[0]
        country_name = country_data['name']['common']
        flag = country_data['flag']        
        return country_name, flag
    else:
        return None, None	

# All Email methods
class Email:
	@staticmethod
	def mail_ru(email):
		Port =random.randint(1024, 65535)
		Ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}:"
		Proxy=str(Ip)+str(Port)
		letters_and_digits = string.ascii_lowercase + string.digits
		md5 = ''.join(random.choice(letters_and_digits) for _ in range(32))
		url = "https://alt-auth.mail.ru/api/v1/pushauth/info"
		payload = f"login={Email}%40mail.ru&md5_post_signature={md5}"
		headers = {
  'User-Agent': "okhttp/4.11.0",
  'Accept-Encoding': "gzip",
  'Content-Type': "application/x-www-form-urlencoded"
}
		try:
		    response = requests.post(url, data=payload, verify=False,proxies={'http': Proxy}).text
		    if '"available":true' in response:
		      return False
		    elif '"available":false' in response:
		      return True
		    else:
			    return False
		except:
		    return False
	@staticmethod
	def yahoo(email):
		url = "https://login.yahoo.com/account/module/create"
		headers = {
  'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
  'Accept-Encoding': "gzip, deflate, br, zstd",
  'Content-Type': "application/x-www-form-urlencoded",
  'sec-ch-ua': "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
  'x-requested-with': "XMLHttpRequest",
  'sec-ch-ua-mobile': "?1",
  'sec-ch-ua-platform': "\"Android\"",
  'origin': "https://login.yahoo.com",
  'sec-fetch-site': "same-origin",
  'sec-fetch-mode': "cors",
  'sec-fetch-dest': "empty",
  'referer': "https://login.yahoo.com/account/create?specId=yidregsimplified&done=https%3A%2F%2Fwww.yahoo.com",
  'accept-language': "ar-IQ,ar;q=0.9,en-US;q=0.8,en;q=0.7",
  'priority': "u=1, i",
}
		response = requests.post(url, headers=headers)
		try:
		    A1 = response.cookies.get_dict()['A1']
		    A1S = response.cookies.get_dict()['A1S']
		    A3 = response.cookies.get_dict()['A3']
		except :
		    A1 , A1S , A3 = ""
		url2= "https://login.yahoo.com/account/module/create"
		params2 = {
  'validateField': "userId"
}
		payload2= "browser-fp-data=%7B%22language%22%3A%22ar-IQ%22%2C%22colorDepth%22%3A24%2C%22deviceMemory%22%3A8%2C%22pixelRatio%22%3A2.625%2C%22hardwareConcurrency%22%3A8%2C%22timezoneOffset%22%3A-180%2C%22timezone%22%3A%22Asia%2FBaghdad%22%2C%22sessionStorage%22%3A1%2C%22localStorage%22%3A1%2C%22indexedDb%22%3A1%2C%22openDatabase%22%3A1%2C%22cpuClass%22%3A%22unknown%22%2C%22platform%22%3A%22Linux+armv81%22%2C%22doNotTrack%22%3A%22unknown%22%2C%22plugins%22%3A%7B%22count%22%3A0%2C%22hash%22%3A%2224700f9f1986800ab4fcc880530dd0ed%22%7D%2C%22canvas%22%3A%22canvas+winding%3Ayes~canvas%22%2C%22webgl%22%3A1%2C%22webglVendorAndRenderer%22%3A%22Google+Inc.+%28Qualcomm%29~ANGLE+%28Qualcomm%2C+Adreno+%28TM%29+650%2C+OpenGL+ES+3.2%29%22%2C%22adBlock%22%3A0%2C%22hasLiedLanguages%22%3A0%2C%22hasLiedResolution%22%3A0%2C%22hasLiedOs%22%3A0%2C%22hasLiedBrowser%22%3A0%2C%22touchSupport%22%3A%7B%22points%22%3A5%2C%22event%22%3A1%2C%22start%22%3A1%7D%2C%22fonts%22%3A%7B%22count%22%3A11%2C%22hash%22%3A%221b3c7bec80639c771f8258bd6a3bf2c6%22%7D%2C%22audio%22%3A%22124.08072766105033%22%2C%22resolution%22%3A%7B%22w%22%3A%22418%22%2C%22h%22%3A%22976%22%7D%2C%22availableResolution%22%3A%7B%22w%22%3A%22976%22%2C%22h%22%3A%22418%22%7D%2C%22ts%22%3A%7B%22serve%22%3A1720045772430%2C%22render%22%3A1720045772199%7D%7D&specId=yidregsimplified&context=REGISTRATION&cacheStored=&crumb=KwOIBM0058KEodO9okWYIQ&acrumb=VDWofGnN&sessionIndex=QQ--&done=https%3A%2F%2Fmail.yahoo.com%2Fd%2F&googleIdToken=&authCode=&attrSetIndex=0&specData=&tos0=oath_freereg%7Cxa%7Cen-JO&multiDomain=&firstName=ToPython&lastName=telebot&userid-domain=yahoo&userId="+email+"&password=5528416973Aa#&mm=6&dd=22&yyyy=2000&signup="

		headers2 = {
  'User-Agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
  'Accept-Encoding': "gzip, deflate, br, zstd",
  'Content-Type': "application/x-www-form-urlencoded",
  'sec-ch-ua': "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
  'x-requested-with': "XMLHttpRequest",
  'sec-ch-ua-mobile': "?1",
  'sec-ch-ua-platform': "\"Android\"",
  'origin': "https://login.yahoo.com",
  'sec-fetch-site': "same-origin",
  'sec-fetch-mode': "cors",
  'sec-fetch-dest': "empty",
  'referer': "https://login.yahoo.com/account/create?specId=yidregsimplified&done=https%3A%2F%2Fwww.yahoo.com",
  'accept-language': "ar-IQ,ar;q=0.9,en-US;q=0.8,en;q=0.7",
  'priority': "u=1, i",
  'Cookie': "A1={}; A3={}; AS=v=1&s=VDWofGnN&d=A6687224c|bsiywIr.2Tqvuuyfyc089wYWWAZGmmI.bAbvQOINtMzNu2igBBTut2Dhk.dlSGkebJbKsSkkYuWm_WEhyBIk90D5v7TASrB21Ic.6WjBtvopO7E9xh3.2sLZfLp9L.jrkKTnXiqkGzP_vfoluyc8uqZCoUSB_Ki7fAFyHXneczVDNa2sK2w1vjmEOX1QEJ4R7CZzjgNAVPVqXAoM9TKXQ7UcwrK9TSeOpksnVRDOR_he.303.87Fj8fc6Xy7FfUxf5TGRdASgXsKKOQylzafq5KSn3K2Hn4mp2EstqRu2zDWtOTRzJA8mF02NRAi_o68jSD8071xXMYBYDGtg2NnR5FxjrtUa4XEX1Lb4wXcZl6ohgsKX_6YDoTGRxzQg6twaaEMMgPu.ZfPcLVMuSqxd8BjbNaMM.JFdsO_A9RuHTgRQw5ZQTyY3KVR6hJ_gIQlqheOA3jsLaKLsD513.nBLEWT0Ox21B4PLKAhaa3C5AkTHjsWCYZMyrplDE1slAT5p4qzaI79uv6ILlpnCzo5y7WYwTiUPUk3l65.yg5Kr6JB.S56osk3jsb4styENve_yyiapBsBxEnIlZwa3RY3tJLuAckfgg3h1OEesOKhrRR6Cm1eUt0OyGWa.FxaxprO3m3rwgz2pv2roFVSCk9rxJv8jGrzPRJWO5UP0V2WBBnGl_HckFIZAA_2owL.QPk7eWkjAH6I4abliZBwhOyjLSYSlPgZpIDKJ5p._XiIbu0eb9AMEUCvO6U8yg.xuxEbOjSFPV5Wb6S91dzWI5r6OfFo09n7cPZy.2sJJSroGvgPHCVn7A4I17bOJi_QOcml.HofySRxkLwCGgNfoCeu1Ammb.kuH9Zi31yH0Z4VztbJgiRSqTfYMZDWBqjT6cI9nxtVdghxuS28kaQcv.6WgdVcikRQGLc1diHLtWfUitzB2CiLt1eZftlVVfK2qHvrwnPk4P85id5PtJoZy.LoalPLFhxC~A; A1S={}".format(A1,A3,A1S)
}
		try:
		    response = requests.post(url2, params=params2,data=urllib.parse.unquote(payload2), headers=headers2)
		    if "IDENTIFIER_NOT_AVAILABLE" in response.text:
		      return False
		    else :
		        return True
		except:
		    return False		    
	@staticmethod
	def gmail(email):
		    try:
		        if "@" in email:
		            email = email.split('@')[0]
		        if not email:
		            return False
		        if len(email.split("@")[0]) < 6:
		            return False
		        if "_" in email:
		            return False
		        url ='https://accounts.google.com/_/signup/validatepersonaldetails?hl=ar&_reqid=72124&rt=j'
		        headers ={
            'Accept':'*/*',
            'Accept-Language':'en-US,en;q=0.9,ar;q=0.8',
            'Content-Length':'1080',
            'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
            'Cookie':'ACCOUNT_CHOOSER=AFx_qI50RgWS2YPtrRsLg5jdWUSb4etOkTUEDsCovfewzH7R2eHUxsbxIQlKQ3WhhWXY4b6FvxZRxr8f9jBG3F-jqyF63uOAW-aRViL0ebgO0SVvTY2qy2A; HSID=AZkgJKTilNQKSuJZ6; SSID=AlYYIGjJs1XP6ng-E; APISID=BBmytEANYvk_EgHQ/AYd8clVhC5dcLBPJ4; SAPISID=Wes_W_cOhdjh6VlI/AFkV3afD5yBJ-x5d5; __Secure-1PAPISID=Wes_W_cOhdjh6VlI/AFkV3afD5yBJ-x5d5; __Secure-3PAPISID=Wes_W_cOhdjh6VlI/AFkV3afD5yBJ-x5d5; LSOLH=_SVI_EJ2i46vqsYIDGAkiP01BRURIZl9xZ0pOdzNfNDJpMWlaWjZBSTBpRGpyUGU4WFZ2Y3ZsZGk4MUkxMHQzSGNKV2JodWFxTGFPbzdxcw_:28322650:b93c; SEARCH_SAMESITE=CgQI4pkB; SID=g.a000gAgOc3SGPF_8gp03oLJwGcnZ1sdJJraldQSJKMEOcE65p-K6M6ihpZxKSRQvpXCQfxfwXwACgYKARASAQASFQHGX2MiTTVvVUYqssEAlJWZTtdDchoVAUF8yKpFmgy8knXN4zGtF-NFVgma0076; __Secure-1PSID=g.a000gAgOc3SGPF_8gp03oLJwGcnZ1sdJJraldQSJKMEOcE65p-K6b-pBwro0QXP82pmL2QviCwACgYKAacSAQASFQHGX2MixDqVCZPT63SlCZ0fiKOEgRoVAUF8yKrkRUviv0JJPx-MoabTip2F0076; __Secure-3PSID=g.a000gAgOc3SGPF_8gp03oLJwGcnZ1sdJJraldQSJKMEOcE65p-K6KRY4ew2rBJqWJFl2s-B6QgACgYKAYQSAQASFQHGX2MiExCmrzQLR-lXqpDnc9COoxoVAUF8yKrPFfBExJoeVsG3f5e3j9Zl0076; LSID=o.console.cloud.google.com|o.drive.google.com|o.gds.google.com|o.mail.google.com|o.play.google.com|o.shell.cloud.google.com|s.IQ|s.youtube:g.a000gQgOc6Ayg_vZb5f9r81vHacudJiOWAUyOfDH0u2j48x7KyUN_DN3xCZJm3CqUkd4Y3HIfAACgYKAbASAQASFQHGX2MiU3BkCG1e8ggA1t9tyObDKBoVAUF8yKqxe3rZV4nuikxNwKSBmaxX0076; __Host-1PLSID=o.console.cloud.google.com|o.drive.google.com|o.gds.google.com|o.mail.google.com|o.play.google.com|o.shell.cloud.google.com|s.IQ|s.youtube:g.a000gQgOc6Ayg_vZb5f9r81vHacudJiOWAUyOfDH0u2j48x7KyUNAbbcwE4LwPukWQpTL9ACSAACgYKAeISAQASFQHGX2MijWOBUAyJRQbbcva40uJyzRoVAUF8yKo85ksVOOi-Ik170ZlcKhxx0076; __Host-3PLSID=o.console.cloud.google.com|o.drive.google.com|o.gds.google.com|o.mail.google.com|o.play.google.com|o.shell.cloud.google.com|s.IQ|s.youtube:g.a000gQgOc6Ayg_vZb5f9r81vHacudJiOWAUyOfDH0u2j48x7KyUNf1mAIZKgqoNklCRMLvJ_wgACgYKAcISAQASFQHGX2Mi7DuaeKz_hjcNooeQw6NJeBoVAUF8yKqZNb58OeSFq93tI_Jl6xNv0076; OTZ=7441011_44_44__44_; NID=511=WgG0OkAiMPUI0GIOtsUhPPXv3yy9cs6vLhyV-9NMK5-4b0qmMmOyTTPpKTdcYRW92W75F9Vb_5C5_46VcRd4IPqZbEqnRfwjLblTflQr9GETPwJ8wkBsPPOD7byLGwsmYpRDKr9wdTCDFi27GCWbbg5NoH_6fNaYH6bgORsmsnJJANQy8oPOOURKkrMwH2Zjs-_QsfjBvAEUInuiWaj8jlxD3cDyjsGI_KJtf1LZn3r9KSYREpxOj0V-_kRQ8u53xikNfmFMrzAFwtLCMepK23m6KUMaG9NXVZ_nW3C6LHHEYM9b3mxkZw; 1P_JAR=2024-02-25-16; AEC=Ae3NU9Ols3JKmrh5mknwQLcXNlmKHknwCHe7g6nDFp6dnjPszZ9XtgMXZA; __Secure-1PSIDTS=sidts-CjIBYfD7Z96OzoXs2FpHz1aSPn-za4ZTgJoESGsXqHVDQTeVfS2-V94aq9-pqCZ8epRJjBAA; __Secure-3PSIDTS=sidts-CjIBYfD7Z96OzoXs2FpHz1aSPn-za4ZTgJoESGsXqHVDQTeVfS2-V94aq9-pqCZ8epRJjBAA; __Host-GAPS=1:JIUgKAXGs_Jl1sIFMe1JbiXKEAcZUmpNSirJfwISElSiyAfjs7O78yPyMJI3wQw9AceZPHVUTLOWr1YIcM_IROt9prNdzQ:F8dknv2-JBBJHwqe; SIDCC=ABTWhQEHFLDT-_NUV5kRfwbDsSV66-YOdtdfyXpYBardFd6iyhDAsU90a4fwusZ3NbkJ0xn4Aw; __Secure-1PSIDCC=ABTWhQECRaO48C3S3eivAvHtgI39hTHcGwswp8bhgubcC7z8u00QYG7Uw46hFPeDlCEtpu2OgA; __Secure-3PSIDCC=ABTWhQG9iKSvW9XlQPEmp8ZWaGZnlvyGaw0aqhyyPfwvRhO-YzqPVhrJYRNXGZ2Ds5UDzAt9Niw',
            'Google-Accounts-Xsrf':'1',
            'Origin':'https://accounts.google.com',
            'Referer':'https://accounts.google.com/signup/v2/createusername?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&hl=ar&parent_directed=true&theme=glif&flowName=GlifWebSignIn&flowEntry=SignUp&TL=ADg0xR2VWkqNiosfc54yGE0dKl4h_d-1-4G6hWMgpHuKJtbORcyy41V09Fo3jwFQ',
            'Sec-Ch-Ua':'"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
            'Sec-Ch-Ua-Arch':'"x86"',
            'Sec-Ch-Ua-Bitness':'"64"',
            'Sec-Ch-Ua-Full-Version':'"122.0.6261.69"',
            'Sec-Ch-Ua-Full-Version-List':'"Chromium";v="122.0.6261.69", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.69"',
            'Sec-Ch-Ua-Mobile':'?0',
            'Sec-Ch-Ua-Model':'""',
            'Sec-Ch-Ua-Platform':'"Windows"',
            'Sec-Ch-Ua-Platform-Version':'"15.0.0"',
            'Sec-Ch-Ua-Wow64':'?0',

            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',

        }
		        data ={
            'continue': 'https://mail.google.com/mail/',
            'hl': 'ar',
            'service': 'mail',
            'theme': 'glif',
            'f.req': '["AEThLlyMr7P9GvzEN_Y4UehtsNRimijvbgyIGWAfpK68JdHbopSgrahjO0AMfeF9QdXMGUBLf-hecf4qIFBwE3PKfnOwvQwpKP1OaHUJiAERVLfWF95RY9Z-ObJGUysj2zQ3wEwP6XVdQoUtWXOpxLTkmwKYqXVOMxbYr-byRz39P61rPAt7yBwmIzYhRf9Ir67gDbReSzLu",null,null,null,null,0,0,"sqjsj","sqjsj","web-glif-signup",0,null,10,[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[5,"77185425430.apps.googleusercontent.com",["https://www.google.com/accounts/OAuthLogin"],null,null,"baa40d55-26ea-42ee-bd2b-78fc97e883ae",null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,5]],1]',
            'at': 'AFoagUUBa1gJwkT2eLWilyQ4NrweCKbRJw:1708880500160',
            'azt': 'AFoagUXEpNBwAk1L6vwFLSCoZsljO6s48g:1708880500160',
            'cookiesDisabled': 'false',
            'deviceinfo': '[null,null,null,null,null,"IQ",null,null,null,"GlifWebSignIn",null,[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[5,"77185425430.apps.googleusercontent.com",["https://www.google.com/accounts/OAuthLogin"],null,null,"baa40d55-26ea-42ee-bd2b-78fc97e883ae",null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,5]],null,null,null,null,1,null,0,1,"",null,null,2,1]',
            'gmscoreversion': 'undefined',
            'flowName': 'GlifWebSignIn',
            'checkConnection': 'youtube:1576',
            'checkedDomains': 'youtube',
            'pstMsg': '1'

        }

		        try:
		            rt = requests.post(url,headers=headers,data=data).text
		            tl = rt.split('"gf.ttu",null,"')[1].split('"]')[0]
		        except:
		            return False
		        url2=f'https://accounts.google.com/_/signup/usernameavailability?hl=ar&TL={tl}&_reqid=470065&rt=j'
		        headers2 ={
                'Accept':'*/*',
                'Accept-Language':'en-US,en;q=0.9,ar;q=0.8',
                'Content-Length':'1080',
                'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',           'Cookie':'ACCOUNT_CHOOSER=AFx_qI50RgWS2YPtrRsLg5jdWUSb4etOkTUEDsCovfewzH7R2eHUxsbxIQlKQ3WhhWXY4b6FvxZRxr8f9jBG3F-jqyF63uOAW-aRViL0ebgO0SVvTY2qy2A; HSID=AZkgJKTilNQKSuJZ6; SSID=AlYYIGjJs1XP6ng-E; APISID=BBmytEANYvk_EgHQ/AYd8clVhC5dcLBPJ4; SAPISID=Wes_W_cOhdjh6VlI/AFkV3afD5yBJ-x5d5; __Secure-1PAPISID=Wes_W_cOhdjh6VlI/AFkV3afD5yBJ-x5d5; __Secure-3PAPISID=Wes_W_cOhdjh6VlI/AFkV3afD5yBJ-x5d5; LSOLH=_SVI_EJ2i46vqsYIDGAkiP01BRURIZl9xZ0pOdzNfNDJpMWlaWjZBSTBpRGpyUGU4WFZ2Y3ZsZGk4MUkxMHQzSGNKV2JodWFxTGFPbzdxcw_:28322650:b93c; SEARCH_SAMESITE=CgQI4pkB; SID=g.a000gAgOc3SGPF_8gp03oLJwGcnZ1sdJJraldQSJKMEOcE65p-K6M6ihpZxKSRQvpXCQfxfwXwACgYKARASAQASFQHGX2MiTTVvVUYqssEAlJWZTtdDchoVAUF8yKpFmgy8knXN4zGtF-NFVgma0076; __Secure-1PSID=g.a000gAgOc3SGPF_8gp03oLJwGcnZ1sdJJraldQSJKMEOcE65p-K6b-pBwro0QXP82pmL2QviCwACgYKAacSAQASFQHGX2MixDqVCZPT63SlCZ0fiKOEgRoVAUF8yKrkRUviv0JJPx-MoabTip2F0076; __Secure-3PSID=g.a000gAgOc3SGPF_8gp03oLJwGcnZ1sdJJraldQSJKMEOcE65p-K6KRY4ew2rBJqWJFl2s-B6QgACgYKAYQSAQASFQHGX2MiExCmrzQLR-lXqpDnc9COoxoVAUF8yKrPFfBExJoeVsG3f5e3j9Zl0076; LSID=o.console.cloud.google.com|o.drive.google.com|o.gds.google.com|o.mail.google.com|o.play.google.com|o.shell.cloud.google.com|s.IQ|s.youtube:g.a000gQgOc6Ayg_vZb5f9r81vHacudJiOWAUyOfDH0u2j48x7KyUN_DN3xCZJm3CqUkd4Y3HIfAACgYKAbASAQASFQHGX2MiU3BkCG1e8ggA1t9tyObDKBoVAUF8yKqxe3rZV4nuikxNwKSBmaxX0076; __Host-1PLSID=o.console.cloud.google.com|o.drive.google.com|o.gds.google.com|o.mail.google.com|o.play.google.com|o.shell.cloud.google.com|s.IQ|s.youtube:g.a000gQgOc6Ayg_vZb5f9r81vHacudJiOWAUyOfDH0u2j48x7KyUNAbbcwE4LwPukWQpTL9ACSAACgYKAeISAQASFQHGX2MijWOBUAyJRQbbcva40uJyzRoVAUF8yKo85ksVOOi-Ik170ZlcKhxx0076; __Host-3PLSID=o.console.cloud.google.com|o.drive.google.com|o.gds.google.com|o.mail.google.com|o.play.google.com|o.shell.cloud.google.com|s.IQ|s.youtube:g.a000gQgOc6Ayg_vZb5f9r81vHacudJiOWAUyOfDH0u2j48x7KyUNf1mAIZKgqoNklCRMLvJ_wgACgYKAcISAQASFQHGX2Mi7DuaeKz_hjcNooeQw6NJeBoVAUF8yKqZNb58OeSFq93tI_Jl6xNv0076; OTZ=7441011_44_44__44_; NID=511=WgG0OkAiMPUI0GIOtsUhPPXv3yy9cs6vLhyV-9NMK5-4b0qmMmOyTTPpKTdcYRW92W75F9Vb_5C5_46VcRd4IPqZbEqnRfwjLblTflQr9GETPwJ8wkBsPPOD7byLGwsmYpRDKr9wdTCDFi27GCWbbg5NoH_6fNaYH6bgORsmsnJJANQy8oPOOURKkrMwH2Zjs-_QsfjBvAEUInuiWaj8jlxD3cDyjsGI_KJtf1LZn3r9KSYREpxOj0V-_kRQ8u53xikNfmFMrzAFwtLCMepK23m6KUMaG9NXVZ_nW3C6LHHEYM9b3mxkZw; 1P_JAR=2024-02-25-16; AEC=Ae3NU9Ols3JKmrh5mknwQLcXNlmKHknwCHe7g6nDFp6dnjPszZ9XtgMXZA; __Secure-1PSIDTS=sidts-CjIBYfD7Z96OzoXs2FpHz1aSPn-za4ZTgJoESGsXqHVDQTeVfS2-V94aq9-pqCZ8epRJjBAA; __Secure-3PSIDTS=sidts-CjIBYfD7Z96OzoXs2FpHz1aSPn-za4ZTgJoESGsXqHVDQTeVfS2-V94aq9-pqCZ8epRJjBAA; __Host-GAPS=1:JIUgKAXGs_Jl1sIFMe1JbiXKEAcZUmpNSirJfwISElSiyAfjs7O78yPyMJI3wQw9AceZPHVUTLOWr1YIcM_IROt9prNdzQ:F8dknv2-JBBJHwqe; SIDCC=ABTWhQEHFLDT-_NUV5kRfwbDsSV66-YOdtdfyXpYBardFd6iyhDAsU90a4fwusZ3NbkJ0xn4Aw; __Secure-1PSIDCC=ABTWhQECRaO48C3S3eivAvHtgI39hTHcGwswp8bhgubcC7z8u00QYG7Uw46hFPeDlCEtpu2OgA; __Secure-3PSIDCC=ABTWhQG9iKSvW9XlQPEmp8ZWaGZnlvyGaw0aqhyyPfwvRhO-YzqPVhrJYRNXGZ2Ds5UDzAt9Niw',
                'Google-Accounts-Xsrf':'1',
                'Origin':'https://accounts.google.com',
                'Referer':'https://accounts.google.com/signup/v2/createusername?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&hl=ar&parent_directed=true&theme=glif&flowName=GlifWebSignIn&flowEntry=SignUp&TL=ADg0xR2VWkqNiosfc54yGE0dKl4h_d-1-4G6hWMgpHuKJtbORcyy41V09Fo3jwFQ',
                'Sec-Ch-Ua':'"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                'Sec-Ch-Ua-Arch':'"x86"',
                'Sec-Ch-Ua-Bitness':'"64"',
                'Sec-Ch-Ua-Full-Version':'"122.0.6261.69"',
                'Sec-Ch-Ua-Full-Version-List':'"Chromium";v="122.0.6261.69", "Not(A:Brand";v="24.0.0.0", "Google Chrome";v="122.0.6261.69"',
                'Sec-Ch-Ua-Mobile':'?0',
                'Sec-Ch-Ua-Model':'""',
                'Sec-Ch-Ua-Platform':'"Windows"',
                'Sec-Ch-Ua-Platform-Version':'"15.0.0"',
                'Sec-Ch-Ua-Wow64':'?0',

                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',

            }
		        data2 = {
                'continue': 'https://mail.google.com/mail/',
                'hl': 'ar',
                'service': 'mail',
                'theme': 'glif',
                'f.req': f'["TL:{tl}","{email}",0,0,1,null,0,9118]',
                'at': 'AFoagUXZ-vJd9xB-Lw69d28mGEa0G9MZcA:1708878454490',
                'azt': 'AFoagUVRJ5PRGr0VZuj1he0nEX0b3oGiZg:1708878454490',
                'cookiesDisabled': 'false',
                'deviceinfo': '[null,null,null,null,null,"IQ",null,null,null,"GlifWebSignIn",null,[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[5,"77185425430.apps.googleusercontent.com",["https://www.google.com/accounts/OAuthLogin"],null,null,"baa40d55-26ea-42ee-bd2b-78fc97e883ae",null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,5]],null,null,null,null,1,null,0,1,"",null,null,2,1]',
                'gmscoreversion': 'undefined',
                'flowName': 'GlifWebSignIn',
                'checkConnection': 'youtube:490',
                'checkedDomains': 'youtube'

            }
		        req = requests.post(url2, headers=headers2, data=data2).text
		        ng = "50726f6772616d6d657220546c65202940534238544b"
		        bytearray = bytes.fromhex(ng)
		        if ('"gf.uar",1') in req:
		            return True
		        else:
		            return False
		      
		    except:
		        return False
	@staticmethod
	def hotmail(email):
	    versions = ["13.1.2", "13.1.1", "13.0.5", "12.1.2", "12.0.3"]
	    oss = [
    "Macintosh; Intel Mac OS X 10_15_7",
     "Macintosh; Intel Mac OS X 10_14_6",
      "iPhone; CPU iPhone OS 14_0 like Mac OS X",
       "iPhone; CPU iPhone OS 13_6 like Mac OS X"]
	    version = random.choice(versions)
	    platform = random.choice(oss)
	    user_agent = f"Mozilla/5.0 ({platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15 Edg/122.0.0.0"
	    url = 'https://signup.live.com'
	    headers={'user-agent': user_agent}
	    response = requests.post(url,headers=headers)
	    try:
	        amsc = response.cookies.get_dict()['amsc']
	        match = re.search(r'"apiCanary":"(.*?)"', response.text)      
	        if match:
	            api_canary= match.group(1)
	            canary = api_canary.encode().decode('unicode_escape')
	            headers = {
      'authority': 'signup.live.com',
      'accept': 'application/json',
      'accept-language': 'en-US,en;q=0.9',
      'canary': canary,
      'user-agent': user_agent,
    }
	            cookies = {
      'amsc':amsc
    }
	            data = {
      'signInName': email+"@hotmail.com",
    }
	            response = requests.post(
      'https://signup.live.com/API/CheckAvailableSigninNames',cookies=cookies,headers=headers,json=data)
	            if '"isAvailable":true' in response.text:
	                return True
	            else:
	                return False
	        else:
	            return False
	    except:
	        return False	        
	@staticmethod
	def outlook(email):
	    versions = ["13.1.2", "13.1.1", "13.0.5", "12.1.2", "12.0.3"]
	    oss = [
    "Macintosh; Intel Mac OS X 10_15_7",
     "Macintosh; Intel Mac OS X 10_14_6",
      "iPhone; CPU iPhone OS 14_0 like Mac OS X",
       "iPhone; CPU iPhone OS 13_6 like Mac OS X"]
	    version = random.choice(versions)
	    platform = random.choice(oss)
	    user_agent = f"Mozilla/5.0 ({platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15 Edg/122.0.0.0"
	    url = 'https://signup.live.com'
	    headers={'user-agent': user_agent}
	    response = requests.post(url,headers=headers)
	    try:
	        amsc = response.cookies.get_dict()['amsc']
	        match = re.search(r'"apiCanary":"(.*?)"', response.text)      
	        if match:
	            api_canary= match.group(1)
	            canary = api_canary.encode().decode('unicode_escape')
	            headers = {
      'authority': 'signup.live.com',
      'accept': 'application/json',
      'accept-language': 'en-US,en;q=0.9',
      'canary': canary,
      'user-agent': user_agent,
    }
	            cookies = {
      'amsc':amsc
    }
	            data = {
      'signInName': email+"@outlook.com",
    }
	            response = requests.post(
      'https://signup.live.com/API/CheckAvailableSigninNames',cookies=cookies,headers=headers,json=data)
	            if '"isAvailable":true' in response.text:
	                return True
	            else:
	                return False
	        else:
	            return False
	    except:
	        return False
	@staticmethod
	def gmx(email):
	    url = 'https://signup.gmx.com/'
	    headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'ar-YE,ar;q=0.9,en-YE;q=0.8,en-US;q=0.7,en;q=0.6',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Referer': 'https://www.gmx.com/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
            'sec-ch-ua': '"Not)A;Brand";v="24", "Chromium";v="116"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'AB_COOKIE': 'A',
        }

	    response = requests.get(url, headers=headers).text
	    try:
	           clientCredentialGuid = re.search(r'"clientCredentialGuid": "(.*?)"', response).group(1)
	           access_token = re.search(r'"accessToken": "(.*?)"', response).group(1)
	    except:
	        clientCredentialGuid = "62c166b0-cb5f-487d-9f7f-28542c057990"
	        access_token = "qXeyJhbGciOiJIUzI1NiJ9.eyJjdCI6ImNsQTV0SXlqbkUzVnNVSTI3TGxtTVYyNnhSdnJHRnBJX0F6cEhpdzdDZmhDc29VUWRJUmpYNkw0U2p6Sm1rc1Q2eWJXUzN1d3dqMVNlUERSSGYzdGtFTmh6eWJGMXVCRXMwTkpOMlFkeEF4a1hBVXRCTG5wRXVrYlUtejd3blMxdjZXQjdPOXFXOXRIWENKUzQtZzlWZWVsdFNacVRqRXIyOVdGMFAtbDRfSSIsInNjb3BlIjoicmVnaXN0cmF0aW9uIiwia2lkIjoiNzEwNzg1N2EiLCJleHAiOjE3MjAzNTQyMjk1OTIsIml2IjoiODZWWjZFZW5mOUhRZV9fRGFhNkh4USIsImlhdCI6MTcyMDM1MDYyOTU5MiwidmVyc2lvbiI6Mn0.VfmIbbIGc-5MWVJizMTuGGYNudgSa7sHsUwqfdJt-FI"	    
	    url2 = 'https://signup.gmx.com/suggest/rest/email-alias/availability'
	    headers2 = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'ar-YE,ar;q=0.9,en-YE;q=0.8,en-US;q=0.7,en;q=0.6',
        'Authorization': f'Bearer {access_token}',
        'Connection': 'keep-alive',
        'Content-Type': 'application/json',
        'Origin': 'https://signup.gmx.com',
        'Referer': 'https://signup.gmx.com/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
        'X-CCGUID': clientCredentialGuid,
        'X-UI-APP': '@umreg/registration-app2/7.4.31',
        'sec-ch-ua': '"Not)A;Brand";v="24", "Chromium";v="116"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
    }
	    data2 = {
        'emailAddress': email+"@gmx.com",
        'firstName': '',
        'lastName': '',
        'birthDate': '',
        'city': '',
        'countryCode': 'US',
        'suggestionProducts': [
            'gmxcomFree',
        ],
        'maxResultCountPerProduct': '10',
        'mdhMaxResultCount': '5',
        'initialRequestedEmailAddress': '',
        'requestedEmailAddressProduct': 'gmxcomFree',
    }
	    try:
	       response2 = requests.post(url2,headers=headers2,json=data2).text
	       if '"emailAddressAvailable":true,' in response2 or '"emailAddressAvailable":True,' in response2:
	           return True	       	           
	       else:
	           return False            
	    except :	        
	        return False
	@staticmethod
	def aol(email):
	    try:
	        cokANDdata=requests.get('https://login.aol.com/account/create',headers={'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0','accept-language': 'en-US,en;q=0.9',})
	        AS=cokANDdata.cookies.get_dict()['AS']
	        A1=cokANDdata.cookies.get_dict()['A1']
	        A3=cokANDdata.cookies.get_dict()['A3']
	        A1S=cokANDdata.cookies.get_dict()['A1S']
	        specData=cokANDdata.text.split('''name="attrSetIndex">
        <input type="hidden" value="''')[1].split(f'" name="specData">')[0]
	        specId=cokANDdata.text.split('''name="browser-fp-data" id="browser-fp-data" value="" />
        <input type="hidden" value="''')[1].split(f'" name="specId">')[0]
	        crumb=cokANDdata.text.split('''name="cacheStored">
        <input type="hidden" value="''')[1].split(f'" name="crumb">')[0]
	        sessionIndex=cokANDdata.text.split('''"acrumb">
        <input type="hidden" value="''')[1].split(f'" name="sessionIndex">')[0]
	        acrumb=cokANDdata.text.split('''name="crumb">
        <input type="hidden" value="''')[1].split(f'" name="acrumb">')[0]
	        cookies = {
        'gpp': 'DBAA',
        'gpp_sid': '-1',
        'A1':A1,
        'A3':A3,
        'A1S':A1S,
        '__gads': 'ID=c0M0fd00676f0ea1:T='+'4'+':RT='+'5'+':S=ALNI_MaEGaVTSG6nQFkSJ-RnxSZrF5q5XA',
        '__gpi': 'UID=00000cf0e8904e94:T='+'7'+':RT='+'6'+':S=ALNI_MYCzPrYn9967HtpDSITUe5Z4ZwGOQ',
        'cmp': 't='+'0'+'&j=0&u=1---',
        'AS': AS,
    };headers = {
        'authority': 'login.aol.com',
        'accept': '*/*',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': 'https://login.aol.com',
        'referer': f'https://login.aol.com/account/create?specId={specId}&done=https%3A%2F%2Fwww.aol.com',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'x-requested-with': 'XMLHttpRequest',
    }
	        params = {
        'validateField': 'userId',
    }
	        data = f'browser-fp-data=%7B%22language%22%3A%22en-US%22%2C%22colorDepth%22%3A24%2C%22deviceMemory%22%3A8%2C%22pixelRatio%22%3A1%2C%22hardwareConcurrency%22%3A4%2C%22timezoneOffset%22%3A-60%2C%22timezone%22%3A%22Africa%2FCasablanca%22%2C%22sessionStorage%22%3A1%2C%22localStorage%22%3A1%2C%22indexedDb%22%3A1%2C%22cpuClass%22%3A%22unknown%22%2C%22platform%22%3A%22Win32%22%2C%22doNotTrack%22%3A%22unknown%22%2C%22plugins%22%3A%7B%22count%22%3A5%2C%22hash%22%3A%222c14024bf8584c3f7f63f24ea490e812%22%7D%2C%22canvas%22%3A%22canvas%20winding%3Ayes~canvas%22%2C%22webgl%22%3A1%2C%22webglVendorAndRenderer%22%3A%22Google%20Inc.%20(Intel)~ANGLE%20(Intel%2C%20Intel(R)%20HD%20Graphics%204000%20(0x00000166)%20Direct3D11%20vs_5_0%20ps_5_0%2C%20D3D11)%22%2C%22adBlock%22%3A0%2C%22hasLiedLanguages%22%3A0%2C%22hasLiedResolution%22%3A0%2C%22hasLiedOs%22%3A0%2C%22hasLiedBrowser%22%3A0%2C%22touchSupport%22%3A%7B%22points%22%3A0%2C%22event%22%3A0%2C%22start%22%3A0%7D%2C%22fonts%22%3A%7B%22count%22%3A33%2C%22hash%22%3A%22edeefd360161b4bf944ac045e41d0b21%22%7D%2C%22audio%22%3A%22124.04347527516074%22%2C%22resolution%22%3A%7B%22w%22%3A%221600%22%2C%22h%22%3A%22900%22%7D%2C%22availableResolution%22%3A%7B%22w%22%3A%22860%22%2C%22h%22%3A%221600%22%7D%2C%22ts%22%3A%7B%22serve%22%3A1704793094844%2C%22render%22%3A1704793096534%7D%7D&specId={specId}&cacheStored=&crumb={crumb}&acrumb={acrumb}&sessionIndex={sessionIndex}&done=https%3A%2F%2Fwww.aol.com&googleIdToken=&authCode=&attrSetIndex=0&specData={specData}&multiDomain=&tos0=oath_freereg%7Cus%7Cen-US&firstName=&lastName=&userid-domain=yahoo&userId={email}&password=&mm=&dd=&yyyy=&signup='
	        response = requests.post('https://login.aol.com/account/module/create', params=params,  headers=headers, data=data,cookies=cookies).text
	        if '{"errors":[{"name":"firstName","error":"FIELD_EMPTY"},{"name":"lastName","error":"FIELD_EMPTY"},{"name":"birthDate","error":"INVALID_BIRTHDATE"},{"name":"password","error":"FIELD_EMPTY"}]}' in response:
	            return True
	        else:
	            return False
	    except:
	            return False
	            
# All Twitter methods	            
class Twitter:
    @staticmethod
    def CheckUsers(username):
        url = 'https://twitter.com/i/api/i/users/username_available.json'
        cookies = {
    'g_state': '{"i_l":0}',
    'auth_token': '7ec9ddeab2f7cfb04e2a894d4bfa57fcb1ae6453',
    'ct0': 'af41aee3ed5b1174d39c82bd99c1d8f18da66c271e598a66b0a534bd901c221d9c670857800c93061b5148ff47104d4659917718e5453eb91dd8eab9c18c8bdb453d1d4a9eace0f64c2b45045c20da30',
    'lang': 'en',
}
        headers = {
    'authority': 'twitter.com',
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
    'dnt': '1',
    'referer': 'https://twitter.com/i/flow/single_sign_on',
    'user-agent': str(generate_user_agent()),
    'x-csrf-token': 'af41aee3ed5b1174d39c82bd99c1d8f18da66c271e598a66b0a534bd901c221d9c670857800c93061b5148ff47104d4659917718e5453eb91dd8eab9c18c8bdb453d1d4a9eace0f64c2b45045c20da30',
    'x-twitter-active-user': 'yes',
    'x-twitter-auth-type': 'OAuth2Session',
    'x-twitter-client-language': 'en',
}        
        params = {
    'full_name': 'Ghf',
    'suggest': 'false',
    'username': username,
}
        try:
            response = requests.get(url,params=params,cookies=cookies,headers=headers,
).text
            if "Available!" in response:
                return True
            else:
                return False
        except :
            return False
    @staticmethod
    def CheckEmail(email):
        try:
            response = requests.get(f"https://api.x.com/i/users/email_available.json?email="+str(email)).json()
            if response['taken'] == True or "Email has already been taken." in response or response['valid'] == False:
                return True
            elif response['taken'] == False or 'Available!' in response or response['valid'] == False:
                return False
        except:
            return False
            
    @staticmethod
    def information(username):
        try:
            url2= f'https://twitter.com/i/api/graphql/qW5u-DAuXpMEG0zA1F7UGQ/UserByScreenName?variables=%7B%22screen_name%22%3A%22mess%22%2C%22withSafetyModeUserFields%22%3Atrue%7D&features=%7B%22hidden_profile_likes_enabled%22%3Atrue%2C%22hidden_profile_subscriptions_enabled%22%3Atrue%2C%22rweb_tipjar_consumption_enabled%22%3Atrue%2C%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22subscriptions_verification_info_is_identity_verified_enabled%22%3Atrue%2C%22subscriptions_verification_info_verified_since_enabled%22%3Atrue%2C%22highlights_tweets_tab_ui_enabled%22%3Atrue%2C%22responsive_web_twitter_article_notes_tab_enabled%22%3Atrue%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D&fieldToggles=%7B%22withAuxiliaryUserLabels%22%3Afalse%7D'
            hed2= {
'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
}

            response2= requests.get(url2, headers=hed2).cookies
            guest_id = response2.get_dict()['guest_id']
            guest_id_ads = response2.get_dict()['guest_id_ads']
            guest_id_marketing = response2.get_dict()['guest_id_marketing']
            personalization_id = response2.get_dict()['personalization_id']
        except:
            guest_id = "v1%3A172013462516068736"
            guest_id_ads = "v1%3A172013462516068736"
            guest_id_marketing = "v1%3A172013462516068736"
            personalization_id = '"v1_goEfUjBHjrYuOAuQYzbPAA=="'
        url = f'https://twitter.com/i/api/graphql/qW5u-DAuXpMEG0zA1F7UGQ/UserByScreenName?variables=%7B%22screen_name%22%3A%22{username}%22%2C%22withSafetyModeUserFields%22%3Atrue%7D&features=%7B%22hidden_profile_likes_enabled%22%3Atrue%2C%22hidden_profile_subscriptions_enabled%22%3Atrue%2C%22rweb_tipjar_consumption_enabled%22%3Atrue%2C%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22subscriptions_verification_info_is_identity_verified_enabled%22%3Atrue%2C%22subscriptions_verification_info_verified_since_enabled%22%3Atrue%2C%22highlights_tweets_tab_ui_enabled%22%3Atrue%2C%22responsive_web_twitter_article_notes_tab_enabled%22%3Atrue%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D&fieldToggles=%7B%22withAuxiliaryUserLabels%22%3Afalse%7D'
        hed = {'Accept':'*/*',
'Accept-Encoding':'gzip, deflate, br, zstd',
'Accept-Language':'ar;q=0.8',
'Authorization':'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
'Cookie':f'd_prefs=MjoxLGNvbnNlbnRfdmVyc2lvbjoyLHRleHRfdmVyc2lvbjoxMDAw; gt=1785000746309525950; kdt=ys0wWaFXY4Oxw4XSRMOvZb4Y22quAziEHA6MSfJb; att=1-kSfvpuOymSsPKRUWkUfEA6OPrfhVFOpGoCtPNfC7; lang=en; dnt=1; guest_id={guest_id}; g_state=i_l; guest_id_marketing={guest_id_marketing}; guest_id_ads={guest_id_ads}; personalization_id={personalization_id}; ads_prefs="HBISAAA="; auth_token=8b9b9ceab4cecb0594c01748ff7ad4c436e409f2; ct0=4469d9dcacfbfd5d4b4a186958e8297b0ae66f38cb892194597668b6faeb1ce2776890b781137b08f93a0dcdbff5994a7368999ba58f71f8075cb8c6ea9f1879b8da8135618a5934e76dac0d62c4207a; twid=u%3D1785006610047262720; _twitter_sess=BAh7ESIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoHaWQiJTY5NDU0NTE5MjM5ZTk0ZTJjODdjMzVj%250ANWI3OTgxZGE5Og9jcmVhdGVkX2F0bCsI1BQHK48BOgxjc3JmX2lkIiVmMWUx%250AMzkwZTMxN2VkNTczNjMwMDc3ODZhMTM1OTdkOCIJcHJycCIAOgl1c2VybCsJ%250AAGCX8Q2exRg6CHByc2kMOghwcnVsKwkAYJfxDZ7FGDoIcHJsIiswajMxc3hE%250AaXoxZnRIcko3UVlGMHE4OWV6RzI3MEZZdTFyeTBkcjoIcHJhaQY6H2xhc3Rf%250AcGFzc3dvcmRfY29uZmlybWF0aW9uIhUxNzE0NDE1MjIyMzc1MDAwOh5wYXNz%250Ad29yZF9jb25maXJtYXRpb25fdWlkIhgxNzg1MDA2NjEwMDQ3MjYyNzIw--42512ac7aaa755c40704dcfcb58778a55f7913f2',
'Priority':'u=1, i', 
'Referer':f'https://twitter.com/{username}',
'Sec-Ch-Ua':'"Chromium";v="124", "Brave";v="124", "Not-A.Brand";v="99"',
'Sec-Ch-Ua-Mobile':'?0',
'Sec-Ch-Ua-Platform':"Windows",
'Sec-Fetch-Dest':'empty',
'Sec-Fetch-Mode':'cors',
'Sec-Fetch-Site':'same-origin',
'Sec-Gpc':'1',
'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
'X-Client-Transaction-Id':'d9jWVlF11R8+RKNTTwhl1oaCTYHpN2VyiG3Q98R9vWNR1QHXMlJy1EsyK7z5KpBnYKuKgXaWmYkKRrV+lHF69zQ9NJt/dA',
'X-Csrf-Token':'4469d9dcacfbfd5d4b4a186958e8297b0ae66f38cb892194597668b6faeb1ce2776890b781137b08f93a0dcdbff5994a7368999ba58f71f8075cb8c6ea9f1879b8da8135618a5934e76dac0d62c4207a',
'X-Twitter-Active-User':'yes',
'X-Twitter-Auth-Type':'OAuth2Session',
'X-Twitter-Client-Language':'en'}
        response = requests.get(url, headers=hed).json()
        try:
            username = response['data']['user']['result']['legacy']['screen_name']
        except :
            username = None
        try:
            name = response['data']['user']['result']['legacy']['name']
        except:
            name = None
        try:
            followers = response['data']['user']['result']['legacy']['followers_count']
        except:
            followers = None
        try:
            favourites=response['data']['user']['result']['legacy']['favourites_count']
        except:
            favourites = None
        try:
            friends = response['data']['user']['result']['legacy']['friends_count']
        except:
            friends = None
        try:
            listed = response['data']['user']['result']['legacy']['listed_count']
        except:
            listed = None
        try:
            Id = response['data']['user']['result']['rest_id']
        except:
            Id = None
        try:
            bio = response['data']['user']['result']['legacy']['description']
        except:
            bio = None
        try:
            location = response['data']['user']['result']['legacy']['location']
        except:
            location = None
        try:
            verified = response['data']['user']['result']['legacy']['verified']
        except:
            verified = None
        return {
		    "name" : name ,
		    "username" : username ,
		    "followers" : followers , 
		    "friends" :  friends,
		    "favourites" : favourites ,
		    "id" : Id ,
		    "verified" : verified , 
		    "bio" : bio , 
		    "location" : location , 
		    "listed" : listed , 		    
		    }
    @staticmethod
    def token():
        try:
            url2= f'https://twitter.com/i/api/graphql/qW5u-DAuXpMEG0zA1F7UGQ/UserByScreenName?variables=%7B%22screen_name%22%3A%22mess%22%2C%22withSafetyModeUserFields%22%3Atrue%7D&features=%7B%22hidden_profile_likes_enabled%22%3Atrue%2C%22hidden_profile_subscriptions_enabled%22%3Atrue%2C%22rweb_tipjar_consumption_enabled%22%3Atrue%2C%22responsive_web_graphql_exclude_directive_enabled%22%3Atrue%2C%22verified_phone_label_enabled%22%3Afalse%2C%22subscriptions_verification_info_is_identity_verified_enabled%22%3Atrue%2C%22subscriptions_verification_info_verified_since_enabled%22%3Atrue%2C%22highlights_tweets_tab_ui_enabled%22%3Atrue%2C%22responsive_web_twitter_article_notes_tab_enabled%22%3Atrue%2C%22creator_subscriptions_tweet_preview_api_enabled%22%3Atrue%2C%22responsive_web_graphql_skip_user_profile_image_extensions_enabled%22%3Afalse%2C%22responsive_web_graphql_timeline_navigation_enabled%22%3Atrue%7D&fieldToggles=%7B%22withAuxiliaryUserLabels%22%3Afalse%7D'
            hed2= {
'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
}

            response2= requests.get(url2, headers=hed2).cookies
            guest_id = response2.get_dict()['guest_id']
            guest_id_ads = response2.get_dict()['guest_id_ads']
            guest_id_marketing = response2.get_dict()['guest_id_marketing']
            personalization_id = response2.get_dict()['personalization_id']
        except:
            guest_id = "v1%3A172013462516068736"
            guest_id_ads = "v1%3A172013462516068736"
            guest_id_marketing = "v1%3A172013462516068736"
            personalization_id = '"v1_goEfUjBHjrYuOAuQYzbPAA=="'
        return {
        "guest_id": guest_id ,
        "guest_id_ads": guest_id_ads,
        "guest_id_marketing": guest_id_marketing,
        "personalization_id": personalization_id
        }

# All user agent methods
class UserAgent:
    @staticmethod
    def instagram():
            rnd=str(random.randint(150, 999))
            user_agent = "Instagram 311.0.0.32.118 Android (" + ["23/6.0", "24/7.0", "25/7.1.1", "26/8.0", "27/8.1", "28/9.0"][random.randint(0, 5)] + "; " + str(random.randint(100, 1300)) + "dpi; " + str(random.randint(200, 2000)) + "x" + str(random.randint(200, 2000)) + "; " + ["SAMSUNG", "HUAWEI", "LGE/lge", "HTC", "ASUS", "ZTE", "ONEPLUS", "XIAOMI", "OPPO", "VIVO", "SONY", "REALME"][random.randint(0, 11)] + "; SM-T" + rnd + "; SM-T" + rnd + "; qcom; en_US; 545986"+str(random.randint(111,999))+")"
            return user_agent
    @staticmethod
    def tiktok():
        platforms = ["Linux", "Windows NT 10.0", "Macintosh; Intel Mac OS X 10_15_7"]
        devices = ["vivo 1933", "SM-G960F", "Pixel 3"]
        android_versions = ["11", "12", "10"]
        builds = ["RP1A.200720.012", "QKQ1.200308.002", "RKQ1.201105.002"]
        chrome_versions = ["126.0.6478.71", "125.0.6394.70", "127.0.6500.0"]
        app_versions = ["35.4.2", "35.3.1", "35.5.0"]
        regions = ["MY", "US", "IN"]
        spark_versions = ["1.5.8.6-bugfix", "1.6.0.0", "1.5.9.1"]
        platform = random.choice(platforms)
        device = random.choice(devices)
        android_version = random.choice(android_versions)
        build = random.choice(builds)
        chrome_version = random.choice(chrome_versions)
        app_version = random.choice(app_versions)
        region = random.choice(regions)
        spark_version = random.choice(spark_versions)
        user_agent = (f"Mozilla/5.0 ({platform}; Android {android_version}; {device} Build/{build}; wv) "
                  f"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{chrome_version} "
                  f"Mobile Safari/537.36 trill_350402 JsSdk/1.0 NetType/MOBILE Channel/googleplay "
                  f"AppName/trill app_version/{app_version} ByteLocale/en ByteFullLocale/en Region/{region} "
                  f"AppId/1180 Spark/{spark_version} AppVersion/{app_version} BytedanceWebview/d8a21c6")    
        return user_agent
    @staticmethod
    def facebook():
        devices = ["iPhone7,2", "iPhone8,1", "iPhone9,1"]
        ios_versions = ["10_3_2", "11_4_1", "12_3_1"]
        fb_versions = ["96.0.0.45.70", "97.0.0.46.74", "98.0.0.48.69"]
        fb_builds = ["60548545", "60653633", "60784655"]
        carriers = ["E-Plus", "T-Mobile", "Verizon"]
        locales = ["de_DE", "en_US", "fr_FR"]
        device = random.choice(devices)
        ios_version = random.choice(ios_versions).replace('.', '_')
        fb_version = random.choice(fb_versions)
        fb_build = random.choice(fb_builds)
        carrier = random.choice(carriers)
        locale = random.choice(locales)
        user_agent = (f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_version} like Mac OS X) AppleWebKit/603.2.4 "
                  f"(KHTML, like Gecko) Mobile/14F89 [FBAN/FBIOS;FBAV/{fb_version};FBBV/{fb_build};"
                  f"FBDV/{device};FBMD/iPhone;FBSN/iOS;FBSV/{ios_version.replace('_', '.')};FBSS/2;FBCR/{carrier};"
                  f"FBID/phone;FBLC/{locale};FBOP/5;FBRV/0]")
        return user_agent
    @staticmethod
    def twitter():
        platforms = [
        "Linux; Android 8.0.0", "Linux; Android 9", "Linux; Android 10", "Linux; Android 11"
    ]
        devices = [
        "STF-L09 Build/HUAWEISTF-L09", "Pixel 4 Build/QQ3A.200805.001", "SM-G950F Build/PPR1.180610.011"
    ]
        browsers = [
        "wv", "Mobile Safari", "Chrome"
    ]
        browser_versions = [
        "537.36", "537.38", "537.39"
    ]
        chrome_versions = [
        "125.0.6422.186", "91.0.4472.164", "85.0.4183.121"
    ]
        app_versions = [
        "4.0", "5.0", "6.0"
    ]    
        platform = random.choice(platforms)
        device = random.choice(devices)
        browser = random.choice(browsers)
        browser_version = random.choice(browser_versions)
        chrome_version = random.choice(chrome_versions)
        app_version = random.choice(app_versions)    
        user_agent = (
        f"Mozilla/5.0 ({platform}; {device}; {browser}) AppleWebKit/{browser_version} "
        f"(KHTML, like Gecko) Version/{app_version} Chrome/{chrome_version} Mobile Safari/{browser_version} TwitterAndroid"
    )    
        return user_agent
        
    @staticmethod
    def user_agnet():
        return generate_user_agent()
       
# All TikTok methods
class Tiktok:
    @staticmethod
    def check_email(email, proxy):
        def request_proxy(url, headers, data, handler):
            opener = urllib.request.build_opener(handler)
            urllib.request.install_opener(opener)
            req = urllib.request.Request(url, headers=headers, data=data)
            with urllib.request.urlopen(req) as response:
                response_text = response.read().decode('utf-8')
                if '"is_registered":1' in response_text:
                    return True
                else:
                    return False

        url = "https://www.tiktok.com/passport/web/user/check_email_registered"
        headers = {
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en",
            "User-Agent": str(generate_user_agent()),
            "Accept": "*/*"
        }
        data = {
            'email': email,
            'aid': '1459',
            'language': 'en',
            'faccount_sdk_source': 'web',
            'region': 'CHN'
        }
        data = urllib.parse.urlencode(data).encode('utf-8')
        try:
            handler = urllib.request.ProxyHandler({'http': f"http://{proxy}", 'https': f"http://{proxy}"})
            if request_proxy(url, headers, data, handler):
                return True
        except urllib.error.URLError as e:
            return e
        try:
            handler = urllib.request.ProxyHandler({'http': f"https://{proxy}", 'https': f"https://{proxy}"})
            if request_proxy(url, headers, data, handler):
                return True
        except urllib.error.URLError as e:
            return e
        try:
            socks.set_default_proxy(socks.SOCKS4, proxy.split(':')[0], int(proxy.split(':')[1]))
            socket.socket = socks.socksocket
            handler = urllib.request.ProxyHandler({})
            if request_proxy(url, headers, data, handler):
                return True
        except (urllib.error.URLError, socks.ProxyConnectionError) as e:
            return e
        try:
            socks.set_default_proxy(socks.SOCKS5, proxy.split(':')[0], int(proxy.split(':')[1]))
            socket.socket = socks.socksocket
            handler = urllib.request.ProxyHandler({})
            if request_proxy(url, headers, data, handler):
                return True
        except (urllib.error.URLError, socks.ProxyConnectionError) as e:
            return e
    @staticmethod
    def information(username):
        try:
            headers = {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Android 10; Pixel 3 Build/QKQ1.200308.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.6394.70 Mobile Safari/537.36 trill_350402 JsSdk/1.0 NetType/MOBILE Channel/googleplay AppName/trill app_version/35.3.1 ByteLocale/en ByteFullLocale/en Region/IN AppId/1180 Spark/1.5.9.1 AppVersion/35.3.1 BytedanceWebview/d8a21c6",
                }

            try:
                tikinfo = requests.get(f'https://www.tiktok.com/@{username}', headers=headers).text            
                info = str(tikinfo.split('webapp.user-detail"')[1]).split('"RecommendUserList"')[0]
                try:
                    name = str(info.split('nickname":"')[1]).split('",')[0]
                except:
                    name = ""
                try:
                    followers = str(info.split('followerCount":')[1]).split(',"')[0]
                except:
                    followers = ""
                try:
                    following = str(info.split('followingCount":')[1]).split(',"')[0]
                except:
                    following = ""
                try:
                    like = str(info.split('heart":')[1]).split(',"')[0]
                except:
                    like = ""
                try:
                    video = str(info.split('videoCount":')[1]).split(',"')[0]
                except:
                    video = ""
                try:
                    id = str(info.split('id":"')[1]).split('",')[0]
                except:
                    id = ""                
                try:
                    bio = str(info.split('signature":"')[1]).split('",')[0]
                except:
                    bio = ""
                try:
                    country = str(info.split('region":"')[1]).split('",')[0]
                except:
                    country = ""
                try:
                    private = str(info.split('privateAccount":')[1]).split(',"')[0]
                except:
                    private = ""  
                try:
                   country_name, flag = get_country_info(country)
                except:
                    pass                             
                return {                                    
                    "name": name,
                    "username": username,
                    "email": username+"@hotmail.com",
                    "followers": followers,
                    "following": following,
                    "like": like,
                    "video": video,
                    "private": private,
                    "id": id,
                    "bio": bio,
                    "country": country_name,
                    "flag" : flag,
                    "BY": "@g_4_q"
                }
            except:
                return {
                "message": "Erorr Username"
                }
        except :
            return False
    @staticmethod
    def GenUsers():
        versions = ["13.1.2", "13.1.1", "13.0.5", "12.1.2", "12.0.3"]
        os = ["Macintosh; Intel Mac OS X 10_15_7", "Macintosh; Intel Mac OS X 10_14_6", "iPhone; CPU iPhone OS 14_0 like Mac OS X", "iPhone; CPU iPhone OS 13_6 like Mac OS X"]
        version = random.choice(versions)
        platform = random.choice(os)
        user_agent = f"Mozilla/5.0 ({platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15 Edg/122.0.0.0"
        while True:
            try:
                headers = {"User-Agent": 'Mozilla/5.0 (Linux; Android 10; Lenovo K12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36'}
                passport =requests.get('https://www-useast1a.tiktok.com/passport/web/user/login/?',headers=headers).cookies.get_dict()['passport_csrf_token']
                sessionid="{}".format(str(secrets.token_hex(8) * 2))   
            except:
                return None
            try:
                header = {"User-Agent": 'Mozilla/5.0 (Linux; Android 10; Lenovo K12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36'}
                msToken = requests.get('https://www-useast1a.tiktok.com/passport/web/user/login/?', headers=header).cookies.get_dict()['msToken']
                ttwid = requests.get('https://www.tiktok.com/', headers=header).cookies.get_dict()['ttwid']
            except:
                return None
            try:
                country = random.choice(["BY", "TJ", "TM", "KZ", "GB", "DE", "ES", "FR", "UZ", "KG", "MD", "AC", "AD", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AS", "AU", "AW", "AX", "BA", "BB", "BD", "BF", "BG", "BI", "BJ", "BL", "BM", "BN", "BQ", "BS", "BT", "BV", "BW", "BZ", "CA", "CC", "CD", "CF", "CG", "CI", "CK", "CM", "CN", "CS", "CU", "CV", "CW", "CX", "CY", "DK", "DM", "DR", "EA", "EE", "EH", "EN", "ET", "FJ", "FK", "FM", "FO", "GA", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GN", "GP", "GQ", "GS", "GU", "GW", "GY", "HK", "HR", "HT", "IC", "IE", "IL", "IM", "IN", "IO", "IS", "JE", "KE", "KH", "KI", "KN", "KY", "LA", "LC", "LI", "LK", "LR", "LS", "LU", "LV", "MC", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MS", "MT", "MU", "MV", "MW", "MZ", "NA", "NC", "NE", "NF", "NG", "NJ", "NO", "NR", "NU", "NZ", "PF", "PG", "PK", "PM", "PN", "PR", "PW", "QS", "RE", "RW", "SB", "SC", "SH", "SI", "SJ", "SL", "SM", "SN", "SR", "ST", "SX", "SZ", "TC", "TF", "TG", "TK", "TL", "TO", "TP", "TS", "TV", "TZ", "UG", "UM", "VA", "VC", "VG", "VI", "VU", "WF", "WS", "XA", "XB", "XK", "XX", "YJ", "YT", "ZA", "ZG", "ZM", "ZN", "ZW", "ZZ", "ES", "TR", "AZ", "MA", "LB", "DZ", "ER", "TN", "SS", "BR", "MX", "TH", "ID", "MY", "VN", "PH", "SG", "KR", "JP", "EG", "SY", "PS", "JO", "IQ", "DJ", "KM", "SO", "TD", "OM", "QA", "KW", "AE", "BH", "SA", "YE", "LY", "SD", "MR", "LT", "JM", "CH", "IR", "AN", "FI", "PY", "AR", "GR", "UY", "CR", "DO", "PE", "IT", "TT", "SV", "CZ", "BE", "CO", "TW", "HN", "EC", "SK", "NP", "RS", "NI", "SE", "GT", "CL", "NL", "RO", "HU", "VE", "AT", "PL", "PA", "BO", "GM", "PT"])
  #              pro = random.choice(ugen2)
                rng = int("".join(random.choice('456789') for i in range(1)))
                user = 'qwertyuiopasdfghjklzxcvbnm'
                name = str("".join(random.choice(user) for i in range(rng)))
                params = urlencode({
                    'aid': 1988,
                    'app_language': 'en',
                    'app_name': 'tiktok_web',
                    'battery_info': '0.6',
                    'browser_language': 'en',
                    'browser_name': 'Mozilla',
                    'browser_online': 'true',
                    'browser_platform': 'Win32',
                    'browser_version': '5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
                    'channel': 'tiktok_web',
                    'cookie_enabled': 'true',
                    'device_id': random.randint(6999999999999999999, 7122222222222222222),
                    'device_platform': 'web_pc',
                    'focus_state': 'true',
                    'from_page': 'user',
                    'history_len': '3',
                    'is_fullscreen': 'false',
                    'is_page_visible': 'true',
                    'os': 'windows',
                    'priority_region': f'{country}',
                    'referer': '',
                    'region': f'{country}',
                    "screen_height": random.randint(777, 888),
                    "screen_width": random.randint(1333, 1666),
                    'tz_name': 'Europe/London',
                    'keyword': name,
                    'webcast_language': 'en',
                })
                u = f'https://www.tiktok.com/api/search/user/full/?{params}'
                h = {
                    'Cookie': 'ttwid=' + ttwid + '; tiktok_webapp_theme=light; msToken=2cFfY83w7ZYqeJfgSrtprxuGTSGt6Gc0eDwFbgXg9X2H9QKDvqyP84CCl5rQLohHqsWmMbFe6wbNEP8-opBSk0lOsyjuzONVAKvkGqzDSqpjF06wiD6q7dttLj8SXD1G3Hrp; ttwid=' + ttwid + '; passport_csrf_token=' + passport + '; passport_csrf_token_default=' + passport + '; uid_tt=586f8c5249e9ca4373252f9eee8e7c83c9d67acce516a2f60263e96bd2d05513; uid_tt_ss=586f8c5249e9ca4373252f9eee8e7c83c9d67acce516a2f60263e96bd2d05513; sid_tt=' + sessionid + '; sessionid=' + sessionid + '; sessionid_ss=' + sessionid + '; sid_ucp_v1=1.0.0-KDM4Mzc5NGVjZjZiMTI2YmMwNDliMWZhYTFiZjRmNDQzYjBhMTFmNDkKIAiCiKiSlOmvu2MQgeeEoQYYswsgDDD3_tqbBjgBQOoHEAMaBm1hbGl2YSIgZDI2MTYzZjY4ZTZjOTVkNDljMDNlYzdmNzJkNzAwN2Q; ssid_ucp_v1=1.0.0-KDM4Mzc5NGVjZjZiMTI2YmMwNDliMWZhYTFiZjRmNDQzYjBhMTFmNDkKIAiCiKiSlOmvu2MQgeeEoQYYswsgDDD3_tqbBjgBQOoHEAMaBm1hbGl2YSIgZDI2MTYzZjY4ZTZjOTVkNDljMDNlYzdmNzJkNzAwN2Q; store-idc=maliva; store-country-code=tr; store-country-code-src=uid; tt-target-idc=useast1a; tt-target-idc-sign=cQMNfSjvvlNBGrwBOVqQa00_v09uRkDCThX0h3WaTo3QkciqJxdiEQWfUogQifipphJ2Ew8lBPW5swp2QVAyQLMcRUZM7pXPh0HyaHO8KrEiK9A3hSGZBZxSEAtjUhUMDQUDKDoC0cR0zeg-w2kkEIzXQLMsCGEMP93BoNLamPReCgAQrzLXVcgIYxWPpL5a-6aGuB43e42MWOqeJ5YSA9r0Un4DqveL_K1-LXhXjSwcnPfR6vF53zPExkDb2QMG0jvHTef2Y-aXwqVhDrmc22wJAL5bMgEqtWhsdetK292OW6-_yY0vNW4FeADvZClor00lmXAXqgknfgEXkqbWe8oDu4o4-WTVM8Y0YMAJeS7RJkEW_2Di7V1o17gI8-dYhyE7Zi_Gm9junoMOnpbye8K-E1Tr6NEmp-ceoY1_ic6BewgUoVNqe3A6sYigbBydUam2obTHgrQgOD0Qss3TjvigPlTsC8DrE9DXhiSqAe-dCSnuEL_2tbfXt433ZkPE; tt_csrf_token = PSOxiSio-0SwWbZDgx1udkrvw10E6D869hY4; tt_chain_token=xzQFbQnJcDXq3OHhlmPQA==; __tea_cache_tokens_1988={%22_type_%22:%22default%22%2C%22user_unique_id%22:%227215088339640649222%22%2C%22timestamp%22:1679893715575}; passport_fe_beating_status=true; csrf_session_id=3f2907b98fa47d37c429fe3249297a97; msToken=' + msToken,
                    'User-Agent': user_agent}
                r = requests.get(u, headers=h).json()
                rzo = r['user_list']
                for usz in rzo:
                    email = str(usz['user_info']['unique_id'])
                    return email	                                   
            except Exception as e:
                return None                        
    @staticmethod
    def token():
        versions = ["13.1.2", "13.1.1", "13.0.5", "12.1.2", "12.0.3"]
        os = ["Macintosh; Intel Mac OS X 10_15_7", "Macintosh; Intel Mac OS X 10_14_6", "iPhone; CPU iPhone OS 14_0 like Mac OS X", "iPhone; CPU iPhone OS 13_6 like Mac OS X"]
        version = random.choice(versions)
        platform = random.choice(os)
        user_agent = f"Mozilla/5.0 ({platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15 Edg/122.0.0.0"
        while True:
            try:
                headers = {"User-Agent": 'Mozilla/5.0 (Linux; Android 10; Lenovo K12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36'}
                passport =requests.get('https://www-useast1a.tiktok.com/passport/web/user/login/?',headers=headers).cookies.get_dict()['passport_csrf_token']
                sessionid="{}".format(str(secrets.token_hex(8) * 2))   
                header = {"User-Agent": 'Mozilla/5.0 (Linux; Android 10; Lenovo K12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36'}
                msToken = requests.get('https://www-useast1a.tiktok.com/passport/web/user/login/?', headers=header).cookies.get_dict()['msToken']
                ttwid = requests.get('https://www.tiktok.com/', headers=header).cookies.get_dict()['ttwid']
            except:
                passport = None
                sessionid = None
                msToken = None
                ttwid = None
            return {
            "passport_csrf_token": passport,
            "sessionid": sessionid,
            "msToken": msToken,
            "ttwid": ttwid,
            }

class Spotify:
    @staticmethod
    def Login(username,password):
        headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Pragma": "no-cache",
        "Accept": "*/*"
    }
        try:    
            response = requests.get("https://accounts.spotify.com/en/login?continue=https%3A%2F%2Fopen.spotify.com%2F__noul__%2Fintl-fr", headers=headers)
            device_id = response.cookies.get('__Host-device_id')
            tpase_ssesion = response.cookies.get('__Secure-TPASESSION')
            csrf_token = response.cookies.get('sp_sso_csrf_token')
            csrf_sid = response.cookies.get('__Host-sp_csrf_sid')
            flow_ctx_match = re.search(r'"flowCtx":"(.*?)",', response.text)
            flow_ctx = flow_ctx_match.group(1) if flow_ctx_match else None
            headers_post = {
        "Host": "accounts.spotify.com",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://accounts.spotify.com/en/login?continue=https%3A%2F%2Fopen.spotify.com%2F__noul__%2Fintl-fr",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRF-Token": csrf_token,
        "Content-Length": "3295",
        "Origin": "https://accounts.spotify.com",
        "Alt-Used": "accounts.spotify.com",
        "Connection": "keep-alive",
        "Cookie": f"__Host-device_id={device_id}; __Secure-TPASESSION={tpase_ssesion}; sp_sso_csrf_token={csrf_token}; sp_tr=false; __Host-sp_csrf_sid={csrf_sid}; remember=l7ng4q@gmail.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Priority": "u=4"
    }
            data = {
        "username": username,
        "password": password,
        "remember": "true",
        "continue": "https://accounts-gue1.spotify.com/floss/complete/05-401deaa9-010d-4ae3-a9e2-d26187093d5e;2;044e1130-1a91-4b3c-814a-a8cdaa19db04?state=3-U4aKVH3XRWSij_OZXIEEpFeZxQg8esnqOyWlbUGTPwI2gdjSbM41lmMYRK7oJ7wq4UJOtSCN7pvTSCL0iEIw&flow_ctx=f80afa0b-af40-4765-ab13-429aec3d8545:1707078938",
        "listenerAppExperiment": "true",
        "flowCtx": f"{flow_ctx}:1707078938"
    }
            R0 = requests.post("https://accounts.spotify.com/login/password", headers=headers_post, data=data)

            if 'result":"ok' in R0.text:
                return True
            elif 'errorInvalidCredentials' in R0.text:
                return False
            else:
                return False                
        except:
            return False
    @staticmethod
    def tokens():
        headers = {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Pragma": "no-cache",
        "Accept": "*/*"
    }
        try:
            response = requests.get("https://accounts.spotify.com/en/login?continue=https%3A%2F%2Fopen.spotify.com%2F__noul__%2Fintl-fr", headers=headers)
            try:
                device_id = response.cookies.get('__Host-device_id')
            except:
                device_id = None
            try:
                tpase_ssesion = response.cookies.get('__Secure-TPASESSION')
            except:
                tpase_ssesion = None
            try:
                csrf_token = response.cookies.get('sp_sso_csrf_token')
            except:
                csrf_token = None
            try:
                csrf_sid = response.cookies.get('__Host-sp_csrf_sid')
            except:
                csrf_sid = None
            try:
                flow_ctx_match = re.search(r'"flowCtx":"(.*?)",', response.text)
                flow_ctx = flow_ctx_match.group(1) if flow_ctx_match else None
            except:
                flow_ctx = None
            response_data = {
        "Token": True,
        "device_id": device_id,
        "tpase_ssesion": tpase_ssesion,
        "csrf_token": csrf_token,
        "csrf_sid": csrf_sid,
        "flow_ctx_match": flow_ctx_match.group(0) if flow_ctx_match else None,
        "flow_ctx": flow_ctx        
    }
    
            return (response_data)
        except:
            return (
        {
        "BY": "@g_4_q",
        "Token" : False ,
         }
         )

# cURL method 
class Curl:
    @staticmethod
    def python(code):
        try:
            output = parseCurlString(code)
        except Exception:
            return False                   
        try:
            output = output.split("""####################
#File Name:
#This file is generated by curl2pyreqs.
#Github: https://github.com/knightz1224/curl2pyreqs
####################
#!/bin/env python3""")[1]
            cURL = ("#BY : 𝐋7𝐍\n#Telegram : https://t.me/g_4_q \n#My channel : https://t.me/ToPython \n " + output)
            return {
            "cURL": cURL
            }
        except:
            return False
            
# All Proxy Check methods
class Proxy:
    @staticmethod
    def http(proxy):
        url = 'https://github.com/'
        headers={
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                "Accept": "*/*"
        }
        handler = urllib.request.ProxyHandler({'http': f"http://{proxy}", 'https': f"http://{proxy}"})
        opener = urllib.request.build_opener(handler)
        urllib.request.install_opener(opener)
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                if response.getcode() == 200:
                    return True
                else:
                    return False
        except:
            return False
    @staticmethod
    def https(proxy):
        url = 'https://github.com/'
        headers={
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                "Accept": "*/*"
        }
        handler = urllib.request.ProxyHandler({'http': f'https://{proxy}', 'https': f'https://{proxy}'})
        opener = urllib.request.build_opener(handler)
        urllib.request.install_opener(opener)
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                if response.getcode() == 200:
                    return True
                else:
                    return False
        except:
            return False
    @staticmethod
    def socks4(proxy):
        ip = f'socks4://{proxy}'
        url = 'https://github.com/'
        headers={
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                "Accept": "*/*"
        }
        proxy_type, proxy_address = ip.split('://')
        proxy_host, proxy_port = proxy_address.split(':')
        socks.set_default_proxy(socks.SOCKS4, proxy_host, int(proxy_port))
        socket.socket = socks.socksocket
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                if response.getcode() == 200:
                    return True
                else:
                    return False
        except:
            return False
    @staticmethod
    def socks5(proxy):
        ip = f'socks5://{proxy}'
        url = 'https://github.com/'
        headers={
                "Connection": "keep-alive",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                "Accept": "*/*"
        }
        proxy_type, proxy_address = ip.split('://')
        proxy_host, proxy_port = proxy_address.split(':')
        socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
        socket.socket = socks.socksocket
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                if response.getcode() == 200:
                    return True
                else:
                    return False
        except:
            return False

# Facebook Login methods  
class Facebook:
    @staticmethod
    def Login(email,password):
        try:	         
	           head = {'Host':'b-graph.facebook.com','X-Fb-Connection-Quality':'EXCELLENT','Authorization':'OAuth 350685531728|62f8ce9f74b12f84c123cc23437a4a32','User-Agent':'Dalvik/2.1.0 (Linux; U; Android 7.1.2; RMX3740 Build/QP1A.190711.020) [FBAN/FB4A;FBAV/417.0.0.33.65;FBPN/com.facebook.katana;FBLC/in_ID;FBBV/480086274;FBCR/Corporation Tbk;FBMF/realme;FBBD/realme;FBDV/RMX3740;FBSV/7.1.2;FBCA/x86:armeabi-v7a;FBDM/{density=1.0,width=540,height=960};FB_FW/1;FBRV/483172840;]','X-Tigon-Is-Retry':'false','X-Fb-Friendly-Name':'authenticate','X-Fb-Connection-Bandwidth':str(random.randrange(70000000,80000000)),'Zero-Rated':'0','X-Fb-Net-Hni':str(random.randrange(50000,60000)),'X-Fb-Sim-Hni':str(random.randrange(50000,60000)),'X-Fb-Request-Analytics-Tags':'{"network_tags":{"product":"350685531728","retry_attempt":"0"},"application_tags":"unknown"}','Content-Type':'application/x-www-form-urlencoded','X-Fb-Connection-Type':'WIFI','X-Fb-Device-Group':str(random.randrange(4700,5000)),'Priority':'u=3,i','Accept-Encoding':'gzip, deflate','X-Fb-Http-Engine':'Liger','X-Fb-Client-Ip':'true','X-Fb-Server-Cluster':'true','Content-Length':str(random.randrange(1500,2000))}
	           data = {'adid':str(uuid.uuid4()),'format':'json','device_id':str(uuid.uuid4()),'email':email,'password':'#PWD_FB4A:0:{}:{}'.format(str(time())[:10], password),'generate_analytics_claim':'1','community_id':'','linked_guest_account_userid':'','cpl':True,'try_num':'1','family_device_id':str(uuid.uuid4()),'secure_family_device_id':str(uuid.uuid4()),'credentials_type':'password','account_switcher_uids':[],'fb4a_shared_phone_cpl_experiment':'fb4a_shared_phone_nonce_cpl_at_risk_v3','fb4a_shared_phone_cpl_group':'enable_v3_at_risk','enroll_misauth':False,'generate_session_cookies':'1','error_detail_type':'button_with_disabled','source':'login','machine_id':str(''.join([random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(24)])),'jazoest':str(random.randrange(22000,23000)),'meta_inf_fbmeta':'V2_UNTAGGED','advertiser_id':str(uuid.uuid4()),'encrypted_msisdn':'','currently_logged_in_userid':'0','locale':'id_ID','client_country_code':'ID','fb_api_req_friendly_name':'authenticate','fb_api_caller_class':'Fb4aAuthHandler','api_key':'882a8490361da98702bf97a021ddc14d','sig':str(hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:32]),'access_token':'350685531728|62f8ce9f74b12f84c123cc23437a4a32'}
	           pos  = r.post('https://b-graph.facebook.com/auth/login', data=data, headers=head).json()
	           if ('session_key' in str(pos)) and ('access_token' in str(pos)):	               
	               try:
	                   token  = pos['access_token']
	                   cookie = ''.join(['{}={};'.format(i['name'],i['value']) for i in pos['session_cookies']])
	                   return {
	                   "status": True,
	                   "token": token,
	                   "cookie": cookie
	                   }
	               except:
	                   pass
	               return True              
	           else :
	               return False
        except Exception as e :
            return e
            
    @staticmethod
    def Login2(email,password):
        headers = {
                     'Authority':'www.messenger.com',
                     'Pragma':'no-cache',
                     'Cache-Control':'no-cache',
                     'Sec-Ch-Ua':'"Chromium";v="94", "Google Chrome";v="94", ";Not A Brand";v="99"',
                     'Sec-Ch-Ua-Mobile':'?0',
                     'Sec-Ch-Ua-Platform':'Linux',
                     'Origin':'https://www.messenger.com',
                     'Upgrade-Insecure-Requests':'1',
                     'Dnt':'1',
                     'Content-Type':'application/x-www-form-urlencoded',
                     'User-Agent': generate_user_agent(),
                     'Accept':'text/html, application/xhtml+xml, application/xml;q=0.9, image/avif, image/webp, image/apng, */*;q=0.8, application/signed-exchange;v=b3;q=0.9',
                     'Sec-Fetch-Site':'same-origin',
                     'Sec-Fetch-Mode':'navigate',
                     'Sec-Fetch-User':'?1',
                     'Sec-Fetch-Dest':'document',
                     'Referer':'https://www.messenger.com/',
                     'Accept-Language':'en-US, en;q=0.9',
                 }
        try:
            request = r.get('https://www.messenger.com/').text
            js_datr = re.search('"_js_datr","(.*?)"',str(request)).group(1)
            payload = {
                     'jazoest':re.search('name="jazoest" value="(.*?)"', str(request)).group(1),
                     'lsd':re.search('name="lsd" value="(.*?)"', str(request)).group(1),
                     'initial_request_id':re.search('name="initial_request_id" value="(.*?)"', str(request)).group(1),
                     'timezone':'-420',
                     'lgndim':re.search('name="lgndim" value="(.*?)"', str(request)).group(1),
                     'lgnrnd':re.search('name="lgnrnd" value="(.*?)"', str(request)).group(1),
                     'lgnjs':'n',
                     'email': email,
                     'pass': password,
                     'login':'1',
                     'persistent':'1',
                     'default_persistent':''
                 }
            headers.update({'Content-Length': str(len(payload)),'Cookie':'wd=1010x980; dpr=2; datr=%s'%(js_datr)})
            signature = urllib.parse.urlencode(payload,doseq=True)
            response  = r.post('https://www.messenger.com/login/password/', data=signature, headers=headers)
            if 'c_user' in r.cookies.get_dict():
                     try:
                         coo = r.cookies.get_dict()
                         c_user = coo['c_user']
                         sb = coo['sb']
                         xs = coo['xs']
                         return {
                         'status': True ,
                         'c_user': c_user,
                         'sb' : sb,
                         'xs': xs                     
                         }
                     except:
                         pass
                     return True
            elif 'checkpoint' in response.url:
                     return False
            else:
                return False
        except Exception as e:
            return e
            
# This Just Tests You don't need it, it's on line 1189 
class Tik_Proxy:
    @staticmethod
    def check_email(email, proxy):
        def request_proxy(url, headers, data, handler):
            opener = urllib.request.build_opener(handler)
            urllib.request.install_opener(opener)
            req = urllib.request.Request(url, headers=headers, data=data)
            with urllib.request.urlopen(req) as response:
                response_text = response.read().decode('utf-8')
                if '"is_registered":1' in response_text:
                    return True
                else:
                    return False

        url = "https://www.tiktok.com/passport/web/user/check_email_registered"
        headers = {
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en",
            "User-Agent": str(generate_user_agent()),
            "Accept": "*/*"
        }
        data = {
            'email': email,
            'aid': '1459',
            'language': 'en',
            'faccount_sdk_source': 'web',
            'region': 'CHN'
        }
        data = urllib.parse.urlencode(data).encode('utf-8')
        try:
            handler = urllib.request.ProxyHandler({'http': f"http://{proxy}", 'https': f"http://{proxy}"})
            if request_proxy(url, headers, data, handler):
                return True
        except urllib.error.URLError as e:pass
        try:
            handler = urllib.request.ProxyHandler({'http': f"https://{proxy}", 'https': f"https://{proxy}"})
            if request_proxy(url, headers, data, handler):
                return True
        except urllib.error.URLError as e:pass
        try:
            socks.set_default_proxy(socks.SOCKS4, proxy.split(':')[0], int(proxy.split(':')[1]))
            socket.socket = socks.socksocket
            handler = urllib.request.ProxyHandler({})
            if request_proxy(url, headers, data, handler):
                return True
        except (urllib.error.URLError, socks.ProxyConnectionError) as e:pass
        try:
            socks.set_default_proxy(socks.SOCKS5, proxy.split(':')[0], int(proxy.split(':')[1]))
            socket.socket = socks.socksocket
            handler = urllib.request.ProxyHandler({})
            if request_proxy(url, headers, data, handler):
                return True
        except (urllib.error.URLError, socks.ProxyConnectionError) as e:pass
        return False


#L7N Fuck All im the best                         