# Topython
best Library &lt;Pip> To Checker Account !
# Pip Channel : https://t.me/ToPythonLib
$ Good Luck 
```bash
pip install ToPython

```
# Check the email it is linked to Instagram or not 
```python
from ToPython import Instagram

check = Instagram.CheckEmail("Your Email +@")

if check == True:
    print("Valid Email")
else:
    print("Invalid Email")
  ```  

# Instagram Login (Email-passwod , Username-password , Phone-password)
```python
from ToPython import Instagram

check = Instagram.Login("Your Email-Username","Your Password")

if check == True :
    print("Done Login")
elif check == False :
    print("Login failed")
else :
    print("ban")        
```
# Check the Usernames available on Instagram 
```python
from ToPython import Instagram

check = Instagram.CheckUsers("Your Username ")

if check == True :
    print("Available Username")
elif check == False :
    print("Unavailable Username")
else :
    print("ban") 
```
# Fetch specific Instagram account information 
```python
from ToPython import Instagram

info_ig = Instagram.information("Your Username")

print(info_ig) # Can You Use json
```
# Send a message to reset your Instagram account password 
```python
from ToPython import Instagram

reset = Instagram.Rests("Email-User") # Email or Username

print(reset) 
```
# Get Usernames from Instagram 
```python
from ToPython import Instagram

Generate = Instagram.GenUsers()
if Generate == None:
    print(None)
else:
    print(Generate)
```
