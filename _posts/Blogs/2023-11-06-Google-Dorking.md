---
title: "Google Dorking"
layout: post
date: 2023-06-14 22:44
image: /assets/images\BlogPics/dork.jpg
headerImage: true
tag:
- Tips
- Google dorking
- Ethical Hacking
- Pentesting
- Osint
star: false
category: blogs
author: johndoe
description: ""

---

# Overview

#### What is a Google Dork?
Google Dorking, also known as Google hacking, involves the utilization of specialized Google search methods to gain unauthorized access to vulnerable websites or uncover information that isn't publicly accessible through standard public search results.

Those contents may include confidential data like usernames, passwords, credit card details, email addresses, shell scripts, user accounts, and more.

Google Dorks aren't restricted to Google alone, they can also be employed with search engines such as Bing and Yahoo. While the outcomes may differ, they still fulfill the same objective.

<br/>

# Google Dorking Commands

### Intitle operator
The intitle operator helps you find web pages containing particular words or phrases within their title tags. For example, if you want to locate pages that have the term "admin" in their title and also include "index of" in the title, you can use the search query: 
```bash
intitle: "index of" admin
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_11_32-intitle_ _index of_ admin - Google Search.png>)

### Intext operator
The intext operator is used to find web pages that have particular words or phrases within the main content of the page. For example, if you want to find pages that have the word contact in their content you can use th query :
```bash
intext: contact
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_20_18-intext_ contact - Google Search.png>)

### Filetype operator
The filetype operator allows you to search for specific file types, such as PDFs or Word documents. For example, if you’re looking for txt files that contain the phrase “passwords”, you would use the query :
```bash
filetype:pdf passwords
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_27_47-filetype_txt passwords - Google Search.png>)

### Inurl operator
The inurl operator is used to find web pages with particular words or phrases in their URLs. For instance, if you want to locate pages with "login.php" in their URLs, you can use the search query: 
```bash
inurl:login.php
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_31_10-inurl_login.php - Google Search.png>)

### Site operator
The site operator enables you to narrow down your search to a particular website or domain. For example, if you want to find pages related to the term "pentesting" within whatever domain, you should use the search query : 
```bash
site:*.com "pentesting"
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_34_45-Clipboard.png>)

### Cache operator
The cache operator is employed to access the stored or saved copy of a webpage. When you perform a search for a website on Google, the search engine generates a saved version of that webpage within its own system. This saved version can come in handy when the original website is temporarily unavailable or if you wish to view an earlier iteration of the website.
```bash
cache:https://www.google.com
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_44_51-Settings.png>)

### Include results
```bash
site:twitter.com +site:twitter.*
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_53_43-Clipboard.png>)

### Exclude results
```bash
site:twitter.com -site:twitter.*
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_55_16-site_twitter.com -site_twitter._ - Google Search.png>)

### AND operator
```bash
inurl:hackthebox & inurl:tryhackme
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 18_59_38-inurl_hackthebox & inurl_tryhackme - Google Search.png>)

### OR operator
```bash
inurl:hackthebox | inurl:tryhackme
```
![Alt text](<../../assets/images/BlogPics/2023-11-02 19_02_12-inurl_hackthebox _ inurl_tryhackme - Recherche Google.png>)

# Summary
Certainly! Google Dorking is a potent method that allows us to perform advanced searches on Google. With Google Dorks, we can find particular information and discover vulnerabilities that are publicly accessible. It's a crucial asset in the arsenal of a penetration tester.

<br/>

That was the end of the blog, thanks for reading, I hope you learnt something new.

<p>Happy Hacking!</p>