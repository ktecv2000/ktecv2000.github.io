---
layout: post
title: \[Hackerone\] Chaining CVEs - from 404 to RCE
categories: bugbounty
description: 
keywords: bugbounty
---

[hackerone](https://hackerone.com/hacktivity)上面的bugbounty文章真的都非常好看，於是想每隔一段時間就把上面熱門的文章po出來，並且加入我自己的理解。

![](/images/2019-05-07-hackerone-Chaining-CVEs-to-REC/hackerone_post.PNG)
# Initial Recon
一開始作者就像往常pentest一樣找找子網域、爆目錄，其中subdomain enumeration找到了一個他想測試的target，但是連進去後只有一個404頁面，隨後也沒爆出任何的目錄。
  
但後來仔細一看這個404 page footer有這麼一段文字 - `Copyright 2010 | Built on xxxx CMS`，感覺版本老舊，google看看有沒有對應的payload，結果沒找到東西。
  
這時靈光乍現try了一下路徑`target/xxxx` (the name of CMS)，結果被redirect到一個登入介面`/josso/signin`。
  
# The Red Herring
首先先嘗試登入，然而運氣不好沒有成功，再來開始亂try URL，結果直接噴出stack trace，並透漏出後台是`Apache Tomcat`，版本是`5.5.20`。
  
這是個挺老的版本，[搜尋一下](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-887/version_id-29850/Apache-Tomcat-5.5.20.html)馬上能找到不少CVE，作者try了其中一個

## CVE-2007-0450 Directory Travesal
![](/images/2019-05-07-hackerone-Chaining-CVEs-to-REC/CVE-2007-0450.PNG)
  
### Inconsistency to ACL bypass

![](/images/2019-05-07-hackerone-Chaining-CVEs-to-REC/inconsistency.PNG)

![](/images/2019-05-07-hackerone-Chaining-CVEs-to-REC/Path-Normalization.PNG)

### 漏洞成因
由於Apache只認slash(`/`)為唯一directory separator，但Tomcat認為slash(`/`)、backslash(`\`)都是，並且也接受URL encode的形式(`%5c`)，所以以下的URL path
```
/forbiden/%5c../
```
首先Apache收到這個URL後，會認為這個resource是`/forbiden/`底下的`/%5c../`，比對一下ACL，OK！不是存取`/forbiden/`，放行。
  
接著pass給後方container Tomcat處理，Tomcat認為`%5c`也是directory separator，於是在Tomcat眼裡這串URL相當於這樣
```
/forbiden//../
```
也就等於是`/forbiden/`，這下成功繞過ACL了。

# The Second CVE
利用`target/josso/%5C../`繞過ACL後，頁面被redirect到Jboss web console，此時又關聯了一個CVE

![](/images/2019-05-07-hackerone-Chaining-CVEs-to-REC/CVE-2007-1036.PNG)