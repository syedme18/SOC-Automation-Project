# SOC Automation Project

## 📌 Project Architecture

Here is the diagram of the project:
<img width="1002" height="613" alt="1" src="https://github.com/user-attachments/assets/c8a48641-012e-4c8d-a21a-67b798bb265e" />


```
Windows 10 client (Wazuh agent)
→ Sends events (logs, alerts) to the Wazuh Manager.

Wazuh Manager
→ Receives events from the agent. It analyzes them using rules and decoders.

Wazuh Manager → Shuffle
→ Sends alerts to Shuffle for orchestration and automation.

Shuffle
→ Enriches IOCs from the alerts (e.g., queries VirusTotal, IP reputation services).

Shuffle → TheHive
→ Sends enriched alerts as incidents/cases to TheHive.

Shuffle → Internet
→ Sends email notifications (e.g., to analysts or ticketing systems).

SOC Analyst
→ Receives email alerts and can also send email responses.

SOC Analyst → Shuffle → Wazuh
→ Sends response actions (e.g., block IP, isolate machine). Shuffle handles automation, and Wazuh enforces it.
```

---

## 🧰 Phase 1: Installing Windows 10 + Sysmon

### ✅ Install Windows 10 on VMware

Windows 10 has been installed and imported into VMware.

### ✅ Install Sysmon

1. Download Sysmon from Microsoft’s official website.
   <img width="1919" height="1079" alt="2" src="https://github.com/user-attachments/assets/e8902d11-62d2-4e2e-8191-d5782708a886" />


2. Download the Sysmon config file from:
   [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
   Click on `sysmonconfig.xml`
   <img width="1919" height="1079" alt="3" src="https://github.com/user-attachments/assets/19778123-9335-4151-9292-90dabac6a94f" />


3. Click on **Raw**
   <img width="1920" height="1080" alt="4" src="https://github.com/user-attachments/assets/6ecf3c2f-efc4-47f7-90a4-7c05cd9c5ddf" />


4. Right-click and **Save As**

5. Extract the Sysmon zip file
   <img width="1920" height="1080" alt="5" src="https://github.com/user-attachments/assets/27e398fc-233d-4191-9e01-0a8367fbac24" />


6. Open PowerShell as Administrator, navigate to the Sysmon folder, and run:

   ```powershell
   .\sysmon64.exe -i sysmonconfig.xml
   ```

   Accept the agreement when prompted.
   <img width="1052" height="794" alt="6" src="https://github.com/user-attachments/assets/76441483-e6e1-4ffb-9572-8b7bbc5bc7dc" />

   <img width="1055" height="798" alt="7" src="https://github.com/user-attachments/assets/c90a82bb-61f4-416f-a7ee-f4f70dadfb2a" />


7. To verify installation, go to:
   **Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon**
   <img width="228" height="562" alt="8" src="https://github.com/user-attachments/assets/860e13ec-403e-40e0-b653-4f70c8fd7802" />


---

## ☁️ Phase 2: Installing Wazuh on DigitalOcean

### ✅ Create Wazuh Droplet

* Go to DigitalOcean → Create Droplet
  <img width="296" height="787" alt="9" src="https://github.com/user-attachments/assets/cde68f3c-05f5-4aaa-92bc-bb53d8871249" />


* Region: Bangalore

* OS: Ubuntu 22.04

* Droplet Type: Basic

* CPU: Premium Intel (\$48/mo - 8GB RAM, 50GB SSD)
  <img width="1445" height="463" alt="10" src="https://github.com/user-attachments/assets/ec521f3f-20b2-4867-b8af-15e83f196364" />

* Authentication: Password

* Hostname (optional): `Wazuh`

* Click **Create Droplet**
  <img width="725" height="193" alt="11" src="https://github.com/user-attachments/assets/9c51329b-2342-4f6b-ba94-65d57e6ecec6" />


---

### 🔐 Set Up a Firewall

1. Go to **Networking > Firewalls**
   <img width="328" height="699" alt="12" src="https://github.com/user-attachments/assets/29ea8ee1-893a-4560-903f-eda37f357d28" />

   <img width="853" height="142" alt="13" src="https://github.com/user-attachments/assets/9423bd88-7352-4825-9848-40cdac1e79e7" />


2. Create a firewall:

   * Name: `Fwall`
   * Inbound Rules:

     * Allow All TCP — Source: your IP
     * Allow All UDP — Source: your IP
       <img width="1238" height="625" alt="14" src="https://github.com/user-attachments/assets/e82607f3-aa90-4c35-9464-f0298811d82b" />


3. Attach the firewall to the droplet:

   * Go to Droplets → Wazuh → Networking → Edit Firewall
   * Select `Fwall` and attach
     `ss15`

---

### 🔌 Connect to Wazuh Using PuTTY

* Open **PuTTY**

* Enter the droplet IP and connect
  <img width="673" height="665" alt="16" src="https://github.com/user-attachments/assets/6b77e24e-51d4-4934-b4a4-4b565cc29099" />


* Login using username and password
  <img width="991" height="702" alt="17" src="https://github.com/user-attachments/assets/c7f7be72-54ad-4517-8961-da55f80406f9" />


---

### ⚙️ Install Wazuh

Update and upgrade system:

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

Install Wazuh:

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a -i
```

> 📎 Reference: [Wazuh Installation Lab](https://github.com/syedme18/Wazuh-Installation-and-Agent-deployment-lab)

After installation, credentials will be displayed.
<img width="502" height="680" alt="18" src="https://github.com/user-attachments/assets/b35d9d23-43f8-4868-8df6-0dfd6d74e4b7" />


Access the dashboard:

```
https://<droplet-ip>:443
```

Proceed through the browser warning.
<img width="355" height="283" alt="19" src="https://github.com/user-attachments/assets/9b9c8411-dd51-4920-86e7-656f518d10de" />

<img width="1688" height="689" alt="20" src="https://github.com/user-attachments/assets/816eefe2-cbe6-4b9a-954f-e45340735a61" />

<img width="1919" height="635" alt="21" src="https://github.com/user-attachments/assets/3f0f9eb4-5874-4219-8acf-c2e70fc2e559" />


Login using the provided credentials.
<img width="1919" height="904" alt="22" src="https://github.com/user-attachments/assets/5771f3a2-e758-4a59-905f-ff72bc249d4e" />


✅ Wazuh is now running in the cloud!

---

## 🐝 Phase 3: Installing TheHive

### ✅ Create TheHive Droplet

* Repeat droplet creation (Ubuntu 22.04)
* Attach the same firewall `Fwall`

---

### 🧱 Install Dependencies

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
```

---

### ☕ Install Java (Amazon Corretto 11)

```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```

---

### 🗃️ Install Cassandra

```bash
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```

---

### 🔍 Install Elasticsearch

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```

---

### 🐝 Install TheHive

```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

---

### ⚙️ Configure Cassandra for TheHive

Open Cassandra configuration:

```bash
sudo nano /etc/cassandra/cassandra.yaml
```

* Change `listen_address` to your machine’s public IP
  <img width="1024" height="906" alt="23" src="https://github.com/user-attachments/assets/b54d20ce-77da-4c8f-9cf4-afd6aedce7aa" />

  <img width="528" height="81" alt="24" src="https://github.com/user-attachments/assets/005a862d-273c-4371-9842-96f433196472" />


* Change `rpc_address` to public IP <br>
  <img width="490" height="57" alt="25" src="https://github.com/user-attachments/assets/65e2a29e-0efc-47af-866f-b64e7a78cda0" />


Now search for `seed_provider` in the Cassandra config file and change the localhost address (`127.0.0.1`) to the **public IP** of your machine.
<img width="764" height="209" alt="26" src="https://github.com/user-attachments/assets/e39b13b0-47b2-4f59-b45e-9fa0970dee07" />


Save the file using `Ctrl + X`, then press `Y` and `Enter`.

Stop the Cassandra service:

```bash
systemctl stop cassandra.service
```

Clear old Cassandra files:

```bash
rm -rf /var/lib/cassandra/*
```

Start Cassandra again:

```bash
systemctl start cassandra.service
systemctl status cassandra.service
```

Check status output
<img width="1916" height="423" alt="27" src="https://github.com/user-attachments/assets/f43f9d77-ac82-477c-add3-5887c957a07f" />


---

## ⚙️ Configure Elasticsearch

Open config file:

```bash
nano /etc/elasticsearch/elasticsearch.yml
```

Search for `network.host` and set it to your machine’s **public IP**.
<img width="768" height="95" alt="28" src="https://github.com/user-attachments/assets/93d27594-befe-4c6a-936e-53f57ddc38fd" />


Below that:

* Uncomment `http.port`
* Uncomment `cluster.initial_master_nodes:`
* Remove `node-2` if present

Start and enable the service:

```bash
systemctl start elasticsearch.service
systemctl enable elasticsearch.service
systemctl status elasticsearch.service
```

<img width="1890" height="349" alt="29" src="https://github.com/user-attachments/assets/a37a502f-278f-4feb-8035-6c8c77f2526a" />


---

## ⚙️ Configure TheHive

Check directory permissions:

```bash
ls -la /opt/thp
```

Only `root` has access initially
<img width="566" height="128" alt="30" src="https://github.com/user-attachments/assets/f06f4559-b65f-449b-bd65-909cd8935ec3" />


Change ownership to `thehive` user:

```bash
chown -R thehive:thehive /opt/thp
```

Verify permissions:

```bash
ls -la /opt/thp
```

<img width="605" height="104" alt="31" src="https://github.com/user-attachments/assets/bb73a0d8-c955-4069-94b9-bf6c5ada1509" />


---

### 🛠️ Edit TheHive Configuration

Open config file:

```bash
nano /etc/thehive/application.conf
```

Under **Database and Index Configuration**:

* Change host IPs to the **machine’s public IP**
  <img width="844" height="272" alt="32" src="https://github.com/user-attachments/assets/1a6a7329-bb97-43af-b4d4-7c4cd6e078bb" />


Also:

* Change `cluster.name` to match Cassandra’s cluster name
* Under `index.search`, replace hostname IP with public IP
  <img width="535" height="380" alt="33" src="https://github.com/user-attachments/assets/e50dfb5f-0f3f-43a1-bab1-a1704bad44f7" />


Under **Service Configuration**:

* Change `application.baseUrl` from `localhost` to the public IP
  <img width="582" height="77" alt="34" src="https://github.com/user-attachments/assets/43ce5573-e5ee-4559-b3e5-ad2bc4969888" />


Save and exit.

Start TheHive:

```bash
systemctl start thehive
systemctl status thehive
```

<img width="1915" height="226" alt="35" src="https://github.com/user-attachments/assets/5c51ad9a-88e7-48cd-9a95-fa278c66343b" />


Now verify all three services are **active and running**: Cassandra, Elasticsearch, and TheHive
<img width="1919" height="909" alt="36" src="https://github.com/user-attachments/assets/50c93fbd-126e-4cfc-af21-b2b91d764566" />


---

### 🔓 Access TheHive Web Interface

Open your browser and navigate to:

```
http://<public-ip>:9000
```

<img width="1919" height="966" alt="37" src="https://github.com/user-attachments/assets/897822b9-6439-476e-9923-81a0792d08a0" />


Login using default credentials:

* **Username**: `admin@thehive.local`
* **Password**: `secret`

Welcome to TheHive dashboard!
<img width="1902" height="939" alt="38" src="https://github.com/user-attachments/assets/d3df96e7-0d06-4e10-853f-288f9f062c93" />


---

## 📦 Add Wazuh Agent (Windows Client with Sysmon)

1. Open the **Wazuh Web UI**

2. Click on `Add Agent`
   <img width="1919" height="333" alt="39" src="https://github.com/user-attachments/assets/414376ed-0f44-44ec-bf34-1d102ccafe83" />


3. Select your OS (`Windows`)

4. Enter:

   * **Server IP** (Wazuh Manager's IP)
   * (Optional) Agent name: e.g., `Agent 1`

5. Leave all else as default

6. Copy the first command and run it on your Windows machine in **PowerShell as Administrator**

7. Once done, copy and run the **second command**

Wazuh agent will be successfully deployed.
You should now see **agent count** go from 0 to 1.
`ss40`

---

## 🧰 Test: Transmit Mimikatz to Trigger Wazuh Alert

### Step 1: Backup `ossec.conf`

Go to:

```
C:\Program Files (x86)\ossec-agent
```

Find `ossec.conf`
Make a backup:

* Copy `ossec.conf` to `ossec-backup.conf`
  `<img width="805" height="605" alt="41" src="https://github.com/user-attachments/assets/ea6c96ed-25b8-4cba-b7e9-1dcc78f53cf2" />

  <img width="179" height="169" alt="42" src="https://github.com/user-attachments/assets/bce61b91-6b93-48fd-9a68-00764e49b5e8" />


---

### Step 2: Modify `ossec.conf` for Sysmon Logs

* Open `ossec.conf` with Notepad (Admin privileges)

* Copy an existing `<localfile> ... </localfile>` block and paste it again
  <img width="839" height="579" alt="43" src="https://github.com/user-attachments/assets/6f44f6e3-6d0b-4a9e-85be-a216e8360a60" />


* In the `<location>` tag, replace `Application` with **Sysmon's Event Channel Name**

To find the name:

1. Go to **Event Viewer > Applications and Services > Microsoft > Windows > Sysmon**
2. Right-click on `Operational` → Properties
3. Copy the **Full Name**
   <img width="1021" height="762" alt="44" src="https://github.com/user-attachments/assets/c6e4ca89-9a7e-4c4a-b13e-77d05190a1fd" />


Paste this Full Name into the `<location>` tag.
Save the file.
<img width="557" height="91" alt="45" src="https://github.com/user-attachments/assets/9be499bc-d4de-4a5a-a1dd-cba4e0751b5a" />


You can repeat this step for other logs like `PowerShell`.

Restart the Wazuh agent via Windows Services
<img width="799" height="589" alt="46" src="https://github.com/user-attachments/assets/9fd08ba3-745a-4a3d-bb80-4423caa93a93" />


Wait a few minutes and check for Sysmon events in Wazuh
<img width="1919" height="842" alt="47" src="https://github.com/user-attachments/assets/0cfe8ecf-32e0-429a-9ebc-d053d7cab954" />


---

### Step 3: Trigger Mimikatz Alert

Disable **Windows Defender** temporarily:

1. Open **Windows Security**

2. Go to **Virus & Threat Protection** → Manage Settings
   <img width="246" height="292" alt="48" src="https://github.com/user-attachments/assets/a957aa8f-f7e7-44f2-9b31-ada7845677fe" />


3. Under Exclusions → Add or Remove Exclusion
   <img width="505" height="160" alt="49" src="https://github.com/user-attachments/assets/fac17686-0891-4b47-a5c8-45b4b625849d" />


4. Add the `Downloads` folder as an exclusion

Also disable browser protections:

* Open Chrome → Settings → Privacy and Security → Safe Browsing → Select **No Protection**
  <img width="950" height="316" alt="50" src="https://github.com/user-attachments/assets/5864417a-2a6e-419b-8c5c-d28859aa6322" />

### 📁 Download and Run Mimikatz

Download Mimikatz from the official repository:
[https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919)
<img width="956" height="242" alt="51" src="https://github.com/user-attachments/assets/e18c2503-6741-4931-ae35-496d02e42c6a" />

---

### ⚙️ Modify Wazuh Manager to Log All Events

Create a backup of the Wazuh config:

```bash
cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf
```

Edit the config file:

```bash
nano /var/ossec/etc/ossec.conf
```

Inside `<ossec_config>` tag, find `<logall>` and change from `no` to `yes`:
<img width="746" height="346" alt="52" src="https://github.com/user-attachments/assets/fd7b3740-6a51-4b5f-b6c5-d5989ea7ea24" />


Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager.service
```

---

### ⚙️ Enable Filebeat Archives Module

Edit Filebeat configuration:

```bash
nano /etc/filebeat/filebeat.yml
```

Under `filebeat.modules`, set:

```yaml
archives:
  enabled: true
```

<img width="244" height="143" alt="53" src="https://github.com/user-attachments/assets/c5ab877e-c994-44c9-a1c1-891bfddee573" />


Restart Filebeat:

```bash
systemctl restart filebeat.service
```

---

### 📊 Create Index Pattern in Wazuh

Navigate to:

> Wazuh > Stack Management > Index Patterns

Wazuh comes with three default index types:

* alerts
* monitoring
* statistics

<img width="1161" height="640" alt="54" src="https://github.com/user-attachments/assets/611601e2-603f-4206-b5f9-33acaf23428c" />


Click `Create index pattern`:

* Enter: `wazuh-archives-*`
* Click `Next step`

<img width="1473" height="180" alt="55" src="https://github.com/user-attachments/assets/0b466719-9675-4eec-bf5d-a79cd3eba4f5" />


Select `@timestamp` as the time field and finish creation.

Now go to `Discover` and select `wazuh-archives-*` to view full logs.
<img width="460" height="509" alt="56" src="https://github.com/user-attachments/assets/f84e867d-6432-4278-a877-b46ee118038c" />


---

### 🔢 Simulate Mimikatz Detection

Run `mimikatz.exe` from your Windows client machine.
<img width="524" height="162" alt="57" src="https://github.com/user-attachments/assets/8d87caef-3f1b-4126-b449-c896b88cecce" />


Then, in Wazuh Discover tab, search `mimikatz`. You should see hits.
<img width="1919" height="275" alt="58" src="https://github.com/user-attachments/assets/832f6cda-5f7a-4c28-b977-2489a63c4754" />

<img width="1577" height="807" alt="59" src="https://github.com/user-attachments/assets/fdc2cba9-a305-4f4e-9d38-0b935b23b72a" />


View the `originalFileName` field — it will show `mimikatz.exe`.
<img width="608" height="57" alt="60" src="https://github.com/user-attachments/assets/eaf6476f-8e77-4540-9796-ca9ab07aa836" />


---

### ⚡️ Create Detection Rule in Wazuh for Mimikatz

Go to:

> Management > Rules

<img width="740" height="499" alt="61" src="https://github.com/user-attachments/assets/bc5ede64-52f6-40ad-8d31-830b7d8c9414" />


Click on `Manage Rule Files` and search `Sysmon` → Event ID 1.
<img width="323" height="627" alt="62" src="https://github.com/user-attachments/assets/6c2fb0dc-ee96-4c27-88f1-3cbd1200b538" />



Copy the reference rule and head back. Click `Custom Rules`.
<img width="1005" height="145" alt="64" src="https://github.com/user-attachments/assets/90c4d0fe-35cf-45cd-b2d1-b7b91c1a90a5" />

Click the pen icon to edit `local_rules.xml`

Paste the copied rule and modify as follows:

* Set `id="100002"`
* Set `level="7"`
* Set `<field name="originalFileName" type="pcre2">(?i)mimikatz\.exe</field>`
* Remove `<options>no_full_log</options>`
* Add description: `Mimikatz Detected`
* Set MITRE ID: `T1003`

Final rule example:
<img width="857" height="173" alt="65" src="https://github.com/user-attachments/assets/91759ecf-80d9-4428-ab93-336aac67de1c" />


Restart the Wazuh Manager:

```bash
systemctl restart wazuh-manager.service
```

Run Mimikatz again in PowerShell.
<img width="523" height="148" alt="66" src="https://github.com/user-attachments/assets/77747e9b-d921-4159-a043-41602136696c" />


Check `Security Events` in Wazuh — you should see a Mimikatz detection.
<img width="1891" height="188" alt="67" src="https://github.com/user-attachments/assets/6dbf5fa1-0d2d-498b-9b4c-669131aa6c33" />


---

## 🪧 Configure Shuffle for Automation

### 🔄 Workflow Overview

1. Mimikatz Alert Sent to Shuffle
2. Shuffle Receives Mimikatz Alert (Extracts SHA256 hash)
3. Checks VirusTotal for reputation
4. Sends enriched alert to TheHive
5. Sends email to SOC analyst

---

### 🔗 Connect Wazuh with Shuffle

Go to [https://shuffler.io](https://shuffler.io) and create an account.
Home screen: 

<img width="1918" height="858" alt="68" src="https://github.com/user-attachments/assets/a1cebe68-8ae6-444c-8547-54f1fdc5407a" />

Click `Create Workflow`, name it and define use cases.
<img width="729" height="839" alt="69" src="https://github.com/user-attachments/assets/00442e13-2e56-4df2-af47-9bd0a397af6a" />

<img width="1919" height="880" alt="70" src="https://github.com/user-attachments/assets/f23dfedf-f6c1-49d3-b034-13c7fe410954" />


From left sidebar, drag `Webhook` into triggers.
<img width="293" height="877" alt="71" src="https://github.com/user-attachments/assets/8edf8585-cecc-46e7-86c7-98c148900311" />


Click on the Webhook and rename to `Wazuh-Alerts`. Copy the webhook URL.
<img width="394" height="160" alt="72" src="https://github.com/user-attachments/assets/1bb47756-2753-43e1-99fb-b5366f41093f" />


Click on `Change Me` block. Under actions, choose `Repeat back to me` and set it to **Runtime argument**. Save the workflow.
<img width="1488" height="834" alt="73" src="https://github.com/user-attachments/assets/c1360e6e-5b24-4833-a19f-c2ef29b5e36e" />


Edit `ossec.conf` on Wazuh Manager:

```bash
nano /var/ossec/etc/ossec.conf
```

Paste the following under `<global>`:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://<YOUR_SHUFFLE_URL>/api/v1/hooks/<HOOK_ID></hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
  <rule_id>100002</rule_id>
</integration>
```

Update `<hook_url>` with the copied webhook URL.
<img width="1087" height="134" alt="74" src="https://github.com/user-attachments/assets/a76a83a1-c6f7-4e57-9327-94dcbca2c5b7" />


Restart Wazuh Manager:

```bash
systemctl restart wazuh-manager.service
```

Now, on your Windows client, run `mimikatz.exe` again in PowerShell.

In Shuffle:

* Click `Webhook`
* Click `Start`

<img width="385" height="214" alt="75" src="https://github.com/user-attachments/assets/2775c01f-7c1e-4527-9329-6672401f7d36" />

### 👁️ View Workflow Output in Shuffle

At the bottom of the Shuffle editor, click the person icon to view the current execution state. You should see the Mimikatz alert exactly as it appeared in the Wazuh alert.
<img width="586" height="829" alt="76" src="https://github.com/user-attachments/assets/1e8d8bfb-6706-4631-963f-3c6d8abeb6c3" />


This confirms that the Mimikatz alert was successfully sent from Wazuh to Shuffle.

---

### 🧪 Extract Hash from Wazuh Alert

Click the `Change Me` block in Shuffle.

* Change the action from `Repeat back to me` to `Regex Capture Group`.
  <img width="1036" height="692" alt="77" src="https://github.com/user-attachments/assets/f55d5e59-4908-44d8-885f-fd8f760ab3d3" />


Under **Input Data**:

* Click the plus `+` icon
* Hover over `Runtime Argument`
* Scroll and select `hashes`
  <img width="689" height="458" alt="78" src="https://github.com/user-attachments/assets/68b2469e-bca8-40fe-8f6f-14251562d528" />


In the **Regex** field, write a regular expression to extract the SHA256 hash. You can use AI assistance for help if needed.
<img width="1014" height="287" alt="79" src="https://github.com/user-attachments/assets/276ba06e-e570-458e-83a1-d041f25e7344" />


Rename this block to `Sha256Extraction`.
<img width="432" height="734" alt="80" src="https://github.com/user-attachments/assets/9ad7064a-84fd-480e-b9d3-5cda13ea8a1f" />


Click `Change Me` again — it should now display the extracted SHA256 hash from the JSON alert.
<img width="1521" height="637" alt="81" src="https://github.com/user-attachments/assets/b6d462d9-4aa3-48b0-b5dd-a8ccf66ae9e5" />


---

### 🧪 VirusTotal Hash Reputation Check

Sign in to [VirusTotal](https://www.virustotal.com).
<img width="1919" height="729" alt="82" src="https://github.com/user-attachments/assets/ee191484-b8b6-4e5c-a029-ef442cb47d43" />


Copy your personal API key.
<img width="1113" height="173" alt="83" src="https://github.com/user-attachments/assets/e6a8a96f-a5e3-4a85-9e85-93c1b81c1132" />


Now return to Shuffle:

* Search for `VirusTotal` under Apps
* Click to activate it
* Drag `VirusTotal` into your workflow after `Sha256Extraction`
  <img width="596" height="301" alt="84" src="https://github.com/user-attachments/assets/791852b3-36a3-4095-96ce-d7bfe9e8f26f" />


Click the VirusTotal block:

* In actions, select `Get Hash Report`
* Authenticate with your API key
* For ID, use: `$sha256_extraction.group_0.#`
  <img width="427" height="735" alt="85" src="https://github.com/user-attachments/assets/33e274ee-a9e4-4bb7-908f-3f17794812d4" />


Click `Save`. Then go to the person icon again and refresh the workflow. You will now see the VirusTotal report included with the alert.
<img width="383" height="699" alt="86" src="https://github.com/user-attachments/assets/fdb2bc82-0dc2-45ea-82e0-8563658858ff" />


---

### 🐝 Create Alert in TheHive from Shuffle

Search for `TheHive` in Shuffle Apps and click to activate.
<img width="290" height="366" alt="87" src="https://github.com/user-attachments/assets/03fda045-f903-4fce-a4e3-f340644e3048" />


Once activated, drag and drop TheHive into your workflow.

Next, go to your TheHive web interface (running in the cloud). Create a new organization. The default admin organization only has the admin user.
<img width="619" height="301" alt="88" src="https://github.com/user-attachments/assets/a0257b6c-a806-4878-82c4-0f35d93b201f" />


Enter the organization name and description, then confirm to create.
<img width="862" height="856" alt="89" src="https://github.com/user-attachments/assets/d4804965-60dd-407b-a1a3-9323fa797db2" />


Click on the new organization (`MyCases`). You’ll see that there are no users.
<img width="384" height="178" alt="90" src="https://github.com/user-attachments/assets/5a72c63a-1654-4d8c-9c18-4b587170c836" />


Create two users:

1. Regular user (example: Syed Mohd Hassan)
   <img width="849" height="791" alt="91" src="https://github.com/user-attachments/assets/0f14514b-d68a-4f93-b939-e9f21572ada4" />

2. Service account for Shuffle integration
   <img width="850" height="788" alt="92" src="https://github.com/user-attachments/assets/3b253df7-0bec-466b-8307-2195f2eb0c04" />


Set a password for the Syed user:

* Hover over the user → Click `Preview`
* Scroll down → Set password → Click `Confirm`
  <img width="1457" height="90" alt="93" src="https://github.com/user-attachments/assets/cef51308-3c40-4243-8740-5c76a2be2efa" />

  

For the service user (`Shuffle Soar`), hover → preview → click `Create` under API key. Copy or store this key securely.
`ss95`

Log out from the Hive admin account. Then log in as `syed@project.com`.
`ss96`
`ss97`

Now go back to Shuffle:

* Click on TheHive block
* Click `Authenticate TheHive`
  `ss98`

Enter your API key and the TheHive URL (including port number), then click `Submit`.
`ss99`

Now connect the VirusTotal block to TheHive.

* Click on TheHive block again
* Change action from `Create Case` to `Create Alert`
  `ss100`

---
