# Eldeeb SubSeeker 🔍

![Version](https://img.shields.io/badge/version-5.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)
![License](https://img.shields.io/badge/license-MIT-red.svg)

**Eldeeb SubSeeker** is an advanced, high-performance subdomain enumeration tool (similar to Subfinder) equipped with cutting-edge techniques for bug bounty hunters and penetration testers. It comes with both a powerful **CLI** and a sleek, modern **GUI**.

أداة **Eldeeb SubSeeker** هي أداة متطورة وعالية الأداء لاكتشاف النطاقات الفرعية (Subdomains) تشبه أداة Subfinder، مصممة خصيصاً لمكتشفي الثغرات (Bug Bounty Hunters) ومختبري الاختراق. تأتي الأداة بواجهة سطر أوامر (CLI) سريعة، وواجهة رسومية حديثة (GUI).

---

## ✨ Features | المميزات

- 🚀 **Asynchronous & Fast**: Uses `asyncio` and `aiohttp` for lightning-fast concurrent scanning.
- 🌐 **Multiple Data Sources**: Extracts subdomains from AlienVault OTX, CertSpotter, DNSdumpster, and VirusTotal.
- 🎯 **IP & Domain Support**: Can scan a direct domain, or take an IP address, extract all root domains hosted on it, and scan them all!
- 🕳️ **Hidden Techniques**: Supports DNS Bruteforcing (using wordlists) and AXFR (Zone Transfer) attacks.
- 🔄 **Recursive Scanning**: Capability to perform deep recursive scans to find nested subdomains.
- 🖥️ **Modern GUI**: A beautifully designed dark-mode GUI using `customtkinter` with full copy/paste support, progress tracking, and multithreading.
- 💾 **Export Results**: Save your findings easily to a text file.

---

## 🛠️ Prerequisites | المتطلبات

Ensure you have Python 3.8+ installed. 
تأكد من تثبيت بايثون 3.8 أو أحدث.

Install the required dependencies using `pip`:
قم بتثبيت المكتبات المطلوبة:

```bash
pip install aiohttp dnspython customtkinter
```

*(You can also create a `requirements.txt` file and install using `pip install -r requirements.txt`)*

---

## 💻 Usage | طريقة الاستخدام

### 1. Graphical User Interface (GUI) - الواجهة الرسومية

The easiest and most interactive way to use the tool.
الطريقة الأسهل والأكثر تفاعلية لاستخدام الأداة.

```bash
python eldeeb_subseeker_gui.py
```
- Enter your **Target Domain** or **IP**.
- Adjust threads and select options like **Recursive** or **Hidden Mode** (Bruteforce/AXFR).
- Click **Start Scan** and watch the results stream in real-time!

### 2. Command Line Interface (CLI) - سطر الأوامر

For hackers who prefer the terminal.
للمتخصصين الذين يفضلون استخدام سطر الأوامر.

```bash
python eldeeb_subseeker.py -d example.com -t 100 -o results.txt
```

**Options | الخيارات:**
- `-d`, `--domain` : Target domain (e.g., example.com) | النطاق المستهدف
- `-recursive` : Enable recursive scanning | تفعيل المسح المتكرر
- `-t`, `--threads` : Number of concurrent threads (Default: 100) | عدد الخيوط المتزامنة
- `-o`, `--output` : File to save results | ملف لحفظ النتائج
- `-brute` : Enable DNS bruteforce | تفعيل هجوم القاموس
- `-w`, `--wordlist` : Wordlist file for bruteforcing | ملف القاموس

---

## 📸 Screenshots | صور الأداة

![GUI Screenshot](https://raw.githubusercontent.com/abdelmoneimbelal/Eldeeb-sub-seeker/refs/heads/master/image.png)

---

## ⚠️ Disclaimer | إخلاء مسؤولية

This tool is created for educational purposes and ethical hacking ONLY. The author is not responsible for any misuse or damage caused by this tool. Ensure you have explicit permission before scanning any target.

هذه الأداة مصممة للأغراض التعليمية والاختراق الأخلاقي فقط. المبرمج غير مسؤول عن أي سوء استخدام أو ضرر ينتج عن استخدام هذه الأداة. تأكد من حصولك على إذن صريح قبل فحص أي هدف.

---

**Developed with ❤️ by [Abdelmoneim Belal](https://github.com/abdelmoneimbelal)**
