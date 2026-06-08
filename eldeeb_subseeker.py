#!/usr/bin/env python3
# eldeeb_subseeker.py - أداة شبيهة بـ subfinder بتقنيات 2027

import asyncio
import aiohttp
import json
import sys
import argparse
import re
from typing import Set, List, Dict
from urllib.parse import urlparse
import random
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import dns.resolver

class EldeebSubSeeker:
    def __init__(self, domain: str, recursive: bool = False, threads: int = 100, output: str = None):
        self.domain = domain
        self.recursive = recursive
        self.threads = threads
        self.output_file = output
        self.found_domains: Set[str] = set()
        self.semaphore = asyncio.Semaphore(threads)
        self.session = None
        self.proxy_list = []  # يمكن ملؤها بقائمة بروكسيات
        
    async def fetch(self, url: str, headers: Dict = None) -> str:
        """جلب بيانات من API مع إدارة الأخطاء والبروكسي"""
        async with self.semaphore:
            try:
                async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    return ""
            except:
                return ""
    
    async def source_virustotal(self) -> Set[str]:
        """مصدر VirusTotal (يتطلب API key)"""
        # ملاحظة: يجب إدخال مفتاح API حقيقي للاستخدام الفعلي
        api_key = "YOUR_VIRUSTOTAL_API_KEY"
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": api_key}
        data = await self.fetch(url, headers)
        if not data:
            return set()
        try:
            js = json.loads(data)
            return {item['id'] for item in js.get('data', [])}
        except:
            return set()
    
    async def source_alienvault(self) -> Set[str]:
        """مصدر AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        data = await self.fetch(url)
        if not data:
            return set()
        try:
            js = json.loads(data)
            subdomains = set()
            for record in js.get('passive_dns', []):
                host = record.get('hostname', '')
                if host.endswith(f".{self.domain}"):
                    subdomains.add(host)
            return subdomains
        except:
            return set()
    
    async def source_certspotter(self) -> Set[str]:
        """مصدر CertSpotter (شهادات SSL)"""
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        data = await self.fetch(url)
        if not data:
            return set()
        subdomains = set()
        try:
            js = json.loads(data)
            for entry in js:
                for dns in entry.get('dns_names', []):
                    if dns.endswith(f".{self.domain}") or dns == self.domain:
                        subdomains.add(dns)
        except:
            pass
        return subdomains
    
    async def source_dnsdumpster(self) -> Set[str]:
        """مصدر DNSdumpster (scraping)"""
        # DNSdumpster لا يقدم API رسمي، نستخدم scraping
        url = "https://dnsdumpster.com/"
        async with self.session.get(url) as resp:
            csrf_html = await resp.text()
            csrf_token = re.search(r'name="csrfmiddlewaretoken" value="(.*?)"', csrf_html)
            if not csrf_token:
                return set()
        data = aiohttp.FormData()
        data.add_field('csrfmiddlewaretoken', csrf_token[1])
        data.add_field('targetip', self.domain)
        headers = {'Referer': url}
        async with self.session.post(url, data=data, headers=headers) as resp2:
            html = await resp2.text()
        # استخراج النطاقات من الجدول
        pattern = r'<td class="col-md-4">([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')</td>'
        return set(re.findall(pattern, html))
    
    async def brute_dns(self, wordlist: List[str]) -> Set[str]:
        """هجوم قاموس DNS (bruteforce) - اختياري"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        resolver.timeout = 2
        resolver.lifetime = 2
        found = set()
        
        def check(sub):
            try:
                resolver.resolve(f"{sub}.{self.domain}", 'A')
                return f"{sub}.{self.domain}"
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(check, wordlist)
            found = {r for r in results if r}
        return found
    
    async def run_sources(self):
        """تشغيل جميع المصادر بشكل متزامن"""
        tasks = [
            self.source_alienvault(),
            self.source_certspotter(),
            self.source_dnsdumpster(),
        ]
        # إضافة VirusTotal فقط إذا كان المفتاح موجوداً
        # يمكن تفعيله لاحقاً
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, set):
                self.found_domains.update(res)
    
    async def recursive_scan(self, current_domain: str, depth: int = 2):
        """مسح متكرر للنطاقات الفرعية"""
        if depth == 0:
            return
        seeker = EldeebSubSeeker(current_domain, recursive=False, threads=self.threads)
        async with aiohttp.ClientSession() as sess:
            seeker.session = sess
            await seeker.run_sources()
        new_domains = seeker.found_domains - self.found_domains
        self.found_domains.update(new_domains)
        # لكل نطاق فرعي جديد، قم بمسحه بعمق أقل
        tasks = []
        for sub in new_domains:
            if sub.count('.') - self.domain.count('.') <= depth:
                tasks.append(self.recursive_scan(sub, depth-1))
        if tasks:
            await asyncio.gather(*tasks)
    
    def save_output(self):
        """حفظ النتائج"""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                for d in sorted(self.found_domains):
                    f.write(d + '\n')
        else:
            for d in sorted(self.found_domains):
                print(d)
    
    async def start(self):
        """نقطة الدخول الرئيسية"""
        async with aiohttp.ClientSession() as session:
            self.session = session
            print(f"[INF] بدء المسح الهندسي على {self.domain}")
            await self.run_sources()
            if self.recursive:
                print("[INF] تفعيل الوضع المتكرر...")
                await self.recursive_scan(self.domain, depth=2)
        self.save_output()
        print(f"[INF] اكتمل. تم العثور على {len(self.found_domains)} نطاقاً فرعياً.")

def main():
    parser = argparse.ArgumentParser(description="Eldeeb SubSeeker - أداة هندسية لكشف النطاقات الفرعية (2027)")
    parser.add_argument("-d", "--domain", required=True, help="النطاق الأساسي (مثال: example.com)")
    parser.add_argument("-recursive", action="store_true", help="تفعيل المسح المتكرر للنطاقات الفرعية")
    parser.add_argument("-t", "--threads", type=int, default=100, help="عدد الخيوط المتزامنة")
    parser.add_argument("-o", "--output", help="ملف لحفظ النتائج")
    parser.add_argument("-brute", action="store_true", help="تفعيل هجوم القاموس (DNS bruteforce)")
    parser.add_argument("-w", "--wordlist", help="ملف القاموس للهجوم العنيف")
    args = parser.parse_args()
    
    seeker = EldeebSubSeeker(args.domain, args.recursive, args.threads, args.output)
    asyncio.run(seeker.start())

if __name__ == "__main__":
    main()