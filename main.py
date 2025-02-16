#!/usr/bin/env python
from __future__ import unicode_literals
import sys, os
from cyber_sentinel.crawler import Crawler
from cyber_sentinel.attacks import *
from cyber_sentinel.utils import get_url_host, validate_url, dict_iterate, read_config, check_boolean_option
from cyber_sentinel.client import Client, NotAPage, RedirectedToExternal
from cyber_sentinel.app_detect import app_detect
from cyber_sentinel.logger import Log
from datetime import datetime, timedelta
from timeit import default_timer as timer

attacks = {
    1: all_attacks,
    2: xss_attack,
    3: hpp_attack,
    4: sql_error_attack,
    5: csrf_attack,
    6: crlf_attack,
    7: lfi_attack,
    8: directory_listing_attack,
    9: breach_attack,
    10: clickjack_attack,
    11: cookiescan_attack
}

GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[36m"
RED = "\033[1;31m"
RESET = "\033[0m"
CRED2 = "\33[91m"
CGREY = "\33[90m"
CGREYBG = "\33[96m"
CITALIC = "\33[3m"
BLINK = "\33[6m"

def run(target_url, choice, scan_all_pages):
    target_url = validate_url(target_url)
    date_now = datetime.today()
    start_scan = timer()
    additional_pages = []
    
    
    client = Client()
    log = Log()

    apps = app_detect(target_url, client)
    detected_apps = {}
    selected_attack_function = attacks.get(choice)
    
    if apps:
        print(RED+'Detected Technologies:'+RESET)
        for app, app_types in dict_iterate(apps):
            for app_type in app_types:
                detected_apps.setdefault(app_type, []).append(app)
            app_types_string = ", ".join(app_types)
            print(GREEN +'\t{} - {}'.format(app_types_string, app) + RESET)

    if scan_all_pages:
        all_pages = Crawler(target_url, client, additional_pages=additional_pages)
    else:
        page = client.get(target_url)
        all_pages = [page]
    
    try:
        for page in all_pages:
            if selected_attack_function:
                for page in all_pages:
                    print(RED + 'Checking page: [{}] {}'.format(page.status_code, page.url) + RESET)
                    log.add_url(page.url, color='green')
                    for atk in selected_attack_function():
                        atk(page, client, log)     
            else:
                print(RED + "Invalid choice of attack" + RESET)
    except KeyboardInterrupt:
        print('Interrupted')
    finally:
        end_scan = timer()
        scan_seconds = round(end_scan - start_scan)
        scan_time = str(timedelta(seconds=scan_seconds))
        audit_info = {
            'date': date_now,
            'url': target_url,
            'host': get_url_host(target_url),
            'scan_time': scan_time,
            'detected_apps': detected_apps,
        }
        log.write_html_report('audit_{}.html'.format(get_url_host(target_url)), audit_info)
        print('Scanned Pages : {}'.format(1 if not scan_all_pages else all_pages.count))
        path = os.path.dirname(os.path.abspath(__file__))
        print(RED+f"Report.html is saved in {path}/reports"+RESET)

def main():  
    try:
        while True:
            print("\n" + BLINK + YELLOW + "Main Menu:" + RESET)
            print("1: Run the program")
            print("2: Exit")
            choice1 = input(CYAN + "Enter your choice: " + RESET)
            
            if choice1 == '1':
                target_url = input(YELLOW + "Enter the target URL and press Enter: " + RESET)
                if not target_url:
                    print(RED + "No URL entered." + RESET)
                    continue
                
                scan_all_pages = input(YELLOW + "Scan all pages? (y/n): "+RESET).lower() == 'y'
                # print(scan_all_pages)
                print(BLINK+ RED + "Choose an attack:" + RESET)

                for key, value in attacks.items():
                    print(RED+CITALIC+f"{key}: {value.__name__}"+RESET)
                    
                choice = int(input(YELLOW + "Enter the number corresponding to the attack: " + RESET))
                if choice == 1:
                    print(RED+"Performing all attacks:"+ RESET)
                    run(target_url, 1, scan_all_pages)
                else:
                    run(target_url, choice, scan_all_pages) 
            elif choice1 == '2':
                print(GREEN+ BLINK + "Exiting..." + RESET)
                sys.exit(0)
            else:
                print(RED + "Invalid choice" + RESET)
    except KeyboardInterrupt:
        print(CGREYBG+"Keyboard Interruped"+RESET)

if __name__ == "__main__":
    main()
