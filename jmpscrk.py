#!/usr/bin/env python3
import subprocess
import requests
import datetime

def get_external_ip():
    try:
        # Using ipify service to get external IP
        ip = requests.get("https://api.ipify.org").text.strip()
        return ip
    except Exception as e:
        print("Error retrieving IP:", e)
        return None

def shodan_lookup(ip, api_key):
    # Shodan API endpoint for host information
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            # Print out some host info from Shodan
            print("IP:", data.get('ip_str'))
            print("Hostnames:", data.get('hostnames', []))
            print("OS:", data.get('os'))
            print("Ports:", [item.get('port') for item in data.get('data', []) if 'port' in item])
            print("ISP:", data.get('isp'))
            print("Org:", data.get('org'))
        else:
            print("Failed to retrieve data from Shodan. HTTP Status:", response.status_code)
            print("Response:", response.text)
    except Exception as e:
        print("Error interacting with Shodan:", e)

def run_nmap(ip):
    # current date as YYYY-MM-DD format for output filename
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    output_file = f"{date_str}.xml"
    cmd = ["nmap", ip, "-sV", "-oX", output_file]
    try:
        subprocess.run(cmd, check=True)
        print(f"Nmap scan completed. Results saved in {output_file}")
    except subprocess.CalledProcessError as e:
        print("Nmap scan failed:", e)

def run_searchsploit(xml_path):
    cmd = ["searchsploit", "--nmap", xml_path]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print("searchsploit execution failed:", e)

def main():
    print("[1] Get my IP and search it on Shodan")
    print("[2] Enter IP and search it on Shodan")
    print("[3] Get my IP and run Nmap scan on it: nmap [host] -sV -oX date.xml")
    print("[4] Enter IP and run Nmap scan: nmap [host] -sV -oX date.xml")
    print("[5] Input location of .xml and run searchsploit --nmap")

    choice = input("Select an option: ").strip()

    if choice == "1":
        ip = get_external_ip()
        if ip is not None:
            api_key = input("Enter your Shodan API key: ").strip()
            shodan_lookup(ip, api_key)
        else:
            print("Could not retrieve IP.")
    elif choice == "2":
        ip = input("Enter IP: ").strip()
        if ip is not None:
            api_key = input("Enter your Shodan API key: ").strip()
            shodan_lookup(ip, api_key)
        else:
            print("Could not retrieve IP.")
    elif choice == "3":
        ip = get_external_ip()
        if ip is not None:
            run_nmap(ip)
        else:
            print("Could not retrieve IP.")
    elif choice == "4":
        ip = input("Enter IP: ").strip()
        if ip is not None:
            run_nmap(ip)
        else:
            print("Could not retrieve IP.")
    elif choice == "5":
        xml_path = input("Enter path to the nmap XML file: ").strip()
        run_searchsploit(xml_path)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()

