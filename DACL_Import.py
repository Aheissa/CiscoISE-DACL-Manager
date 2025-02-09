import requests
import getpass
import base64
import warnings
import json
import re
import os
import csv
from urllib3.exceptions import InsecureRequestWarning
from prettytable import PrettyTable

# Suppress only the single InsecureRequestWarning from urllib3 needed
warnings.simplefilter('ignore', InsecureRequestWarning)

IP_FILE = "server_ips.json"

def get_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

def test_credentials(headers, ise_api_url):
    test_url = f"{ise_api_url}/versioninfo"
    print(f"Testing credentials with URL: {test_url}")
    response = requests.get(test_url, headers=headers, verify=False)
    print(f"Response status code: {response.status_code}")
    if response.status_code == 200:
        print(" ====== Credentials are valid.=====")
        return True
    else:
        print(f" ===== !Failed to validate credentials.===== Status Code: {response.status_code}, Response: {response.text}")
        return False

def create_dacl(dacl_data, headers, ise_api_url):
    response = requests.post(ise_api_url, headers=headers, json=dacl_data, verify=False)
    if response.status_code == 201:
        print(f"\n *** Successfully created DACL: {dacl_data['DownloadableAcl']['name']}")
        print(json.dumps(dacl_data["DownloadableAcl"], indent=4))
    else:
        error_message = response.json().get("ERSResponse", {}).get("messages", [{}])[0].get("title", "No error message provided")
        print(f"\n !!! Failed to create DACL: {dacl_data['DownloadableAcl']['name']}, Status Code: {response.status_code},\n Message: {error_message}")

def validate_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def validate_subnet(subnet):
    parts = subnet.split()
    if len(parts) != 2:
        return False
    ip, mask = parts
    return validate_ip(ip) and validate_ip(mask)

def get_validated_ips(prompt, current_ips):
    print(f"Current {prompt}: {', '.join(current_ips)}")
    while True:
        ips = input(f"Enter {prompt} (comma-separated, press Enter to keep current): ").strip()
        if not ips:
            return current_ips
        ips = ips.split(',')
        if all(validate_ip(ip.strip()) for ip in ips):
            return [ip.strip() for ip in ips]
        else:
            print("Invalid IP address format. Please try again.")

def get_validated_subnets(prompt, current_subnets):
    print(f"Current {prompt}: {', '.join(current_subnets)}")
    while True:
        subnets = input(f"Enter {prompt} (comma-separated, each pair separated by space, press Enter to keep current): ").strip()
        if not subnets:
            return current_subnets
        subnets = subnets.split(',')
        if all(validate_subnet(subnet.strip()) for subnet in subnets):
            return [subnet.strip() for subnet in subnets]
        else:
            print("Invalid subnet format. Please try again. Each subnet and wildcard mask should be separated by a space.")

def print_table(ad_server_ips, call_manager_ips, voice_subnets, sccm_server_ips, antivirus_server_ips, pre_auth_ips):
    table = PrettyTable()
    table.field_names = ["Server Type", "IP Addresses"]
    table.add_row(["AD Server IPs", ", ".join(ad_server_ips)])
    table.add_row(["Call Manager IPs", ", ".join(call_manager_ips)])
    table.add_row(["Voice Subnets", ", ".join(voice_subnets)])
    table.add_row(["SCCM Server IPs", ", ".join(sccm_server_ips)])
    table.add_row(["Antivirus Server IPs", ", ".join(antivirus_server_ips)])
    table.add_row(["Pre-Auth IPs", ", ".join(pre_auth_ips)])
    print(table)

def load_server_ips():
    if os.path.exists(IP_FILE):
        with open(IP_FILE, 'r') as file:
            return json.load(file)
    else:
        return {
            "ad_server_ips": ["192.168.1.1"],
            "call_manager_ips": ["192.168.2.1"],
            "voice_subnets": ["192.168.3.0 0.0.0.255"],
            "sccm_server_ips": ["192.168.4.1"],
            "antivirus_server_ips": ["192.168.5.1"],
            "pre_auth_ips": ["192.168.6.1"]
        }

def save_server_ips(server_ips):
    with open(IP_FILE, 'w') as file:
        json.dump(server_ips, file)

def retrieve_dacl_names(headers, ise_api_url):
    response = requests.get(ise_api_url, headers=headers, verify=False)
    if response.status_code == 200:
        total = response.json()["SearchResult"]["total"]
        dacl_list = response.json()["SearchResult"]["resources"]
        dacl_table = PrettyTable()
        dacl_table.field_names = ["Name", "Description"]
        dacl_details = []
        for dacl in dacl_list:
            dacl_name = dacl["name"]
            dacl_description = dacl.get("description", "No description")
            dacl_link = dacl["link"]["href"]
            dacl_table.add_row([dacl_name, dacl_description])
            dacl_details.append({"name": dacl_name, "description": dacl_description, "link": dacl_link})

        # If there are more DACLs than the initial response, fetch the rest
        while len(dacl_details) < total:
            next_page = len(dacl_details) // len(dacl_list) + 1
            paginated_response = requests.get(f"{ise_api_url}?page={next_page}", headers=headers, verify=False)
            if paginated_response.status_code == 200:
                paginated_dacl_list = paginated_response.json()["SearchResult"]["resources"]
                for dacl in paginated_dacl_list:
                    dacl_name = dacl["name"]
                    dacl_description = dacl.get("description", "No description")
                    dacl_link = dacl["link"]["href"]
                    dacl_table.add_row([dacl_name, dacl_description])
                    dacl_details.append({"name": dacl_name, "description": dacl_description, "link": dacl_link})
            else:
                print(f"Failed to retrieve additional DACL names. Status Code: {paginated_response.status_code}, Response: {paginated_response.text}")
                break

        print(dacl_table)
        return dacl_details
    else:
        print(f"Failed to retrieve DACL names. Status Code: {response.status_code}, Response: {response.text}")
        return []

def retrieve_and_save_dacls(headers, ise_api_url):
    dacl_details = retrieve_dacl_names(headers, ise_api_url)
    if not dacl_details:
        return

    dacl_data_list = []
    for dacl in dacl_details:
        dacl_url = dacl["link"]
        response = requests.get(dacl_url, headers=headers, verify=False)
        if response.status_code == 200:
            dacl_data = response.json()["DownloadableAcl"]
            dacl_data_list.append({
                "name": dacl_data["name"],
                "dacl": dacl_data["dacl"]
            })
        else:
            print(f"Failed to retrieve DACL details for {dacl['name']}. Status Code: {response.status_code}, Response: {response.text}")

    csv_file = "dacl_details.csv"
    with open(csv_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["name", "dacl"])
        writer.writeheader()
        writer.writerows(dacl_data_list)

    print(f"DACL details saved to {csv_file}")

def display_banner():
    banner = """
============================================================
                           Notice
============================================================
Privacy and Usage Disclaimer

This script is provided to assist with the management of 
Downloadable Access Control Lists (DACLs) on Cisco ISE. 
Please be aware that by using this tool, you assume all 
responsibility for any changes made to your network 
configuration. It is essential to ensure the privacy 
and security of your network data at all times.

Use this script at your own risk. The creators of this tool 
are not liable for any potential impacts on network 
performance or security. Always test in a controlled 
environment before applying any modifications to your 
production systems.

============================================================
============================================================
                DACL Management Script
============================================================
This script allows you to manage Downloadable Access Control 
Lists (DACLs) on Cisco ISE.You can perform the following 
actions:

1. Customize DACL based on Network Usecases (VOICE_DACL, PRE_AUTH)
2. Configure New DACL based on Custom Requirements.
3. Review Current DACL Templates.
4. Retrieve cCrrent DACL Names.
5. Retrieve All DACL contents and save to a CSV file.
============================================================
"""
    print(banner)

def main():
    display_banner()
    ise_server_ip = input("Enter your ISE PAN IP Address: ")
    username, password = get_credentials()
    ise_api_url = f"https://{ise_server_ip}:9060/ers/config/downloadableacl"
    
    # Encode the credentials for Basic Authentication
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Basic {encoded_credentials}"
    }

    if not test_credentials(headers, ise_api_url):
        return

    # Load server IPs from file or use default values
    server_ips = load_server_ips()
    ad_server_ips = server_ips["ad_server_ips"]
    call_manager_ips = server_ips["call_manager_ips"]
    voice_subnets = server_ips["voice_subnets"]
    sccm_server_ips = server_ips["sccm_server_ips"]
    antivirus_server_ips = server_ips["antivirus_server_ips"]
    pre_auth_ips = server_ips["pre_auth_ips"]

    # Define DACL templates
    dacl_templates = {
        "VOICE_DACL": {
            "description": "DACL for Cisco voice phone allowing necessary services",
            "dacl_template": (
                "#remark Allow DHCP\n"
                "permit udp any eq 68 any eq 67\n"
                "permit udp any eq 67 any eq 68\n"
                "#remark Allow DNS\n"
                "permit udp any any eq 53\n"
                "permit tcp any any eq 53\n"
                "#remark Allow NTP\n"
                "permit udp any any eq 123\n"
                "#remark Allow communication with Call Manager\n"
                "{call_manager_entries}\n"
                "#remark Allow RTP (Voice Traffic)\n"
                "{voice_subnet_entries}\n"
                "#remark Allow SCCP (Skinny Client Control Protocol) if used\n"
                "permit tcp any host {call_manager_ip} eq 2000\n"
                "#remark Allow TFTP for phone configuration and firmware\n"
                "permit udp any eq 69 any\n"
                "#remark Allow HTTP/HTTPS for phone services\n"
                "permit tcp any host {call_manager_ip} eq 80\n"
                "permit tcp any host {call_manager_ip} eq 443\n"
                "#remark Allow ICMP for troubleshooting\n"
                "permit icmp any any\n"
                "#remark Deny all other traffic\n"
                "deny ip any any"
            ),
            "daclType": "IP_AGNOSTIC"
        },
        "MACHINE_ONLY": {
            "description": "DACL for machine authentication only",
            "dacl_template": (
                "#remark Allow DHCP\n"
                "permit udp any eq 68 any eq 67\n"
                "permit udp any eq 67 any eq 68\n"
                "#remark Allow DNS\n"
                "permit udp any any eq 53\n"
                "permit tcp any any eq 53\n"
                "#remark Allow NTP\n"
                "permit udp any any eq 123\n"
                "#remark Allow communication with Active Directory (AD)\n"
                "{ad_server_entries}\n"
                "#remark Allow communication with SCCM\n"
                "{sccm_server_entries}\n"
                "#remark Allow communication with Antivirus Server\n"
                "{antivirus_server_entries}\n"
                "#remark Allow ICMP for troubleshooting\n"
                "permit icmp any any\n"
                "#remark Allow IP permit\n"
                "{pre_auth_ips}\n"
                "#remark Deny all other traffic\n"
                "deny ip any any"
            ),
            "daclType": "IP_AGNOSTIC"
        },
        "CUSTOM_DACL": {
            "description": "DACL for custom use",
            "dacl_template": "permit ip any any",
            "daclType": "IP_AGNOSTIC"
        }
    }

    while True:
        # Print the user inputs in a table
        print("\nCurrent Server IPs:")
        print_table(ad_server_ips, call_manager_ips, voice_subnets, sccm_server_ips, antivirus_server_ips, pre_auth_ips)

        # Ask user to choose an option
        print("\nChoose an option:")
        print("1. Update the list of Customer Server IPs")
        print("2. Review current DACL templates")
        print("3. Create a DACL")
        print("4. Retrieve current DACL names")
        print("5. Retrieve current All DACL conents and save to CSV")
        print("6. Return to main menu")
        print("7. Exit")
        choice = input("Enter your choice (1, 2, 3, 4, 5, 6, or 7): ")

        if choice == "":
            print("Returning to main menu...")
            continue

        if choice == "1":
            # Update the list of IPs
            ad_server_ips = get_validated_ips("AD Server IPs", ad_server_ips)
            call_manager_ips = get_validated_ips("Call Manager IPs", call_manager_ips)
            voice_subnets = get_validated_subnets("Voice Subnets and Wildcard Masks", voice_subnets)
            sccm_server_ips = get_validated_ips("SCCM Server IPs", sccm_server_ips)
            antivirus_server_ips = get_validated_ips("Antivirus Server IPs", antivirus_server_ips)
            pre_auth_ips = get_validated_ips("list of IPs that would like to be permitted by IP in Pre-Auth state", pre_auth_ips)

            # Save the updated IPs to file
            server_ips = {
                "ad_server_ips": ad_server_ips,
                "call_manager_ips": call_manager_ips,
                "voice_subnets": voice_subnets,
                "sccm_server_ips": sccm_server_ips,
                "antivirus_server_ips": antivirus_server_ips,
                "pre_auth_ips": pre_auth_ips
            }
            save_server_ips(server_ips)

            # Print the updated user inputs in a table
            print("\nUpdated User Inputs:")
            print_table(ad_server_ips, call_manager_ips, voice_subnets, sccm_server_ips, antivirus_server_ips, pre_auth_ips)
        elif choice == "2":
            # Show current DACL templates
            print("\nCurrent DACL Templates:")
            for i, template_name in enumerate(dacl_templates.keys(), 1):
                print(f"{i}. {template_name}")
            print("4. Return to main menu")
            choice = input("Enter your choice (1, 2, 3, or 4): ")

            if choice == "":
                print("Returning to main menu...")
                continue

            if choice in map(str, range(1, len(dacl_templates) + 1)):
                selected_template_name = list(dacl_templates.keys())[int(choice) - 1]
                selected_template = dacl_templates[selected_template_name]
                print(f"\nYou selected: {selected_template_name}")
                print(selected_template["dacl_template"])
            input("\nPress Enter to return to the main menu...")
        elif choice == "3":
            # Ask user to choose a DACL template
            print("\nChoose a DACL template to create:")
            for i, template_name in enumerate(dacl_templates.keys(), 1):
                print(f"{i}. {template_name}")
            print("4. Return to main menu")
            choice = input("Enter your choice (1, 2, 3, or 4): ")

            if choice == "":
                print("Returning to main menu...")
                continue

            if choice in map(str, range(1, len(dacl_templates) + 1)):
                selected_template_name = list(dacl_templates.keys())[int(choice) - 1]
                selected_template = dacl_templates[selected_template_name]
                print(f"\nYou selected: {selected_template_name}")

                if selected_template_name == "VOICE_DACL":
                    dacl_name = input("Enter DACL name: ")

                    dacl_entries = set()
                    for ip in call_manager_ips:
                        dacl_entries.add(f"permit tcp any host {ip.strip()} eq 2000")
                        dacl_entries.add(f"permit tcp any host {ip.strip()} eq 2443")
                        dacl_entries.add(f"permit tcp any host {ip.strip()} range 5060 6061")
                        dacl_entries.add(f"permit udp any host {ip.strip()} range 5060 6061")
                        dacl_entries.add(f"permit udp host {ip.strip()} range 16384 32767 any")
                        dacl_entries.add(f"permit tcp any host {ip.strip()} eq 2000")
                        dacl_entries.add(f"permit tcp any host {ip.strip()} eq 80")
                        dacl_entries.add(f"permit tcp any host {ip.strip()} eq 443")

                    call_manager_entries = "\n".join(sorted(dacl_entries))

                    voice_subnet_entries = []
                    for subnet in voice_subnets:
                        voice_subnet, wildcard_mask = subnet.strip().split()
                        voice_subnet_entries.append(f"permit udp {voice_subnet} {wildcard_mask} range 16384 32767")

                    voice_subnet_entries = "\n".join(voice_subnet_entries)

                    dacl = selected_template["dacl_template"].format(
                        call_manager_entries=call_manager_entries,
                        voice_subnet_entries=voice_subnet_entries,
                        call_manager_ip="{call_manager_ip}"
                    )

                    # Print the DACL template for the user to review
                    print("\nDACL Template:\n")
                    print(dacl)

                    dacl_data = {
                        "DownloadableAcl": {
                            "name": dacl_name,
                            "description": selected_template["description"],
                            "dacl": dacl,
                            "daclType": selected_template["daclType"]
                        }
                    }
                elif selected_template_name == "MACHINE_ONLY":
                    dacl_name = input("Enter DACL name: ")

                    ad_server_entries = set()
                    for ip in ad_server_ips:
                        ad_server_entries.add(f"permit tcp any host {ip.strip()} eq 389")
                        ad_server_entries.add(f"permit tcp any host {ip.strip()} eq 636")
                        ad_server_entries.add(f"permit tcp any host {ip.strip()} range 3268 3269")

                    sccm_server_entries = set()
                    for ip in sccm_server_ips:
                        sccm_server_entries.add(f"permit tcp any host {ip.strip()} eq 80")
                        sccm_server_entries.add(f"permit tcp any host {ip.strip()} eq 443")
                        sccm_server_entries.add(f"permit tcp any host {ip.strip()} eq 445")
                        sccm_server_entries.add(f"permit tcp any host {ip.strip()} eq 135")
                        sccm_server_entries.add(f"permit udp any host {ip.strip()} eq 69")

                    antivirus_server_entries = set()
                    for ip in antivirus_server_ips:
                        antivirus_server_entries.add(f"permit tcp any host {ip.strip()} eq 80")
                        antivirus_server_entries.add(f"permit tcp any host {ip.strip()} eq 443")

                    pre_auth_entries = set()
                    for ip in pre_auth_ips:
                        pre_auth_entries.add(f"permit ip any host {ip.strip()}")

                    ad_server_entries = "\n".join(sorted(ad_server_entries))
                    sccm_server_entries = "\n".join(sorted(sccm_server_entries))
                    antivirus_server_entries = "\n".join(sorted(antivirus_server_entries))
                    pre_auth_entries = "\n".join(sorted(pre_auth_entries))

                    dacl = selected_template["dacl_template"].format(
                        ad_server_entries=ad_server_entries,
                        sccm_server_entries=sccm_server_entries,
                        antivirus_server_entries=antivirus_server_entries,
                        pre_auth_ips=pre_auth_entries
                    )

                    # Print the DACL template for the user to review
                    print("\nDACL Template:\n")
                    print(dacl)

                    dacl_data = {
                        "DownloadableAcl": {
                            "name": dacl_name,
                            "description": selected_template["description"],
                            "dacl": dacl,
                            "daclType": selected_template["daclType"]
                        }
                    }
                elif selected_template_name == "CUSTOM_DACL":
                    dacl_name = input("Enter DACL name: ")
                    description = input("Enter description: ")
                    print("Enter DACL entries (type 'done' when finished):")
                    dacl_entries = []
                    while True:
                        entry = input()
                        if entry.lower() == 'done':
                            break
                        dacl_entries.append(entry)
                    dacl = "\n".join(dacl_entries)

                    dacl_data = {
                        "DownloadableAcl": {
                            "name": dacl_name,
                            "description": description,
                            "dacl": dacl,
                            "daclType": selected_template["daclType"]
                        }
                    }

                print("\nPlease confirm the DACL details:")
                print("\nDACL Syntax:\n")
                print(dacl)
                confirm = input("Do you want to create this DACL? (yes/no): ")
                if confirm.lower() == "yes":
                    create_dacl(dacl_data, headers, ise_api_url)
                else:
                    print("DACL creation cancelled.")
            elif choice == "4":
                print("Returning to main menu...")
                continue
            else:
                print("Invalid choice. Please try again.")
        elif choice == "4":
             # Retrieve current DACL names
            dacl_details = retrieve_dacl_names(headers, ise_api_url)
        elif choice == "5":
            retrieve_and_save_dacls(headers, ise_api_url)
        elif choice == "6":
            print("Returning to main menu...")
            continue
        elif choice == "7":
            print("Exiting the program...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()