import logging
import pathlib
from typing import List
import requests
import cloudflare
import configparser
import pandas as pd
import os
import time

class App:
    def __init__(self):        
        self.name_prefix = f"[GONKPihole]"
        self.logger = logging.getLogger("main")
        self.whitelist = self.loadWhitelist()

    def loadWhitelist(self):
        return open("whitelist.txt", "r").read().split("\n")

    def run(self):
        logging.basicConfig(level=logging.INFO)

        config = configparser.ConfigParser()
        config.read('config.ini')

        #check tmp dir
        os.makedirs("./tmp", exist_ok=True)

        all_domains = []
        for list_name in config["Lists"]:
            self.logger.info("Setting list " +  list_name)
            
            self.download_file(config["Lists"][list_name], list_name)
            domains = self.convert_to_domain_list(list_name)
            all_domains = all_domains + domains

        unique_domains = pd.unique(pd.array(all_domains))

        cf_policies = cloudflare.get_firewall_policies(self.name_prefix)

        if len(cf_policies) == 0 or cf_policies[0]['name'].startswith(f"{self.name_prefix}_B"):
            new_name_prefix = f"{self.name_prefix}_A"
            old_name_prefix = f"{self.name_prefix}_B"
        else:
            new_name_prefix = f"{self.name_prefix}_B"
            old_name_prefix = f"{self.name_prefix}_A"

        # Create new lists
        new_cf_lists = []
        try:
            for chunk in self.chunk_list(unique_domains, 1000):
                list_name = f"{new_name_prefix} {len(new_cf_lists) + 1}"
                self.logger.info(f"Creating list {list_name}")
                _list = cloudflare.create_list(list_name, chunk)
                new_cf_lists.append(_list)
                time.sleep(1)
        except Exception as e:
            self.logger.error(f"Error creating new lists: {e}")
            return  # Exit if there's an error creating new lists

        # Create new policy
        try:
            self.logger.info("Creating new firewall policy")
            new_cf_policy = cloudflare.create_gateway_policy(f"{new_name_prefix} Block Ads", [l["id"] for l in new_cf_lists])
        except Exception as e:
            self.logger.error(f"Error creating new firewall policy: {e}")
            # Clean up newly created lists if policy creation fails
            for l in new_cf_lists:
                self.logger.info(f"Deleting list {l['name']} due to policy creation failure")
                cloudflare.delete_list(l["id"])
            return  # Exit if there's an error creating the new policy

        # Delete old lists and policy
        old_cf_lists = cloudflare.get_lists(old_name_prefix)
        old_cf_policies = cloudflare.get_firewall_policies(old_name_prefix)

        if old_cf_policies:
            self.logger.info(f"Deleting old firewall policy {old_cf_policies[0]['name']}")
            cloudflare.delete_firewall_policy(old_cf_policies[0]["id"])

        for l in old_cf_lists:
            self.logger.info(f"Deleting old list {l['name']}")
            cloudflare.delete_list(l["id"])
            time.sleep(1)

        self.logger.info("Done")

    def is_valid_hostname(self, hostname):
        import re
        if len(hostname) > 255:
            return False
        hostname = hostname.rstrip(".")
        allowed = re.compile('^[a-z0-9]([a-z0-9-_]{0,61}[a-z0-9])?$',re.IGNORECASE)
        labels = hostname.split(".")
        
        # the TLD must not be all-numeric
        if re.match(r"^[0-9]+$", labels[-1]):
            return False
        
        return all(allowed.match(x) for x in labels)

    def download_file(self, url, name):
        self.logger.info(f"Downloading file from {url}")

        r = requests.get(url, allow_redirects=True)

        path = pathlib.Path("tmp/" + name)
        open(path, "wb").write(r.content)

        self.logger.info(f"File size: {path.stat().st_size}")

    def convert_to_domain_list(self, file_name: str):
        with open("tmp/"+file_name, "r") as f:
            data = f.read()

        # check if the file is a hosts file or a list of domain
        is_hosts_file = False
        for ip in ["127.0.0.1", "::1", "0.0.0.0"]:
            if ip in data:
                is_hosts_file = True
                break

        domains = []
        for line in data.splitlines():

            
            # skip comments and empty lines
            if line.startswith("#") or line.startswith(";") or line == "\n" or line == "":
                continue

            if is_hosts_file:
                # remove the ip address and the trailing newline
                domain = line.split()[1].rstrip()

                # skip the localhost entry
                if domain == "localhost":
                    continue

            else:
                domain = line.rstrip()

            #Check whitelist
            if domain in self.whitelist:
                continue
            

            domains.append(domain)

        self.logger.info(f"Number of domains: {len(domains)}")

        return domains



    def chunk_list(self, _list: List[str], n: int):
        for i in range(0, len(_list), n):
            yield _list[i : i + n]


if __name__ == "__main__":


    app = App()
    app.run()
