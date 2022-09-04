from email.mime import base
import logging
import json
import msal
import requests
import os
import time

from zipfile import ZipFile

import xml.etree.ElementTree as ElementTree

from secrets import ADDITIONAL_APP_PROPERTIES, APP_ID, APP_NAME, APP_SECRET, INTUNEWIN_DIR, TENANT


class appIDIsEmptyStr(Exception):
    def __init__(self):
        self.message = f"appID cannot be empty string"
        super().__init__(self.message)

class appSecretIsEmptyStr(Exception):
    def __init__(self):
        self.message = f"appSecret cannot be empty string"
        super().__init__(self.message)

class tenantIsEmptyStr(Exception):
    def __init__(self):
        self.message = f"tenant cannot be empty string"
        super().__init__(self.message)

# update_non_existing_inplace will add the to_add to original_dict if they don't exist. will not override
def update_non_existing_inplace(original_dict, to_add) -> dict:
    new = original_dict
    for key in to_add.keys():
        if key not in new:
            new[key] = to_add[key]
    return new

# extract_intune_win_portal will extract 
def extract_intune_win_portal(intunewin_dir: str, app_name: str):
    with ZipFile(f"{intunewin_dir}//{app_name}.portal.intunewin", 'r') as f:
        #extract in different directory
        try: 
            f.extractall('IntuneWinPackage')
        except Exception as e:
            raise e

def parse_detection_xml(intunewin_dir: str, app_name: str) -> dict:
    extract_intune_win_portal(intunewin_dir, app_name=app_name)
    tree = ElementTree.parse(f"{intunewin_dir}/IntuneWinPackage/Metadata/Detection.xml")
    return {
        "name": tree.find("FileName").text,
        "size": int(tree.find("UnencryptedContentSize").text),
        "sizeEncrypted": os.path.getsize(f"{intunewin_dir}/{app_name}.intunewin")
    }

class graphClient:
    def __init__(self, baseURI: str="", apiVersion: str="beta", appID="", appSecret="", tenant="", scopes=[]):
        self.baseURI = baseURI
        self.apiVersion = apiVersion
        self.appID = appID
        self.appSecret = appSecret
        self.scopes = scopes
        self.headers = None

        self.tenant = tenant

        if self.tenant == "":
            raise tenantIsEmptyStr
        self.authority = f"https://login.microsoftonline.com/{self.tenant}"

        self.token = ""

        if self.baseURI == "":
            self.baseURI = "https://graph.microsoft.com/{v}/{e}"
        if self.appID == "":
            raise appIDIsEmptyStr
        if self.appSecret == "":
            raise appSecretIsEmptyStr
        if self.scopes == []:
            logging.info(f"setting default scope")
            self.scopes = ["https://graph.microsoft.com/.default"]

        app = msal.ConfidentialClientApplication(
            self.appID, authority=self.authority, client_credential = self.appSecret)
        self.token = app.acquire_token_silent(self.scopes, account=None)
        if not self.token:
            self.token = app.acquire_token_for_client(scopes=self.scopes)
        self.headers = {'Authorization': 'Bearer ' + self.token['access_token']}

    def get(self, endpoint):
        dest = self.baseURI.format(v=self.apiVersion, e=endpoint)
        return requests.get(dest, headers=self.headers).json()

    def post(self, endpoint, body):
        dest = self.baseURI.format(v=self.apiVersion, e=endpoint)
        print(dest)
        headers = self.headers
        headers['Content-type'] = "application/json"
        return requests.post(dest, json=body, headers=headers).json()

    def patch(self, endpoint, body):
        dest = self.baseURI.format(v=self.apiVersion, e=endpoint)
        headers = self.headers
        headers['Content-type'] = "application/json"
        return requests.patch(dest, json=body, headers=headers).json()

    def delete(self, endpoint):
        dest = self.baseURI.format(v=self.apiVersion, e=endpoint)
        headers = self.headers
        headers["Content-Type"] = "application/json"
        return requests.delete(dest, headers=headers)

    def delete_app(self, app_id):
        return self.delete(f"/deviceAppManagement/mobileApps/{app_id}")


    def list_intune_apps(self, only="#microsoft.graph.win32LobApp") -> list:
        apps = []
        if not only:
            return self.get("deviceAppManagement/mobileApps")["value"]
        for v in self.get("deviceAppManagement/mobileApps")["value"]:
            if v["@odata.type"] == only:
                apps.append(v)
        return apps

    def entry_already_exists(self, new_entry, app) -> bool:
        # naive attempt to detect if we already have an app entry
        return (
            new_entry["setupFilePath"] == app["setupFilePath"] and
            new_entry["fileName"] == app["fileName"] and
            new_entry["displayName"] == app["displayName"]
        )

    def get_app_upload_uri(self, size_info: dict, entry_id) -> str:
        uri = f"deviceAppManagement/mobileApps/{entry_id}/microsoft.graph.win32lobapp/contentVersions/1/files" 
        content_req_resp = self.post(uri, size_info)
        print(content_req_resp)
        for i in range(5):
            uc = f"deviceAppManagement/mobileApps/{entry_id}/microsoft.graph.win32lobapp/contentVersions/1/files/{content_req_resp['id']}"
            print(uc)
            uri_check = self.get(uc)
            if "azureStorageUri" in uri_check:
                break
            time.sleep(5)
        return uri_check["azureStorageUri"]

    # huge shoutout to https://www.cyberdrain.com/automating-with-powershell-automatically-uploading-applications-to-intune-tenants/
    # for providing good example code in powershell
    def create_intune_app_entry(self, intunewin_dir: str, app_name: str, additional_properties: dict) -> dict:
        # (TODO:discentem) Split this up into multiple functions. Shouldn't assume it's coming from this json file
        intunewin_dir = intunewin_dir.removesuffix("/")
        with open(f"{intunewin_dir}/{app_name}.intunewin.json") as f:
            new_entry = json.load(f)["App"]
            # depending on how the .intunewin file is generated, we might need extra properties to be injected
            # additional_properties can be any property from 
            #   https://docs.microsoft.com/en-us/graph/api/resources/intune-apps-win32lobapp?view=graph-rest-1.0
            # additional_properties supports any type that can be automatically parsed by json.dumps()
            new_entry = update_non_existing_inplace(new_entry, additional_properties)

            size_info = parse_detection_xml(intunewin_dir, app_name=app_name)
            
            existing_apps = self.list_intune_apps()
            for app in existing_apps:
                if self.entry_already_exists(new_entry, app):
                    # return self.patch(f"deviceAppManagement/mobileApps/{app['id']}", new_entry)
                    # we should patch instead of delete but this is easier for now
                   self.delete_app(app["id"])
            post_new_app = self.post("deviceAppManagement/mobileApps", new_entry)
            
            '''
            size_info = {
                "name": "whatever",
                "size": 2324,
                "sizeEncrypted": 3423
            }
            '''
            # this doesn't upload yet, but now we get the uri of where we should upload to
            return self.get_app_upload_uri(size_info, post_new_app['id']) 

def main():
    # remove timestamps
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # secrets retrieved from secrets.py
    client = graphClient(appID=APP_ID, appSecret=APP_SECRET, tenant=TENANT)
    
    resp = client.create_intune_app_entry(INTUNEWIN_DIR, APP_NAME, additional_properties=ADDITIONAL_APP_PROPERTIES)
    logging.info(resp)
    # logging.info(client.list_intune_apps())
    

main()