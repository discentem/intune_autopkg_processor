from email.mime import base
import logging
import json
import msal
import requests
import os
import time
import subprocess
from zipfile import ZipFile
import xml.etree.ElementTree as ElementTree

from azure.identity import ClientSecretCredential
import azure.storage.blob
import urllib.parse

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

def run_live(command):
  """
  Run a subprocess with real-time output.
  Can optionally redirect stdout/stderr to a log file.
  Returns only the return-code.
  """
  # Validate that command is not a string
  if isinstance(command, str):
    # Not an array!
    raise TypeError('Command must be an array')
  # Run the command
  logging.info(command)
  if not command:
    exit(1)
  proc = subprocess.Popen(command,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
  while proc.poll() is None:
    l = proc.stdout.readline()
    logging.info(l),
  logging.info(proc.stdout.read())
  return proc.returncode

# update_non_existing_inplace will add the to_add to original_dict if they don't exist. will not override
def update_non_existing_inplace(original_dict, to_add) -> dict:
    new = original_dict
    for key in to_add.keys():
        if key not in new:
            new[key] = to_add[key]
    return new

# extract_intune_win_portal will extract the .portal.intunewin which is just a zip file
def extract_intune_win_portal(intunewin_dir: str, app_name: str):
    with ZipFile(f"{intunewin_dir}//{app_name}.portal.intunewin", 'r') as f:
        #extract in different directory
        try: 
            f.extractall('IntuneWinPackage')
        except Exception as e:
            raise e


'''
        $EncBody = @{
        fileEncryptionInfo = @{
            encryptionKey        = $intunexml.ApplicationInfo.EncryptionInfo.EncryptionKey
            macKey               = $intunexml.ApplicationInfo.EncryptionInfo.MacKey
            initializationVector = $intunexml.ApplicationInfo.EncryptionInfo.InitializationVector
            mac                  = $intunexml.ApplicationInfo.EncryptionInfo.Mac
            profileIdentifier    = $intunexml.ApplicationInfo.EncryptionInfo.ProfileIdentifier
            fileDigest           = $intunexml.ApplicationInfo.EncryptionInfo.FileDigest
            fileDigestAlgorithm  = $intunexml.ApplicationInfo.EncryptionInfo.FileDigestAlgorithm
        }
        '''

def parse_detection_xml(intunewin_dir: str, app_name: str) -> dict:
    extract_intune_win_portal(intunewin_dir, app_name=app_name)
    tree = ElementTree.parse(f"{intunewin_dir}/IntuneWinPackage/Metadata/Detection.xml")
    encryption_info = tree.find("EncryptionInfo")
    return {
        "name": tree.find("FileName").text,
        "size": int(tree.find("UnencryptedContentSize").text),
        "sizeEncrypted": os.path.getsize(f"{intunewin_dir}/{app_name}.intunewin"),
        # used for updating content metadata
        "encryptionKey": encryption_info.find("EncryptionKey").text,
        "macKey": encryption_info.find("MacKey").text,
        "initializationVector": encryption_info.find("InitializationVector").text,
        "mac": encryption_info.find("Mac").text,
        "profileIdentifier": encryption_info.find("ProfileIdentifier").text,
        "fileDigest": encryption_info.find("FileDigest").text,
        "fileDigestAlgorithm": encryption_info.find("FileDigestAlgorithm").text
    }

# borrowed from https://github.com/rahulbagal/upload-file-azure-sas-url/blob/master/azure_sas_upload.py
def parse_storage_sas_url(sas_url):
    o = urllib.parse.urlparse(sas_url)
    # Remove first / from path
    if o.path[0] == '/':
        container_name = o.path[1:]
    else:
        container_name = o.path
    storage_account = o.scheme + "://" + o.netloc + "/"
    return {
        "container_name": container_name, 
        "storage_account": storage_account
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

        token_credential = ClientSecretCredential(
            self.tenant,
            self.appID,
            self.appSecret
        )
    def get(self, endpoint, content_type=""):
        dest = self.baseURI.format(v=self.apiVersion, e=endpoint)
        headers = self.headers
        if content_type != "":
            headers['Content-type'] = content_type
        return requests.get(dest, headers=headers).json()

    def post(self, endpoint, body):
        dest = self.baseURI.format(v=self.apiVersion, e=endpoint)
        # logging.info("POST", dest)
        headers = self.headers
        headers['Content-type'] = "application/json"
        p = requests.post(dest, json=body, headers=headers)
        try:
            print(p.json())
            return p.json()
        except:
            print(p)

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

    def upload_app(self, intunewin_dir, app_name, app_content, entry_id, file_encryption_info, azure_storage_uri, original_entry, azcopy_path="/usr/local/bin/azcopy"):
        # shell out to azcopy for now
        cmd = [azcopy_path]
        args = ["cp", f"{intunewin_dir}/IntuneWinPackage/Contents/IntunePackage.intunewin", azure_storage_uri, "--block-size-mb", "1"] #"--output-type", "'json'"]
        cmd.extend(args)
        rc = run_live(cmd)
        if rc != 0:
            return rc


        commit_uri = f"deviceAppManagement/mobileApps/{entry_id}/microsoft.graph.win32lobapp/contentVersions/1/files/{app_content['id']}/commit"
        '''
        file_encryption_info = {
            "encryptionKey": "",
            "macKey": "",
            "initializationVector": "",
            "mac": "",
            "profileIdentifier": "",
            "fileDigest": "",
            "fileDigestAlgorithm": ""
        }
        '''
        logging.info("file_encryption info:\n")
        logging.info(file_encryption_info)
        commit_req = self.post(commit_uri, file_encryption_info)
        print(commit_req)
        logging.info(f"Waiting for commit results for {app_name}")

        for i in range(5):
            uri = f"/deviceAppManagement/mobileApps/{entry_id}/microsoft.graph.win32lobapp/contentVersions/1/files/{app_content['id']}"
            commit_state = self.get(uri, content_type="application/json")
            print(commit_state)
            wait_statuses = ["commitFilePending", "azureStorageUriRequestSuccess", "commitFileFailed"]
            if "fail" in commit_state['uploadState'] or commit_state['uploadState'] in wait_statuses:
                logging.info("commit still pending... trying again in 5 seconds")
                time.sleep(5)
                continue

            logging.info("metadata was committed successfully")
            break
        
        commit_finalize = self.patch(f"/deviceAppManagement/mobileApps/{entry_id}", {
            "@odata.type": "#microsoft.graph.win32lobapp",
            "committedContentVersion": "1",
        })
        logging.info(commit_finalize)
        logging.info(f"{app_name} is ready for assignment")

        return 0

        # TODO(discentem): post content info to signal app upload is complete

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

    def get_app_content(self, size_info: dict, entry_id) -> dict:
        return self.post(f"deviceAppManagement/mobileApps/{entry_id}/microsoft.graph.win32lobapp/contentVersions/1/files", size_info)

    def get_app_upload_uri(self, app_content, entry_id) -> str:
        # TODO(discentem): use proper retry library
        for i in range(5):
            uc = f"deviceAppManagement/mobileApps/{entry_id}/microsoft.graph.win32lobapp/contentVersions/1/files/{app_content['id']}"
            print(uc)
            uri_check = self.get(uc)
            if uri_check['azureStorageUri'] == None or uri_check['uploadState'] != "azureStorageUriRequestPending":
                time.sleep(5)
                print(uri_check)
                continue
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

            detection_xml = parse_detection_xml(intunewin_dir, app_name=app_name)
            print(detection_xml)
            
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
            entry_id = post_new_app['id']
            app_content = self.get_app_content({
                "name": detection_xml["name"],
                "size": detection_xml["size"],
                "sizeEncrypted": detection_xml["sizeEncrypted"]
            }, entry_id)
            print(app_content)
            azure_uri = self.get_app_upload_uri(app_content, entry_id) 
            return self.upload_app(
                intunewin_dir, 
                app_name, 
                app_content, 
                entry_id, 
                {
                    "fileEncryptionInfo": {
                        "encryptionKey": detection_xml["encryptionKey"],
                        "macKey": detection_xml["macKey"],
                        "initializationVector": detection_xml["initializationVector"],
                        "mac": detection_xml["mac"],
                        "profileIdentifier": detection_xml["profileIdentifier"],
                        "fileDigest": detection_xml["fileDigest"],
                        "fileDigestAlgorithm": detection_xml["fileDigestAlgorithm"]
                    }
                }, 
                azure_uri,
                new_entry
            )

def main():
    # remove timestamps
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    # secrets retrieved from secrets.py
    client = graphClient(appID=APP_ID, appSecret=APP_SECRET, tenant=TENANT)
    
    resp = client.create_intune_app_entry(INTUNEWIN_DIR, APP_NAME, additional_properties=ADDITIONAL_APP_PROPERTIES)
    logging.info(resp)
    # logging.info(client.list_intune_apps())
    

main()