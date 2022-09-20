from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import requests
import os
import base64

# Define a superglobal list of ACLs as objects as caught by the decorator controller
known_acls = list()

class Controller(BaseHTTPRequestHandler):
    from modules.acl import acl_sync, acl_finalize, check_changes
    from modules.nat import nat_sync, nat_finalize, nat_check
    from modules.service import service_sync

    def process(self, path, request):

        if path == "/acl/sync":            
            result = self.acl_sync(request)
            if result["status"]["error"] == "none":
                self.track_acls(request)
        elif path == "/acl/finalize":
            result = self.acl_finalize(request)
            if result["finalized"] == True:
                self.track_acls(request)
        elif path == "/nat/sync":
            result = self.nat_sync(request, known_acls)
        elif path == "/nat/finalize":
            result = self.nat_finalize(request, known_acls)
        elif path == "/service/sync":
            result = self.service_sync(request, known_acls)
        elif path == "/service/finalize":
            result = self.service_finalize(request, known_acls)
        else:
            result = None

        return result

    def tnsr_api_call(self, endpoint, payload, method, type):
        requests.packages.urllib3.disable_warnings()
        
        headers = {
            "Accept" : "application/yang-data+json", 
            "Content-Type" : "application/yang-data+"+type, 
        }
        request_url = (server+"/restconf"+endpoint)
        
        if method == "get":
            api_call = requests.get(request_url, data=payload, verify="ca", headers=headers, cert=("cert", "private_key"))
        elif method == "post":
            api_call = requests.post(request_url, data=payload, verify="ca", headers=headers, cert=("cert", "private_key"))
        elif method == "put":
            api_call = requests.put(request_url, data=payload, verify="ca", headers=headers, cert=("cert", "private_key"))
        elif method == "patch":
            api_call = requests.patch(request_url, data=payload, verify="ca", headers=headers, cert=("cert", "private_key"))
        elif method == "delete":
            api_call = requests.delete(request_url, data=payload, verify="ca", headers=headers, cert=("cert", "private_key"))
        else:
            return

        print("TNSR Return Code: "+str(api_call.status_code))

        return api_call

    def track_acls(self, request):
        global known_acls

        # Check if ACL exists in list
        in_list = False
        list_index = 0
        for i in known_acls:
            if request["parent"]["metadata"]["name"] == i["metadata"]["name"]:
                in_list = True
                break
            list_index += 1

        # Save the ACL if not finalizing
        if not request["finalizing"]:
            # If ACL not in list, add to list. If it is in the list, replace it.
            if not in_list:
                known_acls.append(request["parent"])
                print("tnsrACL discovered and recorded!")
            else:
                known_acls[list_index]=request["parent"]
                print("tnsrACL already recorded, replacing.")

        # Delete the ACL if finalizing
        else:
            if not in_list:
                print("tnsrACL finalized but was never recorded, skipping")
            else:
                known_acls.pop(list_index)
                print("tnsrACL finalized, removed entry from list!")

        #print(json.dumps(known_acls)) # DEBUG

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers.get("content-length"))))
        path = self.path
        # print(path)
        # print(request)

        result = self.process(path, request)
        print (json.dumps(result))

        self.send_response(200) # Send an all-good

        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

# Define environment variables
server = os.environ.get('SERVER')
user = os.environ.get('REMOTE_USER')

f = open("ca", "w")
f.write(base64.b64decode(os.environ.get('CA')).decode("ascii"))
f.close()

f = open("cert", "w")
f.write(base64.b64decode(os.environ.get('CERT')).decode("ascii"))
f.close()

f = open("private_key", "w")
f.write(base64.b64decode(os.environ.get('PRIVATE_KEY')).decode("ascii"))
f.close()

# Start controller
HTTPServer(("", 80), Controller).serve_forever()