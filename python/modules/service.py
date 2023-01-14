def service_sync(self, request, known_acls):
    import json
    import random
    import string

    print("SERVICE SYNC")
    # DEBUG
    #print(json.dumps(request))

    # Verify there is a matching tnsrACL and fetch it
    tnsracl_object = None
    for i in known_acls:
        if request["object"]["metadata"]["annotations"]["tnsr.burrell.tech/tnsrACL"] == i["metadata"]["name"]:
            tnsracl_object = i
            break

    # If there is no tnsrACL object, bail out but retry often
    if tnsracl_object is None:
        result = {
            "resyncAfterSeconds": 10
        }
    # If there is a tnsrACL object, create the tnsrNAT resource 
    else:
        attachments = list()
        index = 0
        for i in request["object"]["spec"]["ports"]:
            attachment = {
                "apiVersion": "burrell.tech/v1",
                "kind": "tnsrNAT",
                "metadata": {
                    "name": request["object"]["metadata"]["name"]+"-"+str(index)
                },
                "spec": {
                    "externalPort": i["port"],
                    "localPort": i["port"],
                    "natInt": tnsracl_object["spec"]["interface"],
                    "localIP": request["object"]["status"]["loadBalancer"]["ingress"][0]["ip"],
                    "protocol": i["protocol"].lower(),
                    "tnsrACL": request["object"]["metadata"]["annotations"]["tnsr.burrell.tech/tnsrACL"]
                }
            }
            attachments.append(attachment)
            index += 1


        result = {
            "resyncAfterSeconds": 120, 
            "attachments": attachments
        }
    
    return result
