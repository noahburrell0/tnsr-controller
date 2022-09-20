def nat_sync(self, request, known_acls):
    import json

    nat_created = False

    print("NAT SYNC")
    # DEBUG
    # print(json.dumps(request))

    # Check existing NAT and ACL entries against the request
    check_results = self.nat_check(
        request["parent"]["spec"]["tnsrACL"],
        request["parent"]["spec"]["natInt"],
        request["parent"]["spec"]["externalPort"],
        request["parent"]["spec"]["localPort"],
        request["parent"]["spec"]["protocol"],
        request["parent"]["spec"]["localIP"],
        request["parent"]["metadata"]["uid"],
        known_acls
    )

    print(json.dumps(check_results, indent=4)) # DEBUG

    # Remove a conflicting NAT entry if there is one
    if check_results["nat_rule_matches"] == False and check_results["nat_rule_conflict"] is not None:
        print("REMOVING CONFLICTING NAT RULE: "+json.dumps(check_results["nat_rule_conflict"], indent=4))
        remove_nat = check_results["nat_rule_conflict"]
        remove_nat_result = self.tnsr_api_call(
            "/data/netgate-nat:nat-config/netgate-nat:static/netgate-nat:mapping-table/netgate-nat:mapping-entry="+remove_nat["transport-protocol"]+","+remove_nat["local-address"]+","+remove_nat["local-port"]+","+remove_nat["external-address"]+","+remove_nat["external-port"]+","+remove_nat["route-table-name"],
            "", "delete", "json"
        )

        # If remove successful, set the conflict to none
        if remove_nat_result.status_code == 204:
            check_results["nat_rule_conflict"] = None

    # Bail out if there is a conflict (still)
    if check_results["nat_rule_conflict"] is not None:
        result = {
            "status": {
                "error": "There is a NAT rule conflict that cannot be reconciled. Please remove the conflicting NAT rule manually in TNSR."
            }
        }
        return result

    # Delete ACL rule if one exists but it does not match the desired state
    if check_results["acl_rule"] is not None and not check_results["acl_rule_matches"]:
        print("REMOVING OUT OF SYNC ACL RULE: "+json.dumps(check_results["acl_rule"], indent=4))
        remove_acl = check_results["acl_rule"]
        remove_acl_result = self.tnsr_api_call(
            "/data/netgate-acl:acl-config/netgate-acl:acl-table/netgate-acl:acl-list="+check_results["acl_object"]["spec"]["name"]+"/netgate-acl:acl-rules/netgate-acl:acl-rule="+remove_acl["sequence"],
            "", "delete", "json"
        )        

        # If remove successful, set the acl rule to none, otherwise bail out
        if remove_acl_result.status_code == 204:
            check_results["acl_rule"] = None
        else:
            result = {
                "status": {
                    "error": "There is an out-of-sync ACL rule that connot be reconciled. Please remove the conflicting ACL rule manually in TNSR."
                }
            }
            return result

    # Create required nat rule if one is needed for this request
    if check_results["nat_rule_matches"] == False and check_results["nat_rule_conflict"] is None:
        payload = """
            <mapping-entry>
                <transport-protocol>"""+request["parent"]["spec"]["protocol"]+"""</transport-protocol>
                <local-address>"""+request["parent"]["spec"]["localIP"]+"""</local-address>
                <local-port>"""+str(request["parent"]["spec"]["localPort"])+"""</local-port>
                <external-if-name>"""+request["parent"]["spec"]["natInt"]+"""</external-if-name>
                <external-port>"""+str(request["parent"]["spec"]["externalPort"])+"""</external-port>
                <external-address>0.0.0.0</external-address>
		        <route-table-name>ipv4-VRF:0</route-table-name>
            </mapping-entry>
        """
        create_nat = self.tnsr_api_call("/data/netgate-nat:nat-config/netgate-nat:static/netgate-nat:mapping-table", payload, "post", "xml")
        if create_nat.status_code == 201 or create_nat.status_code == 409 :
            nat_created = True
    elif check_results["nat_rule_matches"] == True:
        nat_created = True

    # Calculate next available sequence number in ACL rules
    sequence_array = list()
    for i in check_results["acl_rule_list"]:
        sequence_array.append(int(i["sequence"]))
    sequence_array.sort()
    try:
        available_sequence = min(set(range(1, max(sequence_array)+1)) - set(sequence_array))
    except ValueError:
        available_sequence = len(sequence_array)+1
    print("USING ACL SEQUENCE "+str(available_sequence))

    # Create Required ACL rule if required
    acl_rule_created = False
    acl_rule_sequence = -1
    if check_results["acl_rule"] is None:
        payload = """
            <acl-rule>
                <acl-rule-description>"""+request["parent"]["metadata"]["uid"]+"""</acl-rule-description>
                <sequence>"""+str(available_sequence)+"""</sequence>
                <action>permit</action>
                <ip-version>ipv4</ip-version>
                <protocol>"""+request["parent"]["spec"]["protocol"]+"""</protocol>
                <dst-first-port>"""+str(request["parent"]["spec"]["externalPort"])+"""</dst-first-port>
                <dst-last-port>"""+str(request["parent"]["spec"]["externalPort"])+"""</dst-last-port>
            </acl-rule>
        """
        create_acl_rule = self.tnsr_api_call("/data/netgate-acl:acl-config/netgate-acl:acl-table/netgate-acl:acl-list="+check_results["acl_object"]["spec"]["name"]+"/netgate-acl:acl-rules", payload, "post", "xml")
        if create_acl_rule.status_code == 201 or create_acl_rule.status_code == 409 :
            acl_rule_created = True
    else:
        acl_rule_created = True
        acl_rule_sequence = int(check_results["acl_rule"]["sequence"])


    result = {
        "status": {
            "nat_created": nat_created,
            "acl_rule_created": acl_rule_created,
            "acl_rule_sequence": acl_rule_sequence
        }
    }
    return result


def nat_finalize(self, request, known_acls):
    import json

    nat_rule_removed = False
    acl_rule_removed = False
    finalized = False

    print("NAT FINALIZE")
    # DEBUG
    # print(json.dumps(request))

    # Check existing NAT and ACL entries against the request
    check_results = self.nat_check(
        request["parent"]["spec"]["tnsrACL"],
        request["parent"]["spec"]["natInt"],
        request["parent"]["spec"]["externalPort"],
        request["parent"]["spec"]["localPort"],
        request["parent"]["spec"]["protocol"],
        request["parent"]["spec"]["localIP"],
        request["parent"]["metadata"]["uid"],
        known_acls
    )

    # Remove NAT entry if one exists
    if check_results["nat_rule_matches"]:
        remove_nat = check_results["nat_rule"]
        remove_nat_result = self.tnsr_api_call(
            "/data/netgate-nat:nat-config/netgate-nat:static/netgate-nat:mapping-table/netgate-nat:mapping-entry="+remove_nat["transport-protocol"]+","+remove_nat["local-address"]+","+remove_nat["local-port"]+","+remove_nat["external-address"]+","+remove_nat["external-port"]+","+remove_nat["route-table-name"],
            "", "delete", "json"
        )

        # If remove successful, set the conflict to none
        if remove_nat_result.status_code == 204:
            nat_rule_removed = True
    else:
        nat_rule_removed = True

    # Remove ACL rule if one exists
    if check_results["acl_rule_matches"]:
        remove_acl = check_results["acl_rule"]
        remove_acl_result = self.tnsr_api_call(
            "/data/netgate-acl:acl-config/netgate-acl:acl-table/netgate-acl:acl-list="+check_results["acl_object"]["spec"]["name"]+"/netgate-acl:acl-rules/netgate-acl:acl-rule="+str(remove_acl["sequence"]),
            "", "delete", "json"
        )
        # If remove successful, set the conflict to none
        if remove_acl_result.status_code == 204:
            acl_rule_removed = True
    else:
        acl_rule_removed = True

    # Return the finalized status to Kubernetes
    if nat_rule_removed and acl_rule_removed:
        finalized = True

    result = {
        "finalized": finalized
    }
    return result


# Check if a NAT entry already exists on TNSR
def nat_check(self, acl_resource, external_interface, external_port, internal_port, protocol, internal_ip, resource_uid, known_acls):
    import json

    # Look up the ACL and see if a rule exists
    acl_object = None
    for i in known_acls:
        if i["spec"]["name"] == acl_resource:
            acl_object = i
            break

    # Look up the ACL rules on TNSR
    acl_rules_list = json.loads(self.tnsr_api_call("/data/netgate-acl:acl-config/netgate-acl:acl-table/netgate-acl:acl-list="+acl_object["spec"]["name"]+"/netgate-acl:acl-rules", "", "get", "json").text)
    # print(json.dumps(acl_rules_list))# DEBUG

    # See if an ACL rule exists and if it matches the specs
    acl_rule = None
    for i in acl_rules_list["netgate-acl:acl-rules"]["acl-rule"]:
        print(json.dumps(i))# DEBUG PRINT ALL ACL RULES
        if i["acl-rule-description"] == resource_uid:
            acl_rule = i
            print("ACL MATCH FOUND!")
            break

    # Verify that the rule matches the API request if it exists
    acl_rule_matches = True
    if acl_rule is not None:
        if acl_rule["protocol"] != protocol:
            acl_rule_matches = False
        elif acl_rule["dst-first-port"] != external_port:
            acl_rule_matches = False
        elif acl_rule["dst-last-port"] != external_port:
            acl_rule_matches = False
        elif acl_rule["action"] != "permit":
            acl_rule_matches = False
    else:
        acl_rule_matches=False

    # Look up NAT rules
    nat_list = json.loads(self.tnsr_api_call("/data/netgate-nat:nat-config/netgate-nat:static/netgate-nat:mapping-table", "", "get", "json").text)
    # print(json.dumps(nat_list))# DEBUG

    # Check if there is a NAT rule that matches the API request
    nat_rule_matches = False
    nat_rule = None
    for i in nat_list["netgate-nat:mapping-table"]["mapping-entry"]:
        if (
            i["external-if-name"] == external_interface and
            i["external-port"] == str(external_port) and
            i["local-port"] == str(internal_port) and
            i["transport-protocol"] == protocol and
            i["local-address"] == internal_ip
        ):
            nat_rule_matches = True
            nat_rule = i
            break

    # Detect if there is going to be a conflicting rule
    nat_rule_conflict = None
    for i in nat_list["netgate-nat:mapping-table"]["mapping-entry"]:
        if (
            nat_rule_matches == False and
            i["external-port"] == str(external_port) and
            i["transport-protocol"] == protocol
            ):
            nat_rule_conflict = i
            break

    return {
        "acl_object": acl_object,
        "acl_rule": acl_rule,
        "acl_rule_matches": acl_rule_matches,
        "acl_rule_list": acl_rules_list["netgate-acl:acl-rules"]["acl-rule"],
        "nat_rule": nat_rule,
        "nat_rule_list": nat_list,
        "nat_rule_matches": nat_rule_matches,
        "nat_rule_conflict": nat_rule_conflict
        }
