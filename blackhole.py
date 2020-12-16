#!/usr/bin/env python
"""
Create an FMC access policy to black hole the default route into null into 3 steps:
1) authenticate to an FMC
2) compose an access policy and rule
3) assign the policy to a device or device group

The script looks for several OS environment variables: FMCHOST (ip address of the FMC),
FMCPORT (port number of the FMC), FMCADMIN (FMC admin account name), FMCPASS (password for
the FMC admin account).  Please also identify the specific rule ID and name for the
exception traffic to the black hole.
"""

import os
import requests.auth

fmc = f"https://{os.getenv('FMCHOST')}:{os.getenv('FMCPORT')}/api/fmc_platform/v1/"
domain_uuid = ""
headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}
access_policy = {
    "type": "AccessPolicy",
    "name": "DNE Security Access Control Policy",
    "description": "Basic AC Policy",
    "defaultAction": {"action": "BLOCK"},
}
access_rule = {
    "action": "ALLOW", # Any exception to the black hole?
    "enabled": True,
    "type": "AccessRule",
    "name": "Rule1",
    "sourceNetworks": {
        "objects": [
            {
                "type": "Network",
                "overridable": False,
                "id": "INSERT RULE ID HERE",  # Need to identify rule ID
                "name": "INSERT NAME HERE",  # Need to identify a rule Name
            }
        ]
    },
    "sendEventsToFMC": False,
    "logFiles": False,
    "logBegin": False,
    "logEnd": False,
}


def authentication():
    # Get a token and the domain UUID
    basicauth = requests.auth.HTTPBasicAuth(os.getenv('FMCADMIN'), os.getenv('FMCPASS'))
    response = requests.post(fmc + "auth/generatetoken", headers=headers, auth=basicauth, verify=False)
    if response.status_code == 200:
        access_token = response.headers.get("X-auth-access-token")
        domain_uuid = response.headers.get("DOMAIN_UUID")
        headers["DOMAIN_UUID"] = domain_uuid
        headers["X-auth-access-token"] = access_token
    else:
        print(f"Non-200 response encountered! - {response.status_code}")
    return access_token, domain_uuid
