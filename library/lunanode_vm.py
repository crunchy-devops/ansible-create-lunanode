#!/usr/bin/env python

DOCUMENTATION = '''
---
module: lunanode
short_description: Manage your vm on Lunanode
'''

EXAMPLES = '''
- name: Create a Lunanode VM  
  lunanode:
    lunanode_key: "..."
    lunanode_token: "..."
    hostname:
    plan_id:
    region:
    image_id:
    storage:
    state: present
  register: result

- name: Delete that vm 
  lunanode:
    lunanode_key: "..."
    lunanode_token: "..."
    hostname: "k8s-black-master"
    state: absent
  register: result
'''

from ansible.module_utils.basic import *

class LNDynamic:
    LNDYNAMIC_URL = 'https://dynamic.lunanode.com/api/{CATEGORY}/{ACTION}/'

    def __init__(self, api_id, api_key):
        if len(api_id) != 16:
            raise LNDAPIException('supplied api_id incorrect length, must be 16')
        if len(api_key) != 128:
            raise LNDAPIException('supplied api_key incorrect length, must be 128')

        self.api_id = api_id
        self.api_key = bytes(api_key, 'utf-8')
        self.partial_api_key = api_key[:64]

    def request(self, category, action, params = {}):
        import json
        import time
        import hmac
        import hashlib
        import requests

        url = self.LNDYNAMIC_URL.format(CATEGORY=category, ACTION=action)
        request_array = dict(params)
        request_array['api_id'] = self.api_id
        request_array['api_partialkey'] = self.partial_api_key
        request_raw = json.dumps(request_array)
        nonce = str(int(time.time()))
        handler = '{CATEGORY}/{ACTION}/'.format(CATEGORY=category, ACTION=action)
        hasher = hmac.new(self.api_key, bytes('{handler}|{raw}|{nonce}'.format(handler=handler, raw=request_raw, nonce=nonce), 'utf-8'), hashlib.sha512)
        signature = hasher.hexdigest()

        data = {'req': request_raw, 'signature': signature, 'nonce': nonce}
        content = requests.post(url, data=data).json()
        # content is now a dictionary, NOT a string
        if 'success' not in content:
            raise APIException('Server gave invalid repsonse (missing success key)')
        elif content['success'] != 'yes':
            if 'error' in content:
                raise APIException('API error: ' + content['error'])
            else:
                raise APIException('Unknown API error')
        return content

class LNDAPIException(Exception):
    pass

class APIException(Exception):
    pass

def lunanode_vm_present(data):

    api_key = data['lunanode_key']
    api_token = data['lunanode_token']
    api_hostname= data['hostname']
    api_plan_id = data['plan_id']
    api_region= data['region']
    api_image_id= data['image_id']
    api_storage= data['storage']
    del data['state']
    del data['lunanode_key']
    del data['lunanode_token']

    api = LNDynamic(api_key,api_token)
    results = api.request('vm','create', {'hostname': api_hostname, 'plan_id': api_plan_id, 'region': api_region, 'image_id': api_image_id, 'storage': api_storage})
    #headers = {
    #    "Authorization": "token {}" . format(api_key)
    #}
    #url = "{}{}" . format(api_url, '/user/repos')
    #result = requests.post(url, json.dumps(data), headers=headers)

    #if result.status_code == 201:
    #    return False, True, result.json()
    #if result.status_code == 422:
    #    return False, False, result.json()

    # default: something went wrong
    #meta = { 'response': results.json()}
    return True, False, results



def main():

    fields = {
        "lunanode_key": {"required": True, "type": "str"},
        "lunanode_token": {"required": True, "type": "str"},
        "hostname": {"required": True, "type": "str"},
        "plan_id": {"required": True, "type": "int"},
        "region": {"default": True, "type": "str"},
        "image_id": {"default": True, "type": "int"},
        "storage": {"default": True, "type": "int"},
        "state": {
            "default": "present",
            "choices": ['present'],
            "type": 'str'
        },
    }

    choice_map = {
        "present": lunanode_vm_present,
        #"absent": lunanode_vm_absent,
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error deleting repo", meta=result)


if __name__ == '__main__':
    main()
