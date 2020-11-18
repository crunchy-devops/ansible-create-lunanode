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
    keyword: 
    state: present
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

def lunanode_get_cluster_present(data):
    api_key = data['lunanode_key']
    api_token = data['lunanode_token']
    api_keyword= data['keyword']
    del data['state']
    del data['lunanode_key']
    del data['lunanode_token']

    api = LNDynamic(api_key,api_token)
    results = api.request('vm','list')
    val= results.get('vms')
    user_dic= {}
    user_pass={}
    for i in range(0, len(val)):
        flag = 0
        for key, value in val[i].items():
            if key == 'name':
                if api_keyword not in value:
                    break
                print('name=', value)
                user = value
            #if key == 'primaryip':
            #    ip = value
            #    print('ip=', value)
            #if key == 'plan_id':
            #    print('plan_id=', value)
            #if key == 'vm_id':
            #    print('vm_id=', value)
            #    vm_info = api.request('vm', 'info', {'vm_id': value})
            #    st = vm_info.get('info')
            #    try:
            #        print(st['login_details'])
            #        user_login = st['login_details']
            #        a = user_login.split()
            #        print(str(ip), str(a[1]), str(a[3]))
            #        gt = str(a[1])[:-1]
            #        line = "{}  ansible_ssh_user={}  ansible_ssh_pass={} ansible_ssh_extra_args='-o StrictHostKeyChecking=no'\n".format(
            #            str(ip), str(gt), str(a[3]))
            #        user_dic[str(user)] = str(ip)
            #        user_pass[str(user)]= str(a[3])
            #    except KeyError as error:
            #        pass

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
    if not user:
        return True, False, user
    else:
        return False,False, user


def main():

    fields = {
        "lunanode_key": {"required": True, "type": "str"},
        "lunanode_token": {"required": True, "type": "str"},
        "keyword": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ['present'],
            "type": 'str'
        },
    }

    choice_map = {
        "present": lunanode_get_cluster_present,

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
