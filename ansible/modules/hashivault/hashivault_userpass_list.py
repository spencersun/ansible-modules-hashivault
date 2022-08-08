#!/usr/bin/env python
from ansible.module_utils.hashivault import hashivault_argspec
from ansible.module_utils.hashivault import hashivault_auth_client
from ansible.module_utils.hashivault import hashivault_init
from ansible.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_userpass_list
version_added: "pure_ci-1.0.0"
short_description: Hashicorp Vault userpass list module
description:
    - Module to list auth/userpass/users in Hashicorp Vault.
options:
extends_documentation_fragment: hashivault
    mount_point:
        description:
            - name of the auth mount name
        default: userpass
'''
EXAMPLES = '''
---
- hosts: localhost
  tasks:
    - hashivault_userpass_list:
      register: 'vault_userpass_list'
    - debug: msg="Policies are {{vault_userpass_list.users}}"
'''


def main():
    argspec = hashivault_argspec()
    argspec['mount_point'] = dict(required=False, type='str', default='userpass')
    module = hashivault_init(argspec)
    result = hashivault_userpass_list(module.params)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


@hashiwrapper
def hashivault_userpass_list(params):
    client = hashivault_auth_client(params)
    mount_point = params.get('mount_point').strip('/')
    try:
        current_users = client.auth.userpass.list_user(mount_point)['data']['keys']
    except InvalidPath:
        # treat as empty -- this caters to running this in check mode on a fresh install of Vault
        # where the tasks to enable userpass auth may be running in check mode as well
        current_users = []
    return {'users': current_users}


if __name__ == '__main__':
    main()
