#!/usr/bin/env python
from ansible.module_utils.hashivault import hashivault_argspec
from ansible.module_utils.hashivault import hashivault_auth_client
from ansible.module_utils.hashivault import hashivault_init
from ansible.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_ldap_group_list
version_added: "pure_ci-1.0.0"
short_description: Hashicorp Vault ldap_group list module
description:
    - Module to list ldap groups in Hashicorp Vault.
extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
- hosts: localhost
  tasks:
    - hashivault_ldap_group_list:
      register: 'vault_ldap_group_list'
    - debug: msg="Policies are {{vault_ldap_group_list.ldap_groups}}"
'''


def main():
    argspec = hashivault_argspec()
    module = hashivault_init(argspec)
    result = hashivault_ldap_group_list(module.params)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


@hashiwrapper
def hashivault_ldap_group_list(params):
    client = hashivault_auth_client(params)
    try:
        groups = client.auth.ldap.list_groups().get('data', {}).get('keys', [])
    except InvalidPath:
        # treat as empty -- this caters to running this in check mode on a fresh install of Vault
        # where the tasks to enable ldap auth may be running in check mode as well
        groups = []
    return {'ldap_groups': groups}


if __name__ == '__main__':
    main()
