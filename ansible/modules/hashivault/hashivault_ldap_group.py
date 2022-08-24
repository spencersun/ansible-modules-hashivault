#!/usr/bin/env python
from ansible.module_utils.hashivault import hashivault_argspec
from ansible.module_utils.hashivault import hashivault_auth_client
from ansible.module_utils.hashivault import hashivault_init
from ansible.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_ldap_group
version_added: "3.18.3"
short_description: Hashicorp Vault LDAP group configuration module
description:
    - Module to configure LDAP groups in Hashicorp Vault.
options:
    mount_point:
        description:
            - location where this method/backend is mounted. also known as "path"
        default: ldap
    name:
        description:
            - name of the group
        default: None
    policies:
        description:
            - policies to be tied to the group
        default: None
    state:
        description:
            - whether create/update or delete the entity
extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
- hosts: localhost
  tasks:
    - hashivault_ldap_group:
        name: 'my-group'
        policies:
            - 'my-policy'
        token: "{{ vault_token }}"
        url: "{{ vault_url }}"
'''


def main():
    argspec = hashivault_argspec()
    argspec['name'] = dict(required=True, type='str', default=None)
    argspec['mount_point'] = dict(required=False, type='str', default='ldap')
    argspec['policies'] = dict(required=False, type='list', default=[])
    argspec['state'] = dict(required=False, choices=['present', 'absent'], default='present')
    module = hashivault_init(argspec, supports_check_mode=True)
    result = hashivault_ldap_group(module)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


def hashivault_ldap_group_update(group_details, client, group_name, group_policies, mount_point, check_mode=False):
    changed = False

    # existing policies
    if group_details['policies'] is not None:
        if set(group_details['policies']) != set(group_policies):
            changed = True
    # new policies and none existing
    elif len(group_policies) > 0:
        changed = True

    if changed:
        header = '/'.join(['auth', mount_point, 'groups', group_name])
        diff = dict(
            before=dict(policies=group_details['policies']),
            before_header=header,
            after=dict(policies=group_policies),
            after_header=header,
        )
        if not check_mode:
            try:
                response = client.auth.ldap.create_or_update_group(
                    name=group_name,
                    policies=group_policies,
                    mount_point=mount_point
                )
            except Exception as e:
                return {'failed': True, 'msg': str(e)}
            if response.status_code != 204:
                return {'changed': True, 'diff': diff, 'data': response}
        return {'changed': True, 'diff': diff}
    return {'changed': False}


def hashivault_ldap_group_create_or_update(module):
    params = module.params
    client = hashivault_auth_client(params)
    group_name = params.get('name')
    mount_point = params.get('mount_point')
    group_policies = params.get('policies')
    try:
        group_details = client.auth.ldap.read_group(name=group_name, mount_point=mount_point)
    except InvalidPath:
        group_details = None

    if group_details is None:
        diff = dict(
            before='',
            before_header='(absent)',
            after=dict(policies=group_policies),
            after_header='/'.join(['auth', mount_point, 'groups', group_name]),
        )
        if not module.check_mode:
            client.auth.ldap.create_or_update_group(
                name=group_name,
                policies=group_policies,
                mount_point=mount_point
            )
        return {'changed': True, 'diff': diff}
    return hashivault_ldap_group_update(group_details['data'], client, group_name=group_name,
                                        group_policies=group_policies,
                                        check_mode=module.check_mode,
                                        mount_point=mount_point)


def hashivault_ldap_group_delete(module):
    params = module.params
    client = hashivault_auth_client(params)
    group_name = params.get('name')

    try:
        client.auth.ldap.read_group(name=group_name)
    except InvalidPath:
        return {'changed': False}
    if not module.check_mode:
        client.auth.ldap.delete_group(name=group_name)
    return {'changed': True}


@hashiwrapper
def hashivault_ldap_group(module):
    params = module.params
    state = params.get('state')
    if state == 'present':
        return hashivault_ldap_group_create_or_update(module)
    elif state == 'absent':
        return hashivault_ldap_group_delete(module)


if __name__ == '__main__':
    main()
