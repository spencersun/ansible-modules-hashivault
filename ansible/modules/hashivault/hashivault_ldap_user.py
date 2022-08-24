#!/usr/bin/env python
from ansible.module_utils.hashivault import hashivault_argspec
from ansible.module_utils.hashivault import hashivault_auth_client
from ansible.module_utils.hashivault import hashivault_init
from ansible.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_ldap_user
version_added: "pure_ci-1.0.0"
short_description: Hashicorp Vault LDAP user configuration module
description:
    - Module to configure LDAP users in Hashicorp Vault.
options:
    mount_point:
        description:
            - location where this method/backend is mounted. also known as "path"
        default: ldap
    name:
        description:
            - name of the user
        default: None
    policies:
        description:
            - policies to be tied to the user
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
    - hashivault_ldap_user:
        name: 'some-user'
        policies:
            - 'my-policy'
        token: "{{ vault_token }}"
        url: "{{ vault_url }}"
'''


def main():
    argspec = hashivault_argspec()
    argspec['groups'] = dict(required=False, type='list', default=[])
    argspec['name'] = dict(required=True, type='str', default=None)
    argspec['mount_point'] = dict(required=False, type='str', default='ldap')
    argspec['policies'] = dict(required=False, type='list', default=[])
    argspec['state'] = dict(required=False, choices=['present', 'absent'], default='present')
    module = hashivault_init(argspec, supports_check_mode=True)
    result = hashivault_ldap_user(module)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


def _diff_object(groups, **kwargs):
    return dict(groups=','.join(sorted(groups)), **kwargs)


def hashivault_ldap_user_update(user_details, client, user_name, user_groups, user_policies, mount_point, check_mode=False):
    changed = False

    # existing groups
    if user_details['groups'] is not None:
        if set(user_details['groups']) != set(user_groups):
            changed = True
    # new groups and none existing
    elif len(user_groups) > 0:
        changed = True

    # existing policies
    if user_details['policies'] is not None:
        if set(user_details['policies']) != set(user_policies):
            changed = True
    # new policies and none existing
    elif len(user_policies) > 0:
        changed = True

    if changed:
        header = '/'.join(['auth', mount_point, 'users', user_name])
        diff = dict(
            before=_diff_object(groups=user_details['groups'], policies=user_details['policies']),
            before_header=header,
            after=_diff_object(groups=user_groups, policies=user_policies),
            after_header=header,
        )
        if not check_mode:
            try:
                response = client.auth.ldap.create_or_update_user(
                    username=user_name,
                    groups=user_groups,
                    policies=user_policies,
                    mount_point=mount_point
                )
            except Exception as e:
                return {'failed': True, 'msg': str(e)}
            if response.status_code != 204:
                return {'changed': True, 'diff': diff, 'data': response}
        return {'changed': True, 'diff': diff}
    return {'changed': False}


def hashivault_ldap_user_create_or_update(module):
    params = module.params
    client = hashivault_auth_client(params)
    user_name = params.get('name')
    mount_point = params.get('mount_point')
    user_groups = params.get('groups')
    user_policies = params.get('policies')
    try:
        user_details = client.auth.ldap.read_user(username=user_name, mount_point=mount_point)
    except InvalidPath:
        user_details = None

    if user_details is None:
        diff = dict(
            before='',
            before_header='(absent)',
            after=_diff_object(groups=user_groups, policies=user_policies),
            after_header='/'.join(['auth', mount_point, 'users', user_name]),
        )
        if not module.check_mode:
            client.auth.ldap.create_or_update_user(
                username=user_name,
                groups=user_groups,
                policies=user_policies,
                mount_point=mount_point
            )
        return {'changed': True, 'diff': diff}
    return hashivault_ldap_user_update(user_details['data'], client, user_name=user_name,
                                       user_groups=user_groups,
                                       user_policies=user_policies,
                                       check_mode=module.check_mode,
                                       mount_point=mount_point)


def hashivault_ldap_user_delete(module):
    params = module.params
    client = hashivault_auth_client(params)
    user_name = params.get('name')

    try:
        client.auth.ldap.read_user(username=user_name)
    except InvalidPath:
        return {'changed': False}
    if not module.check_mode:
        client.auth.ldap.delete_user(username=user_name)
    return {'changed': True}


@hashiwrapper
def hashivault_ldap_user(module):
    params = module.params
    state = params.get('state')
    if state == 'present':
        return hashivault_ldap_user_create_or_update(module)
    elif state == 'absent':
        return hashivault_ldap_user_delete(module)


if __name__ == '__main__':
    main()
