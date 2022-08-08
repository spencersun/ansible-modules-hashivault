#!/usr/bin/env python
from ansible.module_utils.hashivault import hashivault_argspec
from ansible.module_utils.hashivault import hashivault_auth_client
from ansible.module_utils.hashivault import hashivault_init
from ansible.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_aws_secret_engine_config
version_added: "pure_ci-1.0.0"
short_description: Hashicorp Vault aws secret engine config
description:
    - Module to configure an aws secret engine via variables or json file
options:
    mount_point:
        description:
            - name of the secret engine mount name.
        default: aws
    lease:
        description:
            - lease config.  must be a dict
extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
- hosts: localhost
  tasks:
    - hashivault_aws_secret_engine_config:
        mount_point: aws
        lease:
          lease: 24h0m0s
          lease_max: 24h0m0s

    - hashivault_aws_secret_engine_config:
        mount_point: aws-foo
        lease:
          lease_max: 12h0m0s
'''


def main():
    argspec = hashivault_argspec()
    argspec['mount_point'] = dict(required=False, type='str', default='aws')
    argspec['lease'] = dict(required=True, type='dict')

    module = hashivault_init(argspec, supports_check_mode=True)
    result = hashivault_aws_secret_engine_config(module)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


@hashiwrapper
def hashivault_aws_secret_engine_config(module):
    params = module.params
    client = hashivault_auth_client(params)
    changed = False
    lease = params.get('lease')
    mount_point = params.get('mount_point').strip('/')
    desired_state = lease

    missing = [k for k in ['lease', 'lease_max'] if k not in lease]
    if missing:
        return {
            'rc': 1,
            'failed': True,
            'msg': u"missing key(s) in lease: " + ', '.join(missing),
        }

    try:
        current_state = client.secrets.aws.read_lease_config(mount_point)['data']
    except InvalidPath:
        current_state = {}

    if current_state != desired_state:
        diff_header='/'.join([mount_point, 'config', 'lease'])
        diff = dict(
            before=current_state,
            before_header=diff_header if current_state else '(absent)',
            after=desired_state,
            after_header=diff_header,
        )
        if not module.check_mode:
            client.secrets.aws.configure_lease(mount_point=mount_point, **lease)
        return {'changed': True, 'diff': diff}

    return {'changed': False}


if __name__ == '__main__':
    main()
