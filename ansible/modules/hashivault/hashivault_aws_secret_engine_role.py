#!/usr/bin/env python
from ansible.module_utils.hashivault import hashivault_argspec
from ansible.module_utils.hashivault import hashivault_auth_client
from ansible.module_utils.hashivault import hashivault_init
from ansible.module_utils.hashivault import hashiwrapper
from hvac.exceptions import InvalidPath
import json

ANSIBLE_METADATA = {'status': ['stableinterface'], 'supported_by': 'community', 'version': '1.1'}
DOCUMENTATION = '''
---
module: hashivault_aws_secret_engine_role
version_added: "3.17.6"
short_description: Hashicorp Vault aws secret engine role
description:
    - Module to define a Aws role that vault can generate dynamic credentials for vault
options:
    mount_point:
        description:
            - name of the secret engine mount name.
        default: aws
    name:
        description:
            - name of the role in vault
    credential_type:
        type: string
        choices: ["iam_user", "assumed_role", "federation_token"]
        description:
            - credential type
    policy_document:
        type: dict
        description:
            - policy document
    policy_document_file:
        type: string
        description:
            - path to policy document JSON file
    default_sts_ttl:
        description:
            - default TTL for STS credentials
    max_sts_ttl:
        description:
            - max TTL for STS credentials
    role_arns:
        description:
            - List of ARNs of the AWS roles this Vault role is allowed to assume. Required when credential_type is assumed_role and prohibited otherwise.
    policy_arns:
        description:
            - List of ARNs of the AWS managed policies to be attached to IAM users when they are requested. Valid only when credential_type is iam_user, or legacy_params is True. When credential_type is iam_user, at least one of policy_arns or policy_document must be specified.
    legacy_params:
        type: bool
        description:
            - Flag to send legacy (Vault versions < 0.11.0) parameters in the request.  If true, only policy_document, policy_document_file, and policy_arns are valid.


extends_documentation_fragment: hashivault
'''
EXAMPLES = '''
---
- hosts: localhost
  tasks:
    - hashivault_aws_secret_engine_role:
        name: contributor-role
        policy_document_file: path/to/policy.json
'''


def main():
    argspec = hashivault_argspec()
    argspec['name'] = dict(required=True, type='str')
    argspec['mount_point'] = dict(required=False, type='str', default='aws')
    argspec['credential_type'] = dict(required=True, type='str',
                                      choices=['iam_user', 'assumed_role', 'federation_token',
                                               # when legacy_params=True
                                               'iam_user,federation_token'])
    argspec['policy_document'] = dict(required=False, type='dict')
    argspec['policy_document_file'] = dict(required=False, type='str')
    argspec['default_sts_ttl'] = dict(required=False, type='str', default=None)
    argspec['max_sts_ttl'] = dict(required=False, type='str', default=None)
    argspec['role_arns'] = dict(required=False, type='list')
    argspec['policy_arns'] = dict(required=False, type='list')
    argspec['legacy_params'] = dict(required=False, type='bool', default=False)
    mutually_exclusive = [['policy_document', 'policy_document_file']]
    required_if = [
        ('credential_type', 'assumed_role', ['role_arns']),

        # when credential_type == 'iam_user', at least one of [policy_arns, policy_document,
        # policy_document_file] is required
        ('credential_type', 'iam_user',
             ['policy_arns', 'policy_document', 'policy_document_file'], True),
    ]

    module = hashivault_init(argspec, supports_check_mode=True,
                             mutually_exclusive=mutually_exclusive, required_if=required_if)
    result = hashivault_aws_secret_engine_role(module)
    if result.get('failed'):
        module.fail_json(**result)
    else:
        module.exit_json(**result)


FORBIDDEN_IF_IAM_USER = ['default_sts_ttl', 'max_sts_ttl']


@hashiwrapper
def hashivault_aws_secret_engine_role(module):
    params = module.params
    client = hashivault_auth_client(params)
    name = params.get('name').strip('/')
    mount_point = params.get('mount_point').strip('/')
    credential_type = params.get('credential_type')

    policy_document = params.get('policy_document')
    policy_document_file = params.get('policy_document_file')
    # if policy_document_file is set, set policy_document to contents
    # else assume policy_document is set and use that value
    if policy_document_file:
        policy_document = json.loads(open(policy_document_file, 'r').read())

    legacy_params = params.get('legacy_params')

    desired_state = dict()
    desired_state['credential_type'] = credential_type
    desired_state['policy_document'] = policy_document
    desired_state['default_sts_ttl'] = params.get('default_sts_ttl')
    desired_state['max_sts_ttl'] = params.get('max_sts_ttl')
    desired_state['role_arns'] = params.get('role_arns')
    desired_state['policy_arns'] = params.get('policy_arns')

    if not legacy_params:
        if desired_state['role_arns'] and credential_type != 'assumed_role':
            return {
                'failed': True,
                'rc': 1,
                'msg': 'role_arns forbidden when credential_type != "assumed_role"',
            }

        if desired_state['policy_arns'] and credential_type != 'iam_user':
            return {
                'failed': True,
                'rc': 1,
                'msg': 'role_arns forbidden when credential_type != "iam_user"',
            }

        if credential_type == 'iam_user':
            for param in FORBIDDEN_IF_IAM_USER:
                if desired_state[param]:
                    return {
                        'failed': True,
                        'rc': 1,
                        'msg': '{} forbidden when credential_type == "{}"'.format(
                            param,
                            credential_type,
                        ),
                    }

    try:
        existing_roles = client.secrets.aws.list_roles(mount_point=mount_point)
        existing = name in existing_roles['data']['keys']
    except InvalidPath:
        existing = False

    if existing:
        # check if role content == desired
        current = client.secrets.aws.read_role(name=name, mount_point=mount_point)['data']

        # fixups to the "current" object for diff purposes
        if 'policy_document' in current:
            try:
                current['policy_document'] = json.loads(current['policy_document'])
            except ValueError:
                # just treat it as a diff
                pass

        if 'credential_types' in current:
            current['credential_type'] = ','.join(current.pop('credential_types'))

        if legacy_params or current['credential_type'] == 'iam_user':
            for param in FORBIDDEN_IF_IAM_USER:
                # hvac returns these as int(0)
                # however the argspec default must be None since the argspec
                # type is a string, and "0" will cause create_or_update_role to choke
                # so it's easier just to fix this up before comparing
                current[param] = None

        changed = current != desired_state
    else:
        changed = True

    # make the changes!
    if changed:
        diff_header = '/'.join([mount_point, 'roles', name])
        diff = dict(after=dict(**desired_state), # make a copy, since we modify this later
                    after_header=diff_header)
        credential_type = desired_state.pop('credential_type').split(',')[0]
        if not module.check_mode:
            client.secrets.aws.create_or_update_role(name, credential_type,
                                                     mount_point=mount_point,
                                                     legacy_params=legacy_params,
                                                     **desired_state)
        if existing:
            diff.update(before=current, before_header=diff_header)
        else:
            diff.update(before='', before_header='(absent)')
        return {'changed': changed, 'diff': diff}

    return {'changed': changed}


if __name__ == '__main__':
    main()
