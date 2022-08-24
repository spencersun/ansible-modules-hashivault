#!/usr/bin/env python
from setuptools import setup

py_files = [
    "ansible/module_utils/hashivault",
    "ansible/plugins/lookup/hashivault",
    "ansible/plugins/action/hashivault_read_to_file",
    "ansible/plugins/action/hashivault_write_from_file",
    "ansible/plugins/doc_fragments/hashivault",
]
files = [
    "ansible/modules/hashivault",
]

long_description = open('README.rst', 'r').read()

setup(
    name='pure-ansible-hashivault',
    version='1.0.0',
    description='Ansible Modules for Hashicorp Vault (pure_ci fork)',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    author='CI',
    author_email='ci@purestorage.com',
    url='https://github.com/spencersun/ansible-modules-hashivault',
    py_modules=py_files,
    packages=files,
    install_requires=[
        'ansible>=2.0.0',
        'hvac>=0.11.0',
        'requests',
    ],
)
