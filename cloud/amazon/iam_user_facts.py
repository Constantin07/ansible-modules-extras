#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: iam_user_facts
short_description: Gather IAM user(s) facts in AWS
description:
  - Gather IAM user(s) facts in AWS
version_added: "2.2"
author: "Constantin Bugneac, (@Constantin07)"
options:
  name:
    description:
     - The name of the IAM user to look for.
    required: false
  path:
    description:
     - The path to the IAM user. For more information about paths, see U(http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html).
    required: false
    default: '/'
requirements: [ botocore, boto3 ]
extends_documentation_fragment:
  - aws
'''

EXAMPLES = '''
# Gather facts about "test" user.
- name: Get IAM user facts
  iam_user_facts:
    name: "test"

# Gather facts about all users with "dev" path.
- name: Get IAM user facts
  iam_user_facts:
    path: "dev"

'''

RETURN = '''
arn:
    description: the ARN of the user
    returned: if user exists
    type: string (ARN)
    sample: "arn:aws:iam::156360693172:user/dev/test_user"
create_date:
    description: the datetime user was created
    returned: if user exists
    type: date (UTC)
    sample: "2016-05-24T12:24:59+00:00"
password_last_used:
    description: the last datetime the password was used by user
    returned: if password was used at least once
    type: date (UTC)
    sample: "2016-05-25T13:39:11+00:00"
path:
    description: the path to user
    returned: if user exists
    type: string
    sample: "/dev/"
user_id:
    description: the unique user id
    returned: if user exists
    type: string
    sample: "AIDUIOOCQKTUGI6QJLGH2"
user_name:
    description: the user name
    returned: if user exists
    type: string
    sample: "test_user"
'''

import json

try:
    import boto3
    from botocore.exceptions import ClientError, ParamValidationError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def list_iam_users(connection, module):

    name = module.params.get('name')
    path = module.params.get('path')

    params = dict()
    iam_users = []

    if name and not path:
        params['UserName'] = name
        try:
            iam_users.append(connection.get_user(**params)['User'])
        except (ClientError, ParamValidationError) as e:
            module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))

    if path:
        params['MaxItems'] = 1000
        params['PathPrefix'] = path
    try:
        iam_users = connection.list_users(**params)['Users']
    except (ClientError, ParamValidationError) as e:
        module.fail_json(msg=e.message, **camel_dict_to_snake_dict(e.response))
    if name:
        iam_users = [ user for user in iam_users if user['UserName']==name ]

    module.exit_json(iam_users=[ camel_dict_to_snake_dict(user) for user in iam_users ])


def main():

    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=False, type='str'),
            path=dict(default='/', required=False, type='str')
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    connection = boto3_conn(module, conn_type='client', resource='iam', region=region, endpoint=ec2_url, **aws_connect_params)

    list_iam_users(connection, module)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
