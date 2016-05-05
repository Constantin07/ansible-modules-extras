#!/usr/bin/python
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: ec2_group_facts
short_description: Gather facts about EC2 security group(s) in AWS
description:
    - Gathers facts about EC2 security group(s) in AWS
version_added: "2.2"
author: "Constantin Bugneac (@Constantin07) <constantin.bugneac@endava.com>"
options:
  filters:
    description:
      - A dict of filters to apply. Each dict item consists of a filter key and a filter value. See U(http://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html) for possible filters.
    required: false
    default: null
  lookup:
    description:
      - A list of resource types to check which this security group is associated to.
      - Valid values are any combination of the options 'ec2', 'elb', 'eni', 'rds' or 'all'.
      - Proper Describe* IAM permissions are required to query the specific resources.
    required: false
    default: null
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Gather facts about a particular security group
- ec2_groups_facts:
  filters:
    group-id: sg-29c9c44f

# Gather facts about a particular security group and return associated EC2 instances and ENIs
- ec2_groups_facts:
  filters:
    group-id: sg-29c9c44f
  lookup:
    - ec2
    - eni

# Gather facts about all security groups in a specific VPC
- ec2_group_facts:
  filters:
    vpc-id: vpc-8a2ca6ee

# Gather facts about all security groups in a region
- ec2_group_facts:
'''

RETURN = '''
ec2:
    description: a list of associated EC2 instances with this security group
    returned: when there are instances associated with security group
    type: list
    sample: [ "i-52a644e3", "i-12df34be" ]
elb:
    description: a list of associated ELBs with this security group
    returned: when there are loadbalancers associated with security group
    type: list
    sample: [ "staging-web-elb01" ]
eni:
    description: a list of ENIs associated with this security group
    returned: when there are ENIs associated with security group
    type: list
    sample: [ "eni-b74c0694" ]
rds:
    description: a list of RDS instances associated with this security group
    returned: when there are RDS associated with security group
    type: list
    sample: [ "test-rds-mysql" ]
description:
    description: security group description
    returned: when description exists
    type: string
    sample: "default VPC security group"
id:
    description: security group id
    returned: when security group exists
    type: string
    sample: "sg-29c9c44f"
name:
    description: security group name
    returned: when security group exists
    type: string
    sample: "default"
rules:
    description: inbound rules of security group
    returned: when inbound rules exist
    type: list
    sample: [{
        "from_port": "80",
        "grants": [
            "193.43.18.0/24",
            "sg-29c9c44f"
        ],
        "ip_protocol": "tcp",
        "to_port": "80"
    }]
rules_egress:
    description: outbound rules of security group
    returned: when outbound rules exist
    type: list
    sample: [{
        "from_port": "443",
        "grants": [
            "0.0.0.0/0",
        ],
        "ip_protocol": "tcp",
        "to_port": "443"
    }]
vpc_id:
    description: security group vpc
    returned: when security group exists
    type: string
    sample: "vpc-12ca6e4"
'''

try:
    import boto.ec2
    import boto.ec2.elb
    import boto.rds
    from boto.exception import BotoServerError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def get_rds_instances(module, group):
    """ Get RDS instances associated with this security group """

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)

    try:
        rds_connection = connect_to_aws(boto.rds, region, **aws_connect_params)
        all_rds = rds_connection.get_all_dbinstances()
    except BotoServerError as e:
        module.fail_json(msg = "%s: %s" % (e.error_code, e.error_message))

    rds_instances = []
    for rds in all_rds:
        for membership in rds.vpc_security_groups:
            if group.id == membership.vpc_group:
                rds_instances.append(rds.id)

    return rds_instances


def get_network_interfaces(module, group):
    """ Get elastic network interfaces associated with this security group """

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)

    try:
        eni_connection = connect_to_aws(boto.ec2, region, **aws_connect_params)
        all_enis = eni_connection.get_all_network_interfaces(filters={'group-id': group.id})
    except BotoServerError as e:
        module.fail_json(msg = "%s: %s" % (e.error_code, e.error_message))

    network_interfaces = []
    for eni in all_enis:
        network_interfaces.append(eni.id)

    return network_interfaces


def get_associated_loadbalancers(module, group):
    """ Get elastic load balancers associated with this security group """

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)

    try:
        elb_connection = connect_to_aws(boto.ec2.elb, region, **aws_connect_params)
        all_elbs = elb_connection.get_all_load_balancers()
    except BotoServerError as e:
        module.fail_json(msg = "%s: %s" % (e.error_code, e.error_message))

    associated_loadbalancers = []
    for elb in all_elbs:
        if group.id in elb.security_groups:
            associated_loadbalancers.append(elb.name)

    return associated_loadbalancers


def get_associated_instances(group):
    """ Get instances associated with this security group """

    associated_instances = group.instances()

    instances = []
    for instance in associated_instances:
        instances.append(instance.id)
    
    return instances


def get_group_rules(PermissionList):
    """ Get rule entries for security group """

    rules = []
    for rule in PermissionList:
        grants = []
        for grant in rule.grants:
            if grant.group_id is not None:
                grants.append(grant.group_id)
            elif grant.cidr_ip is not None:
                grants.append(grant.cidr_ip)
        
        permission = {
            'ip_protocol': rule.ip_protocol,
            'from_port': rule.from_port,
            'to_port': rule.to_port,
            'grants': grants
        }
        rules.append(permission)

    return rules


def get_group_info(connection, module, group):
    """ Get security group details """

    lookup = module.params.get('lookup')

    group_info = {
        'id': group.id,
        'name': group.name,
        'description': group.description,
        'vpc_id': group.vpc_id
    }

    group_info['rules'] = get_group_rules(group.rules)
    group_info['rules_egress'] = get_group_rules(group.rules_egress)
    group_info['resources'] = {}
    if any(x in lookup for x in ['ec2', 'all']):
        group_info['resources']['ec2'] = get_associated_instances(group)
    else:
        group_info['resources']['ec2'] = []
    if any(x in lookup for x in ['elb', 'all']):
        group_info['resources']['elb'] = get_associated_loadbalancers(module,group)
    else:
        group_info['resources']['elb'] = []
    if any(x in lookup for x in ['eni', 'all']):
        group_info['resources']['eni'] = get_network_interfaces(module,group)
    else:
        group_info['resources']['eni'] = []
    if any(x in lookup for x in ['rds', 'all']):
        group_info['resources']['rds'] = get_rds_instances(module,group)
    else:
        group_info['resources']['rds'] = []

    return group_info


def list_group(connection, module):
    """ List information about groups matching filters criteria """

    filters = module.params.get('filters')
    group_dict_array = []

    try:
        all_groups = connection.get_all_security_groups(filters=filters)
    except BotoServerError as e:
        module.fail_json(msg=e.message)

    for group in all_groups:
        group_dict_array.append(get_group_info(connection, module, group))

    module.exit_json(groups=group_dict_array)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            filters = dict(default=None, type='dict'),
            lookup = dict(default=[], type='list')
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module)

    if region:
        try:
            connection = connect_to_aws(boto.ec2, region, **aws_connect_params)
        except (boto.exception.NoAuthHandlerFound, AnsibleAWSError), e:
            module.fail_json(msg = "%s: %s" % (e.error_code, e.error_message))
    else:
        module.fail_json(msg="region must be specified")

    list_group(connection, module)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
