from os.path import expanduser
from socket import gethostname
import click
import requests
from requests import HTTPError
import configparser
import xml.etree.ElementTree as ET

from .ec2_utils import EC2API


@click.command()
@click.option('--port', required=True, type=int)
@click.option('--note', default=None, type=str, help='Description of the rule to be added/updated. If omitted, '
                                                     'the machine hostname will be used.')
@click.option('--add/--no-add', default=False, help='If not specified, will try to update an existing rule that has '
                                                    'matching `note`, `port` and `protocol`. Otherwise will add a new '
                                                    'rule.')
@click.option('--group-name', default=None, help='If specified, the rule will be added to the Security Group with '
                                                 'this name. Otherwise will prompt the user to select a SG.')
@click.option('--protocol', default='tcp', show_default=True, help='Protocol to use for the rule')
@click.option('--profile', default='default', show_default=True, help='AWS profile to use')
@click.option('--region', default=None, type=str, help='AWS Region to connect to')
def sg_sesame(port, group_name, note, protocol, add, profile, region):
    description = note if note is not None else gethostname()
    creds, region_from_profile = get_credentials_and_region(profile)
    prioritized_region = [x for x in [region, region_from_profile, 'us-east-1'] if x is not None][0]
    ec2 = EC2API(creds, prioritized_region)
    try:
        response = ec2.get('DescribeSecurityGroups', params={'Filter.1.Name': 'ip-permission.from-port',
                                                             'Filter.1.Value.1': port})
        root = ET.fromstring(response.text)
        if not add:
            group_to_remove_from = find_group_to_remove_from(description, root)
            insert_group_name = EC2API.xml_find(group_to_remove_from, './groupName').text
            remove_rule_from_group(port, protocol, description, group_to_remove_from, ec2)
        else:
            insert_group_name = select_group_to_add_to(group_name, port, root)
        ip_range = my_ip_range()
        insert_rule_to_group(ip_range, port, protocol, description, insert_group_name, ec2)
    except HTTPError as httpe:
        print('Operation failed')
        root = ET.fromstring(httpe.response.text)
        errors = root.findall('.//Message')
        for error in errors:
            print(error.text)
    except ValueError as ve:
        print(ve)


def my_ip_range():
    my_ip = requests.get('https://ip.me').text.strip()
    ip_range = f'{my_ip}/32'
    return ip_range


def insert_rule_to_group(ip_range, port, protocol, description, insert_group_name, ec2):
    print(f'Inserting rule {ip_range}:{port}({description}) to group {insert_group_name}')
    ec2.get('AuthorizeSecurityGroupIngress', params={
        'IpPermissions.1.IpRanges.1.CidrIp': ip_range,
        'GroupName': insert_group_name,
        'IpPermissions.1.IpRanges.1.Description': description,
        'IpPermissions.1.FromPort': port,
        'IpPermissions.1.ToPort': port,
        'IpPermissions.1.IpProtocol': protocol})


def select_group_to_add_to(group_name, port, root):
    groups = EC2API.xml_findall(root, f'./securityGroupInfo/item')
    if len(groups) == 0:
        raise ValueError(f'No groups found with a rule for port {port}')
    if not group_name:
        print(f'Multiple Security Groups have a rule with port {port}')
        for i, g in enumerate(groups):
            print(f'[{i + 1}]', EC2API.xml_find(g, './groupId').text, EC2API.xml_find(g, './groupName').text)
        group_num = input('Which group would you like to update? ')
        insert_group_name = EC2API.xml_find(groups[int(group_num) - 1], './groupName').text
    else:
        insert_group_name = group_name
    return insert_group_name


def find_group_to_remove_from(description, root):
    groups = EC2API.xml_findall(
        root,
        f"./securityGroupInfo/item/ipPermissions/item/ipRanges/item/[description='{description}']/../../../..")
    if len(groups) > 1:
        print(f'Multiple Security Groups have a rule with the note {description}')
        for i, g in enumerate(groups):
            print(f'[{i + 1}]', EC2API.xml_find(g, './groupId').text, EC2API.xml_find(g, './groupName').text)
        group_num = input('Which group would you like to update? ')
        group_to_remove_from = groups[int(group_num) - 1]
    elif len(groups) == 1:
        group_to_remove_from = groups[0]
    else:
        raise ValueError(f'No group found with a rule that has a note {description}, and --add was not set')
    return group_to_remove_from


def remove_rule_from_group(port, protocol, description, group_to_remove_from, ec2: EC2API):
    range_to_remove = EC2API.xml_find(group_to_remove_from,
                                      f"./ipPermissions/item/ipRanges/item/[description='{description}']")
    remove_group_name = EC2API.xml_find(group_to_remove_from, './groupName').text
    ip_to_remove = EC2API.xml_find(range_to_remove, './cidrIp').text
    print(f'Removing rule {ip_to_remove}:{port}({description}) from group {remove_group_name}')
    ec2.get('RevokeSecurityGroupIngress', params={
        'GroupName': remove_group_name,
        'IpPermissions.1.IpRanges.1.CidrIp': ip_to_remove,
        'IpPermissions.1.FromPort': port,
        'IpPermissions.1.ToPort': port,
        'IpPermissions.1.IpProtocol': protocol})


def get_credentials_and_region(profile,
                               default_credentials_file='~/.aws/credentials',
                               default_config_file='~/.aws/config'):
    cred_config = configparser.ConfigParser()
    cred_config.read(expanduser(default_credentials_file))
    creds = cred_config[profile]

    config = configparser.ConfigParser()
    config.read(expanduser(default_config_file))
    profile_name = 'default' if profile == 'default' else f'profile-{profile}'
    region = None
    if profile_name in config:
        region = config[profile_name].get('region')
    return creds, region


if __name__ == '__main__':
    sg_sesame()
