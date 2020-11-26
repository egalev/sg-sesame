import builtins
from tempfile import NamedTemporaryFile
from unittest import mock
from unittest.mock import MagicMock

import pytest

from sg_sesame import sg_sesame
from sg_sesame.sg_sesame import (
    insert_rule_to_group,
    get_credentials_and_region,
    remove_rule_from_group,
    find_group_to_remove_from,
    select_group_to_add_to,
)


def test_sg_sesame():
    assert sg_sesame is not None


IP_RANGE = "1.1.1.1/32"
PROTOCOL = "tcp"
DESCRIPTION = "description"
GROUP_NAME = "g1"
PORT = 22


def test_insert_rule_to_group():
    ec2_mock = MagicMock()
    insert_rule_to_group(IP_RANGE, PORT, PROTOCOL, DESCRIPTION, GROUP_NAME, ec2_mock)
    ec2_mock.get.assert_called_once_with(
        "AuthorizeSecurityGroupIngress",
        params={
            "IpPermissions.1.IpRanges.1.CidrIp": IP_RANGE,
            "GroupName": GROUP_NAME,
            "IpPermissions.1.IpRanges.1.Description": DESCRIPTION,
            "IpPermissions.1.FromPort": PORT,
            "IpPermissions.1.ToPort": PORT,
            "IpPermissions.1.IpProtocol": PROTOCOL,
        },
    )


def test_remove_rule_from_group():
    ec2_mock = MagicMock()
    group_mock = MagicMock()
    group_mock.find.return_value.text = GROUP_NAME
    group_mock.find.return_value.find.return_value.text = IP_RANGE
    remove_rule_from_group(PORT, PROTOCOL, DESCRIPTION, group_mock, ec2_mock)
    ec2_mock.get.assert_called_once_with(
        "RevokeSecurityGroupIngress",
        params={
            "GroupName": GROUP_NAME,
            "IpPermissions.1.IpRanges.1.CidrIp": IP_RANGE,
            "IpPermissions.1.FromPort": PORT,
            "IpPermissions.1.ToPort": PORT,
            "IpPermissions.1.IpProtocol": PROTOCOL,
        },
    )


def test_find_group_to_remove_from_missing():
    xml_mock = MagicMock()
    with pytest.raises(ValueError):
        find_group_to_remove_from(DESCRIPTION, xml_mock)


def test_find_group_to_remove_from_exactly_one():
    xml_mock = MagicMock()
    xml_mock.findall.return_value = ["g1"]
    group = find_group_to_remove_from(DESCRIPTION, xml_mock)
    assert group == "g1"


def test_find_group_to_remove_from_more_than_one():
    xml_mock = MagicMock()
    groups = [MagicMock(), MagicMock()]
    groups[0].find.return_value.text.side_effect = ["sg-1", "g1"]
    groups[1].find.return_value.text.side_effect = ["sg-2", "g2"]
    xml_mock.findall.return_value = groups
    with mock.patch.object(builtins, "input", lambda _: "2"):
        group = find_group_to_remove_from(DESCRIPTION, xml_mock)
    assert group == groups[1]


def test_select_group_to_add_to_missing():
    xml_mock = MagicMock()
    with pytest.raises(ValueError):
        select_group_to_add_to(GROUP_NAME, PORT, xml_mock)


def test_get_credentials_and_region():
    with NamedTemporaryFile() as temp_credfile, NamedTemporaryFile() as temp_conffile:
        temp_credfile.write(
            b"""
        [prof1]
        aws_access_key_id = ABC123
        aws_secret_access_key = abc123"""
        )
        temp_conffile.write(
            b"""
        [profile-prof1]
        region = us-east-2"""
        )
        temp_credfile.flush()
        temp_conffile.flush()
        cred, region = get_credentials_and_region(
            "prof1", temp_credfile.name, temp_conffile.name
        )
        assert cred["aws_access_key_id"] == "ABC123"
        assert cred["aws_secret_access_key"] == "abc123"
        assert region == "us-east-2"
