from xml.etree import ElementTree as ET

import requests
from requests_aws4auth import AWS4Auth


class EC2API:
    endpoint = 'https://ec2.amazonaws.com/'
    version = '2016-11-15'
    namespace_map = {'': 'http://ec2.amazonaws.com/doc/2016-11-15/'}

    def __init__(self, creds, region):
        self._auth = AWS4Auth(creds['aws_access_key_id'], creds['aws_secret_access_key'], region, 'ec2')

    def _make_request(self, method, action, params, raise_for_status=True):
        all_params = dict(Version=self.version, Action=action)
        all_params.update(params)
        response = requests.request(method, self.endpoint, auth=self._auth, params=all_params)
        if raise_for_status:
            response.raise_for_status()
        return response

    def get(self, action, params, raise_for_status=True):
        return self._make_request('get', action, params, raise_for_status)

    @staticmethod
    def xml_find(root: ET.Element, path: str):
        return root.find(path, EC2API.namespace_map)

    @staticmethod
    def xml_findall(root: ET.Element, path: str):
        return root.findall(path, EC2API.namespace_map)
