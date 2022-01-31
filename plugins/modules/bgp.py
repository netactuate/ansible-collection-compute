#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2018, Dennis Durling <djdtahoe@gmail.com>
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
import time
import os
import re
from ansible.module_utils.basic import AnsibleModule
try:
    from naapi.api import NetActuateNodeDriver
    HAS_NAAPI = True
except ImportError:
    HAS_NAAPI = False
try:
    import ipaddress
    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False

# this is so class Foo: becomes a new style class in py2 also
# pylint: disable=invalid-name
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
module: bgp
short_description: Manage virtual machines on NetActuate infrastructure.
description:
  - Retrieve BGP session information for NetActuate nodes
version_added: "1.1.0"
author: "Dennis Durling (@tahoe)"
options:
  auth_token:
    description:
      - API Key which should be set in ENV variable HOSTVIRTUAL_API_KEY
      - C(auth_token) is required.
  hostname:
    description:
      - Hostname of the node for which to provision sessions and/or retrieve session configuration details.
  mbpkgid:
    description:
      - The purchased package ID the node is associated with. Optional if C(hostname) is a unique identifier.
  build:
    description:
      - Request provisioning of sessions to fulfil requirements as defined by parameters.
    default: False
  ipv6:
    description:
      - Request IPv6 sessions in addition to IPv4.
    default: True
  redundant:
    description:
      - Request two sessions be provisioned for redundancy.
    default: False
  group_id:
    description:
      - The unique NetActuate-provided BGP group identifier with which to associate requested sessions.
'''

EXAMPLES = '''
- name: Retrieve session configuration
  hosts: all
  remote_user: root
  gather_facts: no
  netactuate.compute.bgp:
    auth_token: "{{ auth_token }}"
    hostname: "{{ inventory_hostname }}"
  delegate_to: localhost
  register: nodebgp
'''

RETURN = '''
---
id:
  description: Device UUID.
  returned: success
  type: string
  sample: 5551212
hostname:
  description: Device FQDN
  returned: success
  type: string
  sample: a.b.com
state:
  description: Device state
  returned: success
  type: string
  sample: running
private_ipv4:
  description: Private IPv4 Address
  returned: success
  type: string
  sample: 10.100.11.129
public_ipv6:
  description: Public IPv6 Address
  returned: success
  type: string
  sample: ::1
bgp_peers:
  description: BGP Sesssions
  returned: success
  type: dict
  sample: '{
        "IPv4": [ "192.0.2.1" ], "IPv6": [ "2001:db8::1" ], "group_id": "9999", "localasn": 65002, "peerasn": "65001",
        "localpeerv4": "192.0.2.2", "localpeerv6": "2001:db8::2"
    }'
'''

HOSTVIRTUAL_API_KEY_ENV_VAR = "HOSTVIRTUAL_API_KEY"

NAME_RE = '({0}|{0}{1}*{0})'.format('[a-zA-Z0-9]', r'[a-zA-Z0-9\-]')
HOSTNAME_RE = r'({0}\.)*{0}$'.format(NAME_RE)
MAX_DEVICES = 100

ALLOWED_STATES = ['running', 'present', 'terminated', 'stopped']

# pylint: disable=too-many-instance-attributes
# pylint: disable=broad-except
class NetActuateComputeBgp:
    """Net Actuate Compute BGP class for handling
    BGP session configuration
    """
    def __init__(self, module=None):
        """All we take is the configured module, we do the rest here"""

        # Need the module for just about everything
        self.module = module

        # Handle auth via auth_token
        auth_token = self.module.params.get('auth_token')

        # now conn is just our api driver
        self.conn = NetActuateNodeDriver(auth_token)

        ##
        # set some local variables used inside most if not all methods
        ##
        # directly from the module parameters
        self.mbpkgid = self.module.params.get('mbpkgid')
        self.build = self.module.params.get('build')
        self.group_id = self.module.params.get('group_id')
        self.ipv6 = self.module.params.get('ipv6')
        self.redundant = self.module.params.get('redundant')

        # from internal methods, these use attributes or module, or both
        # if mbpkgid is not set, but hostname is set, then we
        # will look up mbpkgid by hostname
        self.hostname = self._check_valid_hostname()
        # this sets the mbpkgid if not set and the hostname is found
        # also sets back to None if there is None
        self.mbpkgid = self._check_valid_mbpkgid()

        # Set our default return components
        self.node = self._get_node()
        self.changed = False

    ###
    # Section: Helper functions that do not modify anything
    ##
    def _check_valid_mbpkgid(self):
        """Makes sure no other mbpkgid's have the same hostname
        Also returns mbpkgid if one is found and no problems found
        """
        # .servers() returns a list of dicts
        avail_nodes = self.conn.servers().json()
        # ... except when it returns an error as a dict
        if 'error' in avail_nodes:
            if 'msg' in avail_nodes and not 'Precondition Failed: No servers found' in avail_nodes['msg']:
                self.module.fail_json(msg=("API error: {0}").format(avail_nodes['msg']))

        mbpkgid = None

        for node in avail_nodes:
            # if node['status'].lower() == 'terminated':
            #     continue
            if 'fqdn' in node and node['fqdn'] == self.hostname:
                if mbpkgid is not None:
                    self.module.fail_json(
                        msg=(
                            "Failed resolving hostname to mbpkgid because "
                            "multiple instances of the hostname exist, "
                            "please specify mbpkgid for this node."
                        )
                    )
                    break
                mbpkgid = node['mbpkgid']

        if self.mbpkgid is not None and mbpkgid != self.mbpkgid:
            self.module.fail_json(
                msg=(
                    "Hostname {0} mbpkgid = {1} from the Ansible inventory "
                    "disagrees with mbpkgid = {2} from the API."
                ).format(self.hostname, self.module.params.get('mbpkgid'), mbpkgid)
            )

        return mbpkgid

    def _check_valid_hostname(self):
        """The user will set the hostname so we have to check if it's
        valid.
        Does not return on success
        Calls fail_json on failure
        """
        if re.match(HOSTNAME_RE, self.module.params.get('hostname')) is None:
            self.module.fail_json(msg="Invalid hostname: {0}"
                                  .format(self.hostname))
        return self.module.params.get('hostname')

    def _serialize_node(self):
        """Returns a json object describing the node as shown in RETURN doc
        """
        if self.node is None:
            self.module.fail_json(
                msg="Tried to serialize the node for return but it was None")

        device_data = {}
        device_data['id'] = self.node['mbpkgid']
        device_data['hostname'] = self.node['fqdn']
        device_data['state'] = self.node['status'].lower()

        # IP lookup
        ip_addresses = []
        netips = self.conn.networkips(self.node['mbpkgid']).json()
        for iptype, iplist in netips.items():
            if '4' in iptype:
                addr_type = 4
            else:
                addr_type = 6
            for ip in iplist:
                ip_addresses.append(
                    {
                        'address': ip['ip'],
                        'address_family': addr_type,
                        'public': True
                    }
                )

        for ipdata in ip_addresses:
            if ipdata['public']:
                if ipdata['address_family'] == 6:
                    device_data['public_ipv6'] = ipdata['address']
                elif ipdata['address_family'] == 4:
                    device_data['public_ipv4'] = ipdata['address']

        sess_details = []

        if not self.build:
            # Only search for BGP sessions for this node's IPs
            get_sessions = self.conn.bgp_sessions().json()
            if not get_sessions or 'sessions' not in get_sessions:
                self.module.fail_json(msg="No sessions were found for this account.")
            sess_ids = []
            for sess in get_sessions['sessions']:
                sess_id = sess['id']
                sess_peer = sess['customer_ip']
                if HAS_IPADDRESS:
                    sess_peer = ipaddress.ip_address(sess_peer)
                for ipdata in ip_addresses:
                    node_ip = ipdata['address']
                    if HAS_IPADDRESS:
                        node_ip = ipaddress.ip_address(node_ip)
                    if node_ip == sess_peer:
                        sess_ids.append(sess_id)

            # pull detailed session information
            for sess_id in sess_ids:
                sess_info = self.conn.bgp_sessions(sess_id).json()['session']
                sess_details.append(sess_info);
        else:
            # Build/retrieve sessions
            create_sessions = self.conn.bgp_create_sessions(self.mbpkgid, self.group_id,
                ipv6=self.ipv6, redundant=self.redundant).json()
            if create_sessions is None or not create_sessions['success']:
                self.module.fail_json(msg="The server was unable to provision the requested sessions.")
            sess_details = create_sessions['sessions']

        if len(sess_details) == 0:
            self.module.fail_json(msg="No sessions were found for this node.")

        # Get IPv4 and IPv6 peering information
        device_data['bgp_peers'] = {}
        peers_v4 = []
        peers_v6 = []
        for sess_info in sess_details:
            device_data['bgp_peers']['group_id'] = sess_info['group_id']
            device_data['bgp_peers']['localasn'] = sess_info['customer_asn']
            device_data['bgp_peers']['peerasn'] = sess_info['provider_asn']
            if sess_info['provider_ip_type'] == 'ipv4':
                device_data['bgp_peers']['localpeerv4'] = sess_info['customer_peer_ip']
                peers_v4.append(sess_info['provider_peer_ip'])
            else:
                device_data['bgp_peers']['localpeerv6'] = sess_info['customer_peer_ip']
                peers_v6.append(sess_info['provider_peer_ip'])
        device_data['bgp_peers']['IPv4'] = peers_v4
        device_data['bgp_peers']['IPv6'] = peers_v6

        return device_data

    def _get_node(self):
        """Just try to get the node (dict), otherwise return failure
        This function needs to get the specified node by mbpkgid
        or, if no mbpkgid is provided,
        """
        node = None

        # return early if we can't specify an mbpkgid
        if self.mbpkgid is None:
            return node

        # we have an mbpkgid so this call will work now so use it
        try:
            node = self.conn.servers(mbpkgid=self.mbpkgid).json()
        except Exception:
            # we don't want to fail from this function
            # just return the default, None
            pass
        return node

    def __call__(self):
        """Allows us to call our object from main()
        Handles everything at a high level
        by calling the appropriate method and handles
        the respones back to main other than a failure inside
        a called method
        Arguments:  None

        Return:     dict containing:
                    changed:    bool
                    device:     dict of device data
        """
        try:
            return {
                'changed': self.changed,
                'device': self._serialize_node()
            }
        except Exception as e:
            self.module.fail_json(
                msg="Narrowed down: {0}".format(str(e))
            )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            auth_token=dict(
                default=os.environ.get(HOSTVIRTUAL_API_KEY_ENV_VAR),
                no_log=True),
            hostname=dict(required=True, aliases=['name']),
            mbpkgid=dict(required=False, type=int),
            build=dict(default=False, type=bool),
            group_id=dict(type=int),
            ipv6=dict(default=True, type=bool),
            redundant=dict(default=False, type=bool)
        ),
        required_if=[
            ( 'build', True, ('group_id',) )
        ]
    )

    # don't proceed without authentication...
    if not module.params.get('auth_token'):
        _fail_msg = ("if HostVirtual API key is not in environment "
                     "variable %s, the auth_token parameter "
                     "is required" % HOSTVIRTUAL_API_KEY_ENV_VAR)
        module.fail_json(msg=_fail_msg)

    # don't proceed without the proper imports
    if not HAS_NAAPI:
        module.fail_json(msg="Failed to import module naapi, please pip install.")

    try:
        # return results
        get_bgp = NetActuateComputeBgp(module=module)
        module.exit_json(**get_bgp())
    except Exception as e:
        module.fail_json(
            msg="Failed to get BGP configuration for node {0}. Error was: {1}"
            .format(module.params.get('hostname'), str(e)))


if __name__ == '__main__':
    main()
