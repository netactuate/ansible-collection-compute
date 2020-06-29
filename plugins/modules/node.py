'''
module: node
short_description: Manage virtual machines on NetActuate infrastructure.
description:
  - Deploy newly purchaced packages.
  - Build, destroy, start and stop previously built packages.
version_added: "2.6.0"
author: "Dennis Durling (@tahoe)"
options:
  auth_token:
    description:
      - API Key which should be set in ENV variable HOSTVIRTUAL_API_KEY
      - C(auth_token) is required.
  hostname:
    description:
      - Hostname of the node. C(name) can only be a valid hostname.
      - Either C(name) is required.
  name:
    description:
      - Custom display name of the instances.
      - Host name will be set to C(name) if not specified.
      - Either C(name) or C(hostname) is required.
  ssh_public_key:
    description:
      - Path to the ssh key that will be used for node authentication.
      - C(ssh_public_key) is required for host authentication setup.
  operating_system:
    description:
      - Either the ID or full name of the OS to be installed on the node.
      - C(operating_system) is required.
      - NOTE, to many choices to list here. Will provide a script for customers
        to list OSes.
  mbpkgid:
    description:
      - The purchased package ID the node is associated with.
      - Required as purchasing new nodes is not yet available here.
  state:
    description:
      - Desired state of the instance.
    default: running
    choices: [ present, running, stopped, terminated ]
  location:
    description:
      - Name or id of physical location the node should be built in.
      - Required.
      - Note, Currently once this is set it cannot be changed from ansible.
'''
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

# this is so class Foo: becomes a new style class in py2 also
# pylint: disable=invalid-name
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

EXAMPLES = '''
- name: Running
  hosts: all
  remote_user: root
  gather_facts: no
  netactuate.compute.node:
    state: running

- name: Stopped
  hosts: all
  remote_user: root
  gather_facts: no
  netactuate.compute.node:
    state: stopped
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
ip_addresses:
  description: Dictionary of configured IP addresses.
  returned: success
  type: dict
  sample: '[{ "address": "8.8.8.8", "address_family": "4", "public": "true" }]'
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
state:
  description: Device state
  returned: success
  type: string
  sample: running
'''

HOSTVIRTUAL_API_KEY_ENV_VAR = "HOSTVIRTUAL_API_KEY"

NAME_RE = '({0}|{0}{1}*{0})'.format('[a-zA-Z0-9]', r'[a-zA-Z0-9\-]')
HOSTNAME_RE = r'({0}\.)*{0}$'.format(NAME_RE)
MAX_DEVICES = 100

ALLOWED_STATES = ['running', 'present', 'terminated', 'stopped']

# pylint: disable=too-many-instance-attributes
# pylint: disable=broad-except
class NetActuateComputeState:
    """Net Actuate Compute State class for handling
    checking and changing state
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
        # from the api connection
        # the api returns locations in a dict, we want a list
        self.avail_locs = self._sorted_locations()
        # no mods to the output, already a list
        self.avail_oses = self.conn.os_list().json()

        # directly from the module parameters
        self.desired_state = self.module.params.get('state').lower()
        self.mbpkgid = self.module.params.get('mbpkgid')
        self.os_arg = self.module.params.get('operating_system')
        self.loc_arg = self.module.params.get('location')
        self.unique = self.module.params.get('unique')
        self.plan = self.module.params.get('plan')
        self.package_billing = self.module.params.get('package_billing')
        self.contract_id = self.module.params.get('contract_id')
        self.ssh_key_file = self.module.params.get('ssh_public_key')

        # from internal methods, these use attributes or module, or both
        # if mbpkgid is not set, but unique and hostname are set, then we
        # will look up mbpkgid by hostname
        self.hostname = self._check_valid_hostname()
        # this sets the mbpkgid if not set and the hostname is found
        # also sets back to None if there is None
        self.mbpkgid = self._check_valid_mbpkgid()
        self.ssh_key = self._get_ssh_auth()
        self.image = self._get_os()
        self.location = self._get_location()

        # Set our default return components
        self.node = self._get_node()
        self.changed = False

    def _sorted_locations(self):
        locations = self.conn.locations().json()
        if 'error' in locations:
            if 'msg' in locations:
                self.module.fail_json(msg=("API error: {0}").format(avail_nodes['msg']))

        return sorted(locations, key=lambda x: int(x['id']))


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

    def _get_ssh_auth(self):
        """Figure out the ssh public key for building into the node
        Returns the public key on success,
        Calls fail_json on failure
        """
        try:
            key = open(self.ssh_key_file).read()
        except OSError as e:
            self.module.fail_json(
                msg=(
                    "Could not load ssh_public_key for {0},"
                    "Error was: {1}"
                ).format(self.hostname, str(e))
            )
        if key:
            return key
        self.module.fail_json(
            msg=(
                "ssh_public_key file for {0} is empty."
            ).format(self.hostname)
        )

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
        device_data['ip_addresses'] = []
        netips = self.conn.networkips(self.node['mbpkgid']).json()
        for iptype, iplist in netips.items():
            if '4' in iptype:
                addr_type = 4
            else:
                addr_type = 6
            for ip in iplist:
                device_data['ip_addresses'].append(
                    {
                        'address': ip['ip'],
                        'address_family': addr_type,
                        'public': True
                    }
                )

        # Also include each IPs as a key for easier lookup in roles.
        # Key names:
        # - public_ipv4
        # - public_ipv6
        # - private_ipv4
        # - private_ipv6 (if there is one)
        for ipdata in device_data['ip_addresses']:
            if ipdata['public']:
                if ipdata['address_family'] == 6:
                    device_data['public_ipv6'] = ipdata['address']
                elif ipdata['address_family'] == 4:
                    device_data['public_ipv4'] = ipdata['address']
            elif not ipdata['public']:
                if ipdata['address_family'] == 6:
                    device_data['private_ipv6'] = ipdata['address']
                elif ipdata['address_family'] == 4:
                    device_data['private_ipv4'] = ipdata['address']
        return device_data

    def _get_location(self):
        """Check if a location is allowed/available

        Runs fail_json(msg) if we can't use it
        Returns a location dict otherwise
        """
        location = None
        loc_possible_list = [
            loc for loc in self.avail_locs
            if self.loc_arg in [loc['name'], loc['id']]
        ]

        if not loc_possible_list:
            _msg = "Location '{0}' not found".format(self.loc_arg)
            self.module.fail_json(msg=_msg)
        else:
            # if we get more than one, just send the first
            location = loc_possible_list[0]
        return location

    def _get_os(self):
        """Check if provided os is allowed/available

        Raises an exception if we can't use it
        Returns an image/OS dict otherwise
        """
        image = None
        os_possible_list = [
            os for os in self.avail_oses
            if self.os_arg in [os['os'], os['id']]
        ]

        if not os_possible_list:
            _msg = "Image '{0}' not found".format(self.os_arg)
            self.module.fail_json(msg=_msg)
        else:
            image = os_possible_list[0]
        return image

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

    def _get_job(self, mbpkgid=None, job_id=None):
        """Get a specific job's status from the api"""
        result = {}
        if mbpkgid is not None and job_id is not None:
            try:
                result = self.conn.get_job(mbpkgid, job_id).json()
            except Exception as e:
                self.module.fail_json(
                    msg="Failed to get job status for node {}, job_id {} "
                    "with error: {}".format(self.hostname, job_id, str(e))
                )
        return result

    ###
    # Section:  Main functions that will initiate self.node/self.changed
    #           updates or they will make updates themseleves
    ###
    def wait_for_state(self, wait_state, timeout=600, interval=10):
        """Called after build_node to wait to make sure it built OK
        Arguments:
            node_id:            int     ID of node
            timeout:            int     timeout in seconds
            interval:           float   sleep time between loops
            state:      string  string of the desired state
        """
        try_node = None
        for _ in range(0, timeout, int(interval)):
            try:
                try_node = self.conn.servers(mbpkgid=self.mbpkgid).json()
                if try_node["status"].lower() == wait_state:
                    break
            except Exception as e:
                self.module.fail_json(
                    msg=(
                        "Failed to get updated status for {0} Error was {1}"
                    ).format(self.hostname, str(e))
                )
            time.sleep(interval)
        self.node = try_node
        self.changed = True

    def wait_for_job_complete(self, result=None, state=None):
        """Calls _get_job until timeout or status == 5
        Either fail_json will be called or wait_for_state
        """
        timeout = 600
        interval = 5

        try:
            # get the job id from the result
            job_id = result.get('id', None)
            # only time the 'id' isn't in the result is for build
            # in that case the job dict is in the main dict under
            # key 'build'
            if job_id is None:

                # try the build key
                build = result.get('build', None)

                # if no build key, then fail
                if build is None:
                    self.module.fail_json(
                        msg=(
                            "Failed to get job_id for node {0} from result {1}"
                        ).format(self.hostname, result)
                    )
                else:
                    job_id = build['id']
                    # given where we got this from, we probably don't have
                    # an mbpkgid, get it from the outter result
                    self.mbpkgid = result['mbpkgid']

            # now get the mbpkgid or we can't do anything
            mbpkgid = self.mbpkgid
            if mbpkgid is None:
                if getattr(self, 'node', None) is not None:
                    mbpkgid = self.node['mbpkgid']
                else:
                    self.module.fail_json(
                        msg=(
                            "Cannot check job status, not enough information "
                            "No mbpkgid or no job_id or neither found"
                            "Result is: ******{0}".format(result)
                        )
                    )
            # we got what we need (mbpkgid, job_id)
            status = None
            # loop through range/interval (timeout) until we get status == 5
            for _ in range(0, timeout, int(interval)):
                status = self._get_job(mbpkgid, job_id)
                # break on 5, 6 or 7 so we don't wait forever to find out it failed.
                # since they never change from these states
                if status and status['status'] in ['5', '6', '7']:
                    break
                time.sleep(interval)

            # we've timed out, last check
            if status is None or status['status'] != '5':
                # problem!
                self.module.fail_json(
                    msg=(
                        "Failed to get completed status for node {}. "
                        "Desired state was {}, Job status was {}"
                    ).format(self.hostname, state, status)
                )
            else:
                # call to wait_for_state "should" return very quickly!
                # wait for the node to reach the desired state
                self.wait_for_state(state)
        except Exception as e:
            self.module.fail_json(
                msg="wait_for_job_completed failed: {0}".format(str(e))
            )

    def build_node(self):
        """Build nodes
        If the node has never been built, it uses only params.
        Otherwise it uses info from node if possible
        NOTE:   I don't like the logic here, this whole thing assumes
        """
        try:
            # set up params to build the node
            if self.node is None:
                # no node exists yet
                # probably no mbpkgid exists either
                params = {
                    'mbpkgid': self.mbpkgid,
                    'image': self.image['id'],
                    'fqdn': self.hostname,
                    'location': self.location['id'],
                    'ssh_key': self.ssh_key,
                    'plan': self.plan,
                    'package_billing': self.package_billing,
                    'package_billing_contract_id': self.contract_id,
                    'unique': self.unique
                }
            else:
                # node exists
                params = {
                    'mbpkgid': self.node['mbpkgid'],
                    'image': self.image['id'],
                    'fqdn': self.hostname,
                    'location': self.node['location_id'],
                    'ssh_key': self.ssh_key,
                    'plan': self.plan,
                    'package_billing': self.package_billing,
                    'package_billing_contract_id': self.contract_id,
                    'unique': self.unique,
                }
        except Exception as e:
            self.module.fail_json(
                msg="build_node failed: {0}".format(str(e))
            )

        # start the build process and get the job_id in the result
        try:
            result = self.conn.buy_build(params=params).json()
        except Exception as e:
            self.module.fail_json(
                msg="Failed to build node for node {0} with: {1}"
                .format(self.hostname, str(e)))

        # wait for job to complete and state to be verified
        self.wait_for_job_complete(result=result, state='running')

    def start_node(self):
        """Call API to start a running node
        """
        try:
            if self.node and getattr(self.node, 'mbpkgid', None) is not None:
                result = self.conn.start(self.node['mbpkgid']).json()
            elif self.mbpkgid is not None:
                result = self.conn.start(self.mbpkgid).json()
        except Exception as e:
            self.module.fail_json(
                msg="Failed to start node for node {0} with: {1}"
                .format(self.hostname, str(e)))


        # wait for job to complete and state to be verified
        self.wait_for_job_complete(result=result, state='running')

    def stop_node(self, force=False):
        """Call API to stop a running node
        """
        mbpkgid = self.node['mbpkgid'] if self.node else self.mbpkgid
        if mbpkgid is None:
            self.module.fail_json(
                msg=(
                    "Failed to stop node {0}, no mbpkgid found"
                ).format(self.hostname)
            )
        try:
            result = self.conn.shutdown(mbpkgid, force=force).json()
        except Exception as e:
            self.module.fail_json(
                msg=(
                    "Failed to stop node for node {0} with: {1}"
                ).format(self.hostname, str(e))
            )

        # wait for job to complete and state to be verified
        self.wait_for_job_complete(result=result, state='stopped')

    ###
    #
    # Section: ensure_<state> methods
    #
    # All methods require that the node be built at least
    # once so that it is registered
    #
    ###
    def ensure_node_running(self):
        """Called when we want to just make sure the node is running
        Builds node if it's not built
        Starts node if it's not started
        """
        # if the node has never been built, build it and return
        # since the default state of a newly built node should be
        # 'running' or it will fail
        try:
            if self.node is None or self.node['status'].lower() == 'terminated':
                self.build_node()
            elif self.node.state != 'running':
                self.start_node()
        except Exception as e:
            self.module.fail_json(
                msg="ensure_node_running failed: {0}".format(str(e))
            )

    def ensure_node_stopped(self):
        """Called when we want to just make sure that a node is NOT running
        Builds node if it's not built
        Stops node if it's not started
        """
        if self.node['status'].lower() != 'stopped':
            if self.node['status'].lower() == 'terminated':
                self.build_node()
            self.stop_node()

    def ensure_node_present(self):
        """Called when we want to just make sure that a node is NOT terminated
        Meaning that it is at least installed
        If we have to build it, it will actually be in state 'running'
        But 'running' is > 'present' so still true...
        """
        # only do anything if the node.state == 'terminated'
        if self.node.state == 'terminated':
            # build_node will set changed to True after it installs it
            self.build_node()

    def ensure_node_terminated(self, cancel_billing=True):
        """Calls the api endpoint to delete the node and returns the result"""
        extra_params = {
            'cancel_billing': cancel_billing,
        }
        try:
            result = self.conn.delete(self.mbpkgid, extra_params=extra_params).json()
        except Exception as e:
            self.module.fail_json(
                msg="Failed to delete node for node {0} with: {1}"
                .format(self.hostname, str(e)))

        self.wait_for_job_complete(result=result, state='terminated')

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
        # first check
        try:
            if self.node is None and self.desired_state == 'terminated':
                return {
                    'changed': False,
                    'device': {
                        'state': 'terminated',
                    },
                }

            # We only need to do any work if the below conditions exist
            # otherwise we will return the defaults
            try:
                if self.node is None or self.node['status'].lower() != self.desired_state:
                    try:
                        if self.desired_state == 'running':
                            self.ensure_node_running()
                    except Exception:
                        self.module.fail_json(msg="Failed to ensure_node_running")

                    try:
                        if self.desired_state == 'stopped':
                            self.ensure_node_stopped()
                    except Exception:
                        self.module.fail_json(msg="Failed to ensure_node_stopped")

                    try:
                        if self.desired_state == 'present':
                            self.ensure_node_present()
                    except Exception:
                        self.module.fail_json(msg="Failed to ensure_node_present")

                    try:
                        if self.desired_state == 'terminated':
                            self.ensure_node_terminated()
                    except Exception:
                        self.module.fail_json(msg="Failed to ensure_node_terminated")

                # in order to return, we must have a node object and a status (changed)
                # whether or not state has changed to the desired state
                return {
                    'changed': self.changed,
                    'device': self._serialize_node()
                }
            except Exception as e:
                self.module.fail_json(
                    msg="Narrowed down: {0}".format(str(e))
                )
        except Exception as e:
            self.module.fail_json(
                msg="Initial failure: {0}".format(str(e))
            )


def main():
    """Main function, calls ensure_state to handle all the logic
    for determining which ensure_node_<state> function to call.
    mainly to keep this function clean
    """
    module = AnsibleModule(
        argument_spec=dict(
            auth_token=dict(
                default=os.environ.get(HOSTVIRTUAL_API_KEY_ENV_VAR),
                no_log=True),
            hostname=dict(required=True, aliases=['name']),
            mbpkgid=dict(required=False),
            operating_system=dict(required=True),
            ssh_public_key=dict(required=True),
            location=dict(required=True),
            state=dict(choices=ALLOWED_STATES, default='running'),
            plan=dict(required=False),
            package_billing=dict(default='usage'),
            contract_id=dict(required=False),
            unique=dict(default=True),
        ),
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
        # build_provisioned_node returns a dictionary so we just reference
        # the return value here
        ensure_state = NetActuateComputeState(module=module)
        module.exit_json(**ensure_state())
    except Exception as e:
        module.fail_json(
            msg="failed to set machine state for node {0} "
            "to {1}. Error was: {2}"
            .format(module.params.get('hostname'),
                    module.params.get('state'), str(e)))


if __name__ == '__main__':
    main()
