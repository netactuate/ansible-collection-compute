NetActuate Compute Collection
=========

This repository contains the netactuate.compute collection, including the "node" and "bgp" modules.  The netactuate.compute.node module allows for automation of provisioning, de-provisioning, startup and shutdown tasks of compute nodes.  The netactuate.compute.bgp module allows for provisioning of BGP sessions and programmatic retrieval of session configuration details.

Requirements
------------

  * Ansible >= 2.8.0
  * naapi >= 0.1.7

Installation
------------

    pip install naapi>=0.1.7 ansible>=2.8.0
    ansible-galaxy collection install netactuate.compute


Node Module
=========

Variables
---------

List of required Role or Host variables

	state
		Desired state. One of [ present, running, stopped, terminated ]
	location
		Install location. ID or full name of location from portal.
	operating_system
		Install OS. ID or full name of OS from portal.
	ssh_public_key
		Path to your public key file.
	mbpkgid
		Package ID of purchased package to work with.  Optional.  If mbpkgid is not specified for an existing node, it will
		be resolved by the hostname parameter if the unique parameter is true and there is exactly one non-terminated node with
		that hostname.  mbpkgid will not yet be assigned for a new node and is not expected.
	hostname
		FQDN to set for the node.
	unique
		Indicates that the hostname is unique and can be used as a node identifier.  If an attempt is made to build a
		node with a duplicate hostname while unique=true, an error will be returned.
	auth_token
		API key from settings page on portal.
		This can also be set in the environment variable HOSTVIRTUAL_API_KEY.
		If both are set, the module parameter takes precedence over the environment variable.
	package_billing
		Desired package billing.  Absent for standard subscription billing, otherwise 'contract' to associate with a contract service or 'usage' for usage billing.
	contract_id
		Optional for standard or usage billing, required for contract billing.  The contract ID to associate the node with.


Dependencies
------------

This module does not depend on any other roles, it is the base role to ensure
your OS is installed and running.

Examples
----------------

Both examples assume an inventory.txt containing the following:

    [master]
    localhost ansible_connection=local ansible_python_interpreter=python

This is the minimum you need in a playbook to ensure running state for the specified node.

    ---
    - hosts: master
      connection: local

      tasks:
      - name: Ensure netactuate.compute.node is running
        netactuate.compute.node:
          auth_token: <api key from portal>
          hostname: <node hostname>
          ssh_public_key: <ssh public key content>
          operating_system: <image name or ID from portal>
          location: <location name or ID from portal>
          plan: <plan name from portal>
          state: running
          unique: true
        delegate_to: localhost

This is a a more complete example exhibiting dynamic inventory enrollment.

    ---
    - hosts: master
      connection: local

      vars:
        auth_token: <your API key goes here>
        nodes:
          - { hostname: node0.example.com, ssh_public_key: keys.pub, operating_system: 'Debian 9.8 x64 (HVM/PV)', location: 'RDU - Raleigh, NC', plan: 'VR1x1x25' }
          - { hostname: node1.example.com, ssh_public_key: keys.pub, operating_system: 'Debian 9.8 x64 (HVM/PV)', location: 'RDU - Raleigh, NC', plan: 'VR1x1x25' }
          - { hostname: node2.example.com, ssh_public_key: keys.pub, operating_system: 'Debian 9.8 x64 (HVM/PV)', location: 'RDU - Raleigh, NC', plan: 'VR1x1x25', mbpkgid: '<PKGID GOES HERE>' }

      tasks:
      - name: Ensure netactuate.compute.node is in the requested state
        netactuate.compute.node:
          hostname: "{{ item.hostname }}"
          ssh_public_key: "{{ item.ssh_public_key }}"
          operating_system: "{{ item.operating_system }}"
          location: "{{ item.location }}"
          plan: "{{ item.plan }}"
          state: running
          unique: true
          auth_token: "{{ auth_token }}"
    #      package_billing: usage
    #      contract_id: 12345
        delegate_to: localhost
        with_items: "{{ nodes }}"
        register: na

      - name: See if it is there
        debug: var=na

      - debug: msg="{{ item.device.public_ipv4 }}"
        with_items: "{{ na.results }}"
        when: item.device.state != "terminated"

      - name: Add host to our inventory
        add_host:
          hostname: "{{ item.device.public_ipv4 }}"
          groups: nodes
          ansible_ssh_extra_args: '-o StrictHostKeyChecking=no'
        with_items: "{{ na.results }}"
        when: (item.device.state != "terminated") and (item.device.public_ipv4 is defined)
        changed_when: False

    - hosts: nodes
      gather_facts: False
      tasks:
      - name: Wait for port 22 to be reachable
        wait_for:
          port: 22
          host: '{{ (ansible_ssh_host|default(ansible_host))|default(inventory_hostname) }}'
          search_regex: OpenSSH
          delay: 60
          connect_timeout: 60
        retries: 6
        vars:
          ansible_connection: local

    - hosts: nodes
      remote_user: root
      connection: ssh
      gather_facts: True
      tasks:
      - name: Install htop
        apt: name=htop state=present


BGP Module
=========

Variables
---------

List of required Role or Host variables

    auth_token:
      API key from settings page on portal.
      This can also be set in the environment variable HOSTVIRTUAL_API_KEY.
      If both are set, the module parameter takes precedence over the environment variable.
    hostname:
      Hostname of the node for which to provision sessions and/or retrieve session configuration details.
    mbpkgid:
      The purchased package ID the node is associated with. Optional if hostname is already a unique identifier.
    build:
      Request provisioning of sessions to fulfil requirements as defined by parameters.
    ipv6:
      Request IPv6 sessions in addition to IPv4 (default=True).
    redundant:
      Request two sessions be provisioned for redundancy (default=False).
    group_id:
      The unique NetActuate-provided BGP group identifier with which to associate requested sessions.

Example
-------

Assuming an inventory.txt containing the following:

    [master]
    localhost ansible_connection=local ansible_python_interpreter=python

    [nodes]
    node01.example.com
    node02.example.com

This is the minimum you need in a playbook to request BGP sessions for specified nodes.

    ---
    - name: BGP
      hosts: nodes
      gather_facts: no
      serial: 1

      tasks:
      - name: Provision peering
        netactuate.compute.bgp:
          auth_token: <api key from portal>
          hostname: "{{ inventory_hostname }}"
          build: true
          group_id: <bgp group id>
        delegate_to: localhost
        register: na

Peering information is included in the return dictionary for further use.

Return
------

On successful execution, the return dictionary will include a "device" key containing information needed to configure the retrieved or newly provisioned sesssions, for example:

    "device": {
        "bgp_peers": {
            "IPv4": [
                "192.0.2.1",
                "192.0.2.2"
            ],
            "IPv6": [
                "2001:db8:100::1",
                "2001:db8:100::2"
            ],
            "group_id": "1111",
            "localasn": "65001",
            "localpeerv4": "192.0.2.100",
            "localpeerv6": "2001:db8:100::1000",
            "peerasn": "65000"
        },
        "hostname": "node01.example.com",
        "id": "2222",
        "public_ipv4": "192.0.2.100",
        "public_ipv6": "2001:db8:100::1000",
        "state": "running"
    }


License
=========

GPLv2
