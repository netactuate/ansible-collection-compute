# Migrating from netactuate.compute to netactuate.cloud

The `netactuate.compute` collection is deprecated. This guide maps its two
modules to their `netactuate.cloud` replacements.

## Install the new collection

    ansible-galaxy collection install netactuate.cloud
    pip install netactuate        # the maintained NetActuate Python SDK

Authentication moves from an `auth_token` module argument to the `api_key`
argument (or the `NETACTUATE_API_KEY` environment variable), shared by every
`netactuate.cloud` module.

## netactuate.compute.node  ->  netactuate.cloud.server

| compute.node        | cloud.server              | notes |
|---------------------|---------------------------|-------|
| auth_token          | api_key                   | or NETACTUATE_API_KEY |
| hostname / name     | fqdn                      | the server FQDN |
| ssh_public_key      | ssh_key                   | public key string; or ssh_key_id |
| operating_system    | image                     | numeric image ID |
| location            | location                  | numeric location ID |
| mbpkgid             | plan (+ package_billing)  | cloud.server provisions from a plan |
| state: present      | state: present            | |
| state: terminated   | state: absent             | |

Power lifecycle differs. `compute.node` folded power state
(`running` / `stopped`) into `state`. `cloud.server` manages existence
(`present` / `absent`); power operations are a separate concern and are not
driven through the `state` argument.

Before:

    - name: Provision a node
      netactuate.compute.node:
        auth_token: "{{ na_token }}"
        hostname: web1.example.com
        operating_system: 1447
        location: 3
        mbpkgid: 12345
        state: running

After:

    - name: Provision a server
      netactuate.cloud.server:
        api_key: "{{ na_api_key }}"
        fqdn: web1.example.com
        image: 1447
        location: 3
        plan: VR1x1x25
        state: present

## netactuate.compute.bgp  ->  netactuate.cloud.bgp_session

| compute.bgp   | cloud.bgp_session | notes |
|---------------|-------------------|-------|
| auth_token    | api_key           | or NETACTUATE_API_KEY |
| mbpkgid       | mbpkgid           | same |
| group_id      | group_id          | same |
| redundant     | redundant         | same |
| build         | state: present    | creation is implied by state=present |
| (n/a)         | ipv6              | select the IPv6 session |

Before:

    - name: Establish a BGP session
      netactuate.compute.bgp:
        auth_token: "{{ na_token }}"
        mbpkgid: 12345
        group_id: 678
        redundant: true
        build: true

After:

    - name: Establish a BGP session
      netactuate.cloud.bgp_session:
        api_key: "{{ na_api_key }}"
        mbpkgid: 12345
        group_id: 678
        redundant: true
        state: present

## Beyond the two modules

`netactuate.cloud` covers far more than compute and BGP: VPCs, DNS zones and
records, NKE clusters, object and block storage, cloud routers and VRFs, magic
mesh, firewall sets and rules, floating IPs, and more. See the collection
documentation for the full module list.
