from sky.api import permanent, ephemeral, infrastructure, ready
from sky.networking import create_network, create_subnets
from sky.compute import get_instances, create_instances, terminate_instances, create_nat_instances, create_security_group, create_load_balancer, register_instances
from sky.database import create_database
from sky.security import upload_ssl_certificate
from sky.state import config

@permanent
@infrastructure
def network():
    print('Setting up network...')
    virtual_network = create_network(network_class='b', internet_connected=True)
    public_subnets = create_subnets(virtual_network, zones=['us-east-1b', 'us-east-1c'], byte_aligned=True, public=True)
    private_subnets = create_subnets(virtual_network, zones=['us-east-1b', 'us-east-1c'], byte_aligned=True)

@permanent
@infrastructure(requires=['network', 'nat', 'application_security_groups'])
def database():
    print('Setting up database...')
    database = create_database(ready.network.virtual_network,
                               ready.network.private_subnets,
                               engine='postgresql',
                               security_groups=ready.application_security_groups.groups,
                               publicly_accessible=False,
                               multi_az=True)

@permanent
@infrastructure(requires=['network'])
def nat():
    print('Setting up nat...')
    servers = create_nat_instances(ready.network.virtual_network,
                                   ready.network.public_subnets,
                                   ready.network.private_subnets)

@permanent
@infrastructure(requires=['network'])
def application_security_groups():
    print('Setting up application_security_groups...')
    groups = [create_security_group(ready.network.virtual_network,
                                    allowed_inbound_traffic=[('HTTP',   '0.0.0.0/0')
                                                            ,('HTTPS',  '0.0.0.0/0')],
                                    allowed_outbound_traffic=[('HTTP',  '0.0.0.0/0')
                                                             ,('HTTPS', '0.0.0.0/0')
                                                             ,('DNS',   '0.0.0.0/0')])]

@ephemeral
@infrastructure(requires=['network', 'database', 'load_balancer', 'application_security_groups'])
def application():
    print('Setting up application...')
    old_servers = get_instances(role='application')
    servers = create_instances(ready.network.virtual_network,
                               ready.network.public_subnets,
                               security_groups=ready.application_security_groups.groups,
                               internet_addressable=True,
                               role='application')
    register_instances(ready.load_balancer.load_balancer, servers)
    terminate_instances(old_servers)

@permanent
@infrastructure(requires=['network'])
def load_balancer():
    print('Setting up load_balancer...')
    ssl_certificate = upload_ssl_certificate('public-key.crt',
                                             'private-key.pem',
                                             certificate_chain='certificate-chain.pem')
    load_balancer = create_load_balancer(ready.network.virtual_network,
                                         ready.network.public_subnets,
                                         ssl_certificate=ssl_certificate)
