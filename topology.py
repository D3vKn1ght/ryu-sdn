#!/usr/bin/env python

"""
linuxrouter.py: Example network with Linux IP router

This example converts a Node into a router using IP forwarding
already built into Linux.

The example topology creates a router and three IP subnets:

    - 192.168.1.0/24 (r0-eth1, IP: 192.168.1.1)
    - 172.16.0.0/12 (r0-eth2, IP: 172.16.0.1)
    - 10.0.0.0/8 (r0-eth3, IP: 10.0.0.1)

Each subnet consists of a single host connected to
a single switch:

    r0-eth1 - s1-eth1 - h1-eth0 (IP: 192.168.1.100)
    r0-eth2 - s2-eth1 - h2-eth0 (IP: 172.16.0.100)
    r0-eth3 - s3-eth1 - h3-eth0 (IP: 10.0.0.100)

The example relies on default routing entries that are
automatically created for each router interface, as well
as 'defaultRoute' parameters for the host interfaces.

Additional routes may be added to the router or hosts by
executing 'ip route' or 'route' commands on the router or hosts.
"""


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node,OVSSwitch, Controller, RemoteController  
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf


class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    # pylint: disable=arguments-differ
    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):
    "A LinuxRouter connecting three IP subnets"

    # pylint: disable=arguments-differ
    def build( self, **_opts ):

        defaultIP = '192.168.1.1/24'  # IP address for r0-eth1
        router = self.addNode( 'r0', cls=LinuxRouter, ip=defaultIP )

        s1, s2, s3 = [ self.addSwitch( s ) for s in ( 's1', 's2', 's3' ) ]

        
        #DMZ
        self.addLink( s1, router, intfName2='r0-eth1',
                      params2={ 'ip' : defaultIP } )  # for clarity
        #Internal
        self.addLink( s2, router, intfName2='r0-eth2',
                      params2={ 'ip' : '172.16.0.1/12' } )
        #Internet
        self.addLink( s3, router, intfName2='r0-eth3',
                      params2={ 'ip' : '10.0.0.1/8' } )

        h1 = self.addHost( 'h1', ip='192.168.1.100/24',
                           defaultRoute='via 192.168.1.1' )
        h2 = self.addHost( 'h2', ip='172.16.0.100/12',
                           defaultRoute='via 172.16.0.1' )
        # h3 = self.addHost( 'h3', ip='10.0.0.100/8',
        #                    defaultRoute='via 10.0.0.1' )

        h3 = self.addHost('h3', ip='0.0.0.0')

        for h, s in [ (h1, s1), (h2, s2), (h3, s3) ]:
            self.addLink( h, s )


def run():
    "Test linux router"
    topo = NetworkTopo()
    net = Mininet( topo=topo, switch=OVSSwitch, controller=None )
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    net.start()
    s3 = net.get('s3')
    s3.cmdPrint("ovs-vsctl add-port s3 ens36") # Thêm card vào switch s3
    
    h3 = net.get('h3')
    info('\n*** Output of "ip addr" on h3:\n')
    h3.cmdPrint('ip addr')
    h3.cmdPrint('dhclient '+h3.defaultIntf().name)

    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    CLI( net )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
