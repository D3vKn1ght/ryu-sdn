#!/usr/bin/env python

"""
linuxrouter.py: Example network with Linux IP router

This example converts a Node into a router using IP forwarding
already built into Linux.

The example topology creates a router and three IP subnets:

    - 192.168.1.0/24 (r0-eth1, IP: 192.168.1.1)
    - 172.16.0.0/12 (r0-eth3, IP: 172.16.0.1)
    - 10.0.0.0/8 (r0-eth4, IP: 10.0.0.1)

Each subnet consists of a single host connected to
a single switch:

    r0-eth1 - s1-eth1 - h1-eth0 (IP: 192.168.1.100)
    r0-eth3 - s2-eth1 - h3-eth0 (IP: 172.16.0.100)
    r0-eth4 - s3-eth1 - h4-eth0 (IP: 10.0.0.100)

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
import random
from define import *


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

        defaultIP = '192.168.1.1/24'  
        router = self.addNode( 'r0', cls=LinuxRouter, ip=defaultIP )

        s1, s2, s3,s4 = [ self.addSwitch( s ) for s in ( 's1', 's2', 's3','s4' ) ]

        # DMZ
        self.addLink( s1, router, intfName2='r0-dmz',
                      params2={ 'ip' : defaultIP } )  # for clarity
        
        #Internal
        self.addLink( s2, router, intfName2='r0-internal',
                      params2={ 'ip' : '172.16.0.1/24' } )
        
        # Internet
        self.addLink( s3, router, intfName2='r0-internet',
                      params2={ 'ip' : '10.0.0.1/24' } )
        
        for i in range(1,3):
            host=self.addHost('inhost'+str(i), ip='172.16.0.'+str(random.randint(2,254))+'/24',  defaultRoute='via 172.16.0.1' )
            self.addLink(host,s2)

        for i in range(1,4):
            host=self.addHost('dmzhost'+str(i), ip='192.168.1.'+str(random.randint(5,254))+'/24',   defaultRoute=f'via 192.168.1.1' )
            self.addLink(host,s1)

        nethost=self.addHost('nethost',ip="10.0.0.5")
        self.addLink(nethost,s4)
        self.addLink(nethost,s3)



def run():
    "Test linux router"
    topo = NetworkTopo()
    net = Mininet( topo=topo, switch=OVSSwitch, controller=None )
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    net.start()

    s4 = net.get('s4')
    s4.cmdPrint(f"ovs-vsctl add-port s4 {nat_card}") # Thêm card vào switch s3
    
    nethost = net.get('nethost')
    info('\n*** Output of "ip addr" on nethost:\n')
    nethost.cmdPrint('ip addr')
    nethost.cmdPrint('dhclient nethost-eth0')
    nethost.cmdPrint('ifconfig nethost-eth1 10.0.0.5/24')
    nethost.cmdPrint('sudo ip route add 192.168.1.0/24 via 10.0.0.1 dev nethost-eth1')
    nethost.cmdPrint('sudo ip route add 172.16.0.0/24 via 10.0.0.1 dev nethost-eth1')

    
  

    info( '*** Routing Table on Router:\n' )
    info( net[ 'r0' ].cmd( 'route' ) )
    CLI( net )
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    run()