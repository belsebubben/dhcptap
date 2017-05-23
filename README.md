# dhcptap
dhcp protocol tracer / viewer to tap / dump and filter dhcp traffic - tested on linux x86_64

## Install on linux
1. install Go 1.8 or later
2. enter the dhcptap directory
3. install libpcap-devel, and dependency libpcap
4. go get
5. go build

## Usage
program will capture packets on interface and needs raw device access so ***root privileges*** are needed


`./dhcptap enp0s25`

Filters will be *ANDED* by default

`space` - enable filters
`r` - reset all filters
`q` - quit

In filter mode pick a field to filter on, the filter will be matched so that
partial matches on names and ips will work i.e
Filter 10.1.

will match 10.1.12 and 10.1.14

pressing `space` again will enable adding a filter on another field, the new
filter is then ANDED

filtering on options will open a submenu where you can filter on all subfilters

example:
`space`
```
FIELD      OCTETS       DESCRIPTION
-----      ------       -----------

Op            1  Message op code / message type.
                 1 = BOOTREQUEST, 2 = BOOTREPLY
Htype         1  Hardware address type, see ARP section in "Assigned
                 Numbers" RFC; e.g., '1' = 10mb ethernet.
Hlen          1  Hardware address length (e.g.  '6' for 10mb
                 ethernet).
Hops          1  Client sets to zero, optionally used by relay agents
                 when booting via a relay agent.
Xid           4  Transaction ID, a random number chosen by the
                 client, used by the client and server to associate
                 messages and responses between a client and a
                 server.
Secs          2  Filled in by client, seconds elapsed since client
                 began address acquisition or renewal process.
Flags         2  Flags (see figure 2).
Ciaddr        4  Client IP address; only filled in if client is in
                 BOUND, RENEW or REBINDING state and can respond
                 to ARP requests.
Yiaddr        4  'your' (client) IP address.
Siaddr        4  IP address of next server to use in bootstrap;
                 returned in DHCPOFFER, DHCPACK by server.
Giaddr        4  Relay agent IP address, used in booting via a
                 relay agent.
Chaddr       16  Client hardware address.
Sname        64  Optional server host name, null terminated string.
File        128  Boot file name, null terminated string; "generic"
                 name or null in DHCPDISCOVER, fully qualified
                 directory-path name in DHCPOFFER.
Options     var  Optional parameters field.  See the options
                 documents for a list of defined options.
```

"Op" `tab``tab`

```
Filter on what field?: Options
Pad                                     Subnet mask                             Time offset                             Routers                                 
Time server                             Name server                             Dns server                              Log server                              
Cookie server                           Lpr server                              Impress server                          Resource location server                
Host name                               Boot file size                          Merit dump file                         Domainname                              
Swap server                             Root path                               Extensions path                         Ip forwarding                           
Non-local source routing                Policy filter                           Maximum datagram reassembly size        Default ip ttl                          
Path mtu aging timeout                  Path mtu plateau table                  Interface mtu                           All subnets local                       
Broadcast address                       Perform mask discovery                  Mask supplier                           Perform router discovery                
Router solicitation                     Static route                            Trailer encapsulation                   Arp cache timeout                       
Ethernet encapsulation                  Tcp default ttl                         Tcp keepalive interval                  Tcp keepalive garbage                   
Nis domain                              Nis servers                             Ntp servers                             Vendor specific info                    
Netbios name server                     Netbios datagram distribution server    Netbios node type                       Netbios scope                           
X window system font server             X window system display server          Request ip address                      Ip address leasetime                    
Option overload                         Dhcp message type                       Server identifier                       Parameter request list                  
Message                                 Maximum dhcp message size               T1                                      T2                                      
Vendor class identifier                 Client-identifier                       Netware/ip domain name                  Netware/ip domain information           
Nis+ domain                             Nis+ servers                            Tftp server name                        Bootfile name                           
Mobile ip home agent                    Smtp server                             Pop3 server                             Nntp server                             
Www server                              Finger server                           Irc server                              Streettalk server                       
Streettalk directory assistance server  User-class identification               Slp-directory-agent                     Slp-service-scope                       
Naming authority                        Client fqdn                             Relay agent information                 Agent remote id                         
Agent subnet mask                       Nds server                              Nds tree name                           Nds context                             
Ieee 1003.1 posix                       Fqdn                                    Authentication                          Vines tcp/ip                            
Server selection                        Client system                           Client ndi                              Ldap                                    
Ipv6 transitions                        Uuid/guid                               Upa servers                             Printer name                            
Mdhcp                                   Swap path                               Ipx compatability                       Netinfo address                         
Netinfo tag                             Url                                     Dhcp failover                           Dhcp autoconfiguration                  
Name service search                     Subnet selection                        Domain search                           Sip servers dhcp option                 
Classless static route                  CableLabs Client Configuration          GeoConf Option                          V-I Vendor Class                        
V-I Vendor-Specific Information         Extension                               Extension                               PXE - undefined (vendor specific)       
PXE - undefined (vendor specific)       Diffserv Code Point (DSCP) for VoIP signalling and media streamsHp - tftp file                          status-code                             
base-time                               start-time-of-state                     query-start-time                        query-end-time                          
dhcp-state                              data-source                             Authenticate                            Msft - classless route                  
Msft - winsock proxy auto detect        End                                     
```
"Rela" `tab` `tab`
```
Filter on Options?: Relay agent information
Filter on option Relay agent information?: 10.12
```
`enter`
`r` 
resetting filters
