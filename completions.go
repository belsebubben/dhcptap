package main

var headerCompletions = map[string]map[string]int{
	/*
		first we complete on all the keys then we set the second prompt to the keys
		of the second map and return the value of that choice or if value does not
		match we return the user input
	*/
	"Opcode":  {"BOOTREQUEST": 1, "BOOTREPLY": 2},
	"Xid":     {},
	"Secs":    {},
	"Flags":   {},
	"Ciaddr":  {},
	"Yiaddr":  {},
	"Giaddr":  {},
	"Siaddr":  {},
	"Chaddr":  {},
	"Sname":   {},
	"Options": {},
}

var promptHelp = `
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
`
