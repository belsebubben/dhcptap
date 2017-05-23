package main

import (
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
)

// Create a layer type, should be unique and high, so it doesn't conflict,
// giving it a name and a decoder to use.
//var LayerTypeDHCP = gopacket.RegisterLayerType(12345, gopacket.LayerTypeMetadata{"DHCP", gopacket.DecodeFunc(decodeDHCP)})

//func (d *DHCP) LayerType() gopacket.LayerType { return LayerTypeDHCP }

/*
func (d *DHCP) ApplicationLayer() gopacket.ApplicationLayer {
	return LayerTypeDHCP
}*/

func (d *DHCP) Payload() []byte {
	return nil
}

func (d *DHCP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

const (
	CLR_0 = "\x1b[30;1m"
	CLR_R = "\x1b[31;1m"
	CLR_G = "\x1b[32;1m"
	CLR_Y = "\x1b[33;1m"
	CLR_B = "\x1b[34;1m"
	CLR_M = "\x1b[35;1m"
	CLR_C = "\x1b[36;1m"
	CLR_W = "\x1b[37;1m"
	CLR_N = "\x1b[0m"
)

func (d *DHCP) String() string {

	var buffer bytes.Buffer
	opts := make([]string, len(d.Options))

	fmt.Fprintf(&buffer, CLR_G)
	fmt.Fprintf(&buffer, "%-28s", "Hw addr: "+d.Chaddr)
	fmt.Fprintf(&buffer, "%-14s", "Op: "+[]string{"REQUEST", "REPLY"}[uint8(d.Op)-1])
	//fmt.Fprintf(&buffer, "%-28s", "Req: "+d.Options)
	fmt.Fprintf(&buffer, "%-29s", "Client IP: "+d.Ciaddr)
	fmt.Fprintf(&buffer, "%-27s", "Your IP: "+d.Yiaddr)
	fmt.Fprintln(&buffer, "Relay agent: "+d.Giaddr)
	fmt.Fprintf(&buffer, CLR_M)
	fmt.Fprintln(&buffer, "Options:")

	// Present options sorted
	for k, _ := range d.Options {
		opts = append(opts, k)
	}
	sort.Strings(opts)

	//for k, v := range d.Options {
	for _, k := range opts {
		if k != "" {
			fmt.Fprintf(&buffer, "%s: %s\n", k, d.Options[k])
		}
	}
	fmt.Fprintf(&buffer, "\n_____________________________________________________________________________________________________________________________")
	return buffer.String()

}

/*	DHCP RFC 2131 https://www.ietf.org/rfc/rfc2131.txt


0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+---------------+---------------+---------------+---------------+
|                            xid (4)                            |
+-------------------------------+-------------------------------+
|           secs (2)            |           flags (2)           |
+-------------------------------+-------------------------------+
|                          ciaddr  (4)                          |
+---------------------------------------------------------------+
|                          yiaddr  (4)                          |
+---------------------------------------------------------------+
|                          siaddr  (4)                          |
+---------------------------------------------------------------+
|                          giaddr  (4)                          |
+---------------------------------------------------------------+
|                                                               |
|                          chaddr  (16)                         |
|                                                               |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                          sname   (64)                         |
+---------------------------------------------------------------+
|                                                               |
|                          file    (128)                        |
+---------------------------------------------------------------+
|                                                               |
|                          options (variable)                   |
+---------------------------------------------------------------+



FIELD      OCTETS       DESCRIPTION
-----      ------       -----------

op            1  Message op code / message type.
                 1 = BOOTREQUEST, 2 = BOOTREPLY
htype         1  Hardware address type, see ARP section in "Assigned
                 Numbers" RFC; e.g., '1' = 10mb ethernet.
hlen          1  Hardware address length (e.g.  '6' for 10mb
                 ethernet).
hops          1  Client sets to zero, optionally used by relay agents
                 when booting via a relay agent.
xid           4  Transaction ID, a random number chosen by the
                 client, used by the client and server to associate
                 messages and responses between a client and a
                 server.
secs          2  Filled in by client, seconds elapsed since client
                 began address acquisition or renewal process.
flags         2  Flags (see figure 2).
ciaddr        4  Client IP address; only filled in if client is in
                 BOUND, RENEW or REBINDING state and can respond
                 to ARP requests.
yiaddr        4  'your' (client) IP address.
siaddr        4  IP address of next server to use in bootstrap;
                 returned in DHCPOFFER, DHCPACK by server.
giaddr        4  Relay agent IP address, used in booting via a
                 relay agent.
chaddr       16  Client hardware address.
sname        64  Optional server host name, null terminated string.
file        128  Boot file name, null terminated string; "generic"
                 name or null in DHCPDISCOVER, fully qualified
                 directory-path name in DHCPOFFER.
options     var  Optional parameters field.  See the options
                 documents for a list of defined options.

*/

type DHCP struct {
	layers.BaseLayer
	// Header fields
	Op      uint8 // 1 = BOOTREQUEST, 2 = BOOTREPLY
	Htype   uint8
	Hlen    uint8
	Hops    uint8
	Xid     string
	Secs    uint16
	Flags   uint16
	Ciaddr  string
	Yiaddr  string
	Siaddr  string
	Giaddr  string
	Chaddr  string
	Sname   [64]byte
	File    [128]byte
	Options map[string]string
	Data    []byte
}

func decodeDHCPpacket(data []byte) (error, *DHCP) {
	d := &DHCP{}
	err := d.DecodeFromBytes(data)
	if err != nil {
		return err, nil
	}
	//p.AddLayer(d)
	//p.SetApplicationLayer(d)
	return nil, d

}

//func (d *DHCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
func (d *DHCP) DecodeFromBytes(data []byte) (err error) {
	//d.buffer = d.buffer[:0]
	err = nil
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Malformed / decoding error!! %v %+v", r, d)
		}
	}()

	d.Data = data

	if len(data) < 236 {
		//df.SetTruncated()
		//fmt.Println("DHCP packet too short!!!!")
		return fmt.Errorf("DHCP packet too short")
	}
	d.Op = uint8(data[0])
	d.Htype = uint8(data[1])
	d.Hlen = uint8(data[2])
	d.Hops = uint8(data[3])

	//fmt.Println(data[8:10])
	d.Secs = binary.BigEndian.Uint16(data[8:10])
	d.Flags = binary.BigEndian.Uint16(data[10:12])
	//fmt.Println(data[10:12])

	d.Ciaddr = net.IP(data[12:16]).String()
	d.Yiaddr = net.IP(data[16:20]).String()
	d.Siaddr = net.IP(data[20:24]).String()
	d.Giaddr = net.IP(data[24:28]).String()
	d.Chaddr = net.HardwareAddr(data[28 : 28+d.Hlen]).String()
	//d.yiaddr = binary.BigEndian.Uint32(data[20:2])
	d.Options = make(map[string]string)
	optidx := 236

	if data[optidx] != 99 && data[optidx+1] != 130 &&
		data[optidx+2] != 83 && data[optidx+3] != 99 {
		return fmt.Errorf("Corrupt options field!")
	} //magic cookie check (99, 130, 83, 99)
	optidx += 4

	for data[optidx] != 255 && optidx < len(data) {
		dhcpoption := dhcp_options[data[optidx]]
		if dhcpoption == "pad" { //pad
			optidx += 1
			continue
		}
		if dhcpoption == "End" {
			break
		} //end
		optlen := data[optidx+1]
		//fmt.Printf("Option: %s len: %3d ;", dhcpoption, data[optidx+1]) // debug
		if decoder, ok := dhcp_options_decoders[dhcpoption]; ok { //Decode option
			d.Options[dhcpoption] = decoder("", data[optidx+2:optidx+2+int(optlen)])

		}
		optidx += 2
		optidx += int(optlen)
	}
	//if d.options["DHCP message type"] == "DHCPACK" {
	//fmt.Println("\n_____________________________________________________________")
	d.Xid = fmt.Sprintf("%02x%02x%02x%02x\n", data[4], data[5], data[6], data[7])
	/*
		fmt.Println(data)
		fmt.Printf("%s\n", d.options["DHCP message type"])
		fmt.Printf("%+v\n", d)
		fmt.Printf("\nOption: %v\n", d.options)
	*/
	//}
	/*
		fmt.Println(d.xid)

	*/
	/*

		d.siaddr = binary.BigEndian.Uint32(data[24:28])
		d.giaddr = binary.BigEndian.Uint32(data[29:33])
		d.chaddr = data[34:50]*/
	return err
}

var dhcp_options_decoders = map[string]func(string, []byte) string{
	"Subnet mask":          decodeIps,
	"Routers":              decodeIps,
	"Swap server":          decodeIps,
	"Broadcast address":    decodeIps,
	"Router solicitation":  decodeIps,
	"Requested ip address": decodeIps,
	"Server identifier":    decodeIps,

	"Time servers":                           decodeIps,
	"Name servers":                           decodeIps,
	"Dns server":                             decodeIps,
	"Log server":                             decodeIps,
	"Cookie server":                          decodeIps,
	"Lpr server":                             decodeIps,
	"Impress server":                         decodeIps,
	"Resource location server":               decodeIps,
	"Nis servers":                            decodeIps,
	"Ntp servers":                            decodeIps,
	"Netbios name server":                    decodeIps,
	"Netbios datagram distribution server":   decodeIps,
	"X window system font server":            decodeIps,
	"X window system display server":         decodeIps,
	"Nis+ servers":                           decodeIps,
	"Mobile ip home agent":                   decodeIps,
	"Smtp server":                            decodeIps,
	"Pop3 server":                            decodeIps,
	"Nntp server":                            decodeIps,
	"Www server":                             decodeIps,
	"Finger server":                          decodeIps,
	"Irc server":                             decodeIps,
	"Streettalk server":                      decodeIps,
	"Streettalk directory assistance server": decodeIps,
	"Nds server":                             decodeIps,
	"Static route":                           decodeIps,

	"Hostname":                decodeStringFromBytes,
	"Merit dump file":         decodeStringFromBytes,
	"Domain name":             decodeStringFromBytes,
	"Root path":               decodeStringFromBytes,
	"Extensions path":         decodeStringFromBytes,
	"Nis domain":              decodeStringFromBytes,
	"Message":                 decodeStringFromBytes,
	"Netware/ip: domain name": decodeStringFromBytes,
	"Nis+ domain":             decodeStringFromBytes,
	"Tftp server name":        decodeStringFromBytes,
	"Boot file name":          decodeStringFromBytes,
	"Nds tree name":           decodeStringFromBytes,
	"Nds context":             decodeStringFromBytes,
	"Vendor specific info":    decodeStringFromBytes,
	"Netbios scope":           decodeStringFromBytes,

	"Policy filter": decodeStringFromBytes,

	"Path mtu plateau table":           decodeUint16Numbers,
	"Bootfile size":                    decodeUint16Numbers,
	"Maximum datagram reassembly size": decodeUint16Numbers,
	"Interface mtu":                    decodeUint16Numbers,
	"Maximum dhcp message size":        decodeUint16Numbers,

	"Default ip ttl":  decodeUint8Numbers,
	"Tcp default ttl": decodeUint8Numbers,

	"Ip forwarding":            decodeBoolean,
	"Non-local source routing": decodeBoolean,
	"All subnets local":        decodeBoolean,
	"Perform mask discovery":   decodeBoolean,
	"Mask supplier":            decodeBoolean,
	"Perform router discovery": decodeBoolean,
	"Trailer encapsulation":    decodeBoolean,
	"Tcp keepalive garbage":    decodeBoolean,

	"Time offset":            decodeuInt32,
	"Path mtu aging timeout": decodeuInt32,
	"Arp cache timeout":      decodeuInt32,
	"Tcp keepalive interval": decodeuInt32,
	"Ip address leasetime":   decodeuInt32,
	"T1": decodeuInt32,
	"T2": decodeuInt32,
	"Ethernet encapsulation":  decodeEthernetEncapsulation,
	"Option overload":         decodeUint8Numbers,
	"Dhcp message type":       decodeMessageType,
	"Parameter request list":  decodeParamRequest,
	"Client-identifier":       decodeClientIdentifier,
	"Client fqdn":             decodeClientFqdn,
	"Relay agent information": decodeOption82,
}

func dhcpOptionsHelp() string {
	var buffer bytes.Buffer

	third_printer := 0
	for idx := 0; idx < len(dhcp_options); idx++ {

		if dhcp_options[idx] == "???" {
			continue
		}

		buffer.WriteString(fmt.Sprintf("%-40s", dhcp_options[idx]))

		if third_printer == 3 {
			third_printer = 0
			buffer.WriteString("\n")
		} else {
			third_printer += 1
		}

	}
	return buffer.String()

}

var dhcp_options = []string{
	/*   0 */ "Pad",
	/*   1 */ "Subnet mask", /**/
	/*   2 */ "Time offset", /**/
	/*   3 */ "Routers", /**/
	/*   4 */ "Time server", /**/
	/*   5 */ "Name server", /**/
	/*   6 */ "Dns server", /**/
	/*   7 */ "Log server", /**/
	/*   8 */ "Cookie server", /**/
	/*   9 */ "Lpr server", /**/
	/*  10 */ "Impress server", /**/
	/*  11 */ "Resource location server", /**/
	/*  12 */ "Host name", /**/
	/*  13 */ "Boot file size", /**/
	/*  14 */ "Merit dump file", /**/
	/*  15 */ "Domainname", /**/
	/*  16 */ "Swap server", /**/
	/*  17 */ "Root path", /**/
	/*  18 */ "Extensions path", /**/
	/*  19 */ "Ip forwarding", /**/
	/*  20 */ "Non-local source routing", /**/
	/*  21 */ "Policy filter", /**/
	/*  22 */ "Maximum datagram reassembly size", /**/
	/*  23 */ "Default ip ttl", /**/
	/*  24 */ "Path mtu aging timeout", /**/
	/*  25 */ "Path mtu plateau table", /**/
	/*  26 */ "Interface mtu", /**/
	/*  27 */ "All subnets local", /**/
	/*  28 */ "Broadcast address", /**/
	/*  29 */ "Perform mask discovery", /**/
	/*  30 */ "Mask supplier", /**/
	/*  31 */ "Perform router discovery", /**/
	/*  32 */ "Router solicitation", /**/
	/*  33 */ "Static route", /**/
	/*  34 */ "Trailer encapsulation", /**/
	/*  35 */ "Arp cache timeout", /**/
	/*  36 */ "Ethernet encapsulation", /**/
	/*  37 */ "Tcp default ttl", /**/
	/*  38 */ "Tcp keepalive interval", /**/
	/*  39 */ "Tcp keepalive garbage", /**/
	/*  40 */ "Nis domain", /**/
	/*  41 */ "Nis servers", /**/
	/*  42 */ "Ntp servers", /**/
	/*  43 */ "Vendor specific info", /**/
	/*  44 */ "Netbios name server", /**/
	/*  45 */ "Netbios datagram distribution server", /**/
	/*  46 */ "Netbios node type", /**/
	/*  47 */ "Netbios scope", /**/
	/*  48 */ "X window system font server", /**/
	/*  49 */ "X window system display server", /**/
	/*  50 */ "Request ip address", /**/
	/*  51 */ "Ip address leasetime", /**/
	/*  52 */ "Option overload", /**/
	/*  53 */ "Dhcp message type", /**/
	/*  54 */ "Server identifier", /**/
	/*  55 */ "Parameter request list", /**/
	/*  56 */ "Message", /**/
	/*  57 */ "Maximum dhcp message size", /**/
	/*  58 */ "T1", /**/
	/*  59 */ "T2", /**/
	/*  60 */ "Vendor class identifier", /**/
	/*  61 */ "Client-identifier", /**/
	/*  62 */ "Netware/ip domain name", /**/
	/*  63 */ "Netware/ip domain information", /**/
	/*  64 */ "Nis+ domain", /**/
	/*  65 */ "Nis+ servers", /**/
	/*  66 */ "Tftp server name", /**/
	/*  67 */ "Bootfile name", /**/
	/*  68 */ "Mobile ip home agent", /**/
	/*  69 */ "Smtp server", /**/
	/*  70 */ "Pop3 server", /**/
	/*  71 */ "Nntp server", /**/
	/*  72 */ "Www server", /**/
	/*  73 */ "Finger server", /**/
	/*  74 */ "Irc server", /**/
	/*  75 */ "Streettalk server", /**/
	/*  76 */ "Streettalk directory assistance server", /**/
	/*  77 */ "User-class identification",
	/*  78 */ "Slp-directory-agent",
	/*  79 */ "Slp-service-scope",
	/*  80 */ "Naming authority",
	/*  81 */ "Client fqdn", /**/
	/*  82 */ "Relay agent information",
	/*  83 */ "Agent remote id",
	/*  84 */ "Agent subnet mask",
	/*  85 */ "Nds server", /**/
	/*  86 */ "Nds tree name", /**/
	/*  87 */ "Nds context", /**/
	/*  88 */ "Ieee 1003.1 posix",
	/*  89 */ "Fqdn",
	/*  90 */ "Authentication",
	/*  91 */ "Vines tcp/ip",
	/*  92 */ "Server selection",
	/*  93 */ "Client system",
	/*  94 */ "Client ndi",
	/*  95 */ "Ldap",
	/*  96 */ "Ipv6 transitions",
	/*  97 */ "Uuid/guid",
	/*  98 */ "Upa servers",
	/*  99 */ "???",
	/* 100 */ "Printer name",
	/* 101 */ "Mdhcp",
	/* 102 */ "???",
	/* 103 */ "???",
	/* 104 */ "???",
	/* 105 */ "???",
	/* 106 */ "???",
	/* 107 */ "???",
	/* 108 */ "Swap path",
	/* 109 */ "???",
	/* 110 */ "Ipx compatability",
	/* 111 */ "???",
	/* 112 */ "Netinfo address",
	/* 113 */ "Netinfo tag",
	/* 114 */ "Url",
	/* 115 */ "Dhcp failover",
	/* 116 */ "Dhcp autoconfiguration",
	/* 117 */ "Name service search",
	/* 118 */ "Subnet selection",
	/* 119 */ "Domain search",
	/* 120 */ "Sip servers dhcp option",
	/* 121 */ "Classless static route",
	/* 122 */ "CableLabs Client Configuration",
	/* 123 */ "GeoConf Option",
	/* 124 */ "V-I Vendor Class",
	/* 125 */ "V-I Vendor-Specific Information",
	/* 126 */ "Extension",
	/* 127 */ "Extension",
	/* 128 */ "PXE - undefined (vendor specific)",
	/* 129 */ "PXE - undefined (vendor specific)",
	/* 130 */ "???",
	/* 131 */ "???",
	/* 132 */ "???",
	/* 133 */ "???",
	/* 134 */ "Diffserv Code Point (DSCP) for VoIP signalling and media streams",
	/* 135 */ "???",
	/* 136 */ "???",
	/* 137 */ "???",
	/* 138 */ "???",
	/* 139 */ "???",
	/* 140 */ "???",
	/* 141 */ "???",
	/* 142 */ "???",
	/* 143 */ "???",
	/* 144 */ "Hp - tftp file",
	/* 145 */ "???",
	/* 146 */ "???",
	/* 147 */ "???",
	/* 148 */ "???",
	/* 149 */ "???",
	/* 150 */ "???",
	/* 151 */ "status-code",
	/* 152 */ "base-time",
	/* 153 */ "start-time-of-state",
	/* 154 */ "query-start-time",
	/* 155 */ "query-end-time",
	/* 156 */ "dhcp-state",
	/* 157 */ "data-source",
	/* 158 */ "???",
	/* 159 */ "???",
	/* 160 */ "???",
	/* 161 */ "???",
	/* 162 */ "???",
	/* 163 */ "???",
	/* 164 */ "???",
	/* 165 */ "???",
	/* 166 */ "???",
	/* 167 */ "???",
	/* 168 */ "???",
	/* 169 */ "???",
	/* 170 */ "???",
	/* 171 */ "???",
	/* 172 */ "???",
	/* 173 */ "???",
	/* 174 */ "???",
	/* 175 */ "???",
	/* 176 */ "???",
	/* 177 */ "???",
	/* 178 */ "???",
	/* 179 */ "???",
	/* 180 */ "???",
	/* 181 */ "???",
	/* 182 */ "???",
	/* 183 */ "???",
	/* 184 */ "???",
	/* 185 */ "???",
	/* 186 */ "???",
	/* 187 */ "???",
	/* 188 */ "???",
	/* 189 */ "???",
	/* 190 */ "???",
	/* 191 */ "???",
	/* 192 */ "???",
	/* 193 */ "???",
	/* 194 */ "???",
	/* 195 */ "???",
	/* 196 */ "???",
	/* 197 */ "???",
	/* 198 */ "???",
	/* 199 */ "???",
	/* 200 */ "???",
	/* 201 */ "???",
	/* 202 */ "???",
	/* 203 */ "???",
	/* 204 */ "???",
	/* 205 */ "???",
	/* 206 */ "???",
	/* 207 */ "???",
	/* 208 */ "???",
	/* 209 */ "???",
	/* 210 */ "Authenticate",
	/* 211 */ "???",
	/* 212 */ "???",
	/* 213 */ "???",
	/* 214 */ "???",
	/* 215 */ "???",
	/* 216 */ "???",
	/* 217 */ "???",
	/* 218 */ "???",
	/* 219 */ "???",
	/* 220 */ "???",
	/* 221 */ "???",
	/* 222 */ "???",
	/* 223 */ "???",
	/* 224 */ "???",
	/* 225 */ "???",
	/* 226 */ "???",
	/* 227 */ "???",
	/* 228 */ "???",
	/* 229 */ "???",
	/* 230 */ "???",
	/* 231 */ "???",
	/* 232 */ "???",
	/* 233 */ "???",
	/* 234 */ "???",
	/* 235 */ "???",
	/* 236 */ "???",
	/* 237 */ "???",
	/* 238 */ "???",
	/* 239 */ "???",
	/* 240 */ "???",
	/* 241 */ "???",
	/* 242 */ "???",
	/* 243 */ "???",
	/* 244 */ "???",
	/* 245 */ "???",
	/* 246 */ "???",
	/* 247 */ "???",
	/* 248 */ "???",
	/* 249 */ "Msft - classless route",
	/* 250 */ "???",
	/* 251 */ "???",
	/* 252 */ "Msft - winsock proxy auto detect",
	/* 253 */ "???",
	/* 254 */ "???",
	/* 255 */ "End"}
