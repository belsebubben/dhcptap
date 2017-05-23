package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

func decodeIps(thing string, data []byte) string {
	ips := []string{}
	//nrips := len(data) / 4

	for thisidx := 0; thisidx < len(data); thisidx += 4 {
		ip := net.IP(data[thisidx : thisidx+4]).String()
		ips = append(ips, ip)
	}

	return fmt.Sprintf("%v", ips)
}

func decodeIpsWithMask(thing string, data []byte) string {
	ips := []string{}
	//nrippairs := len(data) / 8

	for thisidx := 0; thisidx < len(data); thisidx += 8 {
		ip := net.IP(data[thisidx : thisidx+4]).String()
		mask := net.IPMask(data[thisidx+4 : thisidx+8]).String()
		ips = append(ips, ip+"/"+mask)
	}

	return fmt.Sprintf("%v", ips)
}

func decodeStringFromBytes(thing string, data []byte) string {
	return string(data)
}

func decodeUint16Numbers(thing string, data []byte) string {

	var int16s = make([]int16, len(data)/2)
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, int16s)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	return fmt.Sprintf("%v", int16s)

}

func decodeGenericMapping(options string, data []byte) string {
	// get a bunch of mappings (separated by ";") create an enumerated mapping
	// and return corresponding map entry (!!! Only 8 bit mappings)
	mappings := make(map[int]string)

	for idx, key := range strings.Split(options, ";") {
		mappings[idx] = key
	}

	//{0: "RFC 894", 1: "RFC 1042"}
	return mappings[int(data[0])]
}

func decodeEthernetEncapsulation(options string, data []byte) string {
	return decodeGenericMapping("RFC 894;RFC 1042", data)
}

func decodeMessageType(options string, data []byte) string {
	//index := int(data[0]) + 1
	//fmt.Println("Message type:", index)
	return map[int]string{1: "DHCPDISCOVER", 2: "DHCPOFFER", 3: "DHCPREQUEST",
		4: "DHCPDECLINE", 5: "DHCPACK", 6: "DHCPNAK", 7: "DHCPRELEASE",
		8: "DHCPINFORM", 9: "DHCPFORCERENEW", 10: "DHCPLEASEQUERY",
		11: "DHCPLEASEUNASSIGNED", 12: "DHCPLEASEUNKNOWN", 13: "DHCPLEASEACTIVE",
		14: "DHCPBULKLEASEQUERY", 15: "DHCPLEASEQUERYDONE"}[int(data[0])]
}

func decodeParamRequest(options string, data []byte) string {
	var buffer bytes.Buffer
	for _, k := range data {
		fmt.Fprintf(&buffer, "%3d:%s; ", int(k), dhcp_options[int(k)])
	}
	return buffer.String()

}

func decodeClientIdentifier(options string, data []byte) string {
	return net.HardwareAddr(data).String()
}

func decodeClientFqdn(options string, data []byte) string {
	//https://tools.ietf.org/html/rfc4702
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "flags: %3d;", int(data[0]))
	fmt.Fprintf(&buffer, "fqdn: %s", string(data[2:]))
	return buffer.String()
}

/*
func decodeOption82CircuitId(data []byte) string {

}*/

var relay_agent_optiontypes = map[int]string{
	1:   "agent circuit id",     //rfc 3046
	2:   "agent remote id",      //rfc 3046
	4:   "docsis device class.", //rfc 3256
	5:   "link selection",       //rfc 3527
	6:   "subscriber-id",        //rfc 3993
	7:   "radius attributes",    //rfc 4014
	8:   "authentication",
	9:   "vendor-specific information",
	10:  "relay agent flags",
	11:  "server identifier override",
	151: "dhcpv4 virtual subnet selection.",
	152: "dhcpv4 virtual subnet selection control."}

func decodeOption82(options string, data []byte) string {
	/* http://tools.ietf.org/html/rfc3046
		Relay Agent Information option is
	   inserted by the DHCP relay agent when forwarding client-originated
	   DHCP packets to a DHCP server.*/

	firstoption, firstoptlen := relay_agent_optiontypes[int(data[0])], int(data[1])
	/*var firstbuffer bytes.Buffer
	for _, d := range data[2:firstoptlen] {
		fmt.Fprintf(&firstbuffer, "%02x", d)
	}*/
	var secondoption string
	//var secondoptlen int

	if firstoptlen+3 < len(data) {
		secondoption = relay_agent_optiontypes[int(data[firstoptlen+2])]
		//secondoptlen = int(data[firstoptlen+3])
		return fmt.Sprintf("[[%s: %s; %s ;; %s: %s; %s]]", firstoption,
			hex.EncodeToString(data[2:firstoptlen]), strings.Replace(string(data[2:firstoptlen]), "\n", " ", -1),
			secondoption, hex.EncodeToString(data[firstoptlen+3:]), strings.Replace(string(data[firstoptlen+3:]), "\n", " ", -1))

	}

	return fmt.Sprintf("[[%s: %s; %s]]", firstoption, hex.EncodeToString(data[2:firstoptlen]), string(data[2:firstoptlen]))
}

func decodeuInt32(thing string, data []byte) string {
	var int32s = make([]uint32, len(data)/4)
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, int32s)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	return fmt.Sprintf("%v", int32s)

}

func decodeUint8Numbers(thing string, data []byte) string {
	var ints = make([]int, len(data))
	buf := bytes.NewReader(data)
	err := binary.Read(buf, binary.BigEndian, ints)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	return fmt.Sprintf("%v", ints)

}

func decodeBoolean(thing string, data []byte) string {
	return fmt.Sprintf("%v", int(data[0]) == 1)
}
