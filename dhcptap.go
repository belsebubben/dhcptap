package main

import (
        "github.com/google/gopacket"
        _ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"fmt"
	"github.com/peterh/liner"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"
)

type packet struct {
}

func pickInterface(name string) (string, string, error) { // "eth0", "192.168.0.12", nil // interface name, first address of iface
	//ifaces, _ := net.Interfaces()
	var iface *net.Interface
	var err error
	fmt.Println(name)
	if iface, err = net.InterfaceByName(name); err != nil {
		log.Fatalln(name, " : ", err)
	}
	//var pickedInterface = net.Interface
	//for _, iface := range ifaces {
	//	if iface.Name != "lo" && strings.Contains(iface.Name, "0") { // TODO pick name if given
	addrs, _ := iface.Addrs()
	addr := strings.Split(addrs[0].String(), "/")[0] // first address of interface stripped off netmask
	return iface.Name, addr, nil
	//}
	//}
	//return "", "", fmt.Errorf("No interface found")

}

func buildPcapString(mac string) (string, error) {
	/*
		if iFace, addr, err := pickInterface("sdf"); err != nil {
			panic(err)
		} else {
			//return fmt.Sprintf("port 67 or port 68 %s %s", iFace, addr), nil
			return fmt.Sprintf("port 67 or port 68"), nil
		}*/
	return fmt.Sprintf("port 67 or port 68"), nil
}

//func pcapHandler(quit chan struct{}) (chan *packet, error) { // TODO write pkgs to channel and send to processor
func pcapHandler(iface string, quit chan struct{}) (chan *DHCP, error) {
	defer func() { // Needed for every page
		if x := recover(); x != nil {
			log.Fatalf("caught panic: [%v]", x)
		}
	}()

	localQchan := make(chan *DHCP, 1000000)
	var handle *pcap.Handle
	var err error

	//pcapString, _ := buildPcapString("")

	//iface, _, _ := pickInterface("")

	if handle, err = pcap.OpenLive(iface, 65535, true, 0); err != nil {
		panic(err)
	}
	//handle, err = pcap.OpenOffline("/home/caha02/Projects/test/iponly.pcap") // DEBUG testing
	//handle, err = pcap.OpenOffline("/home/caha02/Projects/test/dhcpd.pcap") // DEBUG testing
	if err != nil {
		panic(err)
	}

	pcapstring, _ := buildPcapString("")

	if err = handle.SetBPFFilter(pcapstring); err != nil {
		panic(err)
	}
	var packetSource *gopacket.PacketSource
	packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

	go func(chan *DHCP, chan error) {
		defer close(localQchan)
		defer handle.Close()
		for packet := range packetSource.Packets() {

			err, dhcppacket := decodeDHCPpacket(packet.TransportLayer().LayerPayload())
			if err != nil {
				errorchannel <- err
			}
			localQchan <- dhcppacket
		} // end packet loop

	}(localQchan, errorchannel) // End local capture function

	return localQchan, nil
}

func filterCheck(pkt *DHCP, filter map[string]string) bool {
	// Filters are anded, if one fails false is returned
	var matched bool
	for k, v := range filter {
		if strings.HasPrefix(k, "option_") {
			if strings.HasPrefix(k, "option_Relay agent information_") {
				matched = strings.Contains(pkt.Options["Relay agent information"], v)
			} else {
				matched = strings.Contains(pkt.Options[strings.TrimLeft(k, "options_")], v)
			}
		} else {
			refpkt := reflect.ValueOf(pkt).Elem()
			thefield := refpkt.FieldByName(k)
			//matched = v == fmt.Sprint(thefield.Interface())
			matched = strings.Contains(fmt.Sprint(thefield.Interface()), v)

		}

	}
	return matched

}

func dhcpPacketReceiver(pktChan chan *DHCP, errorchannel chan error) {

	var filter = make(map[string]string)
	var filterActive bool

	for {
		select {
		case pkt := <-pktChan:
			if pkt == nil {
				continue
			}
			//if ok != true { // this should be removed when running for real
			//	signalc <- os.Interrupt // only makes sense during debug
			//} else {
			if filterActive {
				if filterCheck(pkt, filter) {
					fmt.Printf("%+v\n\n", pkt)
				}
			} else {
				fmt.Printf("%+v\n\n", pkt)
			}
			//}
		case decodeerror := <-errorchannel:
			fmt.Printf("%v\n", decodeerror)

		case command, ok := <-commandchannel:
			if ok != true {
				return
			}
			switch command {

			case " ":
				fmt.Printf(CLR_W)
				field, fieldvalue, ferr := FilterPrompt()
				if ferr != nil {
					fmt.Printf("Error setting filters %v", ferr)
					go commander()
				} else {
					filterActive = true
					filter[field] = fieldvalue
					fmt.Print("Filtering on: ")
					for k, v := range filter {
						fmt.Print(k, ":", v)
						fmt.Print(" AND ")
					}
					fmt.Printf("\n")
					time.Sleep(time.Second * 2)
					go commander()
				}

			case "q":
				fmt.Println("Exit ordered from user input!", command)
				signalc <- os.Interrupt
				return

			case "r":
				fmt.Println("Reseting filters!", command)
				for k := range filter {
					delete(filter, k)
				}
				filterActive = false
				time.Sleep(time.Second * 1)

			case "h":
				printHelp()
				fmt.Printf("\nSleeping for 10 seconds")
				time.Sleep(time.Second * 10)
			}
		}
	}
}

func FilterPrompt() (string, string, error) {
	// TODO validate inputs (hinder segfaults)
	//var FilterMap = map[string]string{}
	var err error
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Error creating filter %v", r)
		}
	}()

	fmt.Printf(CLR_W)
	var (
		field, fieldvalue string
	)
	var completions = []string{}

	for k, _ := range headerCompletions {
		completions = append(completions, k)
	}

	line := liner.NewLiner()
	defer line.Close()

	line.SetCompleter(func(line string) (c []string) {
		for _, n := range completions {
			if strings.HasPrefix(n, strings.Title(strings.ToLower(line))) {
				c = append(c, n)
			}
		}
		return
	})

	fmt.Println("\n")
	fmt.Println(promptHelp)

	var lineerr error
	if field, lineerr = line.Prompt("Filter on what field?: "); err != nil { // Pick field to filter on
		log.Print("Error reading line: ", lineerr)
	} else {
		completions = []string{}

		if strings.ToLower(field) == "options" { // There are many options
			fmt.Printf(dhcpOptionsHelp())
			fmt.Println("\n")

			line.Close() // This sucks so much...
			line := liner.NewLiner()

			completions = dhcp_options
			line.SetCompleter(func(line string) (c []string) {
				for _, n := range completions {
					if strings.HasPrefix(n, strings.ToLower(line)) {
						c = append(c, n)
					}
				}
				return
			})

		}

		if fieldvalue, err = line.Prompt(fmt.Sprintf("Filter on %s?: ", field)); err != nil { // Specify filter on field
			log.Print("Error reading line: ", err)
		} else {
			fmt.Println(fieldvalue)
		}

		if strings.ToLower(field) == "options" {
			field = "option" + "_" + fieldvalue
			line.Close() // This sucks so much...
			line := liner.NewLiner()

			if field == "option_Relay agent information" { // Relay agent information
				completions = []string{}
				for _, n := range relay_agent_optiontypes {
					completions = append(completions, n)
				}
				fmt.Println("Completions: ", completions)
				fmt.Println("\n")
				line.Close() // This sucks so much...
				line := liner.NewLiner()
				line.SetCompleter(func(line string) (c []string) {
					for _, n := range completions {
						if strings.HasPrefix(n, strings.ToLower(line)) {
							c = append(c, n)
						}
					}
					return
				})

				fmt.Println("\n")

				if fieldvalue, err = line.Prompt(fmt.Sprintf("Filter on %s?: ", field)); err != nil { // Specify filter on field
					log.Print("Error reading line: ", err)
				} else {
					field = "option_Relay agent information" + "_" + fieldvalue
				}

				if fieldvalue, err = line.Prompt(fmt.Sprintf("Filter on %s?: ", field)); err != nil { // Specify filter on field
					log.Print("Error reading line: ", err)
				} else {
					fmt.Println(fieldvalue)
				}

			} else { // End Relay agent information (This is a normal option)
				if fieldvalue, err = line.Prompt(fmt.Sprintf("Filter on %s?: ", field)); err != nil { // Specify filter on field
					log.Print("Error reading line: ", err)
				} else {
					fmt.Println(fieldvalue)
				}
			}

		}

		fmt.Println("Filters applied: ", field, ":", fieldvalue, "\n")
		return field, fieldvalue, err
	}

	return field, fieldvalue, err
}

func commander() { // Get hold of user commands
	//defer exec.Command("stty", "-F", "/dev/tty", "sane").Run()
	// disable input buffering
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	// do not display entered characters on the screen
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	var b []byte = make([]byte, 1)
	for {
		os.Stdin.Read(b)
		//fmt.Println("I got the byte", b, "("+string(b)+")")
		commanded := string(b)
		if commanded == "q" { // quit
			commandchannel <- "q"
			return
		} else if commanded == " " { // Prompt for command
			exec.Command("stty", "-F", "/dev/tty", "sane").Run()
			exec.Command("stty", "-F", "/dev/tty", "+echo").Run()
			commandchannel <- " "
			return
		} else if commanded == "r" { // reset filters
			commandchannel <- "r"
		} else if commanded == "h" { // print help
			commandchannel <- "h"
		}

	}
}

var signalc = make(chan os.Signal, 1)  // Channel receiving signals
var commandchannel = make(chan string) // Send commands to us
var quitC = make(chan struct{})
var errorchannel = make(chan error) // Send commands to us

func printHelp() {
	fmt.Println("example usage: ", os.Args[0], "eth0")
	fmt.Println("During execution: press <space> to enable/set filters")
	fmt.Println("During execution: press 'q' to quit")
	fmt.Println("During execution: press 'r' to reset filters")
}

func main() {
	//defer profile.Start(profile.CPUProfile).Stop() // Profiling
	defer exec.Command("stty", "-F", "/dev/tty", "sane").Run()
	defer fmt.Println(CLR_N)
	signal.Notify(signalc, os.Interrupt) // ^C
	signal.Notify(signalc, syscall.SIGTERM)

	if len(os.Args) < 2 {
		printHelp()
		log.Fatalf("\nBad usage")
	}

	go commander()
	iface, _, _ := pickInterface(os.Args[1])
	//fmt.Println(buildPcapString("78:ac:c0:ac:c2:2b"))
	qchan, err := pcapHandler(iface, quitC)
	if err != nil {
		fmt.Println(err)
	}
	go dhcpPacketReceiver(qchan, errorchannel)

	command := <-signalc
	exec.Command("stty", "-F", "/dev/tty", "sane").Run()
	fmt.Println("Caught: ", command, " exiting this neat little util.")
	//fmt.Println(Qchan)
}
