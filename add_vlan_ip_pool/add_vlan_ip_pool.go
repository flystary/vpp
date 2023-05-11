//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/binapi/ethernet_types"
	interfaces "git.fd.io/govpp.git/binapi/interface"
	"git.fd.io/govpp.git/binapi/interface_types"
	"git.fd.io/govpp.git/binapi/ip_types"
	"git.fd.io/govpp.git/binapi/l2"
	"git.fd.io/govpp.git/binapi/tapv2"
	"git.fd.io/govpp.git/core"
)

func main() {

	//get params
	_sockAddr := flag.String("sock", socketclient.DefaultSocketName, "Path to VPP binary API socket file")
	vlan_id := flag.Uint64("vlan-id", 0, "vlan id")
	ip := flag.String("ip", "", "")
	netmask := flag.String("netmask", "", "")
	tap_ip := flag.String("tap-ip", "", "")
	tap_netmask := flag.String("tap-netmask", "", "")
	iface_name := flag.String("iface-name", "", "")
	enable_dhcp := flag.Bool("enable-dhcp", false, "")
	dhcp_mode := flag.String("dhcp-mode", "", "")
	remote_server := flag.String("remote-server", "", "")
	gateway := flag.String("gateway", "", "")
	start_ip := flag.String("start-ip", "", "")
	end_ip := flag.String("end-ip", "", "")
	dns1 := flag.String("dns1", "", "")
	dns2 := flag.String("dns2", "", "")
	domain_name := flag.String("domain-name", "", "")
	tftp := flag.String("tftp", "", "")
	lease := flag.String("lease", "", "")
	flag.Parse()
	//check params
	if *ip == "" || *netmask == "" {
		fmt.Println("params illegal")
		os.Exit(3)
	}
	if *vlan_id == 0 || *vlan_id >= 4095 {
		fmt.Println("params illegal")
		os.Exit(3)
	}
	//combine params
	vlanIdstr := strconv.FormatUint(*vlan_id, 10)
	iface := "vlan" + vlanIdstr

	//connect govpp
	conn, err := govpp.Connect(*_sockAddr)
	if err != nil {
		log.Fatalln("connect to vpp error:", err)
	}
	defer conn.Disconnect()
	//init client

	if_client := interfaces.NewServiceClient(conn)
	l2_client := l2.NewServiceClient(conn)
	tap_client := tapv2.NewServiceClient(conn)
	// ch, _ := conn.NewAPIChannel()

	//br
	bridgeId := uint32(*vlan_id)
	// _, err = interfaceDump(&if_client, "bvi"+vlanIdstr)
	_, err = l2_client.BridgeDomainDump(context.Background(), &l2.BridgeDomainDump{
		BdID: bridgeId,
	})
	if err != nil {
		//找不到,重建桥和虚拟接口
		// cmd := "../add_vlan/add_vlan.go " + "--vlan-id " + vlanIdstr
		// out, err := exec.Command("/bin/bash", "-c", cmd).Output()
		// if err != nil {
		// 	log.Fatal(string(out), err)
		// }
		l2_client.BridgeDomainAddDel(context.Background(), &l2.BridgeDomainAddDel{
			BdID:    bridgeId,
			Flood:   true,
			UuFlood: true,
			Forward: true,
			Learn:   true,
			ArpTerm: false,
			ArpUfwd: false,
			MacAge:  0,
			BdTag:   "bridge-domain",
			IsAdd:   true,
		})
	}
	//bvi
	err = addbvi(conn, &if_client, &l2_client, bridgeId)
	if err != nil {
		log.Fatal(err)
	}
	//ether
	if *iface_name != "" {
		delIf(conn, &if_client, &l2_client, *iface_name)
		err = add_if(&if_client, &l2_client, *iface_name, uint32(*vlan_id))
		if err != nil {
			log.Fatal(err)
		}
	}
	//tap
	err = add_tap(&if_client, &l2_client, &tap_client, vlan_id, tap_ip, tap_netmask)
	if err != nil {
		log.Fatal(err)
	}

	//dhcp
	r := dhcp(iface, *enable_dhcp, *dhcp_mode, *lease, *gateway, *ip, *start_ip, *end_ip, *dns1, *dns2, *tftp, *domain_name, *remote_server, *tap_ip)
	if r != 0 {
		fmt.Println("dhcp err!")
		os.Exit(r)
	}

	os.Exit(dnsmasq_restart())

}
func add_if(if_client *interfaces.RPCService, l2_client *l2.RPCService, name string, bridgeId uint32) error {
	// 查找网卡接口
	details, err := interfaceDump(if_client, name)
	if err != nil {
		return err
	}
	//UP
	r1, e1 := (*if_client).SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: details.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if e1 != nil {
		fmt.Println(r1.Retval)
		return e1
	}
	//加TAG
	r2, e2 := (*l2_client).L2InterfaceVlanTagRewrite(context.Background(), &l2.L2InterfaceVlanTagRewrite{
		SwIfIndex: details.SwIfIndex,
		VtrOp:     1,
		// PushDot1q: 1,
		// Tag1:      bridgeId,
	})
	if e2 != nil {
		fmt.Println(r2.Retval)
		return e2
	}

	//添加到br
	r3, e3 := (*l2_client).SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: details.SwIfIndex,
		BdID:        bridgeId,
		PortType:    l2.L2_API_PORT_TYPE_NORMAL, //tap 0 bvi 1
		Shg:         0,
		Enable:      true,
	})
	if e3 != nil {
		fmt.Println(r3.Retval)
		return e3
	}
	return nil
}
func add_tap(if_client *interfaces.RPCService, l2_client *l2.RPCService, tap_client *tapv2.RPCService, vlan_id *uint64, tap_ip *string, tap_netmask *string) error {
	iP4Prefix, _ := parseIP4NetPrefix(*tap_ip, *tap_netmask)
	fmt.Println(iP4Prefix.String())
	// create tap id 10 host-ip4-addr 192.168.10.254/24 host-if-name vdhcp10
	r1, e1 := (*tap_client).TapCreateV2(context.Background(), &tapv2.TapCreateV2{
		ID:               uint32(*vlan_id),
		HostIP4PrefixSet: true,
		HostIP4Prefix:    ip_types.IP4AddressWithPrefix(iP4Prefix),
		HostIfNameSet:    true,
		HostIfName:       "vdhcp" + strconv.FormatUint(*vlan_id, 10),
		UseRandomMac:     true,
		HostBridgeSet:    true,
		HostBridge:       "bvi" + strconv.FormatUint(*vlan_id, 10),
		NumRxQueues:      1,
		// RxRingSz:         512,
		// TxRingSz:         512,
	})
	if e1 != nil {
		fmt.Println(r1.Retval)
		return e1
	}
	// vpp# set int state tap10 up
	r2, e2 := (*if_client).SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: r1.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if e2 != nil {
		fmt.Println(r2.Retval)
		return e2
	}
	// set int l2 bridge tap10 10
	r3, e3 := (*l2_client).SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: r1.SwIfIndex,
		BdID:        uint32(*vlan_id),
		PortType:    l2.L2_API_PORT_TYPE_NORMAL, //tap 0 bvi 1
		Shg:         0,
		Enable:      true,
	})
	if e3 != nil {
		fmt.Println(r3.Retval)
		return e3
	}

	// vpp# set interface l2 tag-rewrite tap10 push dot1q 10
	r4, e4 := (*l2_client).L2InterfaceVlanTagRewrite(context.Background(), &l2.L2InterfaceVlanTagRewrite{
		SwIfIndex: r1.SwIfIndex,
		VtrOp:     1,
		// PushDot1q: 1,
		// Tag1:      uint32(*vlan_id),
	})
	if e4 != nil {
		fmt.Println(r4.Retval)
		return e4
	}
	return nil
}
func delIf(conn *core.Connection, if_client *interfaces.RPCService, l2_client *l2.RPCService, ifName string) {
	ch, _ := conn.NewAPIChannel()
	defer ch.Close()
	reqCtx := ch.SendMultiRequest(&interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(^uint32(0)),
	})
	var subIfIndexArray []uint32
	for {
		ifDetails := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(ifDetails)
		if stop {
			break
		}
		if err != nil {
			log.Fatalf("failed to dump interface: %v", err)
		}
		if ifDetails.InterfaceName == ifName {
			(*l2_client).L2InterfaceVlanTagRewrite(context.Background(), &l2.L2InterfaceVlanTagRewrite{
				SwIfIndex: ifDetails.SwIfIndex,
				VtrOp:     0, //disable vlan subif
				// PushDot1q: 1,
			})
			continue
		}
		if strings.Contains(ifDetails.InterfaceName, ifName) {
			subIfIndexArray = append(subIfIndexArray, ifDetails.SupSwIfIndex)
		}
	}
	for _, v := range subIfIndexArray {
		(*if_client).DeleteSubif(context.Background(), &interfaces.DeleteSubif{
			SwIfIndex: interface_types.InterfaceIndex(v),
		})
	}

}
func interfaceDump(if_client *interfaces.RPCService, interfaceName string) (*interfaces.SwInterfaceDetails, error) {
	rep, err := (*if_client).SwInterfaceDump(context.Background(), &interfaces.SwInterfaceDump{
		NameFilterValid: true,
		NameFilter:      interfaceName,
	})
	if err != nil {
		// fmt.Println(rep)
		return nil, err
	}
	v, e1 := rep.Recv()
	if e1 != nil {
		// fmt.Println()
		return nil, e1
	}
	// fmt.Println("dump: ", v)
	return v, nil
}

func parseIP4NetPrefix(ip string, netmask string) (ip_types.IP4Prefix, error) {
	var seq string = "."
	maskarr := strings.Split(netmask, seq)
	iparr := strings.Split(ip, seq)
	a, _ := strconv.Atoi(maskarr[0])
	b, _ := strconv.Atoi(maskarr[1])
	c, _ := strconv.Atoi(maskarr[2])
	d, _ := strconv.Atoi(maskarr[3])
	ip0, _ := strconv.Atoi(iparr[0])
	ip1, _ := strconv.Atoi(iparr[1])
	ip2, _ := strconv.Atoi(iparr[2])
	ip3, _ := strconv.Atoi(iparr[3])
	ones, _ := net.IPv4Mask(byte(a), byte(b), byte(c), byte(d)).Size()
	return ip_types.ParseIP4Prefix(strconv.FormatInt(int64(ip0&a), 10) + "." +
		strconv.FormatInt(int64(ip1&b), 10) + "." +
		strconv.FormatInt(int64(ip2&c), 10) + "." +
		strconv.FormatInt(int64(ip3&d), 10) +
		"/" + fmt.Sprintf("%d", ones))
}

////////////////////////////////DHCP/////////////////////////////////
func dhcp(iface string, enable_dhcp bool, dhcp_mode string, lease string, gateway string, ip string, start_ip string, end_ip string, dns1 string, dns2 string, tftp string, domain_name string, remote_server string, tap_ip string) int {
	err := ioutil.WriteFile("/etc/dnsmasq.d/"+iface+".conf", []byte("interface="+iface+"\n"), 0666)
	if err != nil {
		return 2
	}
	dhcpconf := "/etc/dnsmasq.d/" + iface + "." + ip + ".conf"
	if enable_dhcp {
		if dhcp_mode == "local" {
			if len(lease) == 0 {
				lease = "720"
			}
			if len(gateway) == 0 {
				gateway = ip
			}
			s := "dhcp-option=" + iface + ",3," + gateway + "\n"
			s += "dhcp-range=" + iface + "," + start_ip + "," + end_ip + "," + lease + "m\n"
			if dns1 != "" || dns2 != "" {
				s += "dhcp-option=" + iface + ",6"
				if dns1 != "" {
					s += "," + dns1
				}
				if dns2 != "" {
					s += "," + dns2
				}
				s += "\n"
			}
			if len(tftp) > 0 {
				s += "dhcp-option=" + iface + ",66," + tftp + "\n"
			}
			if len(domain_name) > 0 {
				s += "dhcp-option=" + iface + ",15," + domain_name + "\n"
			}
			err := ioutil.WriteFile(dhcpconf, []byte(s), 0666)
			if err != nil {
				return 2
			}
		} else if dhcp_mode == "relay" {
			s := "dhcp-relay=" + tap_ip + "," + remote_server + "\n"
			err := ioutil.WriteFile(dhcpconf, []byte(s), 0666)
			if err != nil {
				return 2
			}
		}
	} else {
		err := os.Remove(dhcpconf)
		if err != nil {
			return 2
		}
	}
	return 0
}

////////////////////////////////dnsmasq_restart/////////////////////////////////
func dnsmasq_restart() int {
	out, _ := exec.Command("/bin/bash", "-c", "systemctl is-enabled dnsmasq").Output()
	fmt.Print(string(out))
	if string(out) != "enabled\n" {
		out, _ = exec.Command("/bin/bash", "-c", "systemctl enable dnsmasq").Output()
		fmt.Print(string(out))
	}
	out, _ = exec.Command("/bin/bash", "-c", "systemctl restart dnsmasq").Output()
	// time.Sleep(time.Second)
	fmt.Print(string(out))
	out, _ = exec.Command("/bin/bash", "-c", "systemctl is-active dnsmasq").Output()
	fmt.Print(string(out))
	if string(out) == "active\n" {
		return 0
	} else {
		return 2
	}
}
func addbvi(conn *core.Connection, if_client *interfaces.RPCService, l2_client *l2.RPCService, bridgeId uint32) error {
	//暂时商定取G3MAC为base mac
	mac, err := randomMac(conn)
	if err != nil {
		return err
	}
	MacAddress, _ := ethernet_types.ParseMacAddress(mac)
	bvicreateReply, err := (*l2_client).BviCreate(context.Background(), &l2.BviCreate{
		Mac:          MacAddress,
		UserInstance: uint32(bridgeId),
	})
	if err != nil {
		return err
	}
	//Add bridge
	_, err = (*l2_client).SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: bvicreateReply.SwIfIndex,
		BdID:        bridgeId,
		PortType:    l2.L2_API_PORT_TYPE_BVI, //tap 0 bvi 1
		Shg:         0,
		Enable:      true,
	})
	if err != nil {
		return err
	}
	//IP
	iP4Prefix, _ := ip_types.ParseIP4Prefix("192.168." + strconv.FormatUint(uint64(bridgeId), 10) + ".1" + "/" + "24")
	_, err = (*if_client).SwInterfaceAddDelAddress(context.Background(), &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: bvicreateReply.SwIfIndex,
		IsAdd:     true,
		DelAll:    false,
		Prefix: ip_types.AddressWithPrefix{
			Address: ip_types.Address{
				Af: ip_types.ADDRESS_IP4,
				Un: ip_types.AddressUnionIP4(iP4Prefix.Address),
			},
			Len: iP4Prefix.Len,
		},
	})
	if err != nil {
		return err
	}

	//UP
	_, err = (*if_client).SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: bvicreateReply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return err
	}

	return nil
}
func randomMac(conn *core.Connection) (string, error) {
	ml := make(map[string]string)
	//connect govpp
	ch, _ := conn.NewAPIChannel()
	reqCtx := ch.SendMultiRequest(&interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(^uint32(0)),
	})
	for {
		ifDetails := &interfaces.SwInterfaceDetails{}
		stop, err := reqCtx.ReceiveReply(ifDetails)
		if stop {
			break
		}
		if err != nil {
			log.Fatalf("failed to dump interface: %v", err)
		}
		ml[ifDetails.InterfaceName] = ifDetails.L2Address.String()
	}
	//读取出来后获取G3前半段数据
	pre := ml["G3"][:9]
	buff := make([]byte, 3)
	randmac := ""
	loop := false
	for {
		rand.Read(buff)
		//随机后半段,比对如果后半段出现重复则重新生成。
		randmac = pre + fmt.Sprintf("%02X:%02X:%02X", buff[0], buff[1], buff[2])
		for _, mac := range ml {
			if mac == randmac {
				loop = true
				break
			}
		}
		if loop {
			continue
		} else {
			break
		}
	}
	//拼接在一起返回
	return randmac, nil
}
