//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"errors"
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
	"github.com/namsral/flag"
)

var (
	lanName      string
	ip           string
	netmask      string
	enableDhcp   bool
	dhcpMode     string
	remoteServer string
	gateway      string
	startIp      string
	endIp        string
	dns1         string
	dns2         string
	domainName   string
	tftp         string
	lease        uint64
)

func init() {
	// 参数解析
	flag.StringVar(&lanName, "lanName", "", "")
	flag.StringVar(&ip, "ip", "", "")
	flag.StringVar(&netmask, "netmask", "", "")
	flag.BoolVar(&enableDhcp, "enable-dhcp", false, "")
	flag.StringVar(&dhcpMode, "dhcp-mode", "", "")
	flag.StringVar(&remoteServer, "remote-server", "", "")
	flag.StringVar(&gateway, "gateway", "", "")
	flag.StringVar(&startIp, "start-ip", "", "")
	flag.StringVar(&endIp, "end-ip", "", "")
	flag.StringVar(&dns1, "dns1", "", "")
	flag.StringVar(&dns2, "dns2", "", "")
	flag.StringVar(&domainName, "domain-name", "", "")
	flag.StringVar(&tftp, "tftp", "", "")
	flag.Uint64Var(&lease, "lease", 0, "")
}
func main() {
	_sockAddr := flag.String("sock", socketclient.DefaultSocketName, "Path to VPP binary API socket file")
	flag.Parse()
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
	//delete subInterface
	delIf(conn, &if_client, &l2_client, lanName)
	// 添加接口网卡至LAN
	var bridgeId uint32
	var tap_ip string
	var tap_mask string
	var seq string = "."
	arr := strings.Split(ip, seq)
	a, _ := strconv.Atoi(arr[0])
	b, _ := strconv.Atoi(arr[1])
	c, _ := strconv.Atoi(arr[2])
	//d, _ := strconv.Atoi(arr[3])
	bridgeId = uint32(c)
	tap_ip = fmt.Sprintf("%d.%d.%d.%d", a, b, c, 254)
	tap_mask = netmask
	add_lan_ip_pool(&if_client, &l2_client, &tap_client, bridgeId, tap_ip, tap_mask,
		lanName, ip, netmask,
		enableDhcp, dhcpMode, remoteServer,
		gateway, startIp, endIp,
		dns1, dns2, domainName,
		tftp, uint32(lease))
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
func add_lan_ip_pool(if_client *interfaces.RPCService, l2_client *l2.RPCService, tap_client *tapv2.RPCService, bridgeId uint32, tapIp string, tapMask string, lanName string, ip string, netmask string, enableDhcp bool, dhcpMode string, remoteServer string,
	gateway string, startIp string, endIp string, dns1 string, dns2 string, domainName string, tftp string, lease uint32) error {
	// 网卡名称转换为网卡索引
	var ifIndex uint32 = 0

	// intfs, err := plugin.ifHandler.DumpInterfaces(context.Background())
	intfs, err := (*if_client).SwInterfaceDump(context.Background(), &interfaces.SwInterfaceDump{
		NameFilterValid: true,
		NameFilter:      lanName,
	})
	if err != nil {
		return err
	}
	v, err := intfs.Recv()
	if err != nil {
		return err
	}
	macAddress := v.L2Address.String()
	seq := ":"
	arr := strings.Split(macAddress, seq)
	a := arr[0]
	b := arr[1]
	c := arr[2]
	d := fmt.Sprintf("%0x", bridgeId%255)
	e := arr[4]
	f := arr[5]
	macAddress = a + ":" + b + ":" + c + ":" + d + ":" + e + ":" + f
	ifIndex = uint32(v.SwIfIndex)
	// 如桥域不存在，创建桥域
	_, err = (*l2_client).BridgeDomainDump(context.Background(), &l2.BridgeDomainDump{
		BdID: bridgeId,
	})
	if err != nil {
		(*l2_client).BridgeDomainAddDel(context.Background(), &l2.BridgeDomainAddDel{
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
	bviIfIndex, err := addbvi(if_client, l2_client, bridgeId)
	if err != nil {
		return err
	}
	// 添加网卡
	err = add_if(if_client, l2_client, bridgeId, ifIndex)
	if err != nil {
		return err
	}
	// 添加tap
	tapIfIndex, err := add_tap(if_client, l2_client, tap_client, bridgeId, &tapIp, &tapMask)
	if err != nil {
		return err
	}
	// 写入数据文件
	hostIfName := fmt.Sprint("br", bridgeId)
	hostIfIp := tapIp

	var conf string = "/tmp/database.conf"
	var data string
	data += fmt.Sprintf("%d", ifIndex) + ","
	data += fmt.Sprintf("%d", bridgeId) + ","
	data += fmt.Sprintf("%d", bviIfIndex) + ","
	data += fmt.Sprintf("%d", tapIfIndex) + ","
	data += macAddress + ","
	data += ip + ","
	data += netmask + ","
	data += hostIfName + ","
	data += hostIfIp + "\n"

	file, err3 := os.OpenFile(conf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err3 != nil {
		fmt.Println("OpenFile exit code:", err3)
		return err3
	}
	defer file.Close()
	n, err4 := file.Write([]byte(data))
	fmt.Println("Write byte size", n, ",", "Write exit code:", err4)

	// 重新加载dnsmasq
	reload_system_dnsmasq(bridgeId, ip, netmask, enableDhcp, dhcpMode, remoteServer, gateway, startIp, endIp, dns1, dns2, domainName, tftp, lease)

	return nil
}

func addbvi(if_client *interfaces.RPCService, l2_client *l2.RPCService, bridgeId uint32) (uint32, error) {
	//暂时商定取G3MAC为base mac
	r, e := (*if_client).SwInterfaceDump(context.Background(), &interfaces.SwInterfaceDump{
		NameFilterValid: true,
		NameFilter:      "G3",
	})
	if e != nil {
		return 0, e
	}
	v, err := r.Recv()
	if err != nil {
		return 0, e
	}
	old, _ := strconv.ParseUint(v.L2Address.String()[9:11], 16, 10)
	mac := ""
	//暂时不进位，因为后续IP设置最多使用到256
	if (old + uint64(bridgeId)) > 256 {
		return 0, errors.New("params illegal")
	} else {
		new := fmt.Sprintf("%02X", old+uint64(bridgeId))
		mac = v.L2Address.String()[:9] + new + v.L2Address.String()[11:]
	}
	MacAddress, _ := ethernet_types.ParseMacAddress(mac)
	bvicreateReply, err := (*l2_client).BviCreate(context.Background(), &l2.BviCreate{
		Mac:          MacAddress,
		UserInstance: uint32(bridgeId),
	})
	if err != nil {
		return 0, err
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
		return 0, err
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
		return 0, err
	}

	//UP
	_, err = (*if_client).SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: bvicreateReply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return 0, err
	}

	return uint32(bvicreateReply.SwIfIndex), nil
}
func add_tap(if_client *interfaces.RPCService, l2_client *l2.RPCService, tap_client *tapv2.RPCService, id uint32, tap_ip *string, tap_netmask *string) (uint32, error) {
	iP4Prefix, _ := parseIP4NetPrefix(*tap_ip, *tap_netmask)
	fmt.Println(iP4Prefix.String())
	// create tap id 10 host-ip4-addr 192.168.10.254/24 host-if-name vdhcp10
	r1, e1 := (*tap_client).TapCreateV2(context.Background(), &tapv2.TapCreateV2{
		ID:               id,
		HostIP4PrefixSet: true,
		HostIP4Prefix:    ip_types.IP4AddressWithPrefix(iP4Prefix),
		HostIfNameSet:    true,
		HostIfName:       "dhcp" + strconv.FormatUint(uint64(id), 10),
		UseRandomMac:     true,
		HostBridgeSet:    true,
		HostBridge:       "bvi" + strconv.FormatUint(uint64(id), 10),
		NumRxQueues:      1,
		// RxRingSz:         512,
		// TxRingSz:         512,
	})
	if e1 != nil {
		fmt.Println(r1.Retval)
		return 0, e1
	}
	// vpp# set int state tap10 up
	r2, e2 := (*if_client).SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: r1.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if e2 != nil {
		fmt.Println(r2.Retval)
		return 0, e2
	}
	// set int l2 bridge tap10 10
	r3, e3 := (*l2_client).SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: r1.SwIfIndex,
		BdID:        id,
		PortType:    l2.L2_API_PORT_TYPE_NORMAL, //tap 0 bvi 1
		Shg:         0,
		Enable:      true,
	})
	if e3 != nil {
		fmt.Println(r3.Retval)
		return 0, e3
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
		return 0, e4
	}
	return uint32(r1.SwIfIndex), nil
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
func reload_system_dnsmasq(bridgeId uint32, ip string, netmask string, enableDhcp bool, dhcpMode string, remoteServer string,
	gateway string, startIp string, endIp string, dns1 string, dns2 string, domainName string, tftp string, lease uint32) {
	hostIfName := fmt.Sprintf("br%d", bridgeId)

	var confPath string = "/etc/dnsmasq.d/" + hostIfName + "." + ip + ".conf"
	var confPath2 string = "/etc/dnsmasq.d/" + hostIfName + ".conf"
	var data string
	var data2 string
	if enableDhcp {
		switch dhcpMode {
		case "local":
			if lease == 0 {
				lease = 720
			}
			if len(gateway) == 0 {
				gateway = ip
			}

			s1 := "dhcp-option=" + hostIfName + ",3," + gateway + "\n"
			s2 := "dhcp-range=" + hostIfName + "," + startIp + "," + endIp + "," + fmt.Sprintf("%d", lease) + "m" + "\n"

			s3 := "dhcp-option=" + hostIfName + ",6"
			if len(dns1) > 0 {
				s3 += "," + dns1
			}
			if len(dns2) > 0 {
				s3 += "," + dns2
			}
			s3 += "\n"

			var s4 string
			if len(tftp) > 0 {
				s4 = "dhcp-option=" + hostIfName + ",66," + tftp + "\n"
			}

			var s5 string
			if len(domainName) > 0 {
				s5 = "dhcp-option=" + hostIfName + ",15," + domainName + "\n"
			}

			data = s1 + s2 + s3 + s4 + s5
			writeConfigFile(confPath, data)

			data2 = fmt.Sprintf("interface=%s", hostIfName)
			writeConfigFile(confPath2, data2)
		case "relay":
			data := "dhcp-relay=" + ip + "," + remoteServer + "\n"
			writeConfigFile(confPath, data)

			data2 = fmt.Sprintf("interface=%s", hostIfName)
			writeConfigFile(confPath2, data2)
		}
	} else {
		removeConfigFile(confPath)
		removeConfigFile(confPath2)
	}

	out, err := exec.Command("/bin/sh", "-c", "systemctl restart dnsmasq").Output()
	fmt.Println("exec [systemctl restart dnsmasq] output: ", out)
	fmt.Println("exec [systemctl restart dnsmasq] exit code: ", err)
}
func writeConfigFile(path string, data string) {
	err := ioutil.WriteFile(path, []byte(data), 0666)
	fmt.Println("WriteFile", path, "exit code: ", err)
}

func removeConfigFile(path string) {
	err := os.Remove(path)
	fmt.Println("Remove", path, "exit code: ", err)
}
func add_if(if_client *interfaces.RPCService, l2_client *l2.RPCService, bridgeId uint32, ifIndex uint32) error {
	// 启动网卡
	_, err := (*if_client).SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: interface_types.InterfaceIndex(ifIndex),
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return err
	}
	// 添加网卡至桥域
	_, err = (*l2_client).SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: interface_types.InterfaceIndex(ifIndex),
		BdID:        bridgeId,
		PortType:    l2.L2_API_PORT_TYPE_NORMAL, //tap 0 bvi 1
		Shg:         0,
		Enable:      true,
	})
	if err != nil {
		return err
	}
	return nil
}
