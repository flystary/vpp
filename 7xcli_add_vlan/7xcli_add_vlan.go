// usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/binapi/ethernet_types"
	interfaces "git.fd.io/govpp.git/binapi/interface"
	"git.fd.io/govpp.git/binapi/interface_types"
	"git.fd.io/govpp.git/binapi/ip_types"
	"git.fd.io/govpp.git/binapi/l2"
	"git.fd.io/govpp.git/core"
)

func main() {
	_sockAddr := flag.String("sock", socketclient.DefaultSocketName, "Path to VPP binary API socket file")
	vlan_id := flag.Uint64("vlan-id", 0, "vlan id params")
	flag.Parse()

	if *vlan_id == 0 || *vlan_id >= 4095 {
		fmt.Println("params illegal")
		os.Exit(3)
	}

	conn, err := govpp.Connect(*_sockAddr)
	if err != nil {
		log.Fatalln("connect to vpp error:", err)
	}
	defer conn.Disconnect()

	l2_client := l2.NewServiceClient(conn)
	if_client := interfaces.NewServiceClient(conn)
	// lcp_client := lcp.NewServiceClient(conn)
	rep, err := l2_client.BridgeDomainAddDel(context.Background(), &l2.BridgeDomainAddDel{
		BdID:    uint32(*vlan_id),
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
	if err != nil {
		//-119 为桥已存在
		if rep.Retval != -119 {
			log.Fatal(rep, err)
		}
	}

	mac, err := randomMac(conn)
	if err != nil {
		log.Fatalf("get rand mac failed:%v \n", err)
	}

	MacAddress, _ := ethernet_types.ParseMacAddress(mac)
	bvicreateReply, err := l2_client.BviCreate(context.Background(), &l2.BviCreate{
		Mac:          MacAddress,
		UserInstance: uint32(*vlan_id),
	})
	if err != nil {
		log.Fatal(err)
	}
	//Add bridge
	_, err = l2_client.SwInterfaceSetL2Bridge(context.Background(), &l2.SwInterfaceSetL2Bridge{
		RxSwIfIndex: bvicreateReply.SwIfIndex,
		BdID:        uint32(*vlan_id),
		PortType:    l2.L2_API_PORT_TYPE_BVI, //tap 0 bvi 1
		Shg:         0,
		Enable:      true,
	})
	if err != nil {
		log.Fatal(err)
	}
	//IP
	iP4Prefix, _ := ip_types.ParseIP4Prefix("192.168." + strconv.FormatUint(*vlan_id, 10) + ".1" + "/" + "24")
	_, err = if_client.SwInterfaceAddDelAddress(context.Background(), &interfaces.SwInterfaceAddDelAddress{
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
		log.Fatal(err)
	}

	//UP
	_, err = if_client.SwInterfaceSetFlags(context.Background(), &interfaces.SwInterfaceSetFlags{
		SwIfIndex: bvicreateReply.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		log.Fatal(err)
	}

	//lcp
	cmd1 := "vppctl lcp create " + "bvi" + strconv.FormatUint(*vlan_id, 10) + " host-if VLAN" + strconv.FormatUint(*vlan_id, 10)
	out, err := exec.Command("/bin/bash", "-c", cmd1).Output()
	if err != nil {
		log.Fatal(string(out), err)
	}
	// err = lcpcreate(&if_client, &lcp_client, vlan_id)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	//linux
	cmd := "ip link set " + "VLAN" + strconv.FormatUint(*vlan_id, 10) + " up mtu 1500"
	out, err = exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil {
		log.Fatal(string(out), err)
	}
	cmd = "ip addr add " + "192.168." + strconv.FormatUint(*vlan_id, 10) + ".1" + "/" + "24" +
		" dev " + "VLAN" + strconv.FormatUint(*vlan_id, 10)
	out, err = exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil {
		log.Fatal(string(out), err)
	}

	os.Exit(0)
}

// //lcpcreate
// func lcpcreate(if_client *interfaces.RPCService, lcp_client *lcp.RPCService, vlan_id *uint64) error {
// 	details, err := interfaceDump(if_client, "bvi"+strconv.FormatUint(*vlan_id, 10))
// 	if err != nil {
// 		return err
// 	}
// 	ns, err := (*lcp_client).LcpDefaultNsSet(context.Background(), &lcp.LcpDefaultNsSet{
// 		Namespace: "777777",
// 	})
// 	fmt.Println(err)
// 	fmt.Println(ns)
// 	ns1, err := (*lcp_client).LcpDefaultNsGet(context.Background(), &lcp.LcpDefaultNsGet{})
// 	fmt.Println(err)
// 	fmt.Println(ns1)
// 	_, err = (*lcp_client).LcpItfPairAddDel(context.Background(), &lcp.LcpItfPairAddDel{
// 		IsAdd:      true,
// 		SwIfIndex:  details.SwIfIndex,
// 		HostIfName: "vlan" + strconv.FormatUint(*vlan_id, 10),
// 		HostIfType: lcp.LCP_API_ITF_HOST_TAP,
// 		Namespace:  ns1.Namespace,
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// //interfaceDump
// func interfaceDump(if_client *interfaces.RPCService, interfaceName string) (*interfaces.SwInterfaceDetails, error) {
// 	rep, err := (*if_client).SwInterfaceDump(context.Background(), &interfaces.SwInterfaceDump{
// 		NameFilterValid: true,
// 		NameFilter:      interfaceName,
// 	})
// 	if err != nil {
// 		// fmt.Println(rep)
// 		return nil, err
// 	}
// 	v, e1 := rep.Recv()
// 	if e1 != nil {
// 		// fmt.Println()
// 		return nil, e1
// 	}
// 	// fmt.Println("dump: ", v)
// 	return v, nil
// }

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
