//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/adapter/statsclient"
	"git.fd.io/govpp.git/api"
	interfaces "git.fd.io/govpp.git/binapi/interface"
	"git.fd.io/govpp.git/binapi/interface_types"
	"git.fd.io/govpp.git/core"
)

func main() {
	_sockAddr := flag.String("sock", socketclient.DefaultSocketName, "Path to VPP binary API socket file")
	flag.Parse()
	//map[interface_name][mac,rx,tx]
	m := make(map[string][]string)
	//connect govpp
	conn, err := govpp.Connect(*_sockAddr)
	if err != nil {
		log.Fatalln("connect to vpp error:", err)
	}
	defer conn.Disconnect()

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
		switch ifDetails.InterfaceDevType {
		//dpdk BVI virtio local
		case "BVI":
			m[ifDetails.InterfaceName] = []string{ifDetails.L2Address.String(), ifDetails.InterfaceDevType}
		}
	}
	statsClient := statsclient.NewStatsClient("")
	statsConn, _ := core.ConnectStats(statsClient)
	stat := new(api.InterfaceStats)
	statsConn.GetInterfaceStats(stat)
	for _, v := range stat.Interfaces {
		if _, ok := m[v.InterfaceName]; ok {
			m[v.InterfaceName] = append(m[v.InterfaceName], strconv.FormatUint(v.Rx.Bytes, 10), strconv.FormatUint(v.Tx.Bytes, 10))
		}
	}
	//interface mac rx tx
	for k, v := range m {
		fmt.Println(k, v[0], v[1], v[2], v[3])
	}
}
