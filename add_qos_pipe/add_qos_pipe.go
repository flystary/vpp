//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"flag"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/binapi/classify"
	interfaces "git.fd.io/govpp.git/binapi/interface"
	"git.fd.io/govpp.git/binapi/policer"
	"git.fd.io/govpp.git/binapi/policer_types"
)

func main() {
	//params
	_sockAddr := flag.String("sock", socketclient.DefaultSocketName, "Path to VPP binary API socket file")
	class_id := flag.Uint64("class-id", 0, "class-id")
	class_type := flag.String("type", "", "type")
	interface_id := flag.Uint64("interface-id", 0, "interface-id")
	dst_port := flag.String("dst-port", "", "dst-port")
	dst := flag.String("dst", "", "dst")

	flag.Parse()
	//脚本只处理lan/vlan
	if !strings.Contains(*class_type, "lan") {
		log.Fatalf("params type error : %s", *class_type)
	}
	//connect client
	conn, err := govpp.Connect(*_sockAddr)
	if err != nil {
		log.Fatalln("connect to vpp error:", err)
	}
	defer conn.Disconnect()
	policer_client := policer.NewServiceClient(conn)
	classify_client := classify.NewServiceClient(conn)
	interfaces_client := interfaces.NewServiceClient(conn)
	//vpp# cnfigure policer name policy1 cir 12000 cb 15000 rate kbps round closest type 1r2c conform-action transmit exceed-action drop
	_, err = policer_client.PolicerAddDel(context.Background(), &policer.PolicerAddDel{
		IsAdd:     true,
		Name:      "policy" + strconv.FormatUint(*interface_id, 10),
		Cir:       12000,
		Cb:        15000,
		RateType:  policer_types.SSE2_QOS_RATE_API_KBPS,
		RoundType: policer_types.SSE2_QOS_ROUND_API_TO_CLOSEST,
		Type:      policer_types.SSE2_QOS_POLICER_TYPE_API_1R2C,
		ConformAction: policer_types.Sse2QosAction{
			Type: policer_types.SSE2_QOS_ACTION_API_TRANSMIT,
		},
		ExceedAction: policer_types.Sse2QosAction{
			Type: policer_types.SSE2_QOS_ACTION_API_DROP,
		},
	})
	if err != nil {
		log.Fatalf("PolicerAdd:%v \n", err)
	}
	// vpp# classify table mask l4 dst_port l3 ip4 dst
	// mask, _ := hex.DecodeString("0000000000000000000000000000ffffffff0000ffff00000000000000000000")
	// classifyAddTableReply, err := classify_client.ClassifyAddDelTable(context.Background(), &classify.ClassifyAddDelTable{
	// 	IsAdd:             true,
	// 	Mask:              mask,
	// 	MaskLen:           32,
	// 	MatchNVectors:     2,
	// 	SkipNVectors:      1,
	// 	CurrentDataFlag:   0,
	// 	CurrentDataOffset: 0,
	// 	Nbuckets:          2,
	// })
	// log.Println("classifyAddTableReply=", classifyAddTableReply, err)

	cmd := "vppctl classify table mask l4 dst_port l3 ip4 dst"
	out, err := exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil || len(out) > 0 {
		log.Fatal(string(out), err)
	}

	// //vpp# classify session policer-hit-next policy1 exceed-color table-index 0 match l4 dst_port 5201 l3 ip4 dst 192.168.40.74
	// match := []byte("")
	// classifyAddSessionReply, err := classify_client.ClassifyAddDelSession(context.Background(), &classify.ClassifyAddDelSession{
	// 	IsAdd:        true,
	// 	TableIndex:   classifyAddTableReply.NewTableIndex,
	// 	Match:        match,
	// 	MatchLen:     uint32(len(mask)),
	// 	HitNextIndex: policerAddReply.PolicerIndex,
	// })
	// log.Println("classifyAddDelSessionReply=", classifyAddSessionReply, err)

	cmd = "vppctl classify session policer-hit-next" +
		" policy" + strconv.FormatUint(*interface_id, 10) + " exceed-color" +
		" table-index " + strconv.FormatUint(*class_id, 10) +
		" match l4 dst_port " + *dst_port + " l3 ip4 dst " + *dst

	out, err = exec.Command("/bin/bash", "-c", cmd).Output()
	if err != nil || len(out) > 0 {
		log.Fatal(string(out), err)
	}

	//vpp# set policer classify interface bvi1 ip4-table 0
	interfaceDumpClient, _ := interfaces_client.SwInterfaceDump(context.Background(), &interfaces.SwInterfaceDump{
		NameFilterValid: true,
		NameFilter:      "bvi" + strconv.FormatUint(*interface_id, 10),
	})
	interfaceDetail, _ := interfaceDumpClient.Recv()
	policerClassifySetInterfaceAddReply, err := classify_client.PolicerClassifySetInterface(context.Background(), &classify.PolicerClassifySetInterface{
		IsAdd:         true,
		IP4TableIndex: 0,
		SwIfIndex:     interfaceDetail.SwIfIndex,
	})
	log.Println("policerClassifySetInterfaceAddReply=", policerClassifySetInterfaceAddReply, err)
}
