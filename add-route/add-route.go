//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/namsral/flag"

	"go.ligato.io/cn-infra/v2/agent"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/cn-infra/v2/logging/logrus"
	"go.ligato.io/cn-infra/v2/utils/safeclose"

	"go.ligato.io/vpp-agent/v3/plugins/govppmux"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"

	ifvppcalls "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/vppcalls"
	ifvpp2106 "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/vppcalls/vpp2106"
	l2vppcalls "go.ligato.io/vpp-agent/v3/plugins/vpp/l2plugin/vppcalls"
	l2vpp2106 "go.ligato.io/vpp-agent/v3/plugins/vpp/l2plugin/vppcalls/vpp2106"
	l3vppcalls "go.ligato.io/vpp-agent/v3/plugins/vpp/l3plugin/vppcalls"

	l3vpp2106 "go.ligato.io/vpp-agent/v3/plugins/vpp/l3plugin/vppcalls/vpp2106"

	"go.ligato.io/vpp-agent/v3/plugins/vpp/l3plugin/vrfidx"

	"go.ligato.io/vpp-agent/v3/pkg/idxvpp"
	netallock_mock "go.ligato.io/vpp-agent/v3/plugins/netalloc/mock"
	l3 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l3"
)

func main() {
	// Init close channel to stop the example.
	closeChannel := make(chan struct{})

	// Inject dependencies to example plugin
	ep := &AddLanIpPoolPlugin{
		Log:          logrus.DefaultLogger(),
		closeChannel: closeChannel,
	}

	ep.Deps.GoVppMux = &govppmux.DefaultPlugin
	ep.Log.SetLevel(logging.DebugLevel)

	flag.StringVar(&ep.ip, "ip", "", "")
	flag.StringVar(&ep.netmask, "netmask", "", "")
	flag.StringVar(&ep.nexthop, "nexthop", "", "")

	// Start Agent
	a := agent.NewAgent(
		agent.StartTimeout(10*time.Minute),
		agent.AllPlugins(ep),
		agent.QuitOnClose(closeChannel),
	)

	if err := a.Start(); err != nil {
		log.Fatal()
	}

	ep.Task()

	if err := a.Stop(); err != nil {
		log.Fatal()
	}
}

// PluginName represents name of plugin.
const PluginName = "add_lan_ip_pool"

// ExamplePlugin implements Plugin interface which is used to pass custom plugin instances to the Agent.
type AddLanIpPoolPlugin struct {
	Deps
	ifHandler ifvppcalls.InterfaceVppAPI
	l2Hander  l2vppcalls.L2VppAPI
	l3Hander  l3vppcalls.L3VppAPI

	ifIndexs   ifaceidx.IfaceMetadataIndexRW
	bdIndexes  idxvpp.NameToIndexRW
	vrfIndexes vrfidx.VRFMetadataIndexRW

	// Fields below are used to properly finish the example.
	closeChannel chan struct{}
	Log          logging.Logger

	ip      string
	netmask string
	nexthop string
}

// Deps is example plugin dependencies.
type Deps struct {
	GoVppMux *govppmux.Plugin
}

// Init members of plugin.
func (plugin *AddLanIpPoolPlugin) Init() (err error) {
	plugin.Log.Info("Default plugin loaded ready")
	plugin.ifHandler = ifvpp2106.NewInterfaceVppHandler(plugin.GoVppMux, plugin.Log)

	if ch, err := plugin.GoVppMux.NewAPIChannel(); err == nil {
		plugin.ifIndexs = ifaceidx.NewIfaceIndex(plugin.Log, "bd-test-ifidx")
		plugin.bdIndexes = idxvpp.NewNameToIndex(plugin.Log, "fib-bd-idx", nil)
		plugin.vrfIndexes = vrfidx.NewVRFIndex(logrus.NewLogger("test-vrf"), "test-vrf")

		plugin.l2Hander = l2vpp2106.NewL2VppHandler(ch, plugin.ifIndexs, plugin.bdIndexes, plugin.Log)
		plugin.l3Hander = l3vpp2106.NewL3VppHandler(plugin.GoVppMux, plugin.ifIndexs, plugin.vrfIndexes, netallock_mock.NewMockNetAlloc(), plugin.Log)
	} else {
		return err
	}

	return err
}

// Close is called by Agent Core when the Agent is shutting down. It is supposed
// to clean up resources that were allocated by the plugin during its lifetime.
func (plugin *AddLanIpPoolPlugin) Close() error {
	return safeclose.Close()
}

// String returns plugin name
func (plugin *AddLanIpPoolPlugin) String() string {
	return PluginName
}

// String returns plugin name
func (plugin *AddLanIpPoolPlugin) Task() {
	/*
		// 遍历网卡
		intfs, err := plugin.ifHandler.DumpInterfaces(context.Background())
		fmt.Println("DumpInterfaces exit code:", err)
		for k, v := range intfs {
			fmt.Println(k, v.Meta.SwIfIndex, v.Meta.InternalName)
			plugin.add_route(v.Meta.SwIfIndex, plugin.ip, plugin.netmask, plugin.nexthop)
		}
	*/

	// 网卡名称转换为网卡索引
	var lanName string = "G3"
	var ifIndex uint32 = 0
	intfs, err := plugin.ifHandler.DumpInterfaces(context.Background())
	fmt.Println("DumpInterfaces exit code:", err)
	var fail bool = true
	for _, v := range intfs {
		if lanName == v.Meta.InternalName {
			fail = false
			ifIndex = v.Meta.SwIfIndex
			break
		}
	}
	if fail {
		fmt.Println("invalid ifName:", lanName)
		return
	}
	fmt.Println("ifName -> ifIndex:", lanName, "->", ifIndex)

	plugin.add_route(ifIndex, plugin.ip, plugin.netmask, plugin.nexthop)
}

func (plugin *AddLanIpPoolPlugin) add_route(ifIndex uint32, ip string, netmask string, nexthop string) {
	// 建立映射关系
	plugin.ifIndexs.Put("if", &ifaceidx.IfaceMetadata{SwIfIndex: ifIndex})

	// 设置网卡ip地址
	var seq string = "."
	arr := strings.Split(netmask, seq)
	a, _ := strconv.Atoi(arr[0])
	b, _ := strconv.Atoi(arr[1])
	c, _ := strconv.Atoi(arr[2])
	d, _ := strconv.Atoi(arr[3])
	ones, _ := net.IPv4Mask(byte(a), byte(b), byte(c), byte(d)).Size()
	cird := ip + "/" + fmt.Sprintf("%d", ones)

	// 添加新路由
	newRoute := l3.Route{
		VrfId:             0,
		DstNetwork:        cird,
		NextHopAddr:       nexthop,
		OutgoingInterface: "if",
	}
	err := plugin.l3Hander.VppAddRoute(context.Background(), &newRoute)
	fmt.Println("VppAddRoute exit code:", err)
}
