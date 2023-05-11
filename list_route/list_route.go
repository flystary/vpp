//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"fmt"
	"log"
	"time"

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
	ep := &ListRoutePlugin{
		Log:          logrus.DefaultLogger(),
		closeChannel: closeChannel,
	}

	ep.Deps.GoVppMux = &govppmux.DefaultPlugin
	ep.Log.SetLevel(logging.DebugLevel)

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
const PluginName = "list_route"

// ExamplePlugin implements Plugin interface which is used to pass custom plugin instances to the Agent.
type ListRoutePlugin struct {
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
}

// Deps is example plugin dependencies.
type Deps struct {
	GoVppMux *govppmux.Plugin
}

// Init members of plugin.
func (plugin *ListRoutePlugin) Init() (err error) {
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
func (plugin *ListRoutePlugin) Close() error {
	return safeclose.Close()
}

// String returns plugin name
func (plugin *ListRoutePlugin) String() string {
	return PluginName
}

// String returns plugin name
func (plugin *ListRoutePlugin) Task() {
	plugin.list_fib()
}

func (plugin *ListRoutePlugin) list_fib() {
	// 建立映射关系
	plugin.vrfIndexes.Put("vrf1-ipv4", &vrfidx.VRFMetadata{Index: 0, Protocol: l3.VrfTable_IPV4})
	//plugin.vrfIndexes.Put("vrf1-ipv6", &vrfidx.VRFMetadata{Index: 0, Protocol: l3.VrfTable_IPV6})

	// 列出路由表
	routes, err := plugin.l3Hander.DumpRoutes()
	fmt.Println(err)
	for k, v := range routes {
		fmt.Println(k, v.Meta.OutgoingIfIdx, v.Route.DstNetwork, v.Route.NextHopAddr, "none")
	}
}
