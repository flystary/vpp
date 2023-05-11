//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.ligato.io/cn-infra/v2/agent"
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/cn-infra/v2/logging/logrus"
	"go.ligato.io/cn-infra/v2/utils/safeclose"

	"go.ligato.io/vpp-agent/v3/plugins/govppmux"
	// "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin"
	"go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/ifaceidx"

	ifvppcalls "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/vppcalls"
	ifvpp2106 "go.ligato.io/vpp-agent/v3/plugins/vpp/ifplugin/vppcalls/vpp2106"

	// "go.ligato.io/vpp-agent/v3/plugins/vpp/l2plugin"
	govppapi "git.fd.io/govpp.git/api"
	l2vppcalls "go.ligato.io/vpp-agent/v3/plugins/vpp/l2plugin/vppcalls"
	l2vpp2106 "go.ligato.io/vpp-agent/v3/plugins/vpp/l2plugin/vppcalls/vpp2106"
)

func main() {
	// Init close channel to stop the example.
	closeChannel := make(chan struct{})

	// Inject dependencies to example plugin
	ep := &ListLanPlugin{
		Log:          logrus.DefaultLogger(),
		closeChannel: closeChannel,
	}
	ep.Deps.GoVppMux = &govppmux.DefaultPlugin
	ep.Log.SetLevel(logging.FatalLevel)

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
const PluginName = "list_lan"

// ExamplePlugin implements Plugin interface which is used to pass custom plugin instances to the Agent.
type ListLanPlugin struct {
	Deps
	ifHandler ifvppcalls.InterfaceVppAPI
	l2Hander  l2vppcalls.BridgeDomainVppAPI
	ifIndex   ifaceidx.IfaceMetadataIndexRW
	tmp       string
	// Fields below are used to properly finish the example.
	closeChannel chan struct{}
	Log          logging.Logger
}
type Deps struct {
	GoVppMux *govppmux.Plugin
}

// Init members of plugin.
func (plugin *ListLanPlugin) Init() (err error) {
	plugin.Log.Info("Default plugin loaded ready")
	plugin.ifHandler = ifvpp2106.NewInterfaceVppHandler(plugin.GoVppMux, plugin.Log)

	if ch, err := plugin.GoVppMux.NewAPIChannel(); err == nil {
		plugin.ifIndex = ifaceidx.NewIfaceIndex(plugin.Log, "bd-test-ifidx")
		plugin.l2Hander = l2vpp2106.NewL2VppHandler(ch, plugin.ifIndex, nil, plugin.Log)
	} else {
		return err
	}

	return err
}

// Close is called by Agent Core when the Agent is shutting down. It is supposed
// to clean up resources that were allocated by the plugin during its lifetime.
func (plugin *ListLanPlugin) Close() error {
	return safeclose.Close(plugin.closeChannel)
}

// String returns plugin name
func (plugin *ListLanPlugin) String() string {
	return PluginName
}

func (plugin *ListLanPlugin) Task() {
	plugin.list_lan()
}

func (plugin *ListLanPlugin) list_lan() {
	// 列出网卡信息
	intfs, err := plugin.ifHandler.DumpInterfaces(context.Background())
	fmt.Println("DumpInterfaces exit code: ", err)

	// 网卡状态
	var stats govppapi.InterfaceStats
	plugin.Deps.GoVppMux.GetInterfaceStats(&stats)

	// ifName macAddress linkStatus vlansFormat pvid rxTraffic txTraffic
	// 打印
	fmt.Println("key ifName macAddress linkStatus")
	for k, v := range intfs {
		fmt.Println(k, v.Meta.InternalName, v.Interface.PhysAddress, v.Meta.IsLinkStateUp)
	}
	fmt.Println("key ifName rxTraffic txTraffic")
	for k, v := range stats.Interfaces {
		fmt.Println(k, v.InterfaceName, v.Tx.Bytes, v.Rx.Bytes)
	}

	close(plugin.closeChannel)
}
