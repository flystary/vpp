//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
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
	l2 "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/l2"

	ethtypes "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/ethernet_types"
	ip_types "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/ip_types"
	l2ba "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/l2"
	tapv2 "go.ligato.io/vpp-agent/v3/plugins/vpp/binapi/vpp2106/tapv2"

	ifs "go.ligato.io/vpp-agent/v3/proto/ligato/vpp/interfaces"
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

	// 参数解析
	flag.StringVar(&ep.lanName, "lanName", "", "")
	flag.StringVar(&ep.ip, "ip", "", "")
	flag.StringVar(&ep.netmask, "netmask", "", "")
	flag.BoolVar(&ep.enableDhcp, "enableDhcp", false, "")
	flag.StringVar(&ep.dhcpMode, "dhcpMode", "", "")
	flag.StringVar(&ep.remoteServer, "remoteServer", "", "")
	flag.StringVar(&ep.gateway, "gateway", "", "")
	flag.StringVar(&ep.startIp, "startIp", "", "")
	flag.StringVar(&ep.endIp, "endIp", "", "")
	flag.StringVar(&ep.dns1, "dns1", "", "")
	flag.StringVar(&ep.dns2, "dns2", "", "")
	flag.StringVar(&ep.domainName, "domainName", "", "")
	flag.StringVar(&ep.tftp, "tftp", "", "")
	flag.Uint64Var(&ep.lease, "lease", 0, "")

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
	l2Hander  l2vppcalls.BridgeDomainVppAPI

	ifIndex ifaceidx.IfaceMetadataIndexRW

	// Fields below are used to properly finish the example.
	closeChannel chan struct{}
	Log          logging.Logger

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
		plugin.ifIndex = ifaceidx.NewIfaceIndex(plugin.Log, "bd-test-ifidx")
		plugin.l2Hander = l2vpp2106.NewL2VppHandler(ch, plugin.ifIndex, nil, plugin.Log)
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

func (plugin *AddLanIpPoolPlugin) Task() {
	// 删除子接口网卡
	intfs, err := plugin.ifHandler.DumpInterfaces(context.Background())
	fmt.Println("DumpInterfaces exit code:", err)

	var subIfIndexArray []uint32
	for _, v := range intfs {
		if plugin.lanName == v.Meta.InternalName {
			// 设置VLAN标签为禁用
			err := plugin.ifHandler.SetVLanTagRewrite(v.Meta.SwIfIndex, &ifs.SubInterface{
				TagRwOption: ifs.SubInterface_DISABLED,
				PushDot1Q:   true,
			})
			fmt.Println("SetVLanTagRewrite exit code:", err)
			continue
		}
		exist := strings.Contains(v.Meta.InternalName, plugin.lanName)
		if exist {
			subIfIndexArray = append(subIfIndexArray, v.Meta.SwIfIndex)
		}
	}

	for _, v := range subIfIndexArray {
		err := plugin.ifHandler.DeleteSubif(v)
		fmt.Println("DeleteSubif exit code:", err)
	}

	// 添加接口网卡至LAN

	var bridgeId uint32
	var tap_ip string
	var tap_mask string

	var seq string = "."
	arr := strings.Split(plugin.ip, seq)
	a, _ := strconv.Atoi(arr[0])
	b, _ := strconv.Atoi(arr[1])
	c, _ := strconv.Atoi(arr[2])
	//d, _ := strconv.Atoi(arr[3])

	bridgeId = uint32(c)
	tap_ip = fmt.Sprintf("%d.%d.%d.%d", a, b, c, 254)
	tap_mask = plugin.netmask

	plugin.add_lan_ip_pool(bridgeId, tap_ip, tap_mask,
		plugin.lanName, plugin.ip, plugin.netmask,
		plugin.enableDhcp, plugin.dhcpMode, plugin.remoteServer,
		plugin.gateway, plugin.startIp, plugin.endIp,
		plugin.dns1, plugin.dns2, plugin.domainName,
		plugin.tftp, uint32(plugin.lease))
}

func (plugin *AddLanIpPoolPlugin) add_lan_ip_pool(bridgeId uint32, tapIp string, tapMask string, lanName string, ip string, netmask string, enableDhcp bool, dhcpMode string, remoteServer string,
	gateway string, startIp string, endIp string, dns1 string, dns2 string, domainName string, tftp string, lease uint32) {
	// 网卡名称转换为网卡索引
	var ifIndex uint32 = 0
	var macAddress string

	intfs, err := plugin.ifHandler.DumpInterfaces(context.Background())
	fmt.Println("DumpInterfaces exit code:", err)
	var fail bool = true
	for _, v := range intfs {
		if lanName == v.Meta.InternalName {
			fail = false
			ifIndex = v.Meta.SwIfIndex

			macAddress = v.Interface.PhysAddress
			seq := ":"
			arr := strings.Split(macAddress, seq)
			a := arr[0]
			b := arr[1]
			c := arr[2]
			d := fmt.Sprintf("%0x", bridgeId%255)
			e := arr[4]
			f := arr[5]
			macAddress = a + ":" + b + ":" + c + ":" + d + ":" + e + ":" + f

			break
		}
	}
	if fail {
		fmt.Println("invalid ifName:", lanName)
		return
	}
	fmt.Println("ifName -> ifIndex:", lanName, "->", ifIndex)

	// 如桥域不存在，创建桥域
	bds, err2 := plugin.l2Hander.DumpBridgeDomains()
	fmt.Println("DumpBridgeDomains exit code:", err2)
	var exist bool = false
	for _, v := range bds {
		if bridgeId == v.Meta.BdID {
			exist = true
			break
		}
	}
	if exist {
		var createTestDataInBD = &l2.BridgeDomain{
			Name:                "bridge_domain",
			Flood:               true,
			UnknownUnicastFlood: true,
			Forward:             true,
			Learn:               true,
		}
		err2 := plugin.l2Hander.AddBridgeDomain(bridgeId, createTestDataInBD)
		fmt.Println("AddBridgeDomain exit code:", err2)
	}

	// 添加网卡
	plugin.add_if(bridgeId, ifIndex)

	// 添加bvi
	bviIfIndex := plugin.add_bvi(bridgeId, macAddress, ip, netmask)

	// 添加tap
	tapIfIndex := plugin.add_tap(bridgeId, tapIp, tapMask)

	// 写入数据文件
	hostIfName := fmt.Sprint("br", bridgeId)
	hostIfIp := tapIp

	var conf string = "/tmp/7xcli_database.conf"
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
		return
	}
	defer file.Close()
	n, err4 := file.Write([]byte(data))
	fmt.Println("Write byte size", n, ",", "Write exit code:", err4)

	// 重新加载dnsmasq
	plugin.reload_system_dnsmasq(bridgeId, ip, netmask, enableDhcp, dhcpMode, remoteServer,
		gateway, startIp, endIp, dns1, dns2, domainName, tftp, lease)
}

func (plugin *AddLanIpPoolPlugin) add_if(bridgeId uint32, ifIndex uint32) {
	// 启动网卡
	err7 := plugin.ifHandler.InterfaceAdminUp(context.Background(), ifIndex)
	fmt.Println("InterfaceAdminUp exit code: ", err7)

	// 建立映射关系
	plugin.ifIndex.Put("if", &ifaceidx.IfaceMetadata{SwIfIndex: ifIndex})

	// 添加网卡至桥域
	err4 := plugin.l2Hander.AddInterfaceToBridgeDomain(bridgeId, &l2.BridgeDomain_Interface{
		Name:                    "if",
		BridgedVirtualInterface: false,
		SplitHorizonGroup:       0,
	})
	fmt.Println("AddInterfaceToBridgeDomain exit code: ", err4)
}

func (plugin *AddLanIpPoolPlugin) add_bvi(bridgeId uint32, macAddress string, ip string, netmask string) uint32 {
	// 创建bvi, 设置mac地址
	mac, err := ethtypes.ParseMacAddress(macAddress)
	fmt.Println("ParseMacAddress exit code: ", err)
	req := &l2ba.BviCreate{
		Mac:          mac,
		UserInstance: bridgeId,
	}
	rpy := &l2ba.BviCreateReply{}
	ch, err2 := plugin.GoVppMux.NewAPIChannel()
	fmt.Println("NewAPIChannel exit code:", err2)

	err3 := ch.SendRequest(req).ReceiveReply(rpy)
	fmt.Println("SendRequest,ReceiveReply exit code: ", err3)

	var bviIndex uint32 = uint32(rpy.SwIfIndex)

	// 启动bvi
	err7 := plugin.ifHandler.InterfaceAdminUp(context.Background(), bviIndex)
	fmt.Println("InterfaceAdminUp exit code: ", err7)

	// 设置网卡ip地址
	var seq string = "."
	arr := strings.Split(netmask, seq)
	a, _ := strconv.Atoi(arr[0])
	b, _ := strconv.Atoi(arr[1])
	c, _ := strconv.Atoi(arr[2])
	d, _ := strconv.Atoi(arr[3])

	ones, _ := net.IPv4Mask(byte(a), byte(b), byte(c), byte(d)).Size()
	cird := ip + "/" + fmt.Sprintf("%d", ones)

	parseIp, ipNet, err5 := net.ParseCIDR(cird)
	fmt.Println("ParseCIDR exit code:", err5)

	ipNet.IP = parseIp
	err6 := plugin.ifHandler.AddInterfaceIP(bviIndex, ipNet)
	fmt.Println("AddInterfaceIP exit code: ", err6)

	// 建立映射关系
	plugin.ifIndex.Put("bvi", &ifaceidx.IfaceMetadata{SwIfIndex: bviIndex})

	// 添加bvi至桥域
	err4 := plugin.l2Hander.AddInterfaceToBridgeDomain(bridgeId, &l2.BridgeDomain_Interface{
		Name:                    "bvi",
		BridgedVirtualInterface: true,
		SplitHorizonGroup:       0,
	})
	fmt.Println("AddInterfaceToBridgeDomain exit code: ", err4)

	return bviIndex
}

func (plugin *AddLanIpPoolPlugin) add_tap(bridgeId uint32, ip string, netmask string) uint32 {
	// 创建tap
	var seq string = "."
	arr := strings.Split(netmask, seq)
	a, _ := strconv.Atoi(arr[0])
	b, _ := strconv.Atoi(arr[1])
	c, _ := strconv.Atoi(arr[2])
	d, _ := strconv.Atoi(arr[3])

	ones, _ := net.IPv4Mask(byte(a), byte(b), byte(c), byte(d)).Size()
	cird := ip + "/" + fmt.Sprintf("%d", ones)

	ipAddress, err := ip_types.ParseIP4Prefix(cird)
	fmt.Println("ParseIP4Prefix exit code: ", err)

	req := &tapv2.TapCreateV2{
		ID:               bridgeId,
		NumRxQueues:      1,
		HostIfName:       "br" + fmt.Sprintf("%d", bridgeId),
		HostIfNameSet:    true,
		UseRandomMac:     true,
		HostIP4PrefixSet: true,
		HostIP4Prefix:    ip_types.IP4AddressWithPrefix(ipAddress),
	}
	rpy := &tapv2.TapCreateV2Reply{}
	ch, err2 := plugin.GoVppMux.NewAPIChannel()
	fmt.Println("NewAPIChannel exit code: ", err2)

	err3 := ch.SendRequest(req).ReceiveReply(rpy)
	fmt.Println("SendRequest,ReceiveReply exit code: ", err3)

	var tapIfIndex uint32 = uint32(rpy.SwIfIndex)

	// 启动tap
	err4 := plugin.ifHandler.InterfaceAdminUp(context.Background(), tapIfIndex)
	fmt.Println("InterfaceAdminUp exit code: ", err4)

	// 建立映射关系
	plugin.ifIndex.Put("tap", &ifaceidx.IfaceMetadata{SwIfIndex: tapIfIndex})

	// 添加网卡至桥域
	err5 := plugin.l2Hander.AddInterfaceToBridgeDomain(bridgeId, &l2.BridgeDomain_Interface{
		Name:                    "tap",
		BridgedVirtualInterface: false,
		SplitHorizonGroup:       0,
	})
	fmt.Println("AddInterfaceToBridgeDomain exit code: ", err5)

	return tapIfIndex
}

func (plugin *AddLanIpPoolPlugin) reload_system_dnsmasq(bridgeId uint32, ip string, netmask string, enableDhcp bool, dhcpMode string, remoteServer string,
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
			plugin.writeConfigFile(confPath, data)

			data2 = fmt.Sprintf("interface=%s", hostIfName)
			plugin.writeConfigFile(confPath2, data2)
		case "relay":
			data := "dhcp-relay=" + ip + "," + remoteServer + "\n"
			plugin.writeConfigFile(confPath, data)

			data2 = fmt.Sprintf("interface=%s", hostIfName)
			plugin.writeConfigFile(confPath2, data2)
		}
	} else {
		plugin.removeConfigFile(confPath)
		plugin.removeConfigFile(confPath2)
	}

	out, err := exec.Command("/bin/sh", "-c", "systemctl restart dnsmasq").Output()
	fmt.Println("exec [systemctl restart dnsmasq] output: ", out)
	fmt.Println("exec [systemctl restart dnsmasq] exit code: ", err)
}

func (plugin *AddLanIpPoolPlugin) writeConfigFile(path string, data string) {
	err := ioutil.WriteFile(path, []byte(data), 0666)
	fmt.Println("WriteFile", path, "exit code: ", err)
}

func (plugin *AddLanIpPoolPlugin) removeConfigFile(path string) {
	err := os.Remove(path)
	fmt.Println("Remove", path, "exit code: ", err)
}
