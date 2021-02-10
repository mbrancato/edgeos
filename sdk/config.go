package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
)

var emptyString = []byte(`""`)

type ConfigZonePolicy struct {
	Zone *map[string]ConfigZonePolicyZone `json:"zone,omitempty"`
}

type ConfigZonePolicyZone struct {
	DefaultAction string                               `json:"default-action,omitempty"`
	Interface     []string                             `json:"interface,omitempty"`
	LocalZone     string                               `json:"local-zone,omitempty"`
	From          *map[string]ConfigZonePolicyZoneFrom `json:"from,omitempty"`
	Description   string                               `json:"description,omitempty"`
}

type ConfigZonePolicyZoneFrom struct {
	ContentInspection *ConfigZonePolicyZoneFromContentInspection `json:".content-inspection,omitempty"`
	Firewall          *ConfigZonePolicyZoneFromFirewall          `json:"firewall,omitempty"`
}

type ConfigZonePolicyZoneFromContentInspection struct {
	Enable     string `json:"enable,omitempty"`
	Ipv6Enable string `json:".ipv6-enable,omitempty"`
}

type ConfigZonePolicyZoneFromFirewall struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigLoadBalance struct {
	Group *map[string]ConfigLoadBalanceGroup `json:"group,omitempty"`
}

type ConfigLoadBalanceGroup struct {
	Interface             *map[string]ConfigLoadBalanceGroupInterface `json:"interface,omitempty"`
	LbLocal               string                                      `json:"lb-local,omitempty"`
	GatewayUpdateInterval EdgeOSInt                                   `json:"gateway-update-interval,omitempty"`
	LbLocalMetricChange   string                                      `json:"lb-local-metric-change,omitempty"`
	Sticky                *ConfigLoadBalanceGroupSticky               `json:"sticky,omitempty"`
	FlushOnActive         string                                      `json:"flush-on-active,omitempty"`
	TransitionScript      string                                      `json:"transition-script,omitempty"`
	ExcludeLocalDns       string                                      `json:"exclude-local-dns,omitempty"`
	ReachabilityScript    string                                      `json:"reachability-script,omitempty"`
}

type ConfigLoadBalanceGroupInterface struct {
	Weight           string                                    `json:"weight,omitempty"`
	RouteTest        *ConfigLoadBalanceGroupInterfaceRouteTest `json:"route-test,omitempty"`
	Route            *ConfigLoadBalanceGroupInterfaceRoute     `json:"route,omitempty"`
	FailoverOnly     string                                    `json:"failover-only,omitempty"`
	FailoverPriority string                                    `json:"failover-priority,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTest struct {
	Interval     EdgeOSInt                                      `json:"interval,omitempty"`
	Count        *ConfigLoadBalanceGroupInterfaceRouteTestCount `json:"count,omitempty"`
	InitialDelay EdgeOSInt                                      `json:"initial-delay,omitempty"`
	Type         *ConfigLoadBalanceGroupInterfaceRouteTestType  `json:"type,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTestCount struct {
	Success EdgeOSInt `json:"success,omitempty"`
	Failure EdgeOSInt `json:"failure,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTestType struct {
	Ping    *ConfigLoadBalanceGroupInterfaceRouteTestTypePing `json:"ping,omitempty"`
	Default string                                            `json:"default,omitempty"`
	Script  string                                            `json:"script,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTestTypePing struct {
	Target IP `json:"target,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRoute struct {
	Default string    `json:"default,omitempty"`
	Table   EdgeOSInt `json:"table,omitempty"`
}

type ConfigLoadBalanceGroupSticky struct {
	Proto      string `json:"proto,omitempty"`
	SourceAddr string `json:"source-addr,omitempty"`
	SourcePort string `json:"source-port,omitempty"`
	DestPort   string `json:"dest-port,omitempty"`
	DestAddr   string `json:"dest-addr,omitempty"`
}

type ConfigPortForward struct {
	LanInterface []string                          `json:"lan-interface,omitempty"`
	AutoFirewall string                            `json:"auto-firewall,omitempty"`
	Rule         *map[string]ConfigPortForwardRule `json:"rule,omitempty"`
	WanInterface string                            `json:"wan-interface,omitempty"`
	HairpinNat   string                            `json:"hairpin-nat,omitempty"`
}

type ConfigPortForwardRule struct {
	ForwardTo    *ConfigPortForwardRuleForwardTo `json:"forward-to,omitempty"`
	OriginalPort string                          `json:"original-port,omitempty"`
	Protocol     string                          `json:"protocol,omitempty"`
	Description  string                          `json:"description,omitempty"`
}

type ConfigPortForwardRuleForwardTo struct {
	Address IPv4   `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigVpn struct {
	RsaKeys *ConfigVpnRsaKeys `json:"rsa-keys,omitempty"`
	Ipsec   *ConfigVpnIpsec   `json:"ipsec,omitempty"`
	Pptp    *ConfigVpnPptp    `json:"pptp,omitempty"`
	L2tp    *ConfigVpnL2tp    `json:"l2tp,omitempty"`
}

type ConfigVpnRsaKeys struct {
	LocalKey   *ConfigVpnRsaKeysLocalKey              `json:"local-key,omitempty"`
	RsaKeyName *map[string]ConfigVpnRsaKeysRsaKeyName `json:"rsa-key-name,omitempty"`
}

type ConfigVpnRsaKeysLocalKey struct {
	File string `json:"file,omitempty"`
}

type ConfigVpnRsaKeysRsaKeyName struct {
	RsaKey string `json:"rsa-key,omitempty"`
}

type ConfigVpnIpsec struct {
	AutoUpdate                  EdgeOSInt                          `json:"auto-update,omitempty"`
	NatNetworks                 *ConfigVpnIpsecNatNetworks         `json:"nat-networks,omitempty"`
	AllowAccessToLocalInterface string                             `json:"allow-access-to-local-interface,omitempty"`
	AutoFirewallNatExclude      string                             `json:"auto-firewall-nat-exclude,omitempty"`
	DisableUniqreqids           string                             `json:"disable-uniqreqids,omitempty"`
	SiteToSite                  *ConfigVpnIpsecSiteToSite          `json:"site-to-site,omitempty"`
	RemoteAccess                *ConfigVpnIpsecRemoteAccess        `json:"remote-access,omitempty"`
	IpsecInterfaces             *ConfigVpnIpsecIpsecInterfaces     `json:"ipsec-interfaces,omitempty"`
	GlobalConfig                []string                           `json:"global-config,omitempty"`
	IkeGroup                    *map[string]ConfigVpnIpsecIkeGroup `json:"ike-group,omitempty"`
	EspGroup                    *map[string]ConfigVpnIpsecEspGroup `json:"esp-group,omitempty"`
	IncludeIpsecSecrets         string                             `json:"include-ipsec-secrets,omitempty"`
	IncludeIpsecConf            string                             `json:"include-ipsec-conf,omitempty"`
	Logging                     *ConfigVpnIpsecLogging             `json:"logging,omitempty"`
	NatTraversal                string                             `json:"nat-traversal,omitempty"`
}

type ConfigVpnIpsecNatNetworks struct {
	AllowedNetwork *map[string]ConfigVpnIpsecNatNetworksAllowedNetwork `json:"allowed-network,omitempty"`
}

type ConfigVpnIpsecNatNetworksAllowedNetwork struct {
	Exclude []string `json:"exclude,omitempty"`
}

type ConfigVpnIpsecSiteToSite struct {
	Peer *map[string]ConfigVpnIpsecSiteToSitePeer `json:"peer,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeer struct {
	DefaultEspGroup    string                                         `json:"default-esp-group,omitempty"`
	ForceEncapsulation string                                         `json:"force-encapsulation,omitempty"`
	Vti                *ConfigVpnIpsecSiteToSitePeerVti               `json:"vti,omitempty"`
	ConnectionType     string                                         `json:"connection-type,omitempty"`
	Ikev2Reauth        string                                         `json:"ikev2-reauth,omitempty"`
	Tunnel             *map[string]ConfigVpnIpsecSiteToSitePeerTunnel `json:"tunnel,omitempty"`
	Description        string                                         `json:"description,omitempty"`
	LocalAddress       string                                         `json:"local-address,omitempty"`
	IkeGroup           string                                         `json:"ike-group,omitempty"`
	Authentication     *ConfigVpnIpsecSiteToSitePeerAuthentication    `json:"authentication,omitempty"`
	DhcpInterface      string                                         `json:"dhcp-interface,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerVti struct {
	EspGroup string `json:"esp-group,omitempty"`
	Bind     string `json:"bind,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerTunnel struct {
	Disable             string                                    `json:"disable,omitempty"`
	AllowPublicNetworks string                                    `json:"allow-public-networks,omitempty"`
	Protocol            string                                    `json:"protocol,omitempty"`
	Local               *ConfigVpnIpsecSiteToSitePeerTunnelLocal  `json:"local,omitempty"`
	EspGroup            string                                    `json:"esp-group,omitempty"`
	AllowNatNetworks    string                                    `json:"allow-nat-networks,omitempty"`
	Remote              *ConfigVpnIpsecSiteToSitePeerTunnelRemote `json:"remote,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerTunnelLocal struct {
	Prefix string `json:"prefix,omitempty"`
	Port   string `json:"port,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerTunnelRemote struct {
	Prefix string `json:"prefix,omitempty"`
	Port   string `json:"port,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerAuthentication struct {
	Mode            string                                          `json:"mode,omitempty"`
	X509            *ConfigVpnIpsecSiteToSitePeerAuthenticationX509 `json:"x509,omitempty"`
	PreSharedSecret string                                          `json:"pre-shared-secret,omitempty"`
	Id              string                                          `json:"id,omitempty"`
	RemoteId        string                                          `json:"remote-id,omitempty"`
	RsaKeyName      string                                          `json:"rsa-key-name,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerAuthenticationX509 struct {
	CrlFile    string                                             `json:"crl-file,omitempty"`
	Key        *ConfigVpnIpsecSiteToSitePeerAuthenticationX509Key `json:"key,omitempty"`
	CaCertFile string                                             `json:"ca-cert-file,omitempty"`
	CertFile   string                                             `json:"cert-file,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerAuthenticationX509Key struct {
	Password string `json:"password,omitempty"`
	File     string `json:"file,omitempty"`
}

type ConfigVpnIpsecRemoteAccess struct {
	OutsideAddress    string                                    `json:"outside-address,omitempty"`
	WinsServers       *ConfigVpnIpsecRemoteAccessWinsServers    `json:"wins-servers,omitempty"`
	UpdownScript      string                                    `json:"updown-script,omitempty"`
	Inactivity        string                                    `json:"inactivity,omitempty"`
	DnsServers        *ConfigVpnIpsecRemoteAccessDnsServers     `json:"dns-servers,omitempty"`
	IkeSettings       *ConfigVpnIpsecRemoteAccessIkeSettings    `json:"ike-settings,omitempty"`
	ClientIpPool      *ConfigVpnIpsecRemoteAccessClientIpPool   `json:"client-ip-pool,omitempty"`
	Description       string                                    `json:"description,omitempty"`
	LocalIp           string                                    `json:"local-ip,omitempty"`
	CompatibilityMode string                                    `json:"compatibility-mode,omitempty"`
	EspSettings       *ConfigVpnIpsecRemoteAccessEspSettings    `json:"esp-settings,omitempty"`
	Authentication    *ConfigVpnIpsecRemoteAccessAuthentication `json:"authentication,omitempty"`
	DhcpInterface     string                                    `json:"dhcp-interface,omitempty"`
}

type ConfigVpnIpsecRemoteAccessWinsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigVpnIpsecRemoteAccessDnsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigVpnIpsecRemoteAccessIkeSettings struct {
	Proposal       *map[string]ConfigVpnIpsecRemoteAccessIkeSettingsProposal `json:"proposal,omitempty"`
	EspGroup       string                                                    `json:"esp-group,omitempty"`
	IkeLifetime    string                                                    `json:"ike-lifetime,omitempty"`
	Authentication *ConfigVpnIpsecRemoteAccessIkeSettingsAuthentication      `json:"authentication,omitempty"`
	OperatingMode  string                                                    `json:"operating-mode,omitempty"`
	Fragmentation  string                                                    `json:"fragmentation,omitempty"`
}

type ConfigVpnIpsecRemoteAccessIkeSettingsProposal struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DhGroup    string `json:"dh-group,omitempty"`
}

type ConfigVpnIpsecRemoteAccessIkeSettingsAuthentication struct {
	Mode            string                                                   `json:"mode,omitempty"`
	X509            *ConfigVpnIpsecRemoteAccessIkeSettingsAuthenticationX509 `json:"x509,omitempty"`
	PreSharedSecret string                                                   `json:"pre-shared-secret,omitempty"`
}

type ConfigVpnIpsecRemoteAccessIkeSettingsAuthenticationX509 struct {
	ServerKeyFile     string `json:"server-key-file,omitempty"`
	CrlFile           string `json:"crl-file,omitempty"`
	ServerKeyPassword string `json:"server-key-password,omitempty"`
	RemoteCaCertFile  string `json:"remote-ca-cert-file,omitempty"`
	ServerCertFile    string `json:"server-cert-file,omitempty"`
	ServerKeyType     string `json:"server-key-type,omitempty"`
	RemoteId          string `json:"remote-id,omitempty"`
	LocalId           string `json:"local-id,omitempty"`
	CaCertFile        string `json:"ca-cert-file,omitempty"`
}

type ConfigVpnIpsecRemoteAccessClientIpPool struct {
	Subnet  string `json:"subnet,omitempty"`
	Subnet6 string `json:"subnet6,omitempty"`
}

type ConfigVpnIpsecRemoteAccessEspSettings struct {
	Proposal *map[string]ConfigVpnIpsecRemoteAccessEspSettingsProposal `json:"proposal,omitempty"`
}

type ConfigVpnIpsecRemoteAccessEspSettingsProposal struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DhGroup    string `json:"dh-group,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthentication struct {
	Mode         string                                                           `json:"mode,omitempty"`
	LocalUsers   *ConfigVpnIpsecRemoteAccessAuthenticationLocalUsers              `json:"local-users,omitempty"`
	RadiusServer *map[string]ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthenticationLocalUsers struct {
	Username *map[string]ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername struct {
	Disable  string `json:"disable,omitempty"`
	Password string `json:"password,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer struct {
	Key string `json:"key,omitempty"`
}

type ConfigVpnIpsecIpsecInterfaces struct {
	Interface []string `json:"interface,omitempty"`
}

type ConfigVpnIpsecIkeGroup struct {
	Mode              string                                     `json:"mode,omitempty"`
	DeadPeerDetection *ConfigVpnIpsecIkeGroupDeadPeerDetection   `json:"dead-peer-detection,omitempty"`
	KeyExchange       string                                     `json:"key-exchange,omitempty"`
	Ikev2Reauth       string                                     `json:"ikev2-reauth,omitempty"`
	Lifetime          string                                     `json:"lifetime,omitempty"`
	Proposal          *map[string]ConfigVpnIpsecIkeGroupProposal `json:"proposal,omitempty"`
}

type ConfigVpnIpsecIkeGroupDeadPeerDetection struct {
	Interval string `json:"interval,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Action   string `json:"action,omitempty"`
}

type ConfigVpnIpsecIkeGroupProposal struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DhGroup    string `json:"dh-group,omitempty"`
}

type ConfigVpnIpsecEspGroup struct {
	Mode        string                                     `json:"mode,omitempty"`
	Pfs         string                                     `json:"pfs,omitempty"`
	Lifetime    string                                     `json:"lifetime,omitempty"`
	Proposal    *map[string]ConfigVpnIpsecEspGroupProposal `json:"proposal,omitempty"`
	Compression string                                     `json:"compression,omitempty"`
}

type ConfigVpnIpsecEspGroupProposal struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
}

type ConfigVpnIpsecLogging struct {
	LogModes []string `json:"log-modes,omitempty"`
	LogLevel string   `json:"log-level,omitempty"`
}

type ConfigVpnPptp struct {
	RemoteAccess *ConfigVpnPptpRemoteAccess `json:"remote-access,omitempty"`
}

type ConfigVpnPptpRemoteAccess struct {
	Accounting     *ConfigVpnPptpRemoteAccessAccounting     `json:"accounting,omitempty"`
	OutsideAddress string                                   `json:"outside-address,omitempty"`
	WinsServers    *ConfigVpnPptpRemoteAccessWinsServers    `json:"wins-servers,omitempty"`
	DnsServers     *ConfigVpnPptpRemoteAccessDnsServers     `json:"dns-servers,omitempty"`
	Mtu            EdgeOSInt                                `json:"mtu,omitempty"`
	ClientIpPool   *ConfigVpnPptpRemoteAccessClientIpPool   `json:"client-ip-pool,omitempty"`
	LocalIp        string                                   `json:"local-ip,omitempty"`
	Authentication *ConfigVpnPptpRemoteAccessAuthentication `json:"authentication,omitempty"`
	DhcpInterface  string                                   `json:"dhcp-interface,omitempty"`
}

type ConfigVpnPptpRemoteAccessAccounting struct {
	RadiusServer *map[string]ConfigVpnPptpRemoteAccessAccountingRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnPptpRemoteAccessAccountingRadiusServer struct {
	Key  string    `json:"key,omitempty"`
	Port EdgeOSInt `json:"port,omitempty"`
}

type ConfigVpnPptpRemoteAccessWinsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigVpnPptpRemoteAccessDnsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigVpnPptpRemoteAccessClientIpPool struct {
	Start string `json:"start,omitempty"`
	Stop  string `json:"stop,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthentication struct {
	Mode         string                                                          `json:"mode,omitempty"`
	LocalUsers   *ConfigVpnPptpRemoteAccessAuthenticationLocalUsers              `json:"local-users,omitempty"`
	RadiusServer *map[string]ConfigVpnPptpRemoteAccessAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthenticationLocalUsers struct {
	Username *map[string]ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername struct {
	Disable  string `json:"disable,omitempty"`
	Password string `json:"password,omitempty"`
	StaticIp IPv4   `json:"static-ip,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthenticationRadiusServer struct {
	Key  string    `json:"key,omitempty"`
	Port EdgeOSInt `json:"port,omitempty"`
}

type ConfigVpnL2tp struct {
	RemoteAccess *ConfigVpnL2tpRemoteAccess `json:"remote-access,omitempty"`
}

type ConfigVpnL2tpRemoteAccess struct {
	OutsideNexthop                  string                                   `json:"outside-nexthop,omitempty"`
	Accounting                      *ConfigVpnL2tpRemoteAccessAccounting     `json:"accounting,omitempty"`
	OutsideAddress                  string                                   `json:"outside-address,omitempty"`
	Idle                            string                                   `json:"idle,omitempty"`
	WinsServers                     *ConfigVpnL2tpRemoteAccessWinsServers    `json:"wins-servers,omitempty"`
	DnsServers                      *ConfigVpnL2tpRemoteAccessDnsServers     `json:"dns-servers,omitempty"`
	Mtu                             EdgeOSInt                                `json:"mtu,omitempty"`
	ClientIpPool                    *ConfigVpnL2tpRemoteAccessClientIpPool   `json:"client-ip-pool,omitempty"`
	IpsecSettings                   *ConfigVpnL2tpRemoteAccessIpsecSettings  `json:"ipsec-settings,omitempty"`
	Description                     string                                   `json:"description,omitempty"`
	AllowMultipleClientsFromSameNat string                                   `json:"allow-multiple-clients-from-same-nat,omitempty"`
	LocalIp                         string                                   `json:"local-ip,omitempty"`
	Authentication                  *ConfigVpnL2tpRemoteAccessAuthentication `json:"authentication,omitempty"`
	DhcpInterface                   string                                   `json:"dhcp-interface,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAccounting struct {
	RadiusServer *map[string]ConfigVpnL2tpRemoteAccessAccountingRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAccountingRadiusServer struct {
	Key  string    `json:"key,omitempty"`
	Port EdgeOSInt `json:"port,omitempty"`
}

type ConfigVpnL2tpRemoteAccessWinsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigVpnL2tpRemoteAccessDnsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigVpnL2tpRemoteAccessClientIpPool struct {
	Start string `json:"start,omitempty"`
	Stop  string `json:"stop,omitempty"`
}

type ConfigVpnL2tpRemoteAccessIpsecSettings struct {
	Lifetime       string                                                `json:"lifetime,omitempty"`
	IkeLifetime    string                                                `json:"ike-lifetime,omitempty"`
	Authentication *ConfigVpnL2tpRemoteAccessIpsecSettingsAuthentication `json:"authentication,omitempty"`
	Fragmentation  string                                                `json:"fragmentation,omitempty"`
}

type ConfigVpnL2tpRemoteAccessIpsecSettingsAuthentication struct {
	Mode            string                                                    `json:"mode,omitempty"`
	X509            *ConfigVpnL2tpRemoteAccessIpsecSettingsAuthenticationX509 `json:"x509,omitempty"`
	PreSharedSecret string                                                    `json:"pre-shared-secret,omitempty"`
}

type ConfigVpnL2tpRemoteAccessIpsecSettingsAuthenticationX509 struct {
	ServerKeyFile     string `json:"server-key-file,omitempty"`
	CrlFile           string `json:"crl-file,omitempty"`
	ServerKeyPassword string `json:"server-key-password,omitempty"`
	ServerCertFile    string `json:"server-cert-file,omitempty"`
	CaCertFile        string `json:"ca-cert-file,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthentication struct {
	Mode         string                                                          `json:"mode,omitempty"`
	Require      string                                                          `json:"require,omitempty"`
	LocalUsers   *ConfigVpnL2tpRemoteAccessAuthenticationLocalUsers              `json:"local-users,omitempty"`
	RadiusServer *map[string]ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthenticationLocalUsers struct {
	Username *map[string]ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername struct {
	Disable  string `json:"disable,omitempty"`
	Password string `json:"password,omitempty"`
	StaticIp IPv4   `json:"static-ip,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer struct {
	Key  string    `json:"key,omitempty"`
	Port EdgeOSInt `json:"port,omitempty"`
}

type ConfigTrafficPolicy struct {
	NetworkEmulator *map[string]ConfigTrafficPolicyNetworkEmulator `json:"network-emulator,omitempty"`
	DropTail        *map[string]ConfigTrafficPolicyDropTail        `json:"drop-tail,omitempty"`
	RoundRobin      *map[string]ConfigTrafficPolicyRoundRobin      `json:"round-robin,omitempty"`
	Limiter         *map[string]ConfigTrafficPolicyLimiter         `json:"limiter,omitempty"`
	FairQueue       *map[string]ConfigTrafficPolicyFairQueue       `json:"fair-queue,omitempty"`
	RateControl     *map[string]ConfigTrafficPolicyRateControl     `json:"rate-control,omitempty"`
	Shaper          *map[string]ConfigTrafficPolicyShaper          `json:"shaper,omitempty"`
	PriorityQueue   *map[string]ConfigTrafficPolicyPriorityQueue   `json:"priority-queue,omitempty"`
	RandomDetect    *map[string]ConfigTrafficPolicyRandomDetect    `json:"random-detect,omitempty"`
}

type ConfigTrafficPolicyNetworkEmulator struct {
	PacketCorruption string    `json:"packet-corruption,omitempty"`
	Bandwidth        string    `json:"bandwidth,omitempty"`
	Burst            string    `json:"burst,omitempty"`
	Description      string    `json:"description,omitempty"`
	QueueLimit       EdgeOSInt `json:"queue-limit,omitempty"`
	NetworkDelay     string    `json:"network-delay,omitempty"`
	PacketReordering string    `json:"packet-reordering,omitempty"`
	PacketLoss       string    `json:"packet-loss,omitempty"`
}

type ConfigTrafficPolicyDropTail struct {
	Description string    `json:"description,omitempty"`
	QueueLimit  EdgeOSInt `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyRoundRobin struct {
	Default     *ConfigTrafficPolicyRoundRobinDefault          `json:"default,omitempty"`
	Description string                                         `json:"description,omitempty"`
	Class       *map[string]ConfigTrafficPolicyRoundRobinClass `json:"class,omitempty"`
}

type ConfigTrafficPolicyRoundRobinDefault struct {
	QueueType  string    `json:"queue-type,omitempty"`
	QueueLimit EdgeOSInt `json:"queue-limit,omitempty"`
	Quantum    EdgeOSInt `json:"quantum,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClass struct {
	Match       *map[string]ConfigTrafficPolicyRoundRobinClassMatch `json:"match,omitempty"`
	QueueType   string                                              `json:"queue-type,omitempty"`
	Description string                                              `json:"description,omitempty"`
	QueueLimit  EdgeOSInt                                           `json:"queue-limit,omitempty"`
	Quantum     EdgeOSInt                                           `json:"quantum,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatch struct {
	Interface   string                                        `json:"interface,omitempty"`
	Mark        EdgeOSInt                                     `json:"mark,omitempty"`
	Ether       *ConfigTrafficPolicyRoundRobinClassMatchEther `json:"ether,omitempty"`
	Description string                                        `json:"description,omitempty"`
	Vif         EdgeOSInt                                     `json:"vif,omitempty"`
	Ip          *ConfigTrafficPolicyRoundRobinClassMatchIp    `json:"ip,omitempty"`
	Ipv6        *ConfigTrafficPolicyRoundRobinClassMatchIpv6  `json:"ipv6,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchEther struct {
	Source      MacAddr `json:"source,omitempty"`
	Destination MacAddr `json:"destination,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchIp struct {
	Source      *ConfigTrafficPolicyRoundRobinClassMatchIpSource      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyRoundRobinClassMatchIpDestination `json:"destination,omitempty"`
	Protocol    string                                                `json:"protocol,omitempty"`
	Dscp        string                                                `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchIpSource struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchIpDestination struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchIpv6 struct {
	Source      *ConfigTrafficPolicyRoundRobinClassMatchIpv6Source      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyRoundRobinClassMatchIpv6Destination `json:"destination,omitempty"`
	Protocol    string                                                  `json:"protocol,omitempty"`
	Dscp        string                                                  `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchIpv6Source struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatchIpv6Destination struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyLimiter struct {
	Default     *ConfigTrafficPolicyLimiterDefault          `json:"default,omitempty"`
	Description string                                      `json:"description,omitempty"`
	Class       *map[string]ConfigTrafficPolicyLimiterClass `json:"class,omitempty"`
}

type ConfigTrafficPolicyLimiterDefault struct {
	Bandwidth string `json:"bandwidth,omitempty"`
	Burst     string `json:"burst,omitempty"`
}

type ConfigTrafficPolicyLimiterClass struct {
	Bandwidth   string                                           `json:"bandwidth,omitempty"`
	Match       *map[string]ConfigTrafficPolicyLimiterClassMatch `json:"match,omitempty"`
	Burst       string                                           `json:"burst,omitempty"`
	Description string                                           `json:"description,omitempty"`
	Priority    EdgeOSInt                                        `json:"priority,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatch struct {
	Ether       *ConfigTrafficPolicyLimiterClassMatchEther `json:"ether,omitempty"`
	Description string                                     `json:"description,omitempty"`
	Vif         EdgeOSInt                                  `json:"vif,omitempty"`
	Ip          *ConfigTrafficPolicyLimiterClassMatchIp    `json:"ip,omitempty"`
	Ipv6        *ConfigTrafficPolicyLimiterClassMatchIpv6  `json:"ipv6,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchEther struct {
	Source      MacAddr `json:"source,omitempty"`
	Destination MacAddr `json:"destination,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchIp struct {
	Source      *ConfigTrafficPolicyLimiterClassMatchIpSource      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyLimiterClassMatchIpDestination `json:"destination,omitempty"`
	Protocol    string                                             `json:"protocol,omitempty"`
	Dscp        string                                             `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchIpSource struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchIpDestination struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchIpv6 struct {
	Source      *ConfigTrafficPolicyLimiterClassMatchIpv6Source      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyLimiterClassMatchIpv6Destination `json:"destination,omitempty"`
	Protocol    string                                               `json:"protocol,omitempty"`
	Dscp        string                                               `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchIpv6Source struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatchIpv6Destination struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyFairQueue struct {
	HashInterval EdgeOSInt `json:"hash-interval,omitempty"`
	Description  string    `json:"description,omitempty"`
	QueueLimit   EdgeOSInt `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyRateControl struct {
	Bandwidth   string `json:"bandwidth,omitempty"`
	Burst       string `json:"burst,omitempty"`
	Latency     string `json:"latency,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigTrafficPolicyShaper struct {
	Bandwidth   string                                     `json:"bandwidth,omitempty"`
	Default     *ConfigTrafficPolicyShaperDefault          `json:"default,omitempty"`
	Description string                                     `json:"description,omitempty"`
	Class       *map[string]ConfigTrafficPolicyShaperClass `json:"class,omitempty"`
}

type ConfigTrafficPolicyShaperDefault struct {
	Bandwidth  string    `json:"bandwidth,omitempty"`
	Burst      string    `json:"burst,omitempty"`
	Ceiling    string    `json:"ceiling,omitempty"`
	QueueType  string    `json:"queue-type,omitempty"`
	Priority   EdgeOSInt `json:"priority,omitempty"`
	QueueLimit EdgeOSInt `json:"queue-limit,omitempty"`
	SetDscp    string    `json:".set-dscp,omitempty"`
}

type ConfigTrafficPolicyShaperClass struct {
	Bandwidth   string                                          `json:"bandwidth,omitempty"`
	Match       *map[string]ConfigTrafficPolicyShaperClassMatch `json:"match,omitempty"`
	Burst       string                                          `json:"burst,omitempty"`
	Ceiling     string                                          `json:"ceiling,omitempty"`
	QueueType   string                                          `json:"queue-type,omitempty"`
	Description string                                          `json:"description,omitempty"`
	Priority    EdgeOSInt                                       `json:"priority,omitempty"`
	QueueLimit  EdgeOSInt                                       `json:"queue-limit,omitempty"`
	SetDscp     string                                          `json:".set-dscp,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatch struct {
	Interface   string                                    `json:"interface,omitempty"`
	Mark        string                                    `json:"mark,omitempty"`
	Ether       *ConfigTrafficPolicyShaperClassMatchEther `json:"ether,omitempty"`
	Description string                                    `json:"description,omitempty"`
	Vif         EdgeOSInt                                 `json:"vif,omitempty"`
	Ip          *ConfigTrafficPolicyShaperClassMatchIp    `json:"ip,omitempty"`
	Ipv6        *ConfigTrafficPolicyShaperClassMatchIpv6  `json:"ipv6,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchEther struct {
	Source      MacAddr `json:"source,omitempty"`
	Destination MacAddr `json:"destination,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchIp struct {
	Source      *ConfigTrafficPolicyShaperClassMatchIpSource      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyShaperClassMatchIpDestination `json:"destination,omitempty"`
	Protocol    string                                            `json:"protocol,omitempty"`
	Dscp        string                                            `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchIpSource struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchIpDestination struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchIpv6 struct {
	Source      *ConfigTrafficPolicyShaperClassMatchIpv6Source      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyShaperClassMatchIpv6Destination `json:"destination,omitempty"`
	Protocol    string                                              `json:"protocol,omitempty"`
	Dscp        string                                              `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchIpv6Source struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatchIpv6Destination struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyPriorityQueue struct {
	Default     *ConfigTrafficPolicyPriorityQueueDefault          `json:"default,omitempty"`
	Description string                                            `json:"description,omitempty"`
	Class       *map[string]ConfigTrafficPolicyPriorityQueueClass `json:"class,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueDefault struct {
	QueueType  string    `json:"queue-type,omitempty"`
	QueueLimit EdgeOSInt `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClass struct {
	Match       *map[string]ConfigTrafficPolicyPriorityQueueClassMatch `json:"match,omitempty"`
	QueueType   string                                                 `json:"queue-type,omitempty"`
	Description string                                                 `json:"description,omitempty"`
	QueueLimit  EdgeOSInt                                              `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatch struct {
	Interface   string                                           `json:"interface,omitempty"`
	Mark        EdgeOSInt                                        `json:"mark,omitempty"`
	Ether       *ConfigTrafficPolicyPriorityQueueClassMatchEther `json:"ether,omitempty"`
	Description string                                           `json:"description,omitempty"`
	Vif         EdgeOSInt                                        `json:"vif,omitempty"`
	Ip          *ConfigTrafficPolicyPriorityQueueClassMatchIp    `json:"ip,omitempty"`
	Ipv6        *ConfigTrafficPolicyPriorityQueueClassMatchIpv6  `json:"ipv6,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchEther struct {
	Source      MacAddr `json:"source,omitempty"`
	Destination MacAddr `json:"destination,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchIp struct {
	Source      *ConfigTrafficPolicyPriorityQueueClassMatchIpSource      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyPriorityQueueClassMatchIpDestination `json:"destination,omitempty"`
	Protocol    string                                                   `json:"protocol,omitempty"`
	Dscp        string                                                   `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchIpSource struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchIpDestination struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchIpv6 struct {
	Source      *ConfigTrafficPolicyPriorityQueueClassMatchIpv6Source      `json:"source,omitempty"`
	Destination *ConfigTrafficPolicyPriorityQueueClassMatchIpv6Destination `json:"destination,omitempty"`
	Protocol    string                                                     `json:"protocol,omitempty"`
	Dscp        string                                                     `json:"dscp,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchIpv6Source struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatchIpv6Destination struct {
	Address IPv6Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficPolicyRandomDetect struct {
	Bandwidth   string                                                `json:"bandwidth,omitempty"`
	Description string                                                `json:"description,omitempty"`
	Precedence  *map[string]ConfigTrafficPolicyRandomDetectPrecedence `json:"precedence,omitempty"`
}

type ConfigTrafficPolicyRandomDetectPrecedence struct {
	MarkProbability  EdgeOSInt `json:"mark-probability,omitempty"`
	MinimumThreshold EdgeOSInt `json:"minimum-threshold,omitempty"`
	AveragePacket    EdgeOSInt `json:"average-packet,omitempty"`
	QueueLimit       EdgeOSInt `json:"queue-limit,omitempty"`
	MaximumThreshold EdgeOSInt `json:"maximum-threshold,omitempty"`
}

type ConfigFirewall struct {
	Options              *ConfigFirewallOptions               `json:"options,omitempty"`
	IpSrcRoute           string                               `json:"ip-src-route,omitempty"`
	SendRedirects        string                               `json:"send-redirects,omitempty"`
	Group                *ConfigFirewallGroup                 `json:"group,omitempty"`
	Ipv6ReceiveRedirects string                               `json:"ipv6-receive-redirects,omitempty"`
	AllPing              string                               `json:"all-ping,omitempty"`
	SynCookies           string                               `json:"syn-cookies,omitempty"`
	Modify               *map[string]ConfigFirewallModify     `json:"modify,omitempty"`
	BroadcastPing        string                               `json:"broadcast-ping,omitempty"`
	LogMartians          string                               `json:"log-martians,omitempty"`
	Ipv6Modify           *map[string]ConfigFirewallIpv6Modify `json:"ipv6-modify,omitempty"`
	SourceValidation     string                               `json:"source-validation,omitempty"`
	Name                 *map[string]ConfigFirewallName       `json:"name,omitempty"`
	Ipv6SrcRoute         string                               `json:"ipv6-src-route,omitempty"`
	ReceiveRedirects     string                               `json:"receive-redirects,omitempty"`
	Ipv6Name             *map[string]ConfigFirewallIpv6Name   `json:"ipv6-name,omitempty"`
}

type ConfigFirewallOptions struct {
	MssClamp  *ConfigFirewallOptionsMssClamp  `json:"mss-clamp,omitempty"`
	MssClamp6 *ConfigFirewallOptionsMssClamp6 `json:"mss-clamp6,omitempty"`
}

type ConfigFirewallOptionsMssClamp struct {
	Mss           EdgeOSInt `json:"mss,omitempty"`
	InterfaceType []string  `json:"interface-type,omitempty"`
}

type ConfigFirewallOptionsMssClamp6 struct {
	Mss           EdgeOSInt `json:"mss,omitempty"`
	InterfaceType []string  `json:"interface-type,omitempty"`
}

type ConfigFirewallGroup struct {
	AddressGroup     *map[string]ConfigFirewallGroupAddressGroup     `json:"address-group,omitempty"`
	PortGroup        *map[string]ConfigFirewallGroupPortGroup        `json:"port-group,omitempty"`
	NetworkGroup     *map[string]ConfigFirewallGroupNetworkGroup     `json:"network-group,omitempty"`
	Ipv6AddressGroup *map[string]ConfigFirewallGroupIpv6AddressGroup `json:"ipv6-address-group,omitempty"`
	Ipv6NetworkGroup *map[string]ConfigFirewallGroupIpv6NetworkGroup `json:"ipv6-network-group,omitempty"`
}

type ConfigFirewallGroupAddressGroup struct {
	Description string   `json:"description,omitempty"`
	Address     []string `json:"address,omitempty"`
}

type ConfigFirewallGroupPortGroup struct {
	Description string   `json:"description,omitempty"`
	Port        []string `json:"port,omitempty"`
}

type ConfigFirewallGroupNetworkGroup struct {
	Network     []string `json:"network,omitempty"`
	Description string   `json:"description,omitempty"`
}

type ConfigFirewallGroupIpv6AddressGroup struct {
	Ipv6Address []string `json:"ipv6-address,omitempty"`
	Description string   `json:"description,omitempty"`
}

type ConfigFirewallGroupIpv6NetworkGroup struct {
	Description string   `json:"description,omitempty"`
	Ipv6Network []string `json:"ipv6-network,omitempty"`
}

type ConfigFirewallModify struct {
	Rule             *map[string]ConfigFirewallModifyRule `json:"rule,omitempty"`
	Description      string                               `json:"description,omitempty"`
	EnableDefaultLog string                               `json:"enable-default-log,omitempty"`
}

type ConfigFirewallModifyRule struct {
	Disable     string                               `json:"disable,omitempty"`
	Limit       *ConfigFirewallModifyRuleLimit       `json:"limit,omitempty"`
	Source      *ConfigFirewallModifyRuleSource      `json:"source,omitempty"`
	Mark        string                               `json:"mark,omitempty"`
	Modify      *ConfigFirewallModifyRuleModify      `json:"modify,omitempty"`
	Destination *ConfigFirewallModifyRuleDestination `json:"destination,omitempty"`
	Protocol    string                               `json:"protocol,omitempty"`
	State       *ConfigFirewallModifyRuleState       `json:"state,omitempty"`
	Time        *ConfigFirewallModifyRuleTime        `json:"time,omitempty"`
	Ipsec       *ConfigFirewallModifyRuleIpsec       `json:"ipsec,omitempty"`
	Action      string                               `json:"action,omitempty"`
	Description string                               `json:"description,omitempty"`
	Tcp         *ConfigFirewallModifyRuleTcp         `json:"tcp,omitempty"`
	Fragment    *ConfigFirewallModifyRuleFragment    `json:"fragment,omitempty"`
	Icmp        *ConfigFirewallModifyRuleIcmp        `json:"icmp,omitempty"`
	P2p         *ConfigFirewallModifyRuleP2p         `json:"p2p,omitempty"`
	Connmark    string                               `json:"connmark,omitempty"`
	Log         string                               `json:"log,omitempty"`
	Application *ConfigFirewallModifyRuleApplication `json:"application,omitempty"`
	Dscp        EdgeOSInt                            `json:"dscp,omitempty"`
	Statistic   *ConfigFirewallModifyRuleStatistic   `json:"statistic,omitempty"`
	Recent      *ConfigFirewallModifyRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallModifyRuleLimit struct {
	Rate  string    `json:"rate,omitempty"`
	Burst EdgeOSInt `json:"burst,omitempty"`
}

type ConfigFirewallModifyRuleSource struct {
	Group      *ConfigFirewallModifyRuleSourceGroup `json:"group,omitempty"`
	MacAddress string                               `json:"mac-address,omitempty"`
	Address    string                               `json:"address,omitempty"`
	Port       string                               `json:"port,omitempty"`
}

type ConfigFirewallModifyRuleSourceGroup struct {
	AddressGroup string `json:"address-group,omitempty"`
	PortGroup    string `json:"port-group,omitempty"`
	NetworkGroup string `json:"network-group,omitempty"`
}

type ConfigFirewallModifyRuleModify struct {
	TcpMss   string                                  `json:"tcp-mss,omitempty"`
	Mark     string                                  `json:"mark,omitempty"`
	Table    string                                  `json:"table,omitempty"`
	Connmark *ConfigFirewallModifyRuleModifyConnmark `json:"connmark,omitempty"`
	Dscp     EdgeOSInt                               `json:"dscp,omitempty"`
	LbGroup  string                                  `json:"lb-group,omitempty"`
}

type ConfigFirewallModifyRuleModifyConnmark struct {
	SaveMark    string    `json:"save-mark,omitempty"`
	RestoreMark string    `json:"restore-mark,omitempty"`
	SetMark     EdgeOSInt `json:"set-mark,omitempty"`
}

type ConfigFirewallModifyRuleDestination struct {
	Group   *ConfigFirewallModifyRuleDestinationGroup `json:"group,omitempty"`
	Address string                                    `json:"address,omitempty"`
	Port    string                                    `json:"port,omitempty"`
}

type ConfigFirewallModifyRuleDestinationGroup struct {
	AddressGroup string `json:"address-group,omitempty"`
	PortGroup    string `json:"port-group,omitempty"`
	NetworkGroup string `json:"network-group,omitempty"`
}

type ConfigFirewallModifyRuleState struct {
	Related     string `json:"related,omitempty"`
	Invalid     string `json:"invalid,omitempty"`
	Established string `json:"established,omitempty"`
	New         string `json:"new,omitempty"`
}

type ConfigFirewallModifyRuleTime struct {
	Stopdate   string `json:"stopdate,omitempty"`
	Contiguous string `json:"contiguous,omitempty"`
	Starttime  string `json:"starttime,omitempty"`
	Stoptime   string `json:"stoptime,omitempty"`
	Weekdays   string `json:"weekdays,omitempty"`
	Utc        string `json:"utc,omitempty"`
	Startdate  string `json:"startdate,omitempty"`
	Monthdays  string `json:"monthdays,omitempty"`
}

type ConfigFirewallModifyRuleIpsec struct {
	MatchNone  string `json:"match-none,omitempty"`
	MatchIpsec string `json:"match-ipsec,omitempty"`
}

type ConfigFirewallModifyRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallModifyRuleFragment struct {
	MatchNonFrag string `json:"match-non-frag,omitempty"`
	MatchFrag    string `json:"match-frag,omitempty"`
}

type ConfigFirewallModifyRuleIcmp struct {
	Code     EdgeOSInt `json:"code,omitempty"`
	TypeName string    `json:"type-name,omitempty"`
	Type     EdgeOSInt `json:"type,omitempty"`
}

type ConfigFirewallModifyRuleP2p struct {
	Bittorrent    string `json:"bittorrent,omitempty"`
	Gnutella      string `json:"gnutella,omitempty"`
	All           string `json:"all,omitempty"`
	Applejuice    string `json:"applejuice,omitempty"`
	Edonkey       string `json:"edonkey,omitempty"`
	Kazaa         string `json:"kazaa,omitempty"`
	Directconnect string `json:"directconnect,omitempty"`
}

type ConfigFirewallModifyRuleApplication struct {
	Category       string `json:"category,omitempty"`
	CustomCategory string `json:"custom-category,omitempty"`
}

type ConfigFirewallModifyRuleStatistic struct {
	Probability string `json:"probability,omitempty"`
}

type ConfigFirewallModifyRuleRecent struct {
	Count EdgeOSInt `json:"count,omitempty"`
	Time  EdgeOSInt `json:"time,omitempty"`
}

type ConfigFirewallIpv6Modify struct {
	Rule             *map[string]ConfigFirewallIpv6ModifyRule `json:"rule,omitempty"`
	Description      string                                   `json:"description,omitempty"`
	EnableDefaultLog string                                   `json:"enable-default-log,omitempty"`
}

type ConfigFirewallIpv6ModifyRule struct {
	Disable     string                                   `json:"disable,omitempty"`
	Icmpv6      *ConfigFirewallIpv6ModifyRuleIcmpv6      `json:"icmpv6,omitempty"`
	Limit       *ConfigFirewallIpv6ModifyRuleLimit       `json:"limit,omitempty"`
	Source      *ConfigFirewallIpv6ModifyRuleSource      `json:"source,omitempty"`
	Mark        string                                   `json:"mark,omitempty"`
	Modify      *ConfigFirewallIpv6ModifyRuleModify      `json:"modify,omitempty"`
	Destination *ConfigFirewallIpv6ModifyRuleDestination `json:"destination,omitempty"`
	Protocol    string                                   `json:"protocol,omitempty"`
	State       *ConfigFirewallIpv6ModifyRuleState       `json:"state,omitempty"`
	Time        *ConfigFirewallIpv6ModifyRuleTime        `json:"time,omitempty"`
	Ipsec       *ConfigFirewallIpv6ModifyRuleIpsec       `json:"ipsec,omitempty"`
	Action      string                                   `json:"action,omitempty"`
	Description string                                   `json:"description,omitempty"`
	Tcp         *ConfigFirewallIpv6ModifyRuleTcp         `json:"tcp,omitempty"`
	P2p         *ConfigFirewallIpv6ModifyRuleP2p         `json:"p2p,omitempty"`
	Connmark    string                                   `json:"connmark,omitempty"`
	Log         string                                   `json:"log,omitempty"`
	Dscp        EdgeOSInt                                `json:"dscp,omitempty"`
	Recent      *ConfigFirewallIpv6ModifyRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleIcmpv6 struct {
	Type string `json:"type,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleLimit struct {
	Rate  string    `json:"rate,omitempty"`
	Burst EdgeOSInt `json:"burst,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleSource struct {
	Group      *ConfigFirewallIpv6ModifyRuleSourceGroup `json:"group,omitempty"`
	MacAddress string                                   `json:"mac-address,omitempty"`
	Address    string                                   `json:"address,omitempty"`
	Port       string                                   `json:"port,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleSourceGroup struct {
	PortGroup        string `json:"port-group,omitempty"`
	Ipv6AddressGroup string `json:"ipv6-address-group,omitempty"`
	Ipv6NetworkGroup string `json:"ipv6-network-group,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleModify struct {
	TcpMss   string                                      `json:"tcp-mss,omitempty"`
	Mark     string                                      `json:"mark,omitempty"`
	Table    string                                      `json:"table,omitempty"`
	Connmark *ConfigFirewallIpv6ModifyRuleModifyConnmark `json:"connmark,omitempty"`
	Dscp     EdgeOSInt                                   `json:"dscp,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleModifyConnmark struct {
	SaveMark    string    `json:"save-mark,omitempty"`
	RestoreMark string    `json:"restore-mark,omitempty"`
	SetMark     EdgeOSInt `json:"set-mark,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleDestination struct {
	Group   *ConfigFirewallIpv6ModifyRuleDestinationGroup `json:"group,omitempty"`
	Address string                                        `json:"address,omitempty"`
	Port    string                                        `json:"port,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleDestinationGroup struct {
	PortGroup        string `json:"port-group,omitempty"`
	Ipv6AddressGroup string `json:"ipv6-address-group,omitempty"`
	Ipv6NetworkGroup string `json:"ipv6-network-group,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleState struct {
	Related     string `json:"related,omitempty"`
	Invalid     string `json:"invalid,omitempty"`
	Established string `json:"established,omitempty"`
	New         string `json:"new,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleTime struct {
	Stopdate   string `json:"stopdate,omitempty"`
	Contiguous string `json:"contiguous,omitempty"`
	Starttime  string `json:"starttime,omitempty"`
	Stoptime   string `json:"stoptime,omitempty"`
	Weekdays   string `json:"weekdays,omitempty"`
	Utc        string `json:"utc,omitempty"`
	Startdate  string `json:"startdate,omitempty"`
	Monthdays  string `json:"monthdays,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleIpsec struct {
	MatchNone  string `json:"match-none,omitempty"`
	MatchIpsec string `json:"match-ipsec,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleP2p struct {
	Bittorrent    string `json:"bittorrent,omitempty"`
	Gnutella      string `json:"gnutella,omitempty"`
	All           string `json:"all,omitempty"`
	Applejuice    string `json:"applejuice,omitempty"`
	Edonkey       string `json:"edonkey,omitempty"`
	Kazaa         string `json:"kazaa,omitempty"`
	Directconnect string `json:"directconnect,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleRecent struct {
	Count EdgeOSInt `json:"count,omitempty"`
	Time  EdgeOSInt `json:"time,omitempty"`
}

type ConfigFirewallName struct {
	DefaultAction    string                             `json:"default-action,omitempty"`
	Rule             *map[string]ConfigFirewallNameRule `json:"rule,omitempty"`
	Description      string                             `json:"description,omitempty"`
	EnableDefaultLog string                             `json:"enable-default-log,omitempty"`
}

type ConfigFirewallNameRule struct {
	Disable     string                             `json:"disable,omitempty"`
	Limit       *ConfigFirewallNameRuleLimit       `json:"limit,omitempty"`
	Source      *ConfigFirewallNameRuleSource      `json:"source,omitempty"`
	Mark        string                             `json:"mark,omitempty"`
	Destination *ConfigFirewallNameRuleDestination `json:"destination,omitempty"`
	Protocol    string                             `json:"protocol,omitempty"`
	State       *ConfigFirewallNameRuleState       `json:"state,omitempty"`
	Time        *ConfigFirewallNameRuleTime        `json:"time,omitempty"`
	Ipsec       *ConfigFirewallNameRuleIpsec       `json:"ipsec,omitempty"`
	Action      string                             `json:"action,omitempty"`
	Description string                             `json:"description,omitempty"`
	Tcp         *ConfigFirewallNameRuleTcp         `json:"tcp,omitempty"`
	Fragment    *ConfigFirewallNameRuleFragment    `json:"fragment,omitempty"`
	Icmp        *ConfigFirewallNameRuleIcmp        `json:"icmp,omitempty"`
	P2p         *ConfigFirewallNameRuleP2p         `json:"p2p,omitempty"`
	Log         string                             `json:"log,omitempty"`
	Application *ConfigFirewallNameRuleApplication `json:"application,omitempty"`
	Dscp        EdgeOSInt                          `json:"dscp,omitempty"`
	Recent      *ConfigFirewallNameRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallNameRuleLimit struct {
	Rate  string    `json:"rate,omitempty"`
	Burst EdgeOSInt `json:"burst,omitempty"`
}

type ConfigFirewallNameRuleSource struct {
	Group      *ConfigFirewallNameRuleSourceGroup `json:"group,omitempty"`
	MacAddress string                             `json:"mac-address,omitempty"`
	Address    string                             `json:"address,omitempty"`
	Port       string                             `json:"port,omitempty"`
}

type ConfigFirewallNameRuleSourceGroup struct {
	AddressGroup string `json:"address-group,omitempty"`
	PortGroup    string `json:"port-group,omitempty"`
	NetworkGroup string `json:"network-group,omitempty"`
}

type ConfigFirewallNameRuleDestination struct {
	Group   *ConfigFirewallNameRuleDestinationGroup `json:"group,omitempty"`
	Address string                                  `json:"address,omitempty"`
	Port    string                                  `json:"port,omitempty"`
}

type ConfigFirewallNameRuleDestinationGroup struct {
	AddressGroup string `json:"address-group,omitempty"`
	PortGroup    string `json:"port-group,omitempty"`
	NetworkGroup string `json:"network-group,omitempty"`
}

type ConfigFirewallNameRuleState struct {
	Related     string `json:"related,omitempty"`
	Invalid     string `json:"invalid,omitempty"`
	Established string `json:"established,omitempty"`
	New         string `json:"new,omitempty"`
}

type ConfigFirewallNameRuleTime struct {
	Stopdate   string `json:"stopdate,omitempty"`
	Contiguous string `json:"contiguous,omitempty"`
	Starttime  string `json:"starttime,omitempty"`
	Stoptime   string `json:"stoptime,omitempty"`
	Weekdays   string `json:"weekdays,omitempty"`
	Utc        string `json:"utc,omitempty"`
	Startdate  string `json:"startdate,omitempty"`
	Monthdays  string `json:"monthdays,omitempty"`
}

type ConfigFirewallNameRuleIpsec struct {
	MatchNone  string `json:"match-none,omitempty"`
	MatchIpsec string `json:"match-ipsec,omitempty"`
}

type ConfigFirewallNameRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallNameRuleFragment struct {
	MatchNonFrag string `json:"match-non-frag,omitempty"`
	MatchFrag    string `json:"match-frag,omitempty"`
}

type ConfigFirewallNameRuleIcmp struct {
	Code     EdgeOSInt `json:"code,omitempty"`
	TypeName string    `json:"type-name,omitempty"`
	Type     EdgeOSInt `json:"type,omitempty"`
}

type ConfigFirewallNameRuleP2p struct {
	Bittorrent    string `json:"bittorrent,omitempty"`
	Gnutella      string `json:"gnutella,omitempty"`
	All           string `json:"all,omitempty"`
	Applejuice    string `json:"applejuice,omitempty"`
	Edonkey       string `json:"edonkey,omitempty"`
	Kazaa         string `json:"kazaa,omitempty"`
	Directconnect string `json:"directconnect,omitempty"`
}

type ConfigFirewallNameRuleApplication struct {
	Category       string `json:"category,omitempty"`
	CustomCategory string `json:"custom-category,omitempty"`
}

type ConfigFirewallNameRuleRecent struct {
	Count EdgeOSInt `json:"count,omitempty"`
	Time  EdgeOSInt `json:"time,omitempty"`
}

type ConfigFirewallIpv6Name struct {
	DefaultAction    string                                 `json:"default-action,omitempty"`
	Rule             *map[string]ConfigFirewallIpv6NameRule `json:"rule,omitempty"`
	Description      string                                 `json:"description,omitempty"`
	EnableDefaultLog string                                 `json:"enable-default-log,omitempty"`
}

type ConfigFirewallIpv6NameRule struct {
	Disable     string                                 `json:"disable,omitempty"`
	Icmpv6      *ConfigFirewallIpv6NameRuleIcmpv6      `json:"icmpv6,omitempty"`
	Limit       *ConfigFirewallIpv6NameRuleLimit       `json:"limit,omitempty"`
	Source      *ConfigFirewallIpv6NameRuleSource      `json:"source,omitempty"`
	Mark        string                                 `json:"mark,omitempty"`
	Destination *ConfigFirewallIpv6NameRuleDestination `json:"destination,omitempty"`
	Protocol    string                                 `json:"protocol,omitempty"`
	State       *ConfigFirewallIpv6NameRuleState       `json:"state,omitempty"`
	Time        *ConfigFirewallIpv6NameRuleTime        `json:"time,omitempty"`
	Ipsec       *ConfigFirewallIpv6NameRuleIpsec       `json:"ipsec,omitempty"`
	Action      string                                 `json:"action,omitempty"`
	Description string                                 `json:"description,omitempty"`
	Tcp         *ConfigFirewallIpv6NameRuleTcp         `json:"tcp,omitempty"`
	P2p         *ConfigFirewallIpv6NameRuleP2p         `json:"p2p,omitempty"`
	Log         string                                 `json:"log,omitempty"`
	Dscp        EdgeOSInt                              `json:"dscp,omitempty"`
	Recent      *ConfigFirewallIpv6NameRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallIpv6NameRuleIcmpv6 struct {
	Type string `json:"type,omitempty"`
}

type ConfigFirewallIpv6NameRuleLimit struct {
	Rate  string    `json:"rate,omitempty"`
	Burst EdgeOSInt `json:"burst,omitempty"`
}

type ConfigFirewallIpv6NameRuleSource struct {
	Group      *ConfigFirewallIpv6NameRuleSourceGroup `json:"group,omitempty"`
	MacAddress string                                 `json:"mac-address,omitempty"`
	Address    string                                 `json:"address,omitempty"`
	Port       string                                 `json:"port,omitempty"`
}

type ConfigFirewallIpv6NameRuleSourceGroup struct {
	PortGroup        string `json:"port-group,omitempty"`
	Ipv6AddressGroup string `json:"ipv6-address-group,omitempty"`
	Ipv6NetworkGroup string `json:"ipv6-network-group,omitempty"`
}

type ConfigFirewallIpv6NameRuleDestination struct {
	Group   *ConfigFirewallIpv6NameRuleDestinationGroup `json:"group,omitempty"`
	Address string                                      `json:"address,omitempty"`
	Port    string                                      `json:"port,omitempty"`
}

type ConfigFirewallIpv6NameRuleDestinationGroup struct {
	PortGroup        string `json:"port-group,omitempty"`
	Ipv6AddressGroup string `json:"ipv6-address-group,omitempty"`
	Ipv6NetworkGroup string `json:"ipv6-network-group,omitempty"`
}

type ConfigFirewallIpv6NameRuleState struct {
	Related     string `json:"related,omitempty"`
	Invalid     string `json:"invalid,omitempty"`
	Established string `json:"established,omitempty"`
	New         string `json:"new,omitempty"`
}

type ConfigFirewallIpv6NameRuleTime struct {
	Stopdate   string `json:"stopdate,omitempty"`
	Contiguous string `json:"contiguous,omitempty"`
	Starttime  string `json:"starttime,omitempty"`
	Stoptime   string `json:"stoptime,omitempty"`
	Weekdays   string `json:"weekdays,omitempty"`
	Utc        string `json:"utc,omitempty"`
	Startdate  string `json:"startdate,omitempty"`
	Monthdays  string `json:"monthdays,omitempty"`
}

type ConfigFirewallIpv6NameRuleIpsec struct {
	MatchNone  string `json:"match-none,omitempty"`
	MatchIpsec string `json:"match-ipsec,omitempty"`
}

type ConfigFirewallIpv6NameRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallIpv6NameRuleP2p struct {
	Bittorrent    string `json:"bittorrent,omitempty"`
	Gnutella      string `json:"gnutella,omitempty"`
	All           string `json:"all,omitempty"`
	Applejuice    string `json:"applejuice,omitempty"`
	Edonkey       string `json:"edonkey,omitempty"`
	Kazaa         string `json:"kazaa,omitempty"`
	Directconnect string `json:"directconnect,omitempty"`
}

type ConfigFirewallIpv6NameRuleRecent struct {
	Count EdgeOSInt `json:"count,omitempty"`
	Time  EdgeOSInt `json:"time,omitempty"`
}

type ConfigSystem struct {
	Options           *ConfigSystemOptions           `json:"options,omitempty"`
	Syslog            *ConfigSystemSyslog            `json:"syslog,omitempty"`
	FlowAccounting    *ConfigSystemFlowAccounting    `json:"flow-accounting,omitempty"`
	GatewayAddress    string                         `json:"gateway-address,omitempty"`
	TaskScheduler     *ConfigSystemTaskScheduler     `json:"task-scheduler,omitempty"`
	AnalyticsHandler  *ConfigSystemAnalyticsHandler  `json:"analytics-handler,omitempty"`
	TimeZone          string                         `json:"time-zone,omitempty"`
	Systemd           *ConfigSystemSystemd           `json:"systemd,omitempty"`
	Conntrack         *ConfigSystemConntrack         `json:"conntrack,omitempty"`
	NameServer        []string                       `json:"name-server,omitempty"`
	DomainName        string                         `json:"domain-name,omitempty"`
	StaticHostMapping *ConfigSystemStaticHostMapping `json:"static-host-mapping,omitempty"`
	HostName          string                         `json:"host-name,omitempty"`
	Ntp               *ConfigSystemNtp               `json:"ntp,omitempty"`
	Coredump          *ConfigSystemCoredump          `json:"coredump,omitempty"`
	DomainSearch      *ConfigSystemDomainSearch      `json:"domain-search,omitempty"`
	ConfigManagement  *ConfigSystemConfigManagement  `json:"config-management,omitempty"`
	TrafficAnalysis   *ConfigSystemTrafficAnalysis   `json:"traffic-analysis,omitempty"`
	CrashHandler      *ConfigSystemCrashHandler      `json:"crash-handler,omitempty"`
	Ip                *ConfigSystemIp                `json:"ip,omitempty"`
	Ipv6              *ConfigSystemIpv6              `json:"ipv6,omitempty"`
	Login             *ConfigSystemLogin             `json:"login,omitempty"`
	PacketRxCoreNum   string                         `json:"packet-rx-core-num,omitempty"`
	Package           *ConfigSystemPackage           `json:"package,omitempty"`
	Offload           *ConfigSystemOffload           `json:"offload,omitempty"`
}

type ConfigSystemOptions struct {
	RebootOnPanic bool `json:"reboot-on-panic,omitempty"`
}

type ConfigSystemSyslog struct {
	Host    *map[string]ConfigSystemSyslogHost `json:"host,omitempty"`
	File    *map[string]ConfigSystemSyslogFile `json:"file,omitempty"`
	User    *map[string]ConfigSystemSyslogUser `json:"user,omitempty"`
	Global  *ConfigSystemSyslogGlobal          `json:"global,omitempty"`
	Console *ConfigSystemSyslogConsole         `json:"console,omitempty"`
}

type ConfigSystemSyslogHost struct {
	Facility *map[string]ConfigSystemSyslogHostFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogHostFacility struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogFile struct {
	Archive  *ConfigSystemSyslogFileArchive             `json:"archive,omitempty"`
	Facility *map[string]ConfigSystemSyslogFileFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogFileArchive struct {
	Files EdgeOSInt `json:"files,omitempty"`
	Size  EdgeOSInt `json:"size,omitempty"`
}

type ConfigSystemSyslogFileFacility struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogUser struct {
	Facility *map[string]ConfigSystemSyslogUserFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogUserFacility struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogGlobal struct {
	Archive  *ConfigSystemSyslogGlobalArchive             `json:"archive,omitempty"`
	Facility *map[string]ConfigSystemSyslogGlobalFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogGlobalArchive struct {
	Files EdgeOSInt `json:"files,omitempty"`
	Size  EdgeOSInt `json:"size,omitempty"`
}

type ConfigSystemSyslogGlobalFacility struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogConsole struct {
	Facility *map[string]ConfigSystemSyslogConsoleFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogConsoleFacility struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemFlowAccounting struct {
	Netflow            *ConfigSystemFlowAccountingNetflow   `json:"netflow,omitempty"`
	Interface          []string                             `json:"interface,omitempty"`
	Sflow              *ConfigSystemFlowAccountingSflow     `json:"sflow,omitempty"`
	Aggregate          *ConfigSystemFlowAccountingAggregate `json:"aggregate,omitempty"`
	Unms               *ConfigSystemFlowAccountingUnms      `json:"unms,omitempty"`
	IngressCapture     string                               `json:"ingress-capture,omitempty"`
	SyslogFacility     string                               `json:"syslog-facility,omitempty"`
	DisableMemoryTable string                               `json:"disable-memory-table,omitempty"`
}

type ConfigSystemFlowAccountingNetflow struct {
	EngineId     EdgeOSInt                                           `json:"engine-id,omitempty"`
	SamplingRate EdgeOSInt                                           `json:"sampling-rate,omitempty"`
	Mode         string                                              `json:"mode,omitempty"`
	Timeout      *ConfigSystemFlowAccountingNetflowTimeout           `json:"timeout,omitempty"`
	Server       *map[string]ConfigSystemFlowAccountingNetflowServer `json:"server,omitempty"`
	Version      string                                              `json:"version,omitempty"`
	EnableEgress *ConfigSystemFlowAccountingNetflowEnableEgress      `json:"enable-egress,omitempty"`
}

type ConfigSystemFlowAccountingNetflowTimeout struct {
	TcpFin         EdgeOSInt `json:"tcp-fin,omitempty"`
	Udp            EdgeOSInt `json:"udp,omitempty"`
	FlowGeneric    EdgeOSInt `json:"flow-generic,omitempty"`
	MaxActiveLife  EdgeOSInt `json:"max-active-life,omitempty"`
	TcpRst         EdgeOSInt `json:"tcp-rst,omitempty"`
	Icmp           EdgeOSInt `json:"icmp,omitempty"`
	TcpGeneric     EdgeOSInt `json:"tcp-generic,omitempty"`
	ExpiryInterval EdgeOSInt `json:"expiry-interval,omitempty"`
}

type ConfigSystemFlowAccountingNetflowServer struct {
	Port EdgeOSInt `json:"port,omitempty"`
}

type ConfigSystemFlowAccountingNetflowEnableEgress struct {
	EngineId EdgeOSInt `json:"engine-id,omitempty"`
}

type ConfigSystemFlowAccountingSflow struct {
	SamplingRate EdgeOSInt                                         `json:"sampling-rate,omitempty"`
	AgentAddress string                                            `json:"agent-address,omitempty"`
	Agentid      EdgeOSInt                                         `json:".agentid,omitempty"`
	Server       *map[string]ConfigSystemFlowAccountingSflowServer `json:"server,omitempty"`
}

type ConfigSystemFlowAccountingSflowServer struct {
	Port EdgeOSInt `json:"port,omitempty"`
}

type ConfigSystemFlowAccountingAggregate struct {
	Egress  []string `json:"egress,omitempty"`
	Ingress []string `json:"ingress,omitempty"`
}

type ConfigSystemFlowAccountingUnms struct {
	Exclude string `json:"exclude,omitempty"`
	Subnets string `json:"subnets,omitempty"`
}

type ConfigSystemTaskScheduler struct {
	Task *map[string]ConfigSystemTaskSchedulerTask `json:"task,omitempty"`
}

type ConfigSystemTaskSchedulerTask struct {
	Executable  *ConfigSystemTaskSchedulerTaskExecutable `json:"executable,omitempty"`
	CrontabSpec string                                   `json:"crontab-spec,omitempty"`
	Interval    string                                   `json:"interval,omitempty"`
}

type ConfigSystemTaskSchedulerTaskExecutable struct {
	Path      string `json:"path,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type ConfigSystemAnalyticsHandler struct {
	SendAnalyticsReport string `json:"send-analytics-report,omitempty"`
}

type ConfigSystemSystemd struct {
	Journal *ConfigSystemSystemdJournal `json:"journal,omitempty"`
}

type ConfigSystemSystemdJournal struct {
	RateLimitBurst    EdgeOSInt `json:"rate-limit-burst,omitempty"`
	MaxRetention      EdgeOSInt `json:"max-retention,omitempty"`
	RuntimeMaxUse     EdgeOSInt `json:"runtime-max-use,omitempty"`
	Storage           string    `json:"storage,omitempty"`
	RateLimitInterval EdgeOSInt `json:"rate-limit-interval,omitempty"`
}

type ConfigSystemConntrack struct {
	Ignore          *ConfigSystemConntrackIgnore  `json:"ignore,omitempty"`
	Timeout         *ConfigSystemConntrackTimeout `json:"timeout,omitempty"`
	Tcp             *ConfigSystemConntrackTcp     `json:"tcp,omitempty"`
	Log             *ConfigSystemConntrackLog     `json:"log,omitempty"`
	Modules         *ConfigSystemConntrackModules `json:"modules,omitempty"`
	HashSize        string                        `json:"hash-size,omitempty"`
	TableSize       string                        `json:"table-size,omitempty"`
	ExpectTableSize string                        `json:"expect-table-size,omitempty"`
}

type ConfigSystemConntrackIgnore struct {
	Rule *map[string]ConfigSystemConntrackIgnoreRule `json:"rule,omitempty"`
}

type ConfigSystemConntrackIgnoreRule struct {
	InboundInterface string                                      `json:"inbound-interface,omitempty"`
	Source           *ConfigSystemConntrackIgnoreRuleSource      `json:"source,omitempty"`
	Destination      *ConfigSystemConntrackIgnoreRuleDestination `json:"destination,omitempty"`
	Protocol         string                                      `json:"protocol,omitempty"`
	Description      string                                      `json:"description,omitempty"`
}

type ConfigSystemConntrackIgnoreRuleSource struct {
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigSystemConntrackIgnoreRuleDestination struct {
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigSystemConntrackTimeout struct {
	Udp    *ConfigSystemConntrackTimeoutUdp    `json:"udp,omitempty"`
	Other  EdgeOSInt                           `json:"other,omitempty"`
	Tcp    *ConfigSystemConntrackTimeoutTcp    `json:"tcp,omitempty"`
	Icmp   EdgeOSInt                           `json:"icmp,omitempty"`
	Custom *ConfigSystemConntrackTimeoutCustom `json:".custom,omitempty"`
}

type ConfigSystemConntrackTimeoutUdp struct {
	Stream EdgeOSInt `json:"stream,omitempty"`
	Other  EdgeOSInt `json:"other,omitempty"`
}

type ConfigSystemConntrackTimeoutTcp struct {
	FinWait     EdgeOSInt `json:"fin-wait,omitempty"`
	TimeWait    EdgeOSInt `json:"time-wait,omitempty"`
	Close       EdgeOSInt `json:"close,omitempty"`
	SynSent     EdgeOSInt `json:"syn-sent,omitempty"`
	Established EdgeOSInt `json:"established,omitempty"`
	SynRecv     EdgeOSInt `json:"syn-recv,omitempty"`
	LastAck     EdgeOSInt `json:"last-ack,omitempty"`
	CloseWait   EdgeOSInt `json:"close-wait,omitempty"`
}

type ConfigSystemConntrackTimeoutCustom struct {
	Rule *map[string]ConfigSystemConntrackTimeoutCustomRule `json:"rule,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRule struct {
	Source      *ConfigSystemConntrackTimeoutCustomRuleSource      `json:"source,omitempty"`
	Destination *ConfigSystemConntrackTimeoutCustomRuleDestination `json:"destination,omitempty"`
	Protocol    *ConfigSystemConntrackTimeoutCustomRuleProtocol    `json:"protocol,omitempty"`
	Description string                                             `json:"description,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleSource struct {
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleDestination struct {
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleProtocol struct {
	Udp   *ConfigSystemConntrackTimeoutCustomRuleProtocolUdp `json:"udp,omitempty"`
	Other EdgeOSInt                                          `json:"other,omitempty"`
	Tcp   *ConfigSystemConntrackTimeoutCustomRuleProtocolTcp `json:"tcp,omitempty"`
	Icmp  EdgeOSInt                                          `json:"icmp,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleProtocolUdp struct {
	Stream EdgeOSInt `json:"stream,omitempty"`
	Other  EdgeOSInt `json:"other,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleProtocolTcp struct {
	FinWait     EdgeOSInt `json:"fin-wait,omitempty"`
	TimeWait    EdgeOSInt `json:"time-wait,omitempty"`
	Close       EdgeOSInt `json:"close,omitempty"`
	SynSent     EdgeOSInt `json:"syn-sent,omitempty"`
	Established EdgeOSInt `json:"established,omitempty"`
	SynRecv     EdgeOSInt `json:"syn-recv,omitempty"`
	LastAck     EdgeOSInt `json:"last-ack,omitempty"`
	CloseWait   EdgeOSInt `json:"close-wait,omitempty"`
}

type ConfigSystemConntrackTcp struct {
	Loose               string    `json:"loose,omitempty"`
	HalfOpenConnections EdgeOSInt `json:"half-open-connections,omitempty"`
	MaxRetrans          EdgeOSInt `json:"max-retrans,omitempty"`
}

type ConfigSystemConntrackLog struct {
	Udp   *ConfigSystemConntrackLogUdp   `json:"udp,omitempty"`
	Other *ConfigSystemConntrackLogOther `json:"other,omitempty"`
	Tcp   *ConfigSystemConntrackLogTcp   `json:"tcp,omitempty"`
	Icmp  *ConfigSystemConntrackLogIcmp  `json:"icmp,omitempty"`
}

type ConfigSystemConntrackLogUdp struct {
	Destroy string `json:"destroy,omitempty"`
	Update  string `json:"update,omitempty"`
	New     string `json:"new,omitempty"`
}

type ConfigSystemConntrackLogOther struct {
	Destroy string `json:"destroy,omitempty"`
	Update  string `json:"update,omitempty"`
	New     string `json:"new,omitempty"`
}

type ConfigSystemConntrackLogTcp struct {
	Destroy string                             `json:"destroy,omitempty"`
	Update  *ConfigSystemConntrackLogTcpUpdate `json:"update,omitempty"`
	New     string                             `json:"new,omitempty"`
}

type ConfigSystemConntrackLogTcpUpdate struct {
	FinWait     string `json:"fin-wait,omitempty"`
	TimeWait    string `json:"time-wait,omitempty"`
	Established string `json:"established,omitempty"`
	SynReceived string `json:"syn-received,omitempty"`
	LastAck     string `json:"last-ack,omitempty"`
	CloseWait   string `json:"close-wait,omitempty"`
}

type ConfigSystemConntrackLogIcmp struct {
	Destroy string `json:"destroy,omitempty"`
	Update  string `json:"update,omitempty"`
	New     string `json:"new,omitempty"`
}

type ConfigSystemConntrackModules struct {
	Ftp    *ConfigSystemConntrackModulesFtp    `json:"ftp,omitempty"`
	Nfs    *ConfigSystemConntrackModulesNfs    `json:".nfs,omitempty"`
	Rtsp   *ConfigSystemConntrackModulesRtsp   `json:"rtsp,omitempty"`
	Gre    *ConfigSystemConntrackModulesGre    `json:"gre,omitempty"`
	Tftp   *ConfigSystemConntrackModulesTftp   `json:"tftp,omitempty"`
	Pptp   *ConfigSystemConntrackModulesPptp   `json:"pptp,omitempty"`
	Sqlnet *ConfigSystemConntrackModulesSqlnet `json:".sqlnet,omitempty"`
	Sip    *ConfigSystemConntrackModulesSip    `json:"sip,omitempty"`
	H323   *ConfigSystemConntrackModulesH323   `json:"h323,omitempty"`
}

type ConfigSystemConntrackModulesFtp struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesNfs struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesRtsp struct {
	Enable string `json:"enable,omitempty"`
}

type ConfigSystemConntrackModulesGre struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesTftp struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesPptp struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesSqlnet struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesSip struct {
	Disable                  string   `json:"disable,omitempty"`
	EnableIndirectSignalling string   `json:"enable-indirect-signalling,omitempty"`
	EnableIndirectMedia      string   `json:"enable-indirect-media,omitempty"`
	Port                     []string `json:"port,omitempty"`
}

type ConfigSystemConntrackModulesH323 struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigSystemStaticHostMapping struct {
	HostName *map[string]ConfigSystemStaticHostMappingHostName `json:"host-name,omitempty"`
}

type ConfigSystemStaticHostMappingHostName struct {
	Alias []string `json:"alias,omitempty"`
	Inet  []string `json:"inet,omitempty"`
}

type ConfigSystemNtp struct {
	Server *map[string]ConfigSystemNtpServer `json:"server,omitempty"`
}

type ConfigSystemNtpServer struct {
	Prefer   string `json:"prefer,omitempty"`
	Preempt  string `json:"preempt,omitempty"`
	Noselect string `json:"noselect,omitempty"`
}

type ConfigSystemCoredump struct {
	Enabled bool `json:"enabled,omitempty"`
}

type ConfigSystemDomainSearch struct {
	Domain []string `json:"domain,omitempty"`
}

type ConfigSystemConfigManagement struct {
	CommitRevisions EdgeOSInt                                  `json:"commit-revisions,omitempty"`
	CommitArchive   *ConfigSystemConfigManagementCommitArchive `json:"commit-archive,omitempty"`
}

type ConfigSystemConfigManagementCommitArchive struct {
	Location []string `json:"location,omitempty"`
}

type ConfigSystemTrafficAnalysis struct {
	SignatureUpdate *ConfigSystemTrafficAnalysisSignatureUpdate           `json:"signature-update,omitempty"`
	Dpi             string                                                `json:"dpi,omitempty"`
	CustomCategory  *map[string]ConfigSystemTrafficAnalysisCustomCategory `json:"custom-category,omitempty"`
	Export          string                                                `json:"export,omitempty"`
}

type ConfigSystemTrafficAnalysisSignatureUpdate struct {
	Disable    string    `json:"disable,omitempty"`
	UpdateHour EdgeOSInt `json:"update-hour,omitempty"`
}

type ConfigSystemTrafficAnalysisCustomCategory struct {
	Name []string `json:"name,omitempty"`
}

type ConfigSystemCrashHandler struct {
	SaveCoreFile    string `json:"save-core-file,omitempty"`
	SendCrashReport string `json:"send-crash-report,omitempty"`
}

type ConfigSystemIp struct {
	DisableForwarding  string             `json:"disable-forwarding,omitempty"`
	OverrideHostnameIp IPv4               `json:"override-hostname-ip,omitempty"`
	Arp                *ConfigSystemIpArp `json:"arp,omitempty"`
}

type ConfigSystemIpArp struct {
	StaleTime         string `json:"stale-time,omitempty"`
	BaseReachableTime string `json:"base-reachable-time,omitempty"`
	TableSize         string `json:"table-size,omitempty"`
}

type ConfigSystemIpv6 struct {
	Disable           string                    `json:"disable,omitempty"`
	Neighbor          *ConfigSystemIpv6Neighbor `json:"neighbor,omitempty"`
	DisableForwarding string                    `json:"disable-forwarding,omitempty"`
	Blacklist         string                    `json:"blacklist,omitempty"`
	StrictDad         string                    `json:"strict-dad,omitempty"`
}

type ConfigSystemIpv6Neighbor struct {
	StaleTime         string `json:"stale-time,omitempty"`
	BaseReachableTime string `json:"base-reachable-time,omitempty"`
	TableSize         string `json:"table-size,omitempty"`
}

type ConfigSystemLogin struct {
	RadiusServer *map[string]ConfigSystemLoginRadiusServer `json:"radius-server,omitempty"`
	User         *map[string]ConfigSystemLoginUser         `json:"user,omitempty"`
	Banner       *ConfigSystemLoginBanner                  `json:"banner,omitempty"`
}

type ConfigSystemLoginRadiusServer struct {
	Timeout EdgeOSInt `json:"timeout,omitempty"`
	Secret  string    `json:"secret,omitempty"`
	Port    EdgeOSInt `json:"port,omitempty"`
}

type ConfigSystemLoginUser struct {
	Group          []string                             `json:"group,omitempty"`
	HomeDirectory  string                               `json:"home-directory,omitempty"`
	Level          string                               `json:"level,omitempty"`
	FullName       string                               `json:"full-name,omitempty"`
	Authentication *ConfigSystemLoginUserAuthentication `json:"authentication,omitempty"`
}

type ConfigSystemLoginUserAuthentication struct {
	EncryptedPassword string                                                    `json:"encrypted-password,omitempty"`
	PublicKeys        *map[string]ConfigSystemLoginUserAuthenticationPublicKeys `json:"public-keys,omitempty"`
	PlaintextPassword string                                                    `json:"plaintext-password,omitempty"`
}

type ConfigSystemLoginUserAuthenticationPublicKeys struct {
	Options string `json:"options,omitempty"`
	Key     string `json:"key,omitempty"`
	Type    string `json:"type,omitempty"`
}

type ConfigSystemLoginBanner struct {
	PostLogin string `json:"post-login,omitempty"`
	PreLogin  string `json:"pre-login,omitempty"`
}

type ConfigSystemPackage struct {
	Repository *map[string]ConfigSystemPackageRepository `json:"repository,omitempty"`
	AutoSync   string                                    `json:".auto-sync,omitempty"`
}

type ConfigSystemPackageRepository struct {
	Password     string `json:"password,omitempty"`
	Distribution string `json:"distribution,omitempty"`
	Url          string `json:"url,omitempty"`
	Components   string `json:"components,omitempty"`
	Description  string `json:"description,omitempty"`
	Username     string `json:"username,omitempty"`
}

type ConfigSystemOffload struct {
	Hwnat        string                   `json:"hwnat,omitempty"`
	Ipv4         *ConfigSystemOffloadIpv4 `json:"ipv4,omitempty"`
	Ipsec        string                   `json:"ipsec,omitempty"`
	FlowLifetime string                   `json:"flow-lifetime,omitempty"`
	Ipv6         *ConfigSystemOffloadIpv6 `json:"ipv6,omitempty"`
}

type ConfigSystemOffloadIpv4 struct {
	DisableFlowFlushingUponFibChanges string    `json:"disable-flow-flushing-upon-fib-changes,omitempty"`
	Bonding                           string    `json:"bonding,omitempty"`
	Pppoe                             string    `json:"pppoe,omitempty"`
	Forwarding                        string    `json:"forwarding,omitempty"`
	Gre                               string    `json:"gre,omitempty"`
	Vlan                              string    `json:"vlan,omitempty"`
	TableSize                         EdgeOSInt `json:"table-size,omitempty"`
}

type ConfigSystemOffloadIpv6 struct {
	DisableFlowFlushingUponFibChanges string    `json:"disable-flow-flushing-upon-fib-changes,omitempty"`
	Bonding                           string    `json:"bonding,omitempty"`
	Pppoe                             string    `json:"pppoe,omitempty"`
	Forwarding                        string    `json:"forwarding,omitempty"`
	Vlan                              string    `json:"vlan,omitempty"`
	TableSize                         EdgeOSInt `json:"table-size,omitempty"`
}

type ConfigTrafficControl struct {
	OptimizedQueue *ConfigTrafficControlOptimizedQueue        `json:"optimized-queue,omitempty"`
	SmartQueue     *map[string]ConfigTrafficControlSmartQueue `json:"smart-queue,omitempty"`
	AdvancedQueue  *ConfigTrafficControlAdvancedQueue         `json:"advanced-queue,omitempty"`
}

type ConfigTrafficControlOptimizedQueue struct {
	Policy []string `json:"policy,omitempty"`
}

type ConfigTrafficControlSmartQueue struct {
	WanInterface string                                  `json:"wan-interface,omitempty"`
	Download     *ConfigTrafficControlSmartQueueDownload `json:"download,omitempty"`
	Upload       *ConfigTrafficControlSmartQueueUpload   `json:"upload,omitempty"`
}

type ConfigTrafficControlSmartQueueDownload struct {
	Rate       string    `json:"rate,omitempty"`
	HtbQuantum EdgeOSInt `json:"htb-quantum,omitempty"`
	Limit      EdgeOSInt `json:"limit,omitempty"`
	Target     string    `json:"target,omitempty"`
	Interval   string    `json:"interval,omitempty"`
	Burst      string    `json:"burst,omitempty"`
	Ecn        string    `json:"ecn,omitempty"`
	FqQuantum  EdgeOSInt `json:"fq-quantum,omitempty"`
	Flows      EdgeOSInt `json:"flows,omitempty"`
}

type ConfigTrafficControlSmartQueueUpload struct {
	Rate       string    `json:"rate,omitempty"`
	HtbQuantum EdgeOSInt `json:"htb-quantum,omitempty"`
	Limit      EdgeOSInt `json:"limit,omitempty"`
	Target     string    `json:"target,omitempty"`
	Interval   string    `json:"interval,omitempty"`
	Burst      string    `json:"burst,omitempty"`
	Ecn        string    `json:"ecn,omitempty"`
	FqQuantum  EdgeOSInt `json:"fq-quantum,omitempty"`
	Flows      EdgeOSInt `json:"flows,omitempty"`
}

type ConfigTrafficControlAdvancedQueue struct {
	Filters   *ConfigTrafficControlAdvancedQueueFilters   `json:"filters,omitempty"`
	Leaf      *ConfigTrafficControlAdvancedQueueLeaf      `json:"leaf,omitempty"`
	Branch    *ConfigTrafficControlAdvancedQueueBranch    `json:"branch,omitempty"`
	QueueType *ConfigTrafficControlAdvancedQueueQueueType `json:"queue-type,omitempty"`
	Root      *ConfigTrafficControlAdvancedQueueRoot      `json:"root,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFilters struct {
	Match *map[string]ConfigTrafficControlAdvancedQueueFiltersMatch `json:"match,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatch struct {
	Interface   string                                                    `json:"interface,omitempty"`
	Target      string                                                    `json:"target,omitempty"`
	Mark        string                                                    `json:"mark,omitempty"`
	Ether       *ConfigTrafficControlAdvancedQueueFiltersMatchEther       `json:"ether,omitempty"`
	Description string                                                    `json:"description,omitempty"`
	Application *ConfigTrafficControlAdvancedQueueFiltersMatchApplication `json:"application,omitempty"`
	AttachTo    string                                                    `json:"attach-to,omitempty"`
	Ip          *ConfigTrafficControlAdvancedQueueFiltersMatchIp          `json:"ip,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatchEther struct {
	Source      MacAddr `json:"source,omitempty"`
	Destination MacAddr `json:"destination,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatchApplication struct {
	Category       string `json:"category,omitempty"`
	CustomCategory string `json:"custom-category,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatchIp struct {
	Source      *ConfigTrafficControlAdvancedQueueFiltersMatchIpSource      `json:"source,omitempty"`
	Destination *ConfigTrafficControlAdvancedQueueFiltersMatchIpDestination `json:"destination,omitempty"`
	Protocol    EdgeOSInt                                                   `json:"protocol,omitempty"`
	Dscp        EdgeOSInt                                                   `json:"dscp,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatchIpSource struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatchIpDestination struct {
	Address IPv4Net `json:"address,omitempty"`
	Port    string  `json:"port,omitempty"`
}

type ConfigTrafficControlAdvancedQueueLeaf struct {
	Queue *map[string]ConfigTrafficControlAdvancedQueueLeafQueue `json:"queue,omitempty"`
}

type ConfigTrafficControlAdvancedQueueLeafQueue struct {
	Bandwidth   string                                           `json:"bandwidth,omitempty"`
	Burst       *ConfigTrafficControlAdvancedQueueLeafQueueBurst `json:"burst,omitempty"`
	Ceiling     string                                           `json:"ceiling,omitempty"`
	QueueType   string                                           `json:"queue-type,omitempty"`
	Description string                                           `json:"description,omitempty"`
	Parent      string                                           `json:"parent,omitempty"`
	Priority    EdgeOSInt                                        `json:"priority,omitempty"`
}

type ConfigTrafficControlAdvancedQueueLeafQueueBurst struct {
	BurstRate string `json:"burst-rate,omitempty"`
	BurstSize string `json:"burst-size,omitempty"`
}

type ConfigTrafficControlAdvancedQueueBranch struct {
	Queue *map[string]ConfigTrafficControlAdvancedQueueBranchQueue `json:"queue,omitempty"`
}

type ConfigTrafficControlAdvancedQueueBranchQueue struct {
	Bandwidth   string    `json:"bandwidth,omitempty"`
	Description string    `json:"description,omitempty"`
	Parent      string    `json:"parent,omitempty"`
	Priority    EdgeOSInt `json:"priority,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueType struct {
	Pfifo   *map[string]ConfigTrafficControlAdvancedQueueQueueTypePfifo   `json:"pfifo,omitempty"`
	Hfq     *map[string]ConfigTrafficControlAdvancedQueueQueueTypeHfq     `json:"hfq,omitempty"`
	FqCodel *map[string]ConfigTrafficControlAdvancedQueueQueueTypeFqCodel `json:"fq-codel,omitempty"`
	Sfq     *map[string]ConfigTrafficControlAdvancedQueueQueueTypeSfq     `json:"sfq,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypePfifo struct {
	Limit EdgeOSInt `json:"limit,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypeHfq struct {
	Burst          *ConfigTrafficControlAdvancedQueueQueueTypeHfqBurst `json:"burst,omitempty"`
	Description    string                                              `json:"description,omitempty"`
	HostIdentifier string                                              `json:"host-identifier,omitempty"`
	Subnet         IPv4Net                                             `json:"subnet,omitempty"`
	MaxRate        string                                              `json:"max-rate,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypeHfqBurst struct {
	BurstRate string `json:"burst-rate,omitempty"`
	BurstSize string `json:"burst-size,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypeFqCodel struct {
	Limit    EdgeOSInt `json:"limit,omitempty"`
	Target   string    `json:"target,omitempty"`
	Interval string    `json:"interval,omitempty"`
	Ecn      string    `json:"ecn,omitempty"`
	Flows    EdgeOSInt `json:"flows,omitempty"`
	Quantum  EdgeOSInt `json:"quantum,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypeSfq struct {
	HashInterval EdgeOSInt `json:"hash-interval,omitempty"`
	Description  string    `json:"description,omitempty"`
	QueueLimit   EdgeOSInt `json:"queue-limit,omitempty"`
}

type ConfigTrafficControlAdvancedQueueRoot struct {
	Queue *map[string]ConfigTrafficControlAdvancedQueueRootQueue `json:"queue,omitempty"`
}

type ConfigTrafficControlAdvancedQueueRootQueue struct {
	Bandwidth   string    `json:"bandwidth,omitempty"`
	Default     EdgeOSInt `json:"default,omitempty"`
	Description string    `json:"description,omitempty"`
	AttachTo    string    `json:"attach-to,omitempty"`
}

type ConfigService struct {
	UbntDiscover       *ConfigServiceUbntDiscover       `json:"ubnt-discover,omitempty"`
	UdapiServer        string                           `json:"udapi-server,omitempty"`
	Snmp               *ConfigServiceSnmp               `json:"snmp,omitempty"`
	Dhcpv6Server       *ConfigServiceDhcpv6Server       `json:"dhcpv6-server,omitempty"`
	Upnp               *ConfigServiceUpnp               `json:"upnp,omitempty"`
	Lldp               *ConfigServiceLldp               `json:"lldp,omitempty"`
	Nat                *ConfigServiceNat                `json:"nat,omitempty"`
	Webproxy           *ConfigServiceWebproxy           `json:"webproxy,omitempty"`
	Suspend            *ConfigServiceSuspend            `json:"suspend,omitempty"`
	Unms               *ConfigServiceUnms               `json:"unms,omitempty"`
	Mdns               *ConfigServiceMdns               `json:"mdns,omitempty"`
	UbntDiscoverServer *ConfigServiceUbntDiscoverServer `json:"ubnt-discover-server,omitempty"`
	DhcpServer         *ConfigServiceDhcpServer         `json:"dhcp-server,omitempty"`
	Ssh                *ConfigServiceSsh                `json:"ssh,omitempty"`
	Gui                *ConfigServiceGui                `json:"gui,omitempty"`
	PppoeServer        *ConfigServicePppoeServer        `json:"pppoe-server,omitempty"`
	SshRecovery        *ConfigServiceSshRecovery        `json:"ssh-recovery,omitempty"`
	Dns                *ConfigServiceDns                `json:"dns,omitempty"`
	DhcpRelay          *ConfigServiceDhcpRelay          `json:"dhcp-relay,omitempty"`
	Upnp2              *ConfigServiceUpnp2              `json:"upnp2,omitempty"`
	Telnet             *ConfigServiceTelnet             `json:"telnet,omitempty"`
	Dhcpv6Relay        *ConfigServiceDhcpv6Relay        `json:"dhcpv6-relay,omitempty"`
}

type ConfigServiceUbntDiscover struct {
	Disable   string                                         `json:"disable,omitempty"`
	Interface *map[string]ConfigServiceUbntDiscoverInterface `json:"interface,omitempty"`
}

type ConfigServiceUbntDiscoverInterface struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigServiceSnmp struct {
	Contact         string                                     `json:"contact,omitempty"`
	Location        string                                     `json:"location,omitempty"`
	ListenAddress   *map[string]ConfigServiceSnmpListenAddress `json:"listen-address,omitempty"`
	Description     string                                     `json:"description,omitempty"`
	V3              *ConfigServiceSnmpV3                       `json:"v3,omitempty"`
	TrapSource      IP                                         `json:"trap-source,omitempty"`
	TrapTarget      *map[string]ConfigServiceSnmpTrapTarget    `json:"trap-target,omitempty"`
	Community       *map[string]ConfigServiceSnmpCommunity     `json:"community,omitempty"`
	IgnoreInterface []string                                   `json:"ignore-interface,omitempty"`
}

type ConfigServiceSnmpListenAddress struct {
	Interface string    `json:"interface,omitempty"`
	Port      EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceSnmpV3 struct {
	Group      *map[string]ConfigServiceSnmpV3Group      `json:"group,omitempty"`
	Tsm        *ConfigServiceSnmpV3Tsm                   `json:"tsm,omitempty"`
	User       *map[string]ConfigServiceSnmpV3User       `json:"user,omitempty"`
	View       *map[string]ConfigServiceSnmpV3View       `json:"view,omitempty"`
	TrapTarget *map[string]ConfigServiceSnmpV3TrapTarget `json:"trap-target,omitempty"`
	Engineid   string                                    `json:"engineid,omitempty"`
}

type ConfigServiceSnmpV3Group struct {
	Mode     string `json:"mode,omitempty"`
	View     string `json:"view,omitempty"`
	Seclevel string `json:"seclevel,omitempty"`
}

type ConfigServiceSnmpV3Tsm struct {
	LocalKey string    `json:"local-key,omitempty"`
	Port     EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceSnmpV3User struct {
	TsmKey   string                          `json:"tsm-key,omitempty"`
	Privacy  *ConfigServiceSnmpV3UserPrivacy `json:"privacy,omitempty"`
	Mode     string                          `json:"mode,omitempty"`
	Auth     *ConfigServiceSnmpV3UserAuth    `json:"auth,omitempty"`
	Group    string                          `json:"group,omitempty"`
	Engineid string                          `json:"engineid,omitempty"`
}

type ConfigServiceSnmpV3UserPrivacy struct {
	PlaintextKey string `json:"plaintext-key,omitempty"`
	EncryptedKey string `json:"encrypted-key,omitempty"`
	Type         string `json:"type,omitempty"`
}

type ConfigServiceSnmpV3UserAuth struct {
	PlaintextKey string `json:"plaintext-key,omitempty"`
	EncryptedKey string `json:"encrypted-key,omitempty"`
	Type         string `json:"type,omitempty"`
}

type ConfigServiceSnmpV3View struct {
	Oid *map[string]ConfigServiceSnmpV3ViewOid `json:"oid,omitempty"`
}

type ConfigServiceSnmpV3ViewOid struct {
	Exclude string `json:"exclude,omitempty"`
	Mask    string `json:"mask,omitempty"`
}

type ConfigServiceSnmpV3TrapTarget struct {
	Privacy  *ConfigServiceSnmpV3TrapTargetPrivacy `json:"privacy,omitempty"`
	Auth     *ConfigServiceSnmpV3TrapTargetAuth    `json:"auth,omitempty"`
	User     string                                `json:"user,omitempty"`
	Protocol string                                `json:"protocol,omitempty"`
	Type     string                                `json:"type,omitempty"`
	Port     EdgeOSInt                             `json:"port,omitempty"`
	Engineid string                                `json:"engineid,omitempty"`
}

type ConfigServiceSnmpV3TrapTargetPrivacy struct {
	PlaintextKey string `json:"plaintext-key,omitempty"`
	EncryptedKey string `json:"encrypted-key,omitempty"`
	Type         string `json:"type,omitempty"`
}

type ConfigServiceSnmpV3TrapTargetAuth struct {
	PlaintextKey string `json:"plaintext-key,omitempty"`
	EncryptedKey string `json:"encrypted-key,omitempty"`
	Type         string `json:"type,omitempty"`
}

type ConfigServiceSnmpTrapTarget struct {
	Port      EdgeOSInt `json:"port,omitempty"`
	Community string    `json:"community,omitempty"`
}

type ConfigServiceSnmpCommunity struct {
	Network       []string `json:"network,omitempty"`
	Authorization string   `json:"authorization,omitempty"`
	Client        []string `json:"client,omitempty"`
}

type ConfigServiceDhcpv6Server struct {
	Preference        string                                                 `json:"preference,omitempty"`
	SharedNetworkName *map[string]ConfigServiceDhcpv6ServerSharedNetworkName `json:"shared-network-name,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkName struct {
	NameServer string                                                       `json:"name-server,omitempty"`
	Subnet     *map[string]ConfigServiceDhcpv6ServerSharedNetworkNameSubnet `json:"subnet,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnet struct {
	NisServer        string                                                                    `json:"nis-server,omitempty"`
	StaticMapping    *map[string]ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping `json:"static-mapping,omitempty"`
	SntpServer       string                                                                    `json:"sntp-server,omitempty"`
	PrefixDelegation *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegation         `json:"prefix-delegation,omitempty"`
	NisplusDomain    string                                                                    `json:"nisplus-domain,omitempty"`
	SipServerAddress string                                                                    `json:"sip-server-address,omitempty"`
	SipServerName    string                                                                    `json:"sip-server-name,omitempty"`
	NameServer       string                                                                    `json:"name-server,omitempty"`
	NisDomain        string                                                                    `json:"nis-domain,omitempty"`
	DomainSearch     string                                                                    `json:"domain-search,omitempty"`
	LeaseTime        *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetLeaseTime                `json:"lease-time,omitempty"`
	NisplusServer    string                                                                    `json:"nisplus-server,omitempty"`
	AddressRange     *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRange             `json:"address-range,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping struct {
	Ipv6Address string `json:"ipv6-address,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegation struct {
	Start *map[string]ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart `json:"start,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart struct {
	Stop *map[string]ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop `json:"stop,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop struct {
	PrefixLength string `json:"prefix-length,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetLeaseTime struct {
	Maximum string `json:"maximum,omitempty"`
	Default string `json:"default,omitempty"`
	Minimum string `json:"minimum,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRange struct {
	Prefix *map[string]ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix `json:"prefix,omitempty"`
	Start  *map[string]ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart  `json:"start,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix struct {
	Temporary string `json:"temporary,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart struct {
	Stop string `json:"stop,omitempty"`
}

type ConfigServiceUpnp struct {
	ListenOn *map[string]ConfigServiceUpnpListenOn `json:"listen-on,omitempty"`
}

type ConfigServiceUpnpListenOn struct {
	OutboundInterface string `json:"outbound-interface,omitempty"`
}

type ConfigServiceLldp struct {
	LegacyProtocols   *ConfigServiceLldpLegacyProtocols      `json:"legacy-protocols,omitempty"`
	Interface         *map[string]ConfigServiceLldpInterface `json:"interface,omitempty"`
	ManagementAddress IPv4                                   `json:"management-address,omitempty"`
	ListenVlan        string                                 `json:".listen-vlan,omitempty"`
}

type ConfigServiceLldpLegacyProtocols struct {
	Cdp   string `json:"cdp,omitempty"`
	Sonmp string `json:"sonmp,omitempty"`
	Edp   string `json:"edp,omitempty"`
	Fdp   string `json:"fdp,omitempty"`
}

type ConfigServiceLldpInterface struct {
	Disable  string                              `json:"disable,omitempty"`
	Location *ConfigServiceLldpInterfaceLocation `json:"location,omitempty"`
}

type ConfigServiceLldpInterfaceLocation struct {
	CivicBased      *ConfigServiceLldpInterfaceLocationCivicBased      `json:"civic-based,omitempty"`
	Elin            string                                             `json:"elin,omitempty"`
	CoordinateBased *ConfigServiceLldpInterfaceLocationCoordinateBased `json:"coordinate-based,omitempty"`
}

type ConfigServiceLldpInterfaceLocationCivicBased struct {
	CountryCode string                                                         `json:"country-code,omitempty"`
	CaType      *map[string]ConfigServiceLldpInterfaceLocationCivicBasedCaType `json:"ca-type,omitempty"`
}

type ConfigServiceLldpInterfaceLocationCivicBasedCaType struct {
	CaValue string `json:"ca-value,omitempty"`
}

type ConfigServiceLldpInterfaceLocationCoordinateBased struct {
	Datum     string `json:"datum,omitempty"`
	Longitude string `json:"longitude,omitempty"`
	Altitude  string `json:"altitude,omitempty"`
	Latitude  string `json:"latitude,omitempty"`
}

type ConfigServiceNat struct {
	Rule *map[string]ConfigServiceNatRule `json:"rule,omitempty"`
}

type ConfigServiceNatRule struct {
	OutsideAddress    *ConfigServiceNatRuleOutsideAddress `json:"outside-address,omitempty"`
	Disable           string                              `json:"disable,omitempty"`
	InboundInterface  string                              `json:"inbound-interface,omitempty"`
	Exclude           string                              `json:"exclude,omitempty"`
	Source            *ConfigServiceNatRuleSource         `json:"source,omitempty"`
	OutboundInterface string                              `json:"outbound-interface,omitempty"`
	Destination       *ConfigServiceNatRuleDestination    `json:"destination,omitempty"`
	Protocol          string                              `json:"protocol,omitempty"`
	Type              string                              `json:"type,omitempty"`
	Description       string                              `json:"description,omitempty"`
	Log               string                              `json:"log,omitempty"`
	InsideAddress     *ConfigServiceNatRuleInsideAddress  `json:"inside-address,omitempty"`
}

type ConfigServiceNatRuleOutsideAddress struct {
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigServiceNatRuleSource struct {
	Group   *ConfigServiceNatRuleSourceGroup `json:"group,omitempty"`
	Address string                           `json:"address,omitempty"`
	Port    string                           `json:"port,omitempty"`
}

type ConfigServiceNatRuleSourceGroup struct {
	AddressGroup string `json:"address-group,omitempty"`
	PortGroup    string `json:"port-group,omitempty"`
	NetworkGroup string `json:"network-group,omitempty"`
}

type ConfigServiceNatRuleDestination struct {
	Group   *ConfigServiceNatRuleDestinationGroup `json:"group,omitempty"`
	Address string                                `json:"address,omitempty"`
	Port    string                                `json:"port,omitempty"`
}

type ConfigServiceNatRuleDestinationGroup struct {
	AddressGroup string `json:"address-group,omitempty"`
	PortGroup    string `json:"port-group,omitempty"`
	NetworkGroup string `json:"network-group,omitempty"`
}

type ConfigServiceNatRuleInsideAddress struct {
	Address string `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigServiceWebproxy struct {
	DomainBlock       []string                                       `json:"domain-block,omitempty"`
	MinimumObjectSize EdgeOSInt                                      `json:"minimum-object-size,omitempty"`
	ProxyBypass       []string                                       `json:"proxy-bypass,omitempty"`
	ProxyBypassSource []string                                       `json:"proxy-bypass-source,omitempty"`
	ListenAddress     *map[string]ConfigServiceWebproxyListenAddress `json:"listen-address,omitempty"`
	DomainNoncache    []string                                       `json:"domain-noncache,omitempty"`
	MemCacheSize      EdgeOSInt                                      `json:"mem-cache-size,omitempty"`
	MaximumObjectSize EdgeOSInt                                      `json:"maximum-object-size,omitempty"`
	DefaultPort       EdgeOSInt                                      `json:"default-port,omitempty"`
	AppendDomain      string                                         `json:"append-domain,omitempty"`
	UrlFiltering      *ConfigServiceWebproxyUrlFiltering             `json:"url-filtering,omitempty"`
	EnableAccessLog   string                                         `json:"enable-access-log,omitempty"`
	Administrator     string                                         `json:"administrator,omitempty"`
	CacheSize         EdgeOSInt                                      `json:"cache-size,omitempty"`
	ReplyBlockMime    []string                                       `json:"reply-block-mime,omitempty"`
	ReplyBodyMaxSize  EdgeOSInt                                      `json:"reply-body-max-size,omitempty"`
}

type ConfigServiceWebproxyListenAddress struct {
	DisableTransparent string    `json:"disable-transparent,omitempty"`
	Port               EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceWebproxyUrlFiltering struct {
	Disable    string                                       `json:"disable,omitempty"`
	Squidguard *ConfigServiceWebproxyUrlFilteringSquidguard `json:"squidguard,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguard struct {
	AutoUpdate        *ConfigServiceWebproxyUrlFilteringSquidguardAutoUpdate             `json:"auto-update,omitempty"`
	DefaultAction     string                                                             `json:"default-action,omitempty"`
	EnableSafeSearch  string                                                             `json:"enable-safe-search,omitempty"`
	SourceGroup       *map[string]ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup `json:"source-group,omitempty"`
	RedirectUrl       string                                                             `json:"redirect-url,omitempty"`
	LocalBlock        []string                                                           `json:"local-block,omitempty"`
	BlockCategory     []string                                                           `json:"block-category,omitempty"`
	LocalOk           []string                                                           `json:"local-ok,omitempty"`
	TimePeriod        *map[string]ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod  `json:"time-period,omitempty"`
	LocalOkUrl        []string                                                           `json:"local-ok-url,omitempty"`
	AllowIpaddrUrl    string                                                             `json:"allow-ipaddr-url,omitempty"`
	Rule              *map[string]ConfigServiceWebproxyUrlFilteringSquidguardRule        `json:"rule,omitempty"`
	LocalBlockKeyword []string                                                           `json:"local-block-keyword,omitempty"`
	AllowCategory     []string                                                           `json:"allow-category,omitempty"`
	Log               []string                                                           `json:"log,omitempty"`
	LocalBlockUrl     []string                                                           `json:"local-block-url,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardAutoUpdate struct {
	UpdateHour EdgeOSInt `json:"update-hour,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup struct {
	Description string   `json:"description,omitempty"`
	Address     []string `json:"address,omitempty"`
	Domain      []string `json:"domain,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod struct {
	Description string                                                                `json:"description,omitempty"`
	Days        *map[string]ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays `json:"days,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays struct {
	Time string `json:"time,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardRule struct {
	DefaultAction     string   `json:"default-action,omitempty"`
	EnableSafeSearch  string   `json:"enable-safe-search,omitempty"`
	SourceGroup       string   `json:"source-group,omitempty"`
	RedirectUrl       string   `json:"redirect-url,omitempty"`
	LocalBlock        []string `json:"local-block,omitempty"`
	BlockCategory     []string `json:"block-category,omitempty"`
	LocalOk           []string `json:"local-ok,omitempty"`
	TimePeriod        string   `json:"time-period,omitempty"`
	LocalOkUrl        []string `json:"local-ok-url,omitempty"`
	AllowIpaddrUrl    string   `json:"allow-ipaddr-url,omitempty"`
	Description       string   `json:"description,omitempty"`
	LocalBlockKeyword []string `json:"local-block-keyword,omitempty"`
	AllowCategory     []string `json:"allow-category,omitempty"`
	Log               []string `json:"log,omitempty"`
	LocalBlockUrl     []string `json:"local-block-url,omitempty"`
}

type ConfigServiceSuspend struct {
	ForwardTo   *ConfigServiceSuspendForwardTo `json:"forward-to,omitempty"`
	AllowDomain []string                       `json:"allow-domain,omitempty"`
	UserIp      []string                       `json:"user-ip,omitempty"`
	Redirect    *ConfigServiceSuspendRedirect  `json:"redirect,omitempty"`
	AllowIp     []string                       `json:"allow-ip,omitempty"`
}

type ConfigServiceSuspendForwardTo struct {
	HttpPort  EdgeOSInt `json:"http-port,omitempty"`
	Address   IPv4      `json:"address,omitempty"`
	HttpsPort EdgeOSInt `json:"https-port,omitempty"`
}

type ConfigServiceSuspendRedirect struct {
	HttpPort  EdgeOSInt `json:"http-port,omitempty"`
	Url       string    `json:"url,omitempty"`
	HttpsPort EdgeOSInt `json:"https-port,omitempty"`
}

type ConfigServiceUnms struct {
	Disable    string                    `json:"disable,omitempty"`
	Connection string                    `json:"connection,omitempty"`
	Lldp       *ConfigServiceUnmsLldp    `json:"lldp,omitempty"`
	RestApi    *ConfigServiceUnmsRestApi `json:"rest-api,omitempty"`
}

type ConfigServiceUnmsLldp struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigServiceUnmsRestApi struct {
	Interface string    `json:"interface,omitempty"`
	Port      EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceMdns struct {
	Reflector string                     `json:"reflector,omitempty"`
	Repeater  *ConfigServiceMdnsRepeater `json:"repeater,omitempty"`
}

type ConfigServiceMdnsRepeater struct {
	Interface []string `json:"interface,omitempty"`
}

type ConfigServiceUbntDiscoverServer struct {
	Disable  string `json:"disable,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type ConfigServiceDhcpServer struct {
	UseDnsmasq        string                                               `json:"use-dnsmasq,omitempty"`
	StaticArp         string                                               `json:"static-arp,omitempty"`
	HostfileUpdate    string                                               `json:"hostfile-update,omitempty"`
	SharedNetworkName *map[string]ConfigServiceDhcpServerSharedNetworkName `json:"shared-network-name,omitempty"`
	Disabled          bool                                                 `json:"disabled,omitempty"`
	DynamicDnsUpdate  *ConfigServiceDhcpServerDynamicDnsUpdate             `json:"dynamic-dns-update,omitempty"`
	GlobalParameters  []string                                             `json:"global-parameters,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkName struct {
	Disable                 string                                                     `json:"disable,omitempty"`
	SharedNetworkParameters []string                                                   `json:"shared-network-parameters,omitempty"`
	Authoritative           string                                                     `json:"authoritative,omitempty"`
	Description             string                                                     `json:"description,omitempty"`
	Subnet                  *map[string]ConfigServiceDhcpServerSharedNetworkNameSubnet `json:"subnet,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnet struct {
	StaticMapping      *map[string]ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping `json:"static-mapping,omitempty"`
	BootfileName       string                                                                  `json:"bootfile-name,omitempty"`
	BootfileServer     string                                                                  `json:"bootfile-server,omitempty"`
	PopServer          []string                                                                `json:"pop-server,omitempty"`
	Exclude            []string                                                                `json:"exclude,omitempty"`
	DomainName         string                                                                  `json:"domain-name,omitempty"`
	StaticRoute        *ConfigServiceDhcpServerSharedNetworkNameSubnetStaticRoute              `json:"static-route,omitempty"`
	SubnetParameters   []string                                                                `json:"subnet-parameters,omitempty"`
	Start              *map[string]ConfigServiceDhcpServerSharedNetworkNameSubnetStart         `json:"start,omitempty"`
	TimeServer         []string                                                                `json:"time-server,omitempty"`
	WpadUrl            string                                                                  `json:"wpad-url,omitempty"`
	UnifiController    IPv4                                                                    `json:"unifi-controller,omitempty"`
	Lease              EdgeOSInt                                                               `json:"lease,omitempty"`
	DefaultRouter      IPv4                                                                    `json:"default-router,omitempty"`
	TftpServerName     string                                                                  `json:"tftp-server-name,omitempty"`
	IpForwarding       *ConfigServiceDhcpServerSharedNetworkNameSubnetIpForwarding             `json:"ip-forwarding,omitempty"`
	DnsServer          []string                                                                `json:"dns-server,omitempty"`
	NtpServer          []string                                                                `json:"ntp-server,omitempty"`
	TimeOffset         string                                                                  `json:"time-offset,omitempty"`
	SmtpServer         []string                                                                `json:"smtp-server,omitempty"`
	WinsServer         []string                                                                `json:"wins-server,omitempty"`
	ClientPrefixLength EdgeOSInt                                                               `json:"client-prefix-length,omitempty"`
	Failover           *ConfigServiceDhcpServerSharedNetworkNameSubnetFailover                 `json:"failover,omitempty"`
	ServerIdentifier   IPv4                                                                    `json:"server-identifier,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping struct {
	Disable                 string   `json:"disable,omitempty"`
	IpAddress               IPv4     `json:"ip-address,omitempty"`
	StaticMappingParameters []string `json:"static-mapping-parameters,omitempty"`
	MacAddress              MacAddr  `json:"mac-address,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetStaticRoute struct {
	DestinationSubnet IPv4Net `json:"destination-subnet,omitempty"`
	Router            IPv4    `json:"router,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetStart struct {
	Stop IPv4 `json:"stop,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetIpForwarding struct {
	Enable bool `json:"enable,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetFailover struct {
	PeerAddress  IPv4   `json:"peer-address,omitempty"`
	Status       string `json:"status,omitempty"`
	LocalAddress IPv4   `json:"local-address,omitempty"`
	Name         string `json:"name,omitempty"`
}

type ConfigServiceDhcpServerDynamicDnsUpdate struct {
	Enable bool `json:"enable,omitempty"`
}

type ConfigServiceSsh struct {
	DisablePasswordAuthentication string    `json:"disable-password-authentication,omitempty"`
	ListenAddress                 []string  `json:"listen-address,omitempty"`
	AllowRoot                     string    `json:"allow-root,omitempty"`
	ProtocolVersion               string    `json:"protocol-version,omitempty"`
	DisableHostValidation         string    `json:"disable-host-validation,omitempty"`
	Port                          EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceGui struct {
	CaFile        string    `json:"ca-file,omitempty"`
	HttpPort      EdgeOSInt `json:"http-port,omitempty"`
	ListenAddress []string  `json:"listen-address,omitempty"`
	HttpsPort     EdgeOSInt `json:"https-port,omitempty"`
	DhFile        string    `json:"dh-file,omitempty"`
	CertFile      string    `json:"cert-file,omitempty"`
	OlderCiphers  string    `json:"older-ciphers,omitempty"`
	Debug         string    `json:"debug,omitempty"`
}

type ConfigServicePppoeServer struct {
	Encryption         string                                  `json:"encryption,omitempty"`
	ServiceName        string                                  `json:"service-name,omitempty"`
	WinsServers        *ConfigServicePppoeServerWinsServers    `json:"wins-servers,omitempty"`
	Interface          []string                                `json:"interface,omitempty"`
	DnsServers         *ConfigServicePppoeServerDnsServers     `json:"dns-servers,omitempty"`
	Mtu                EdgeOSInt                               `json:"mtu,omitempty"`
	ClientIpPool       *ConfigServicePppoeServerClientIpPool   `json:"client-ip-pool,omitempty"`
	Radius             *ConfigServicePppoeServerRadius         `json:"radius,omitempty"`
	LocalIp            string                                  `json:"local-ip,omitempty"`
	Authentication     *ConfigServicePppoeServerAuthentication `json:"authentication,omitempty"`
	AccessConcentrator string                                  `json:"access-concentrator,omitempty"`
}

type ConfigServicePppoeServerWinsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigServicePppoeServerDnsServers struct {
	Server2 string `json:"server-2,omitempty"`
	Server1 string `json:"server-1,omitempty"`
}

type ConfigServicePppoeServerClientIpPool struct {
	Start string `json:"start,omitempty"`
	Stop  string `json:"stop,omitempty"`
}

type ConfigServicePppoeServerRadius struct {
	DefaultInterimInterval EdgeOSInt `json:"default-interim-interval,omitempty"`
}

type ConfigServicePppoeServerAuthentication struct {
	Mode         string                                                         `json:"mode,omitempty"`
	LocalUsers   *ConfigServicePppoeServerAuthenticationLocalUsers              `json:"local-users,omitempty"`
	RadiusServer *map[string]ConfigServicePppoeServerAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigServicePppoeServerAuthenticationLocalUsers struct {
	Username *map[string]ConfigServicePppoeServerAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigServicePppoeServerAuthenticationLocalUsersUsername struct {
	Disable  string `json:"disable,omitempty"`
	Password string `json:"password,omitempty"`
	StaticIp IPv4   `json:"static-ip,omitempty"`
}

type ConfigServicePppoeServerAuthenticationRadiusServer struct {
	Key string `json:"key,omitempty"`
}

type ConfigServiceSshRecovery struct {
	ListenOn []string  `json:"listen-on,omitempty"`
	Lifetime string    `json:"lifetime,omitempty"`
	Disabled string    `json:"disabled,omitempty"`
	Port     EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceDns struct {
	Dynamic    *ConfigServiceDnsDynamic    `json:"dynamic,omitempty"`
	Forwarding *ConfigServiceDnsForwarding `json:"forwarding,omitempty"`
}

type ConfigServiceDnsDynamic struct {
	Interface *map[string]ConfigServiceDnsDynamicInterface `json:"interface,omitempty"`
}

type ConfigServiceDnsDynamicInterface struct {
	Web     string                                              `json:"web,omitempty"`
	WebSkip string                                              `json:"web-skip,omitempty"`
	Service *map[string]ConfigServiceDnsDynamicInterfaceService `json:"service,omitempty"`
}

type ConfigServiceDnsDynamicInterfaceService struct {
	Options  string   `json:"options,omitempty"`
	Password string   `json:"password,omitempty"`
	Server   string   `json:"server,omitempty"`
	HostName []string `json:"host-name,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Login    string   `json:"login,omitempty"`
}

type ConfigServiceDnsForwarding struct {
	Options             []string  `json:"options,omitempty"`
	ExceptInterface     []string  `json:"except-interface,omitempty"`
	ForcePublicDnsBoost string    `json:"force-public-dns-boost,omitempty"`
	ListenOn            []string  `json:"listen-on,omitempty"`
	NameServer          []string  `json:"name-server,omitempty"`
	System              string    `json:"system,omitempty"`
	Dhcp                []string  `json:"dhcp,omitempty"`
	CacheSize           EdgeOSInt `json:"cache-size,omitempty"`
}

type ConfigServiceDhcpRelay struct {
	Interface    []string                            `json:"interface,omitempty"`
	RelayOptions *ConfigServiceDhcpRelayRelayOptions `json:"relay-options,omitempty"`
	Server       []string                            `json:"server,omitempty"`
}

type ConfigServiceDhcpRelayRelayOptions struct {
	HopCount           EdgeOSInt `json:"hop-count,omitempty"`
	MaxSize            EdgeOSInt `json:"max-size,omitempty"`
	Port               EdgeOSInt `json:"port,omitempty"`
	RelayAgentsPackets string    `json:"relay-agents-packets,omitempty"`
}

type ConfigServiceUpnp2 struct {
	ListenOn   []string                   `json:"listen-on,omitempty"`
	NatPmp     string                     `json:"nat-pmp,omitempty"`
	BitRate    *ConfigServiceUpnp2BitRate `json:"bit-rate,omitempty"`
	Wan        string                     `json:"wan,omitempty"`
	Port       EdgeOSInt                  `json:"port,omitempty"`
	SecureMode string                     `json:"secure-mode,omitempty"`
	Acl        *ConfigServiceUpnp2Acl     `json:"acl,omitempty"`
}

type ConfigServiceUpnp2BitRate struct {
	Up   EdgeOSInt `json:"up,omitempty"`
	Down EdgeOSInt `json:"down,omitempty"`
}

type ConfigServiceUpnp2Acl struct {
	Rule *map[string]ConfigServiceUpnp2AclRule `json:"rule,omitempty"`
}

type ConfigServiceUpnp2AclRule struct {
	Action       string  `json:"action,omitempty"`
	Description  string  `json:"description,omitempty"`
	ExternalPort string  `json:"external-port,omitempty"`
	LocalPort    string  `json:"local-port,omitempty"`
	Subnet       IPv4Net `json:"subnet,omitempty"`
}

type ConfigServiceTelnet struct {
	ListenAddress IP        `json:"listen-address,omitempty"`
	AllowRoot     string    `json:"allow-root,omitempty"`
	Port          EdgeOSInt `json:"port,omitempty"`
}

type ConfigServiceDhcpv6Relay struct {
	ListenInterface      *map[string]ConfigServiceDhcpv6RelayListenInterface   `json:"listen-interface,omitempty"`
	MaxHopCount          string                                                `json:"max-hop-count,omitempty"`
	UseInterfaceIdOption string                                                `json:"use-interface-id-option,omitempty"`
	UpstreamInterface    *map[string]ConfigServiceDhcpv6RelayUpstreamInterface `json:"upstream-interface,omitempty"`
	ListenPort           string                                                `json:"listen-port,omitempty"`
}

type ConfigServiceDhcpv6RelayListenInterface struct {
	Address string `json:"address,omitempty"`
}

type ConfigServiceDhcpv6RelayUpstreamInterface struct {
	Address string `json:"address,omitempty"`
}

type ConfigProtocols struct {
	Rip       *ConfigProtocolsRip            `json:"rip,omitempty"`
	Mpls      *ConfigProtocolsMpls           `json:"mpls,omitempty"`
	Bfd       *ConfigProtocolsBfd            `json:"bfd,omitempty"`
	Ripng     *ConfigProtocolsRipng          `json:"ripng,omitempty"`
	Vrf       *map[string]ConfigProtocolsVrf `json:".vrf,omitempty"`
	Static    *ConfigProtocolsStatic         `json:"static,omitempty"`
	Rsvp      *ConfigProtocolsRsvp           `json:"rsvp,omitempty"`
	Vpls      *ConfigProtocolsVpls           `json:"vpls,omitempty"`
	Ldp       *ConfigProtocolsLdp            `json:"ldp,omitempty"`
	IgmpProxy *ConfigProtocolsIgmpProxy      `json:"igmp-proxy,omitempty"`
	Bgp       *map[string]ConfigProtocolsBgp `json:"bgp,omitempty"`
	Ospfv3    *ConfigProtocolsOspfv3         `json:"ospfv3,omitempty"`
	Ospf      *ConfigProtocolsOspf           `json:"ospf,omitempty"`
}

type ConfigProtocolsRip struct {
	Interface          []string                                      `json:"interface,omitempty"`
	Neighbor           []string                                      `json:"neighbor,omitempty"`
	Route              []string                                      `json:"route,omitempty"`
	Bfd                *ConfigProtocolsRipBfd                        `json:"bfd,omitempty"`
	DefaultDistance    EdgeOSInt                                     `json:"default-distance,omitempty"`
	Timers             *ConfigProtocolsRipTimers                     `json:"timers,omitempty"`
	Network            []string                                      `json:"network,omitempty"`
	DefaultMetric      EdgeOSInt                                     `json:"default-metric,omitempty"`
	Vrf                *map[string]ConfigProtocolsRipVrf             `json:".vrf,omitempty"`
	NetworkDistance    *map[string]ConfigProtocolsRipNetworkDistance `json:"network-distance,omitempty"`
	PassiveInterface   []string                                      `json:"passive-interface,omitempty"`
	Redistribute       *ConfigProtocolsRipRedistribute               `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipDistributeList             `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipDefaultInformation         `json:"default-information,omitempty"`
}

type ConfigProtocolsRipBfd struct {
	Neighbor      *map[string]ConfigProtocolsRipBfdNeighbor `json:"neighbor,omitempty"`
	AllInterfaces string                                    `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsRipBfdNeighbor struct {
	FallOver string `json:"fall-over,omitempty"`
}

type ConfigProtocolsRipTimers struct {
	Update            EdgeOSInt `json:"update,omitempty"`
	Timeout           EdgeOSInt `json:"timeout,omitempty"`
	GarbageCollection EdgeOSInt `json:"garbage-collection,omitempty"`
}

type ConfigProtocolsRipVrf struct {
	Interface          []string                                         `json:"interface,omitempty"`
	Bfd                *ConfigProtocolsRipVrfBfd                        `json:"bfd,omitempty"`
	DefaultDistance    EdgeOSInt                                        `json:"default-distance,omitempty"`
	Network            []string                                         `json:"network,omitempty"`
	DefaultMetric      EdgeOSInt                                        `json:"default-metric,omitempty"`
	NetworkDistance    *map[string]ConfigProtocolsRipVrfNetworkDistance `json:"network-distance,omitempty"`
	Redistribute       *ConfigProtocolsRipVrfRedistribute               `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipVrfDistributeList             `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipVrfDefaultInformation         `json:"default-information,omitempty"`
}

type ConfigProtocolsRipVrfBfd struct {
	Neighbor      *map[string]ConfigProtocolsRipVrfBfdNeighbor `json:"neighbor,omitempty"`
	AllInterfaces string                                       `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsRipVrfBfdNeighbor struct {
	FallOver string `json:"fall-over,omitempty"`
}

type ConfigProtocolsRipVrfNetworkDistance struct {
	Distance   EdgeOSInt `json:"distance,omitempty"`
	AccessList string    `json:"access-list,omitempty"`
}

type ConfigProtocolsRipVrfRedistribute struct {
	Connected *ConfigProtocolsRipVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipVrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipVrfRedistributeBgp       `json:"bgp,omitempty"`
	Ospf      *ConfigProtocolsRipVrfRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeBgp struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeOspf struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfDistributeList struct {
	Interface  *map[string]ConfigProtocolsRipVrfDistributeListInterface `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipVrfDistributeListAccessList           `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipVrfDistributeListPrefixList           `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListInterface struct {
	AccessList *ConfigProtocolsRipVrfDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipVrfDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListInterfaceAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDefaultInformation struct {
	Originate string `json:"originate,omitempty"`
}

type ConfigProtocolsRipNetworkDistance struct {
	Distance   EdgeOSInt `json:"distance,omitempty"`
	AccessList string    `json:"access-list,omitempty"`
}

type ConfigProtocolsRipRedistribute struct {
	Connected *ConfigProtocolsRipRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsRipRedistributeKernel    `json:"kernel,omitempty"`
	Ospf      *ConfigProtocolsRipRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsRipRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeBgp struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeKernel struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeOspf struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipDistributeList struct {
	Interface  *map[string]ConfigProtocolsRipDistributeListInterface `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipDistributeListAccessList           `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipDistributeListPrefixList           `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipDistributeListInterface struct {
	AccessList *ConfigProtocolsRipDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipDistributeListInterfaceAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipDistributeListAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipDefaultInformation struct {
	Originate string `json:"originate,omitempty"`
}

type ConfigProtocolsMpls struct {
	LspTunneling         *ConfigProtocolsMplsLspTunneling                 `json:"lsp-tunneling,omitempty"`
	AcGroup              *map[string]ConfigProtocolsMplsAcGroup           `json:"ac-group,omitempty"`
	LocalPacketHandling  string                                           `json:"local-packet-handling,omitempty"`
	Interface            *map[string]ConfigProtocolsMplsInterface         `json:"interface,omitempty"`
	L2CircuitFibEntry    *map[string]ConfigProtocolsMplsL2CircuitFibEntry `json:".l2-circuit-fib-entry,omitempty"`
	EnableAllInterfaces  string                                           `json:"enable-all-interfaces,omitempty"`
	MsPw                 *map[string]ConfigProtocolsMplsMsPw              `json:"ms-pw,omitempty"`
	IngressTtl           string                                           `json:"ingress-ttl,omitempty"`
	TeClass              *map[string]ConfigProtocolsMplsTeClass           `json:"te-class,omitempty"`
	LspModel             *ConfigProtocolsMplsLspModel                     `json:"lsp-model,omitempty"`
	FtnEntry             *ConfigProtocolsMplsFtnEntry                     `json:"ftn-entry,omitempty"`
	ClassToExp           *map[string]ConfigProtocolsMplsClassToExp        `json:"class-to-exp,omitempty"`
	L2Circuit            *map[string]ConfigProtocolsMplsL2Circuit         `json:".l2-circuit,omitempty"`
	EgressTtl            string                                           `json:"egress-ttl,omitempty"`
	MinLabelValue        *map[string]ConfigProtocolsMplsMinLabelValue     `json:"min-label-value,omitempty"`
	AdminGroup           *map[string]ConfigProtocolsMplsAdminGroup        `json:"admin-group,omitempty"`
	MsPwStitch           *map[string]ConfigProtocolsMplsMsPwStitch        `json:"ms-pw-stitch,omitempty"`
	ClassType            *map[string]ConfigProtocolsMplsClassType         `json:"class-type,omitempty"`
	IlmEntry             *map[string]ConfigProtocolsMplsIlmEntry          `json:"ilm-entry,omitempty"`
	SupportDiffservClass string                                           `json:"support-diffserv-class,omitempty"`
	MapRoute             *map[string]ConfigProtocolsMplsMapRoute          `json:"map-route,omitempty"`
	Rsvp                 *ConfigProtocolsMplsRsvp                         `json:"rsvp,omitempty"`
	Ldp                  *ConfigProtocolsMplsLdp                          `json:"ldp,omitempty"`
	Bgp                  *ConfigProtocolsMplsBgp                          `json:"bgp,omitempty"`
	MaxLabelValue        *map[string]ConfigProtocolsMplsMaxLabelValue     `json:"max-label-value,omitempty"`
	PropagateTtl         string                                           `json:"propagate-ttl,omitempty"`
	DisableAllInterfaces string                                           `json:"disable-all-interfaces,omitempty"`
}

type ConfigProtocolsMplsLspTunneling struct {
	Interface *map[string]ConfigProtocolsMplsLspTunnelingInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsLspTunnelingInterface struct {
	InLabel *map[string]ConfigProtocolsMplsLspTunnelingInterfaceInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsMplsLspTunnelingInterfaceInLabel struct {
	OutLabel *map[string]ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel struct {
	NetworkFec string `json:"network-fec,omitempty"`
}

type ConfigProtocolsMplsAcGroup struct {
	GroupId EdgeOSInt `json:"group-id,omitempty"`
}

type ConfigProtocolsMplsInterface struct {
	MulticastHellos    string                                            `json:"multicast-hellos,omitempty"`
	KeepaliveTimeout   string                                            `json:"keepalive-timeout,omitempty"`
	VcMode             *ConfigProtocolsMplsInterfaceVcMode               `json:"vc-mode,omitempty"`
	LdpIgp             *ConfigProtocolsMplsInterfaceLdpIgp               `json:"ldp-igp,omitempty"`
	MaxPduLength       string                                            `json:"max-pdu-length,omitempty"`
	LabelRetentionMode *ConfigProtocolsMplsInterfaceLabelRetentionMode   `json:"label-retention-mode,omitempty"`
	AdminGroup         string                                            `json:"admin-group,omitempty"`
	L2Circuit          *map[string]ConfigProtocolsMplsInterfaceL2Circuit `json:"l2-circuit,omitempty"`
	LabelSwitching     string                                            `json:"label-switching,omitempty"`
	HoldTime           string                                            `json:"hold-time,omitempty"`
	KeepaliveInterval  string                                            `json:"keepalive-interval,omitempty"`
	AdvertisementMode  *ConfigProtocolsMplsInterfaceAdvertisementMode    `json:"advertisement-mode,omitempty"`
	HelloInterval      string                                            `json:"hello-interval,omitempty"`
}

type ConfigProtocolsMplsInterfaceVcMode struct {
	Standby   string `json:"standby,omitempty"`
	Revertive string `json:"revertive,omitempty"`
}

type ConfigProtocolsMplsInterfaceLdpIgp struct {
	Sync      *ConfigProtocolsMplsInterfaceLdpIgpSync `json:"sync,omitempty"`
	SyncDelay string                                  `json:"sync-delay,omitempty"`
}

type ConfigProtocolsMplsInterfaceLdpIgpSync struct {
	Ospf *ConfigProtocolsMplsInterfaceLdpIgpSyncOspf `json:"ospf,omitempty"`
}

type ConfigProtocolsMplsInterfaceLdpIgpSyncOspf struct {
	HolddownTimer string `json:"holddown-timer,omitempty"`
}

type ConfigProtocolsMplsInterfaceLabelRetentionMode struct {
	Liberal      string `json:"liberal,omitempty"`
	Conservative string `json:"conservative,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2Circuit struct {
	Hdlc     *ConfigProtocolsMplsInterfaceL2CircuitHdlc     `json:".hdlc,omitempty"`
	Ppp      *ConfigProtocolsMplsInterfaceL2CircuitPpp      `json:".ppp,omitempty"`
	Ethernet *ConfigProtocolsMplsInterfaceL2CircuitEthernet `json:".ethernet,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2CircuitHdlc struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2CircuitPpp struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2CircuitEthernet struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsInterfaceAdvertisementMode struct {
	DownstreamOnDemand    string `json:"downstream-on-demand,omitempty"`
	DownstreamUnsolicited string `json:"downstream-unsolicited,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntry struct {
	InLabel *map[string]ConfigProtocolsMplsL2CircuitFibEntryInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabel struct {
	OutLabel *map[string]ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel struct {
	Ipv4 *map[string]ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4 `json:"ipv4,omitempty"`
	Ipv6 *map[string]ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6 `json:"ipv6,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4 struct {
	Int *map[string]ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int `json:"int,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int struct {
	Int string `json:"int,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6 struct {
	Int *map[string]ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int `json:"int,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int struct {
	Int string `json:"int,omitempty"`
}

type ConfigProtocolsMplsMsPw struct {
	Description string `json:"description,omitempty"`
}

type ConfigProtocolsMplsTeClass struct {
	Name *map[string]ConfigProtocolsMplsTeClassName `json:"name,omitempty"`
}

type ConfigProtocolsMplsTeClassName struct {
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigProtocolsMplsLspModel struct {
	Pipe string `json:"pipe,omitempty"`
}

type ConfigProtocolsMplsFtnEntry struct {
	TunnelId *map[string]ConfigProtocolsMplsFtnEntryTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelId struct {
	Ip       *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIp       `json:"ip,omitempty"`
	Ipv6mask *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask `json:"ipv6mask,omitempty"`
	Ipv4mask *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask `json:"ipv4mask,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIp struct {
	Mask *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpMask `json:"mask,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMask struct {
	OutLabel *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel struct {
	Nexthop *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop `json:"nexthop,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop struct {
	Interface *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask struct {
	OutLabel *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel struct {
	Nexthop *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop `json:"nexthop,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop struct {
	Interface *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask struct {
	OutLabel *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel struct {
	Nexthop *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop `json:"nexthop,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop struct {
	Interface *map[string]ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface struct {
	Primary   string `json:"primary,omitempty"`
	Secondary string `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsClassToExp struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsMplsL2Circuit struct {
	Ipv4 *map[string]ConfigProtocolsMplsL2CircuitIpv4 `json:"ipv4,omitempty"`
	Id   *map[string]ConfigProtocolsMplsL2CircuitId   `json:"id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4 struct {
	Agi *map[string]ConfigProtocolsMplsL2CircuitIpv4Agi `json:"agi,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4Agi struct {
	Saii *map[string]ConfigProtocolsMplsL2CircuitIpv4AgiSaii `json:"saii,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaii struct {
	Taii *map[string]ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii `json:"taii,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii struct {
	Manual      string                                                           `json:"manual,omitempty"`
	Groupname   *map[string]ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname `json:"groupname,omitempty"`
	ControlWord *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWord          `json:"control-word,omitempty"`
	TunnelId    *map[string]ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId  `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname struct {
	GroupId string `json:"group-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWord struct {
	Manual   string                                                                     `json:"manual,omitempty"`
	TunnelId *map[string]ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId struct {
	Passive string                                                                 `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdReverse `json:"reverse,omitempty"`
	Manual  string                                                                 `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdReverse struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdForward struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId struct {
	Passive string                                                      `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdReverse `json:"reverse,omitempty"`
	Manual  string                                                      `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdReverse struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdForward struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitId struct {
	Ipv4 *map[string]ConfigProtocolsMplsL2CircuitIdIpv4 `json:"ipv4,omitempty"`
	Ipv6 *map[string]ConfigProtocolsMplsL2CircuitIdIpv6 `json:"ipv6,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4 struct {
	Passive     string                                                  `json:"passive,omitempty"`
	Manual      string                                                  `json:"manual,omitempty"`
	Groupname   *map[string]ConfigProtocolsMplsL2CircuitIdIpv4Groupname `json:"groupname,omitempty"`
	ControlWord *ConfigProtocolsMplsL2CircuitIdIpv4ControlWord          `json:"control-word,omitempty"`
	TunnelId    *map[string]ConfigProtocolsMplsL2CircuitIdIpv4TunnelId  `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4Groupname struct {
	ControlWord *ConfigProtocolsMplsL2CircuitIdIpv4GroupnameControlWord `json:"control-word,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4GroupnameControlWord struct {
	Manual string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWord struct {
	Passive  string                                                            `json:"passive,omitempty"`
	Manual   string                                                            `json:"manual,omitempty"`
	TunnelId *map[string]ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId struct {
	Passive string                                                        `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdReverse `json:"reverse,omitempty"`
	Manual  string                                                        `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdReverse struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdForward struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4TunnelId struct {
	Passive string                                             `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdReverse `json:"reverse,omitempty"`
	Manual  string                                             `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdReverse struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdForward struct {
	Passive string `json:"passive,omitempty"`
	Manual  string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv6 struct {
	Manual string `json:"manual,omitempty"`
}

type ConfigProtocolsMplsMinLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsAdminGroup struct {
	Value EdgeOSInt `json:"value,omitempty"`
}

type ConfigProtocolsMplsMsPwStitch struct {
	Vc1 *map[string]ConfigProtocolsMplsMsPwStitchVc1 `json:"vc1,omitempty"`
}

type ConfigProtocolsMplsMsPwStitchVc1 struct {
	Vc2 *map[string]ConfigProtocolsMplsMsPwStitchVc1Vc2 `json:"vc2,omitempty"`
}

type ConfigProtocolsMplsMsPwStitchVc1Vc2 struct {
	Mtu *map[string]ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu `json:"mtu,omitempty"`
}

type ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu struct {
	Ethernet string    `json:"ethernet,omitempty"`
	Vlan     EdgeOSInt `json:"vlan,omitempty"`
}

type ConfigProtocolsMplsClassType struct {
	Name string `json:"name,omitempty"`
}

type ConfigProtocolsMplsIlmEntry struct {
	Interface *map[string]ConfigProtocolsMplsIlmEntryInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterface struct {
	Pop  string                                               `json:"pop,omitempty"`
	Swap *map[string]ConfigProtocolsMplsIlmEntryInterfaceSwap `json:"swap,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwap struct {
	Interface *map[string]ConfigProtocolsMplsIlmEntryInterfaceSwapInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwapInterface struct {
	Ip *map[string]ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp `json:"ip,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp struct {
	Fec *map[string]ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec `json:"fec,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec struct {
	Mask IPv4 `json:"mask,omitempty"`
}

type ConfigProtocolsMplsMapRoute struct {
	Fec IPv4Net `json:"fec,omitempty"`
}

type ConfigProtocolsMplsRsvp struct {
	MinLabelValue *map[string]ConfigProtocolsMplsRsvpMinLabelValue `json:"min-label-value,omitempty"`
	MaxLabelValue *map[string]ConfigProtocolsMplsRsvpMaxLabelValue `json:"max-label-value,omitempty"`
}

type ConfigProtocolsMplsRsvpMinLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsRsvpMaxLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsLdp struct {
	MinLabelValue *map[string]ConfigProtocolsMplsLdpMinLabelValue `json:"min-label-value,omitempty"`
	MaxLabelValue *map[string]ConfigProtocolsMplsLdpMaxLabelValue `json:"max-label-value,omitempty"`
}

type ConfigProtocolsMplsLdpMinLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsLdpMaxLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsBgp struct {
	MinLabelValue *map[string]ConfigProtocolsMplsBgpMinLabelValue `json:"min-label-value,omitempty"`
	MaxLabelValue *map[string]ConfigProtocolsMplsBgpMaxLabelValue `json:"max-label-value,omitempty"`
}

type ConfigProtocolsMplsBgpMinLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsBgpMaxLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsMaxLabelValue struct {
	LabelSpace string `json:"label-space,omitempty"`
}

type ConfigProtocolsBfd struct {
	Interface    *map[string]ConfigProtocolsBfdInterface    `json:"interface,omitempty"`
	Echo         string                                     `json:"echo,omitempty"`
	Notification *ConfigProtocolsBfdNotification            `json:"notification,omitempty"`
	SlowTimer    EdgeOSInt                                  `json:"slow-timer,omitempty"`
	Gtsm         *ConfigProtocolsBfdGtsm                    `json:"gtsm,omitempty"`
	MultihopPeer *map[string]ConfigProtocolsBfdMultihopPeer `json:"multihop-peer,omitempty"`
}

type ConfigProtocolsBfdInterface struct {
	Enable   string                                          `json:"enable,omitempty"`
	Echo     *ConfigProtocolsBfdInterfaceEcho                `json:"echo,omitempty"`
	Auth     *ConfigProtocolsBfdInterfaceAuth                `json:"auth,omitempty"`
	Interval *map[string]ConfigProtocolsBfdInterfaceInterval `json:"interval,omitempty"`
	Session  *ConfigProtocolsBfdInterfaceSession             `json:"session,omitempty"`
}

type ConfigProtocolsBfdInterfaceEcho struct {
	Interval EdgeOSInt `json:"interval,omitempty"`
}

type ConfigProtocolsBfdInterfaceAuth struct {
	Key  string `json:"key,omitempty"`
	Type string `json:"type,omitempty"`
}

type ConfigProtocolsBfdInterfaceInterval struct {
	Minrx *map[string]ConfigProtocolsBfdInterfaceIntervalMinrx `json:"minrx,omitempty"`
}

type ConfigProtocolsBfdInterfaceIntervalMinrx struct {
	Multiplier EdgeOSInt `json:"multiplier,omitempty"`
}

type ConfigProtocolsBfdInterfaceSession struct {
	Source *map[string]ConfigProtocolsBfdInterfaceSessionSource `json:"source,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSource struct {
	Dest *map[string]ConfigProtocolsBfdInterfaceSessionSourceDest `json:"dest,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDest struct {
	Multihop      *ConfigProtocolsBfdInterfaceSessionSourceDestMultihop      `json:"multihop,omitempty"`
	AdminDown     string                                                     `json:"admin-down,omitempty"`
	DemandMode    *ConfigProtocolsBfdInterfaceSessionSourceDestDemandMode    `json:"demand-mode,omitempty"`
	NonPersistent *ConfigProtocolsBfdInterfaceSessionSourceDestNonPersistent `json:"non-persistent,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestMultihop struct {
	AdminDown  string                                                          `json:"admin-down,omitempty"`
	DemandMode *ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandMode `json:"demand-mode,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandMode struct {
	AdminDown     string                                                                       `json:"admin-down,omitempty"`
	NonPersistent *ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandModeNonPersistent `json:"non-persistent,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandModeNonPersistent struct {
	AdminDown string `json:"admin-down,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestDemandMode struct {
	AdminDown     string                                                               `json:"admin-down,omitempty"`
	NonPersistent *ConfigProtocolsBfdInterfaceSessionSourceDestDemandModeNonPersistent `json:"non-persistent,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestDemandModeNonPersistent struct {
	AdminDown string `json:"admin-down,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestNonPersistent struct {
	AdminDown string `json:"admin-down,omitempty"`
}

type ConfigProtocolsBfdNotification struct {
	Enable string `json:"enable,omitempty"`
}

type ConfigProtocolsBfdGtsm struct {
	Enable string    `json:"enable,omitempty"`
	Ttl    EdgeOSInt `json:"ttl,omitempty"`
}

type ConfigProtocolsBfdMultihopPeer struct {
	Auth     *ConfigProtocolsBfdMultihopPeerAuth                `json:"auth,omitempty"`
	Interval *map[string]ConfigProtocolsBfdMultihopPeerInterval `json:"interval,omitempty"`
}

type ConfigProtocolsBfdMultihopPeerAuth struct {
	Key  string `json:"key,omitempty"`
	Type string `json:"type,omitempty"`
}

type ConfigProtocolsBfdMultihopPeerInterval struct {
	Minrx *map[string]ConfigProtocolsBfdMultihopPeerIntervalMinrx `json:"minrx,omitempty"`
}

type ConfigProtocolsBfdMultihopPeerIntervalMinrx struct {
	Multiplier EdgeOSInt `json:"multiplier,omitempty"`
}

type ConfigProtocolsRipng struct {
	Interface          []string                                `json:"interface,omitempty"`
	Route              []string                                `json:"route,omitempty"`
	Timers             *ConfigProtocolsRipngTimers             `json:"timers,omitempty"`
	Network            []string                                `json:"network,omitempty"`
	DefaultMetric      EdgeOSInt                               `json:"default-metric,omitempty"`
	AggregateAddress   []string                                `json:"aggregate-address,omitempty"`
	Vrf                *map[string]ConfigProtocolsRipngVrf     `json:".vrf,omitempty"`
	PassiveInterface   []string                                `json:"passive-interface,omitempty"`
	Redistribute       *ConfigProtocolsRipngRedistribute       `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipngDistributeList     `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipngDefaultInformation `json:"default-information,omitempty"`
}

type ConfigProtocolsRipngTimers struct {
	Update            EdgeOSInt `json:"update,omitempty"`
	Timeout           EdgeOSInt `json:"timeout,omitempty"`
	GarbageCollection EdgeOSInt `json:"garbage-collection,omitempty"`
}

type ConfigProtocolsRipngVrf struct {
	Interface          []string                                   `json:"interface,omitempty"`
	Route              []string                                   `json:"route,omitempty"`
	Timers             *ConfigProtocolsRipngVrfTimers             `json:"timers,omitempty"`
	Network            []string                                   `json:"network,omitempty"`
	DefaultMetric      EdgeOSInt                                  `json:"default-metric,omitempty"`
	AggregateAddress   []string                                   `json:"aggregate-address,omitempty"`
	PassiveInterface   []string                                   `json:"passive-interface,omitempty"`
	Redistribute       *ConfigProtocolsRipngVrfRedistribute       `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipngVrfDistributeList     `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipngVrfDefaultInformation `json:"default-information,omitempty"`
}

type ConfigProtocolsRipngVrfTimers struct {
	Update            EdgeOSInt `json:"update,omitempty"`
	Timeout           EdgeOSInt `json:"timeout,omitempty"`
	GarbageCollection EdgeOSInt `json:"garbage-collection,omitempty"`
}

type ConfigProtocolsRipngVrfRedistribute struct {
	Connected *ConfigProtocolsRipngVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipngVrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipngVrfRedistributeBgp       `json:"bgp,omitempty"`
	Ospfv3    *ConfigProtocolsRipngVrfRedistributeOspfv3    `json:"ospfv3,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeBgp struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeOspfv3 struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeList struct {
	Interface  *map[string]ConfigProtocolsRipngVrfDistributeListInterface `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipngVrfDistributeListAccessList           `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngVrfDistributeListPrefixList           `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListInterface struct {
	AccessList *ConfigProtocolsRipngVrfDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngVrfDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListInterfaceAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDefaultInformation struct {
	Originate string `json:"originate,omitempty"`
}

type ConfigProtocolsRipngRedistribute struct {
	Connected *ConfigProtocolsRipngRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipngRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipngRedistributeBgp       `json:"bgp,omitempty"`
	Ospfv3    *ConfigProtocolsRipngRedistributeOspfv3    `json:"ospfv3,omitempty"`
	Kernel    *ConfigProtocolsRipngRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsRipngRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeBgp struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeOspfv3 struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeKernel struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsRipngDistributeList struct {
	Interface  *map[string]ConfigProtocolsRipngDistributeListInterface `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipngDistributeListAccessList           `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngDistributeListPrefixList           `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngDistributeListInterface struct {
	AccessList *ConfigProtocolsRipngDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngDistributeListInterfaceAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipngDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngDistributeListAccessList struct {
	Out EdgeOSInt `json:"out,omitempty"`
	In  EdgeOSInt `json:"in,omitempty"`
}

type ConfigProtocolsRipngDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngDefaultInformation struct {
	Originate string `json:"originate,omitempty"`
}

type ConfigProtocolsVrf struct {
	Interface   []string                       `json:"interface,omitempty"`
	RouterId    IPv4                           `json:"router-id,omitempty"`
	RouteTarget *ConfigProtocolsVrfRouteTarget `json:"route-target,omitempty"`
	Description string                         `json:"description,omitempty"`
	Import      *ConfigProtocolsVrfImport      `json:"import,omitempty"`
	Rd          *ConfigProtocolsVrfRd          `json:"rd,omitempty"`
}

type ConfigProtocolsVrfRouteTarget struct {
	Both   string `json:"both,omitempty"`
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsVrfImport struct {
	Map string `json:"map,omitempty"`
}

type ConfigProtocolsVrfRd struct {
	Int string `json:"int,omitempty"`
	Ip  string `json:"ip,omitempty"`
}

type ConfigProtocolsStatic struct {
	InterfaceRoute6 *map[string]ConfigProtocolsStaticInterfaceRoute6 `json:"interface-route6,omitempty"`
	Route           *map[string]ConfigProtocolsStaticRoute           `json:"route,omitempty"`
	Bfd             *ConfigProtocolsStaticBfd                        `json:"bfd,omitempty"`
	Vrf             *map[string]ConfigProtocolsStaticVrf             `json:".vrf,omitempty"`
	Table           *map[string]ConfigProtocolsStaticTable           `json:"table,omitempty"`
	InterfaceRoute  *map[string]ConfigProtocolsStaticInterfaceRoute  `json:"interface-route,omitempty"`
	Arp             *map[string]ConfigProtocolsStaticArp             `json:"arp,omitempty"`
	Route6          *map[string]ConfigProtocolsStaticRoute6          `json:"route6,omitempty"`
}

type ConfigProtocolsStaticInterfaceRoute6 struct {
	NextHopInterface *map[string]ConfigProtocolsStaticInterfaceRoute6NextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticInterfaceRoute6NextHopInterface struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticRoute struct {
	NextHop   *map[string]ConfigProtocolsStaticRouteNextHop `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticRouteBlackhole          `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticRouteNextHop struct {
	Disable     string    `json:"disable,omitempty"`
	Bfd         string    `json:"bfd,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticRouteBlackhole struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticBfd struct {
	Interface     *map[string]ConfigProtocolsStaticBfdInterface `json:"interface,omitempty"`
	AllInterfaces *ConfigProtocolsStaticBfdAllInterfaces        `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsStaticBfdInterface struct {
	Ipv4 string `json:"ipv4,omitempty"`
	Ipv6 string `json:"ipv6,omitempty"`
}

type ConfigProtocolsStaticBfdAllInterfaces struct {
	Ipv4 string `json:"ipv4,omitempty"`
	Ipv6 string `json:"ipv6,omitempty"`
}

type ConfigProtocolsStaticVrf struct {
	InterfaceRoute6 *map[string]ConfigProtocolsStaticVrfInterfaceRoute6 `json:"interface-route6,omitempty"`
	Route           *map[string]ConfigProtocolsStaticVrfRoute           `json:"route,omitempty"`
	InterfaceRoute  *map[string]ConfigProtocolsStaticVrfInterfaceRoute  `json:"interface-route,omitempty"`
	Ip              *ConfigProtocolsStaticVrfIp                         `json:"ip,omitempty"`
	Route6          *map[string]ConfigProtocolsStaticVrfRoute6          `json:"route6,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute6 struct {
	NextHopInterface *map[string]ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface struct {
	Gw *map[string]ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw `json:"gw,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigProtocolsStaticVrfRoute struct {
	NextHop   *map[string]ConfigProtocolsStaticVrfRouteNextHop `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticVrfRouteBlackhole          `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticVrfRouteNextHop struct {
	Disable   string `json:"disable,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type ConfigProtocolsStaticVrfRouteBlackhole struct {
	Disable   string `json:"disable,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute struct {
	NextHopInterface *map[string]ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface struct {
	Disable string `json:"disable,omitempty"`
}

type ConfigProtocolsStaticVrfIp struct {
	Forwarding string `json:"forwarding,omitempty"`
}

type ConfigProtocolsStaticVrfRoute6 struct {
	NextHop *map[string]ConfigProtocolsStaticVrfRoute6NextHop `json:"next-hop,omitempty"`
}

type ConfigProtocolsStaticVrfRoute6NextHop struct {
	Disable   string `json:"disable,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type ConfigProtocolsStaticTable struct {
	InterfaceRoute6 *map[string]ConfigProtocolsStaticTableInterfaceRoute6 `json:"interface-route6,omitempty"`
	Route           *map[string]ConfigProtocolsStaticTableRoute           `json:"route,omitempty"`
	Mark            EdgeOSInt                                             `json:"mark,omitempty"`
	Description     string                                                `json:"description,omitempty"`
	InterfaceRoute  *map[string]ConfigProtocolsStaticTableInterfaceRoute  `json:"interface-route,omitempty"`
	Route6          *map[string]ConfigProtocolsStaticTableRoute6          `json:"route6,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRoute6 struct {
	NextHopInterface *map[string]ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRoute struct {
	NextHop   *map[string]ConfigProtocolsStaticTableRouteNextHop `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticTableRouteBlackhole          `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticTableRouteNextHop struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRouteBlackhole struct {
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRoute struct {
	NextHopInterface *map[string]ConfigProtocolsStaticTableInterfaceRouteNextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRouteNextHopInterface struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRoute6 struct {
	NextHop   *map[string]ConfigProtocolsStaticTableRoute6NextHop `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticTableRoute6Blackhole          `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticTableRoute6NextHop struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRoute6Blackhole struct {
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticInterfaceRoute struct {
	NextHopInterface *map[string]ConfigProtocolsStaticInterfaceRouteNextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticInterfaceRouteNextHopInterface struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticArp struct {
	Hwaddr MacAddr `json:"hwaddr,omitempty"`
}

type ConfigProtocolsStaticRoute6 struct {
	NextHop   *map[string]ConfigProtocolsStaticRoute6NextHop `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticRoute6Blackhole          `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticRoute6NextHop struct {
	Disable     string    `json:"disable,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	Bfd         string    `json:"bfd,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsStaticRoute6Blackhole struct {
	Disable     string    `json:"disable,omitempty"`
	Distance    EdgeOSInt `json:"distance,omitempty"`
	Description string    `json:"description,omitempty"`
}

type ConfigProtocolsRsvp struct {
	HelloTimeout             EdgeOSInt                                `json:"hello-timeout,omitempty"`
	Interface                *map[string]ConfigProtocolsRsvpInterface `json:"interface,omitempty"`
	Neighbor                 string                                   `json:"neighbor,omitempty"`
	BundleSend               string                                   `json:"bundle-send,omitempty"`
	ExplicitNull             string                                   `json:"explicit-null,omitempty"`
	OverrideDiffserv         string                                   `json:"override-diffserv,omitempty"`
	PreprogramSuggestedLabel string                                   `json:"preprogram-suggested-label,omitempty"`
	Notification             string                                   `json:"notification,omitempty"`
	Path                     *map[string]ConfigProtocolsRsvpPath      `json:"path,omitempty"`
	From                     IP                                       `json:"from,omitempty"`
	AckWaitTimeout           EdgeOSInt                                `json:"ack-wait-timeout,omitempty"`
	RefreshPathParsing       string                                   `json:"refresh-path-parsing,omitempty"`
	Cspf                     string                                   `json:"cspf,omitempty"`
	GracefulRestart          *ConfigProtocolsRsvpGracefulRestart      `json:"graceful-restart,omitempty"`
	RefreshResvParsing       string                                   `json:"refresh-resv-parsing,omitempty"`
	MessageAck               string                                   `json:"message-ack,omitempty"`
	RefreshReduction         string                                   `json:"refresh-reduction,omitempty"`
	LocalProtection          string                                   `json:"local-protection,omitempty"`
	RefreshTime              EdgeOSInt                                `json:"refresh-time,omitempty"`
	NoPhp                    string                                   `json:"no-php,omitempty"`
	HelloReceipt             string                                   `json:"hello-receipt,omitempty"`
	KeepMultiplier           EdgeOSInt                                `json:"keep-multiplier,omitempty"`
	LoopDetection            string                                   `json:"loop-detection,omitempty"`
	HelloInterval            EdgeOSInt                                `json:"hello-interval,omitempty"`
	Trunk                    *map[string]ConfigProtocolsRsvpTrunk     `json:"trunk,omitempty"`
}

type ConfigProtocolsRsvpInterface struct {
	HelloTimeout     string `json:"hello-timeout,omitempty"`
	Disable          string `json:"disable,omitempty"`
	AckWaitTimeout   string `json:"ack-wait-timeout,omitempty"`
	MessageAck       string `json:"message-ack,omitempty"`
	RefreshReduction string `json:"refresh-reduction,omitempty"`
	RefreshTime      string `json:"refresh-time,omitempty"`
	HelloReceipt     string `json:"hello-receipt,omitempty"`
	KeepMultiplier   string `json:"keep-multiplier,omitempty"`
	NonIanaHello     string `json:"non-IANA-hello,omitempty"`
	HelloInterval    string `json:"hello-interval,omitempty"`
}

type ConfigProtocolsRsvpPath struct {
	Mpls  *ConfigProtocolsRsvpPathMpls  `json:"mpls,omitempty"`
	Gmpls *ConfigProtocolsRsvpPathGmpls `json:".gmpls,omitempty"`
}

type ConfigProtocolsRsvpPathMpls struct {
	Loose      IP                                                `json:"loose,omitempty"`
	Unnumbered *map[string]ConfigProtocolsRsvpPathMplsUnnumbered `json:".unnumbered,omitempty"`
	Strict     IP                                                `json:"strict,omitempty"`
	StrictHop  IP                                                `json:".strict-hop,omitempty"`
}

type ConfigProtocolsRsvpPathMplsUnnumbered struct {
	LinkId IPv4 `json:"link-id,omitempty"`
}

type ConfigProtocolsRsvpPathGmpls struct {
	StrictHop  IP                                                 `json:"strict-hop,omitempty"`
	Unnumbered *map[string]ConfigProtocolsRsvpPathGmplsUnnumbered `json:"unnumbered,omitempty"`
	Strict     IP                                                 `json:".strict,omitempty"`
	Loose      IP                                                 `json:".loose,omitempty"`
}

type ConfigProtocolsRsvpPathGmplsUnnumbered struct {
	LinkId IPv4 `json:"link-id,omitempty"`
}

type ConfigProtocolsRsvpGracefulRestart struct {
	Enable       string    `json:"enable,omitempty"`
	RestartTime  EdgeOSInt `json:"restart-time,omitempty"`
	RecoveryTime EdgeOSInt `json:"recovery-time,omitempty"`
}

type ConfigProtocolsRsvpTrunk struct {
	Gmpls *ConfigProtocolsRsvpTrunkGmpls `json:".gmpls,omitempty"`
	Ipv4  *ConfigProtocolsRsvpTrunkIpv4  `json:"ipv4,omitempty"`
	Ipv6  *ConfigProtocolsRsvpTrunkIpv6  `json:".ipv6,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmpls struct {
	ExtTunnelId        IP                                          `json:"ext-tunnel-id,omitempty"`
	LspMetric          *ConfigProtocolsRsvpTrunkGmplsLspMetric     `json:"lsp-metric,omitempty"`
	EnableIgpShortcut  string                                      `json:".enable-igp-shortcut,omitempty"`
	Capability         *ConfigProtocolsRsvpTrunkGmplsCapability    `json:"capability,omitempty"`
	From               IP                                          `json:"from,omitempty"`
	Gpid               *ConfigProtocolsRsvpTrunkGmplsGpid          `json:"gpid,omitempty"`
	RsvpTrunkRestart   string                                      `json:"rsvp-trunk-restart,omitempty"`
	GmplsLabelSet      *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSet `json:"gmpls-label-set,omitempty"`
	Direction          *ConfigProtocolsRsvpTrunkGmplsDirection     `json:"direction,omitempty"`
	UpdateType         *ConfigProtocolsRsvpTrunkGmplsUpdateType    `json:"update-type,omitempty"`
	DisableIgpShortcut string                                      `json:".disable-igp-shortcut,omitempty"`
	Primary            *ConfigProtocolsRsvpTrunkGmplsPrimary       `json:"primary,omitempty"`
	To                 IP                                          `json:"to,omitempty"`
	Secondary          *ConfigProtocolsRsvpTrunkGmplsSecondary     `json:"secondary,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsLspMetric struct {
	Relative EdgeOSInt `json:"relative,omitempty"`
	Absolute EdgeOSInt `json:"absolute,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsCapability struct {
	Psc1  string `json:"psc-1,omitempty"`
	PbbTe string `json:"pbb-te,omitempty"`
	Psc4  string `json:"psc-4,omitempty"`
	Psc3  string `json:"psc-3,omitempty"`
	Psc2  string `json:"psc-2,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGpid struct {
	Ethernet string `json:"ethernet,omitempty"`
	Ipv4     string `json:"ipv4,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSet struct {
	Range  *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRange  `json:"range,omitempty"`
	Packet *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacket `json:"packet,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRange struct {
	StartRange *map[string]ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange struct {
	EndRange EdgeOSInt `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacket struct {
	Range *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRange `json:"range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRange struct {
	StartRange *map[string]ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange struct {
	EndRange EdgeOSInt `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsDirection struct {
	Bidirectional  string `json:"bidirectional,omitempty"`
	Unidirectional string `json:"unidirectional,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsUpdateType struct {
	MakeBeforeBreak string `json:"make-before-break,omitempty"`
	BreakBeforeMake string `json:"break-before-make,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimary struct {
	Traffic           *ConfigProtocolsRsvpTrunkGmplsPrimaryTraffic                  `json:"traffic,omitempty"`
	Bandwidth         EdgeOSInt                                                     `json:"bandwidth,omitempty"`
	SetupPriority     EdgeOSInt                                                     `json:"setup-priority,omitempty"`
	Record            string                                                        `json:"record,omitempty"`
	IncludeAny        string                                                        `json:"include-any,omitempty"`
	Affinity          string                                                        `json:"affinity,omitempty"`
	ReuseRouteRecord  string                                                        `json:"reuse-route-record,omitempty"`
	ElspPreconfigured string                                                        `json:"elsp-preconfigured,omitempty"`
	Path              string                                                        `json:"path,omitempty"`
	HoldPriority      EdgeOSInt                                                     `json:"hold-priority,omitempty"`
	HopLimit          EdgeOSInt                                                     `json:"hop-limit,omitempty"`
	Cspf              string                                                        `json:"cspf,omitempty"`
	LabelRecord       string                                                        `json:"label-record,omitempty"`
	NoAffinity        string                                                        `json:"no-affinity,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkGmplsPrimaryProtection               `json:"protection,omitempty"`
	RetryLimit        EdgeOSInt                                                     `json:"retry-limit,omitempty"`
	CspfRetryTimer    EdgeOSInt                                                     `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                                        `json:"class-type,omitempty"`
	ElspSignaled      string                                                        `json:"elsp-signaled,omitempty"`
	LocalProtection   string                                                        `json:"local-protection,omitempty"`
	ClassToExpBit     *map[string]ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkGmplsPrimaryFilter                   `json:"filter,omitempty"`
	ExplicitLabel     *map[string]ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel `json:"explicit-label,omitempty"`
	CspfRetryLimit    EdgeOSInt                                                     `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                                        `json:"exclude-any,omitempty"`
	RetryTimer        EdgeOSInt                                                     `json:"retry-timer,omitempty"`
	NoRecord          string                                                        `json:"no-record,omitempty"`
	Llsp              string                                                        `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryTraffic struct {
	ControlledLoad string `json:"controlled-load,omitempty"`
	Guaranteed     string `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryProtection struct {
	Unprotected         string `json:"unprotected,omitempty"`
	DedicatedOneToOne   string `json:"dedicated-one-to-one,omitempty"`
	Shared              string `json:"shared,omitempty"`
	ExtraTraffic        string `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne string `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             string `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryFilter struct {
	SharedExplicit string `json:"shared-explicit,omitempty"`
	Fixed          string `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel struct {
	Reverse string                                                   `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward string                                                   `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabelPacket struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondary struct {
	Traffic           *ConfigProtocolsRsvpTrunkGmplsSecondaryTraffic                  `json:"traffic,omitempty"`
	Bandwidth         EdgeOSInt                                                       `json:"bandwidth,omitempty"`
	SetupPriority     EdgeOSInt                                                       `json:"setup-priority,omitempty"`
	Record            string                                                          `json:"record,omitempty"`
	IncludeAny        string                                                          `json:"include-any,omitempty"`
	Affinity          string                                                          `json:"affinity,omitempty"`
	ReuseRouteRecord  string                                                          `json:"reuse-route-record,omitempty"`
	ElspPreconfigured string                                                          `json:"elsp-preconfigured,omitempty"`
	Path              string                                                          `json:"path,omitempty"`
	HoldPriority      EdgeOSInt                                                       `json:"hold-priority,omitempty"`
	HopLimit          EdgeOSInt                                                       `json:"hop-limit,omitempty"`
	Cspf              string                                                          `json:"cspf,omitempty"`
	LabelRecord       string                                                          `json:"label-record,omitempty"`
	NoAffinity        string                                                          `json:"no-affinity,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkGmplsSecondaryProtection               `json:"protection,omitempty"`
	RetryLimit        EdgeOSInt                                                       `json:"retry-limit,omitempty"`
	CspfRetryTimer    EdgeOSInt                                                       `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                                          `json:"class-type,omitempty"`
	ElspSignaled      string                                                          `json:"elsp-signaled,omitempty"`
	LocalProtection   string                                                          `json:"local-protection,omitempty"`
	ClassToExpBit     *map[string]ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkGmplsSecondaryFilter                   `json:"filter,omitempty"`
	ExplicitLabel     *map[string]ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel `json:"explicit-label,omitempty"`
	CspfRetryLimit    EdgeOSInt                                                       `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                                          `json:"exclude-any,omitempty"`
	RetryTimer        EdgeOSInt                                                       `json:"retry-timer,omitempty"`
	NoRecord          string                                                          `json:"no-record,omitempty"`
	Llsp              string                                                          `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryTraffic struct {
	ControlledLoad string `json:"controlled-load,omitempty"`
	Guaranteed     string `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryProtection struct {
	Unprotected         string `json:"unprotected,omitempty"`
	DedicatedOneToOne   string `json:"dedicated-one-to-one,omitempty"`
	Shared              string `json:"shared,omitempty"`
	ExtraTraffic        string `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne string `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             string `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryFilter struct {
	SharedExplicit string `json:"shared-explicit,omitempty"`
	Fixed          string `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel struct {
	Reverse string                                                     `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward string                                                     `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabelPacket struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4 struct {
	ExtTunnelId       IP                                               `json:"ext-tunnel-id,omitempty"`
	LspMetric         *ConfigProtocolsRsvpTrunkIpv4LspMetric           `json:"lsp-metric,omitempty"`
	From              IPv4                                             `json:"from,omitempty"`
	RsvpTrunkRestart  string                                           `json:".rsvp-trunk-restart,omitempty"`
	Capability        *ConfigProtocolsRsvpTrunkIpv4Capability          `json:".capability,omitempty"`
	Direction         *ConfigProtocolsRsvpTrunkIpv4Direction           `json:".direction,omitempty"`
	MapRoute          *map[string]ConfigProtocolsRsvpTrunkIpv4MapRoute `json:"map-route,omitempty"`
	UpdateType        string                                           `json:"update-type,omitempty"`
	Primary           *ConfigProtocolsRsvpTrunkIpv4Primary             `json:"primary,omitempty"`
	To                IPv4                                             `json:"to,omitempty"`
	EnableIgpShortcut string                                           `json:"enable-igp-shortcut,omitempty"`
	Secondary         *ConfigProtocolsRsvpTrunkIpv4Secondary           `json:"secondary,omitempty"`
	GmplsLabelSet     *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSet       `json:".gmpls-label-set,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4LspMetric struct {
	Relative EdgeOSInt `json:"relative,omitempty"`
	Absolute EdgeOSInt `json:"absolute,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Capability struct {
	Psc1 string `json:"psc-1,omitempty"`
	Psc4 string `json:"psc-4,omitempty"`
	Psc3 string `json:"psc-3,omitempty"`
	Psc2 string `json:"psc-2,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Direction struct {
	Bidirectional  string `json:"bidirectional,omitempty"`
	Unidirectional string `json:"unidirectional,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4MapRoute struct {
	Class string `json:"class,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Primary struct {
	Traffic           string                                                       `json:"traffic,omitempty"`
	Bandwidth         string                                                       `json:"bandwidth,omitempty"`
	SetupPriority     EdgeOSInt                                                    `json:"setup-priority,omitempty"`
	Record            string                                                       `json:"record,omitempty"`
	IncludeAny        string                                                       `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv4PrimaryProtection               `json:".protection,omitempty"`
	ReuseRouteRecord  string                                                       `json:"reuse-route-record,omitempty"`
	ElspPreconfigured string                                                       `json:"elsp-preconfigured,omitempty"`
	Path              string                                                       `json:"path,omitempty"`
	ExplicitLabel     *map[string]ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel `json:".explicit-label,omitempty"`
	ClassToExp        *map[string]ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp    `json:"class-to-exp,omitempty"`
	HoldPriority      EdgeOSInt                                                    `json:"hold-priority,omitempty"`
	HopLimit          EdgeOSInt                                                    `json:"hop-limit,omitempty"`
	Cspf              string                                                       `json:"cspf,omitempty"`
	LabelRecord       string                                                       `json:"label-record,omitempty"`
	NoAffinity        string                                                       `json:"no-affinity,omitempty"`
	RetryLimit        EdgeOSInt                                                    `json:"retry-limit,omitempty"`
	CspfRetryTimer    EdgeOSInt                                                    `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                                       `json:"class-type,omitempty"`
	NoRecord          string                                                       `json:".no-record,omitempty"`
	ElspSignaled      string                                                       `json:"elsp-signaled,omitempty"`
	LocalProtection   string                                                       `json:"local-protection,omitempty"`
	Filter            string                                                       `json:"filter,omitempty"`
	CspfRetryLimit    EdgeOSInt                                                    `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                                       `json:"exclude-any,omitempty"`
	RetryTimer        EdgeOSInt                                                    `json:"retry-timer,omitempty"`
	Llsp              string                                                       `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryProtection struct {
	Unprotected         string `json:"unprotected,omitempty"`
	DedicatedOneToOne   string `json:"dedicated-one-to-one,omitempty"`
	Shared              string `json:"shared,omitempty"`
	ExtraTraffic        string `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne string `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             string `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel struct {
	Reverse string                                                  `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward string                                                  `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabelPacket struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Secondary struct {
	Traffic           string                                                         `json:"traffic,omitempty"`
	Bandwidth         string                                                         `json:"bandwidth,omitempty"`
	SetupPriority     EdgeOSInt                                                      `json:"setup-priority,omitempty"`
	Record            string                                                         `json:"record,omitempty"`
	IncludeAny        string                                                         `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv4SecondaryProtection               `json:".protection,omitempty"`
	ReuseRouteRecord  string                                                         `json:"reuse-route-record,omitempty"`
	ElspPreconfigured string                                                         `json:"elsp-preconfigured,omitempty"`
	Path              string                                                         `json:"path,omitempty"`
	ExplicitLabel     *map[string]ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel `json:".explicit-label,omitempty"`
	ClassToExp        *map[string]ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp    `json:"class-to-exp,omitempty"`
	HoldPriority      EdgeOSInt                                                      `json:"hold-priority,omitempty"`
	HopLimit          EdgeOSInt                                                      `json:"hop-limit,omitempty"`
	Cspf              string                                                         `json:"cspf,omitempty"`
	LabelRecord       string                                                         `json:"label-record,omitempty"`
	NoAffinity        string                                                         `json:"no-affinity,omitempty"`
	RetryLimit        EdgeOSInt                                                      `json:"retry-limit,omitempty"`
	CspfRetryTimer    EdgeOSInt                                                      `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                                         `json:"class-type,omitempty"`
	NoRecord          string                                                         `json:".no-record,omitempty"`
	ElspSignaled      string                                                         `json:"elsp-signaled,omitempty"`
	LocalProtection   string                                                         `json:"local-protection,omitempty"`
	Filter            string                                                         `json:"filter,omitempty"`
	CspfRetryLimit    EdgeOSInt                                                      `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                                         `json:"exclude-any,omitempty"`
	RetryTimer        EdgeOSInt                                                      `json:"retry-timer,omitempty"`
	Llsp              string                                                         `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryProtection struct {
	Unprotected         string `json:"unprotected,omitempty"`
	DedicatedOneToOne   string `json:"dedicated-one-to-one,omitempty"`
	Shared              string `json:"shared,omitempty"`
	ExtraTraffic        string `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne string `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             string `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel struct {
	Reverse string                                                    `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward string                                                    `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabelPacket struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSet struct {
	Range  *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRange  `json:"range,omitempty"`
	Packet *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacket `json:"packet,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRange struct {
	StartRange *map[string]ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange struct {
	EndRange EdgeOSInt `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacket struct {
	Range *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRange `json:"range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRange struct {
	StartRange *map[string]ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange struct {
	EndRange EdgeOSInt `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6 struct {
	ExtTunnelId        IP                                         `json:"ext-tunnel-id,omitempty"`
	LspMetric          *ConfigProtocolsRsvpTrunkIpv6LspMetric     `json:"lsp-metric,omitempty"`
	From               IP                                         `json:"from,omitempty"`
	Ethernet           string                                     `json:"ethernet,omitempty"`
	RsvpTrunkRestart   string                                     `json:"rsvp-trunk-restart,omitempty"`
	Capability         *ConfigProtocolsRsvpTrunkIpv6Capability    `json:".capability,omitempty"`
	Direction          *ConfigProtocolsRsvpTrunkIpv6Direction     `json:".direction,omitempty"`
	MapRoute           *ConfigProtocolsRsvpTrunkIpv6MapRoute      `json:"map-route,omitempty"`
	DisableIgpShortcut string                                     `json:"disable-igp-shortcut,omitempty"`
	UpdateType         *ConfigProtocolsRsvpTrunkIpv6UpdateType    `json:"update-type,omitempty"`
	Primary            *ConfigProtocolsRsvpTrunkIpv6Primary       `json:"primary,omitempty"`
	To                 IP                                         `json:"to,omitempty"`
	EnableIgpShortcut  string                                     `json:"enable-igp-shortcut,omitempty"`
	Secondary          *ConfigProtocolsRsvpTrunkIpv6Secondary     `json:"secondary,omitempty"`
	GmplsLabelSet      *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSet `json:".gmpls-label-set,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6LspMetric struct {
	Relative EdgeOSInt `json:"relative,omitempty"`
	Absolute EdgeOSInt `json:"absolute,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Capability struct {
	Psc1 string `json:"psc-1,omitempty"`
	Psc4 string `json:"psc-4,omitempty"`
	Psc3 string `json:"psc-3,omitempty"`
	Psc2 string `json:"psc-2,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Direction struct {
	Bidirectional  string `json:"bidirectional,omitempty"`
	Unidirectional string `json:"unidirectional,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRoute struct {
	Prefix *map[string]ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix `json:"prefix,omitempty"`
	Mask   *map[string]ConfigProtocolsRsvpTrunkIpv6MapRouteMask   `json:"mask,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix struct {
	Mask *map[string]ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask `json:"mask,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask struct {
	Class string `json:"class,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRouteMask struct {
	Class string `json:"class,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6UpdateType struct {
	MakeBeforeBreak string `json:"make-before-break,omitempty"`
	BreakBeforeMake string `json:"break-before-make,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Primary struct {
	Traffic           *ConfigProtocolsRsvpTrunkIpv6PrimaryTraffic                  `json:"traffic,omitempty"`
	Bandwidth         EdgeOSInt                                                    `json:"bandwidth,omitempty"`
	SetupPriority     EdgeOSInt                                                    `json:"setup-priority,omitempty"`
	Record            string                                                       `json:"record,omitempty"`
	IncludeAny        string                                                       `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv6PrimaryProtection               `json:".protection,omitempty"`
	Affinity          string                                                       `json:"affinity,omitempty"`
	ReuseRouteRecord  string                                                       `json:"reuse-route-record,omitempty"`
	ElspPreconfigured string                                                       `json:"elsp-preconfigured,omitempty"`
	Path              string                                                       `json:"path,omitempty"`
	ExplicitLabel     *map[string]ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel `json:".explicit-label,omitempty"`
	HoldPriority      EdgeOSInt                                                    `json:"hold-priority,omitempty"`
	HopLimit          EdgeOSInt                                                    `json:"hop-limit,omitempty"`
	Cspf              string                                                       `json:"cspf,omitempty"`
	LabelRecord       string                                                       `json:"label-record,omitempty"`
	RetryLimit        EdgeOSInt                                                    `json:"retry-limit,omitempty"`
	CspfRetryTimer    EdgeOSInt                                                    `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                                       `json:"class-type,omitempty"`
	NoRecord          string                                                       `json:".no-record,omitempty"`
	ElspSignaled      string                                                       `json:"elsp-signaled,omitempty"`
	NoAffinity        string                                                       `json:".no-affinity,omitempty"`
	LocalProtection   string                                                       `json:"local-protection,omitempty"`
	ClassToExpBit     *map[string]ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkIpv6PrimaryFilter                   `json:"filter,omitempty"`
	CspfRetryLimit    EdgeOSInt                                                    `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                                       `json:"exclude-any,omitempty"`
	RetryTimer        EdgeOSInt                                                    `json:"retry-timer,omitempty"`
	Llsp              string                                                       `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryTraffic struct {
	ControlledLoad string `json:"controlled-load,omitempty"`
	Guaranteed     string `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryProtection struct {
	Unprotected         string `json:"unprotected,omitempty"`
	DedicatedOneToOne   string `json:"dedicated-one-to-one,omitempty"`
	Shared              string `json:"shared,omitempty"`
	ExtraTraffic        string `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne string `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             string `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel struct {
	Reverse string                                                  `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward string                                                  `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabelPacket struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryFilter struct {
	SharedExplicit string `json:"shared-explicit,omitempty"`
	Fixed          string `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Secondary struct {
	Traffic           *ConfigProtocolsRsvpTrunkIpv6SecondaryTraffic                  `json:"traffic,omitempty"`
	Bandwidth         EdgeOSInt                                                      `json:"bandwidth,omitempty"`
	SetupPriority     EdgeOSInt                                                      `json:"setup-priority,omitempty"`
	Record            string                                                         `json:"record,omitempty"`
	IncludeAny        string                                                         `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv6SecondaryProtection               `json:".protection,omitempty"`
	Affinity          string                                                         `json:"affinity,omitempty"`
	ReuseRouteRecord  string                                                         `json:"reuse-route-record,omitempty"`
	ElspPreconfigured string                                                         `json:"elsp-preconfigured,omitempty"`
	Path              string                                                         `json:"path,omitempty"`
	ExplicitLabel     *map[string]ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel `json:".explicit-label,omitempty"`
	HoldPriority      EdgeOSInt                                                      `json:"hold-priority,omitempty"`
	HopLimit          EdgeOSInt                                                      `json:"hop-limit,omitempty"`
	Cspf              string                                                         `json:"cspf,omitempty"`
	LabelRecord       string                                                         `json:"label-record,omitempty"`
	RetryLimit        EdgeOSInt                                                      `json:"retry-limit,omitempty"`
	CspfRetryTimer    EdgeOSInt                                                      `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                                         `json:"class-type,omitempty"`
	NoRecord          string                                                         `json:".no-record,omitempty"`
	ElspSignaled      string                                                         `json:"elsp-signaled,omitempty"`
	NoAffinity        string                                                         `json:".no-affinity,omitempty"`
	LocalProtection   string                                                         `json:"local-protection,omitempty"`
	ClassToExpBit     *map[string]ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkIpv6SecondaryFilter                   `json:"filter,omitempty"`
	CspfRetryLimit    EdgeOSInt                                                      `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                                         `json:"exclude-any,omitempty"`
	RetryTimer        EdgeOSInt                                                      `json:"retry-timer,omitempty"`
	Llsp              string                                                         `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryTraffic struct {
	ControlledLoad string `json:"controlled-load,omitempty"`
	Guaranteed     string `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryProtection struct {
	Unprotected         string `json:"unprotected,omitempty"`
	DedicatedOneToOne   string `json:"dedicated-one-to-one,omitempty"`
	Shared              string `json:"shared,omitempty"`
	ExtraTraffic        string `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne string `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             string `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel struct {
	Reverse string                                                    `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward string                                                    `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabelPacket struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit struct {
	Bit string `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryFilter struct {
	SharedExplicit string `json:"shared-explicit,omitempty"`
	Fixed          string `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSet struct {
	Range  *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRange  `json:"range,omitempty"`
	Packet *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacket `json:"packet,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRange struct {
	StartRange *map[string]ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange struct {
	EndRange EdgeOSInt `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacket struct {
	Range *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRange `json:"range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRange struct {
	StartRange *map[string]ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange struct {
	EndRange EdgeOSInt `json:"end_range,omitempty"`
}

type ConfigProtocolsVpls struct {
	Interface *map[string]ConfigProtocolsVplsInterface `json:"interface,omitempty"`
	FibEntry  *map[string]ConfigProtocolsVplsFibEntry  `json:"fib-entry,omitempty"`
	Instance  *map[string]ConfigProtocolsVplsInstance  `json:"instance,omitempty"`
}

type ConfigProtocolsVplsInterface struct {
	VlanInstance *map[string]ConfigProtocolsVplsInterfaceVlanInstance `json:"vlan-instance,omitempty"`
	Instance     string                                               `json:"instance,omitempty"`
}

type ConfigProtocolsVplsInterfaceVlanInstance struct {
	Vlan *map[string]ConfigProtocolsVplsInterfaceVlanInstanceVlan `json:"vlan,omitempty"`
}

type ConfigProtocolsVplsInterfaceVlanInstanceVlan struct {
}

type ConfigProtocolsVplsFibEntry struct {
	Peer    *map[string]ConfigProtocolsVplsFibEntryPeer    `json:"peer,omitempty"`
	SpokeVc *map[string]ConfigProtocolsVplsFibEntrySpokeVc `json:".spoke-vc,omitempty"`
}

type ConfigProtocolsVplsFibEntryPeer struct {
	InLabel *map[string]ConfigProtocolsVplsFibEntryPeerInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsVplsFibEntryPeerInLabel struct {
	OutInterface *map[string]ConfigProtocolsVplsFibEntryPeerInLabelOutInterface `json:"out-interface,omitempty"`
}

type ConfigProtocolsVplsFibEntryPeerInLabelOutInterface struct {
	OutLabel string `json:"out-label,omitempty"`
}

type ConfigProtocolsVplsFibEntrySpokeVc struct {
	InLabel *map[string]ConfigProtocolsVplsFibEntrySpokeVcInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsVplsFibEntrySpokeVcInLabel struct {
	OutInterface *map[string]ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface `json:"out-interface,omitempty"`
}

type ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface struct {
	OutLabel string `json:"out-label,omitempty"`
}

type ConfigProtocolsVplsInstance struct {
	Id *map[string]ConfigProtocolsVplsInstanceId `json:"id,omitempty"`
}

type ConfigProtocolsVplsInstanceId struct {
	VplsAcGroup     string                                            `json:"vpls-ac-group,omitempty"`
	VplsPeer        *map[string]ConfigProtocolsVplsInstanceIdVplsPeer `json:"vpls-peer,omitempty"`
	Learning        *ConfigProtocolsVplsInstanceIdLearning            `json:"learning,omitempty"`
	VplsVc          *map[string]ConfigProtocolsVplsInstanceIdVplsVc   `json:"vpls-vc,omitempty"`
	VplsDescription string                                            `json:"vpls-description,omitempty"`
	Signaling       *ConfigProtocolsVplsInstanceIdSignaling           `json:"signaling,omitempty"`
	VplsType        string                                            `json:"vpls-type,omitempty"`
	VplsMtu         string                                            `json:"vpls-mtu,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeer struct {
	Manual   string                                                    `json:"manual,omitempty"`
	TunnelId *map[string]ConfigProtocolsVplsInstanceIdVplsPeerTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeerTunnelId struct {
	Reverse *ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdReverse `json:"reverse,omitempty"`
	Manual  string                                                `json:"manual,omitempty"`
	Forward *ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdReverse struct {
	Manual string `json:"manual,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdForward struct {
	Manual string `json:"manual,omitempty"`
}

type ConfigProtocolsVplsInstanceIdLearning struct {
	Disable string    `json:"disable,omitempty"`
	Limit   EdgeOSInt `json:"limit,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsVc struct {
	Ethernet string `json:"ethernet,omitempty"`
	Vlan     string `json:"vlan,omitempty"`
	Normal   string `json:"normal,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignaling struct {
	Ldp *ConfigProtocolsVplsInstanceIdSignalingLdp `json:"ldp,omitempty"`
	Bgp *ConfigProtocolsVplsInstanceIdSignalingBgp `json:"bgp,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdp struct {
	VplsPeer *map[string]ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer `json:"vpls-peer,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer struct {
	Agi      *map[string]ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi      `json:"agi,omitempty"`
	TunnelId *map[string]ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi struct {
	Saii *map[string]ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii `json:"saii,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii struct {
	Taii *map[string]ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii `json:"taii,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii struct {
	Normal   string                                                                           `json:"normal,omitempty"`
	TunnelId *map[string]ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId struct {
	Reverse string `json:"reverse,omitempty"`
	Normal  string `json:"normal,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId struct {
	Reverse string `json:"reverse,omitempty"`
	Forward string `json:"forward,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingBgp struct {
	VeRange     string `json:"ve-range,omitempty"`
	VeId        string `json:"ve-id,omitempty"`
	RouteTarget string `json:"route-target,omitempty"`
	Rd          string `json:"rd,omitempty"`
}

type ConfigProtocolsLdp struct {
	LdpOptimization           string                                   `json:"ldp-optimization,omitempty"`
	TargetedPeerHelloInterval string                                   `json:"targeted-peer-hello-interval,omitempty"`
	Interface                 *map[string]ConfigProtocolsLdpInterface  `json:"interface,omitempty"`
	Neighbor                  *map[string]ConfigProtocolsLdpNeighbor   `json:"neighbor,omitempty"`
	MulticastHellos           string                                   `json:"multicast-hellos,omitempty"`
	ExplicitNull              string                                   `json:"explicit-null,omitempty"`
	ImportBgpRoutes           string                                   `json:"import-bgp-routes,omitempty"`
	AdvertiseLabels           *ConfigProtocolsLdpAdvertiseLabels       `json:"advertise-labels,omitempty"`
	KeepaliveTimeout          string                                   `json:"keepalive-timeout,omitempty"`
	PropagateRelease          string                                   `json:"propagate-release,omitempty"`
	TransportAddress          *ConfigProtocolsLdpTransportAddress      `json:"transport-address,omitempty"`
	RouterId                  string                                   `json:"router-id,omitempty"`
	ControlMode               *ConfigProtocolsLdpControlMode           `json:"control-mode,omitempty"`
	LabelRetentionMode        *ConfigProtocolsLdpLabelRetentionMode    `json:"label-retention-mode,omitempty"`
	RequestRetryTimeout       string                                   `json:"request-retry-timeout,omitempty"`
	GracefulRestart           *ConfigProtocolsLdpGracefulRestart       `json:"graceful-restart,omitempty"`
	TargetedPeerHoldTime      string                                   `json:"targeted-peer-hold-time,omitempty"`
	LoopDetectionPathVecCount string                                   `json:"loop-detection-path-vec-count,omitempty"`
	HoldTime                  string                                   `json:"hold-time,omitempty"`
	RequestRetry              string                                   `json:"request-retry,omitempty"`
	LoopDetection             string                                   `json:"loop-detection,omitempty"`
	TargetedPeer              *ConfigProtocolsLdpTargetedPeer          `json:"targeted-peer,omitempty"`
	GlobalMergeCapability     *ConfigProtocolsLdpGlobalMergeCapability `json:"global-merge-capability,omitempty"`
	KeepaliveInterval         string                                   `json:"keepalive-interval,omitempty"`
	AdvertisementMode         *ConfigProtocolsLdpAdvertisementMode     `json:"advertisement-mode,omitempty"`
	LoopDetectionHopCount     string                                   `json:"loop-detection-hop-count,omitempty"`
	HelloInterval             EdgeOSInt                                `json:"hello-interval,omitempty"`
	PwStatusTlv               string                                   `json:"pw-status-tlv,omitempty"`
}

type ConfigProtocolsLdpInterface struct {
	Enable             *ConfigProtocolsLdpInterfaceEnable             `json:"enable,omitempty"`
	KeepaliveTimeout   string                                         `json:"keepalive-timeout,omitempty"`
	LabelRetentionMode *ConfigProtocolsLdpInterfaceLabelRetentionMode `json:"label-retention-mode,omitempty"`
	HoldTime           string                                         `json:"hold-time,omitempty"`
	KeepaliveInterval  string                                         `json:"keepalive-interval,omitempty"`
	AdvertisementMode  *ConfigProtocolsLdpInterfaceAdvertisementMode  `json:"advertisement-mode,omitempty"`
	HelloInterval      EdgeOSInt                                      `json:"hello-interval,omitempty"`
}

type ConfigProtocolsLdpInterfaceEnable struct {
	Both string `json:"both,omitempty"`
	Ipv4 string `json:"ipv4,omitempty"`
	Ipv6 string `json:"ipv6,omitempty"`
}

type ConfigProtocolsLdpInterfaceLabelRetentionMode struct {
	Liberal      string `json:"liberal,omitempty"`
	Conservative string `json:"conservative,omitempty"`
}

type ConfigProtocolsLdpInterfaceAdvertisementMode struct {
	DownstreamOnDemand    string `json:"downstream-on-demand,omitempty"`
	DownstreamUnsolicited string `json:"downstream-unsolicited,omitempty"`
}

type ConfigProtocolsLdpNeighbor struct {
	Auth *ConfigProtocolsLdpNeighborAuth `json:"auth,omitempty"`
}

type ConfigProtocolsLdpNeighborAuth struct {
	Md5 *ConfigProtocolsLdpNeighborAuthMd5 `json:"md5,omitempty"`
}

type ConfigProtocolsLdpNeighborAuthMd5 struct {
	Password *map[string]ConfigProtocolsLdpNeighborAuthMd5Password `json:"password,omitempty"`
}

type ConfigProtocolsLdpNeighborAuthMd5Password struct {
	Type EdgeOSInt `json:"type,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabels struct {
	ForAcl *map[string]ConfigProtocolsLdpAdvertiseLabelsForAcl `json:"for-acl,omitempty"`
	For    *ConfigProtocolsLdpAdvertiseLabelsFor               `json:"for,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAcl struct {
	To *ConfigProtocolsLdpAdvertiseLabelsForAclTo `json:"to,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAclTo struct {
	Any string `json:"any,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsFor struct {
	PeerAcl *map[string]ConfigProtocolsLdpAdvertiseLabelsForPeerAcl `json:"peer-acl,omitempty"`
	Any     *ConfigProtocolsLdpAdvertiseLabelsForAny                `json:"any,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForPeerAcl struct {
	To *ConfigProtocolsLdpAdvertiseLabelsForPeerAclTo `json:"to,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForPeerAclTo struct {
	PeerAcl string `json:"peer-acl,omitempty"`
	Any     string `json:"any,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAny struct {
	To *ConfigProtocolsLdpAdvertiseLabelsForAnyTo `json:"to,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAnyTo struct {
	None string `json:"none,omitempty"`
}

type ConfigProtocolsLdpTransportAddress struct {
	Ipv4 *map[string]ConfigProtocolsLdpTransportAddressIpv4 `json:"ipv4,omitempty"`
	Ipv6 *map[string]ConfigProtocolsLdpTransportAddressIpv6 `json:".ipv6,omitempty"`
}

type ConfigProtocolsLdpTransportAddressIpv4 struct {
	Labelspace string `json:"labelspace,omitempty"`
}

type ConfigProtocolsLdpTransportAddressIpv6 struct {
	Labelspace string `json:"labelspace,omitempty"`
}

type ConfigProtocolsLdpControlMode struct {
	Independent string `json:"independent,omitempty"`
	Ordered     string `json:"ordered,omitempty"`
}

type ConfigProtocolsLdpLabelRetentionMode struct {
	Liberal      string `json:"liberal,omitempty"`
	Conservative string `json:"conservative,omitempty"`
}

type ConfigProtocolsLdpGracefulRestart struct {
	Enable  string                                   `json:"enable,omitempty"`
	Disable string                                   `json:"disable,omitempty"`
	Timers  *ConfigProtocolsLdpGracefulRestartTimers `json:"timers,omitempty"`
}

type ConfigProtocolsLdpGracefulRestartTimers struct {
	MaxRecovery      string `json:"max-recovery,omitempty"`
	NeighborLiveness string `json:"neighbor-liveness,omitempty"`
}

type ConfigProtocolsLdpTargetedPeer struct {
	Ipv4 *map[string]ConfigProtocolsLdpTargetedPeerIpv4 `json:"ipv4,omitempty"`
	Ipv6 IPv6                                           `json:".ipv6,omitempty"`
}

type ConfigProtocolsLdpTargetedPeerIpv4 struct {
}

type ConfigProtocolsLdpGlobalMergeCapability struct {
	NonMergeCapable string `json:"non-merge-capable,omitempty"`
	MergeCapable    string `json:"merge-capable,omitempty"`
}

type ConfigProtocolsLdpAdvertisementMode struct {
	DownstreamOnDemand    string `json:"downstream-on-demand,omitempty"`
	DownstreamUnsolicited string `json:"downstream-unsolicited,omitempty"`
}

type ConfigProtocolsIgmpProxy struct {
	Disable           string                                        `json:"disable,omitempty"`
	Interface         *map[string]ConfigProtocolsIgmpProxyInterface `json:"interface,omitempty"`
	DisableQuickleave string                                        `json:"disable-quickleave,omitempty"`
}

type ConfigProtocolsIgmpProxyInterface struct {
	Whitelist []string `json:"whitelist,omitempty"`
	Role      string   `json:"role,omitempty"`
	AltSubnet []string `json:"alt-subnet,omitempty"`
	Threshold string   `json:"threshold,omitempty"`
}

type ConfigProtocolsBgp struct {
	Neighbor         *map[string]ConfigProtocolsBgpNeighbor         `json:"neighbor,omitempty"`
	Timers           *ConfigProtocolsBgpTimers                      `json:"timers,omitempty"`
	MaximumPaths     *ConfigProtocolsBgpMaximumPaths                `json:"maximum-paths,omitempty"`
	Network          *map[string]ConfigProtocolsBgpNetwork          `json:"network,omitempty"`
	AggregateAddress *map[string]ConfigProtocolsBgpAggregateAddress `json:"aggregate-address,omitempty"`
	AddressFamily    *ConfigProtocolsBgpAddressFamily               `json:"address-family,omitempty"`
	Dampening        *ConfigProtocolsBgpDampening                   `json:"dampening,omitempty"`
	Parameters       *ConfigProtocolsBgpParameters                  `json:"parameters,omitempty"`
	Redistribute     *ConfigProtocolsBgpRedistribute                `json:"redistribute,omitempty"`
	PeerGroup        *map[string]ConfigProtocolsBgpPeerGroup        `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpNeighbor struct {
	Weight                       EdgeOSInt                                       `json:"weight,omitempty"`
	NoActivate                   string                                          `json:"no-activate,omitempty"`
	EbgpMultihop                 EdgeOSInt                                       `json:"ebgp-multihop,omitempty"`
	Password                     string                                          `json:"password,omitempty"`
	MaximumPrefix                EdgeOSInt                                       `json:"maximum-prefix,omitempty"`
	FilterList                   *ConfigProtocolsBgpNeighborFilterList           `json:"filter-list,omitempty"`
	AllowasIn                    *ConfigProtocolsBgpNeighborAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient         string                                          `json:"route-reflector-client,omitempty"`
	OverrideCapability           string                                          `json:"override-capability,omitempty"`
	Shutdown                     string                                          `json:"shutdown,omitempty"`
	StrictCapabilityMatch        string                                          `json:"strict-capability-match,omitempty"`
	DisableSendCommunity         *ConfigProtocolsBgpNeighborDisableSendCommunity `json:"disable-send-community,omitempty"`
	Timers                       *ConfigProtocolsBgpNeighborTimers               `json:"timers,omitempty"`
	DefaultOriginate             *ConfigProtocolsBgpNeighborDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient            string                                          `json:"route-server-client,omitempty"`
	Capability                   *ConfigProtocolsBgpNeighborCapability           `json:"capability,omitempty"`
	UpdateSource                 string                                          `json:"update-source,omitempty"`
	TtlSecurity                  *ConfigProtocolsBgpNeighborTtlSecurity          `json:"ttl-security,omitempty"`
	UnsuppressMap                string                                          `json:"unsuppress-map,omitempty"`
	FallOver                     *ConfigProtocolsBgpNeighborFallOver             `json:"fall-over,omitempty"`
	Passive                      string                                          `json:"passive,omitempty"`
	AddressFamily                *ConfigProtocolsBgpNeighborAddressFamily        `json:"address-family,omitempty"`
	Description                  string                                          `json:"description,omitempty"`
	SoftReconfiguration          *ConfigProtocolsBgpNeighborSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	LocalAs                      *map[string]ConfigProtocolsBgpNeighborLocalAs   `json:"local-as,omitempty"`
	AttributeUnchanged           *ConfigProtocolsBgpNeighborAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap                     *ConfigProtocolsBgpNeighborRouteMap             `json:"route-map,omitempty"`
	RemoteAs                     EdgeOSInt                                       `json:"remote-as,omitempty"`
	NexthopSelf                  string                                          `json:"nexthop-self,omitempty"`
	DisableConnectedCheck        string                                          `json:"disable-connected-check,omitempty"`
	DisableCapabilityNegotiation string                                          `json:"disable-capability-negotiation,omitempty"`
	Port                         EdgeOSInt                                       `json:"port,omitempty"`
	AdvertisementInterval        EdgeOSInt                                       `json:"advertisement-interval,omitempty"`
	RemovePrivateAs              string                                          `json:"remove-private-as,omitempty"`
	PrefixList                   *ConfigProtocolsBgpNeighborPrefixList           `json:"prefix-list,omitempty"`
	DistributeList               *ConfigProtocolsBgpNeighborDistributeList       `json:"distribute-list,omitempty"`
	PeerGroup                    string                                          `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpNeighborFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborAllowasIn struct {
	Number EdgeOSInt `json:"number,omitempty"`
}

type ConfigProtocolsBgpNeighborDisableSendCommunity struct {
	Standard string `json:"standard,omitempty"`
	Extended string `json:"extended,omitempty"`
}

type ConfigProtocolsBgpNeighborTimers struct {
	Holdtime  EdgeOSInt `json:"holdtime,omitempty"`
	Keepalive EdgeOSInt `json:"keepalive,omitempty"`
	Connect   EdgeOSInt `json:"connect,omitempty"`
}

type ConfigProtocolsBgpNeighborDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpNeighborCapability struct {
	Dynamic         string                                   `json:"dynamic,omitempty"`
	Orf             *ConfigProtocolsBgpNeighborCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart string                                   `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpNeighborCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpNeighborCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpNeighborCapabilityOrfPrefixList struct {
	Both    string `json:"both,omitempty"`
	Receive string `json:"receive,omitempty"`
	Send    string `json:"send,omitempty"`
}

type ConfigProtocolsBgpNeighborTtlSecurity struct {
	Hops EdgeOSInt `json:"hops,omitempty"`
}

type ConfigProtocolsBgpNeighborFallOver struct {
	Bfd *ConfigProtocolsBgpNeighborFallOverBfd `json:"bfd,omitempty"`
}

type ConfigProtocolsBgpNeighborFallOverBfd struct {
	Multihop string `json:"multihop,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamily struct {
	Ipv6Unicast *ConfigProtocolsBgpNeighborAddressFamilyIpv6Unicast `json:"ipv6-unicast,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6Unicast struct {
	MaximumPrefix        EdgeOSInt                                                               `json:"maximum-prefix,omitempty"`
	FilterList           *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastFilterList           `json:"filter-list,omitempty"`
	AllowasIn            *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient string                                                                  `json:"route-reflector-client,omitempty"`
	NexthopLocal         *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastNexthopLocal         `json:"nexthop-local,omitempty"`
	DisableSendCommunity *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate     *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient    string                                                                  `json:"route-server-client,omitempty"`
	Capability           *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapability           `json:"capability,omitempty"`
	UnsuppressMap        string                                                                  `json:"unsuppress-map,omitempty"`
	SoftReconfiguration  *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	AttributeUnchanged   *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap             *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastRouteMap             `json:"route-map,omitempty"`
	NexthopSelf          string                                                                  `json:"nexthop-self,omitempty"`
	RemovePrivateAs      string                                                                  `json:"remove-private-as,omitempty"`
	PrefixList           *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastPrefixList           `json:"prefix-list,omitempty"`
	DistributeList       *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDistributeList       `json:"distribute-list,omitempty"`
	PeerGroup            string                                                                  `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAllowasIn struct {
	Number EdgeOSInt `json:"number,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastNexthopLocal struct {
	Unchanged string `json:"unchanged,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDisableSendCommunity struct {
	Standard string `json:"standard,omitempty"`
	Extended string `json:"extended,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapability struct {
	Orf             *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart string                                                           `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrfPrefixList struct {
	Receive string `json:"receive,omitempty"`
	Send    string `json:"send,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastSoftReconfiguration struct {
	Inbound string `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAttributeUnchanged struct {
	AsPath  string `json:"as-path,omitempty"`
	NextHop string `json:"next-hop,omitempty"`
	Med     string `json:"med,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastRouteMap struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastPrefixList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDistributeList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborSoftReconfiguration struct {
	Inbound string `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpNeighborLocalAs struct {
	NoPrepend string `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpNeighborAttributeUnchanged struct {
	AsPath  string `json:"as-path,omitempty"`
	NextHop string `json:"next-hop,omitempty"`
	Med     string `json:"med,omitempty"`
}

type ConfigProtocolsBgpNeighborRouteMap struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborPrefixList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborDistributeList struct {
	Word   *map[string]ConfigProtocolsBgpNeighborDistributeListWord `json:"word,omitempty"`
	Export EdgeOSInt                                                `json:"export,omitempty"`
	Import EdgeOSInt                                                `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborDistributeListWord struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsBgpTimers struct {
	Holdtime  EdgeOSInt `json:"holdtime,omitempty"`
	Keepalive EdgeOSInt `json:"keepalive,omitempty"`
}

type ConfigProtocolsBgpMaximumPaths struct {
	Ibgp EdgeOSInt `json:"ibgp,omitempty"`
	Ebgp EdgeOSInt `json:"ebgp,omitempty"`
}

type ConfigProtocolsBgpNetwork struct {
	Backdoor string `json:"backdoor,omitempty"`
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAggregateAddress struct {
	SummaryOnly string `json:"summary-only,omitempty"`
	AsSet       string `json:"as-set,omitempty"`
}

type ConfigProtocolsBgpAddressFamily struct {
	L2vpn       *ConfigProtocolsBgpAddressFamilyL2vpn       `json:"l2vpn,omitempty"`
	Ipv4Unicast *ConfigProtocolsBgpAddressFamilyIpv4Unicast `json:".ipv4-unicast,omitempty"`
	Ipv6Unicast *ConfigProtocolsBgpAddressFamilyIpv6Unicast `json:"ipv6-unicast,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpn struct {
	Vpls *ConfigProtocolsBgpAddressFamilyL2vpnVpls `json:"vpls,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVpls struct {
	Neighbor *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighbor `json:"neighbor,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighbor struct {
	Ipv4 *map[string]ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4 `json:"ipv4,omitempty"`
	Ipv6 *map[string]ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6 `json:"ipv6,omitempty"`
	Tag  *map[string]ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag  `json:"tag,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4 struct {
	Activate string `json:"activate,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6 struct {
	Activate string `json:"activate,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag struct {
	Activate string `json:"activate,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4Unicast struct {
	Vrf *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf `json:"vrf,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf struct {
	Neighbor     *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor  `json:"neighbor,omitempty"`
	Network      *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork   `json:"network,omitempty"`
	Parameters   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParameters           `json:"parameters,omitempty"`
	Redistribute *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistribute         `json:"redistribute,omitempty"`
	PeerGroup    *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor struct {
	Weight                EdgeOSInt                                                                 `json:"weight,omitempty"`
	EbgpMultihop          EdgeOSInt                                                                 `json:"ebgp-multihop,omitempty"`
	MaximumPrefix         EdgeOSInt                                                                 `json:"maximum-prefix,omitempty"`
	FilterList            *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborFilterList          `json:"filter-list,omitempty"`
	AllowasIn             *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAllowasIn           `json:"allowas-in,omitempty"`
	RouteReflectorClient  string                                                                    `json:"route-reflector-client,omitempty"`
	Shutdown              string                                                                    `json:"shutdown,omitempty"`
	Timers                *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborTimers              `json:"timers,omitempty"`
	DefaultOriginate      *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDefaultOriginate    `json:"default-originate,omitempty"`
	Capability            *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapability          `json:"capability,omitempty"`
	UpdateSource          string                                                                    `json:"update-source,omitempty"`
	UnsuppressMap         string                                                                    `json:"unsuppress-map,omitempty"`
	Passive               string                                                                    `json:"passive,omitempty"`
	Description           string                                                                    `json:"description,omitempty"`
	SoftReconfiguration   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborSoftReconfiguration `json:"soft-reconfiguration,omitempty"`
	LocalAs               *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs  `json:"local-as,omitempty"`
	AttributeUnchanged    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAttributeUnchanged  `json:"attribute-unchanged,omitempty"`
	RouteMap              *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborRouteMap            `json:"route-map,omitempty"`
	RemoteAs              EdgeOSInt                                                                 `json:"remote-as,omitempty"`
	Activate              string                                                                    `json:"activate,omitempty"`
	Port                  EdgeOSInt                                                                 `json:"port,omitempty"`
	AdvertisementInterval EdgeOSInt                                                                 `json:"advertisement-interval,omitempty"`
	RemovePrivateAs       string                                                                    `json:"remove-private-as,omitempty"`
	PrefixList            *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborPrefixList          `json:"prefix-list,omitempty"`
	DistributeList        *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeList      `json:"distribute-list,omitempty"`
	PeerGroup             string                                                                    `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAllowasIn struct {
	Number EdgeOSInt `json:"number,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborTimers struct {
	Holdtime  EdgeOSInt `json:"holdtime,omitempty"`
	Keepalive EdgeOSInt `json:"keepalive,omitempty"`
	Connect   EdgeOSInt `json:"connect,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapability struct {
	Dynamic         string                                                              `json:"dynamic,omitempty"`
	Orf             *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart string                                                              `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrfPrefixList struct {
	Both    string `json:"both,omitempty"`
	Receive string `json:"receive,omitempty"`
	Send    string `json:"send,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborSoftReconfiguration struct {
	Inbound string `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs struct {
	NoPrepend string `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAttributeUnchanged struct {
	AsPath  string `json:"as-path,omitempty"`
	NextHop string `json:"next-hop,omitempty"`
	Med     string `json:"med,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborRouteMap struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborPrefixList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeList struct {
	Word *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord `json:"word,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParameters struct {
	Dampening     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersDampening     `json:"dampening,omitempty"`
	Confederation *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersConfederation `json:"confederation,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersDampening struct {
	MaxSuppressTime   EdgeOSInt `json:"max-suppress-time,omitempty"`
	StartSuppressTime EdgeOSInt `json:"start-suppress-time,omitempty"`
	ReUse             EdgeOSInt `json:"re-use,omitempty"`
	HalfLife          EdgeOSInt `json:"half-life,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersConfederation struct {
	Identifier EdgeOSInt `json:"identifier,omitempty"`
	Peers      []string  `json:"peers,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistribute struct {
	Rip       *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeStatic    `json:"static,omitempty"`
	Kernel    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeKernel    `json:"kernel,omitempty"`
	Ospf      *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeRip struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeKernel struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeOspf struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup struct {
	Weight                       EdgeOSInt                                                                   `json:"weight,omitempty"`
	EbgpMultihop                 EdgeOSInt                                                                   `json:"ebgp-multihop,omitempty"`
	MaximumPrefix                EdgeOSInt                                                                   `json:"maximum-prefix,omitempty"`
	FilterList                   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupFilterList           `json:"filter-list,omitempty"`
	AllowasIn                    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient         string                                                                      `json:"route-reflector-client,omitempty"`
	OverrideCapability           string                                                                      `json:"override-capability,omitempty"`
	Shutdown                     string                                                                      `json:"shutdown,omitempty"`
	DisableSendCommunity         *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate             *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDefaultOriginate     `json:"default-originate,omitempty"`
	Capability                   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapability           `json:"capability,omitempty"`
	UpdateSource                 string                                                                      `json:"update-source,omitempty"`
	UnsuppressMap                string                                                                      `json:"unsuppress-map,omitempty"`
	Passive                      string                                                                      `json:"passive,omitempty"`
	Timers                       *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupTimers               `json:".timers,omitempty"`
	Description                  string                                                                      `json:"description,omitempty"`
	SoftReconfiguration          *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	LocalAs                      *map[string]ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs   `json:"local-as,omitempty"`
	AttributeUnchanged           *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap                     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupRouteMap             `json:"route-map,omitempty"`
	RemoteAs                     EdgeOSInt                                                                   `json:"remote-as,omitempty"`
	DisableConnectedCheck        string                                                                      `json:"disable-connected-check,omitempty"`
	DisableCapabilityNegotiation string                                                                      `json:"disable-capability-negotiation,omitempty"`
	RemovePrivateAs              string                                                                      `json:"remove-private-as,omitempty"`
	PrefixList                   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupPrefixList           `json:"prefix-list,omitempty"`
	DistributeList               *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDistributeList       `json:"distribute-list,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAllowasIn struct {
	Number EdgeOSInt `json:"number,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDisableSendCommunity struct {
	Standard string `json:"standard,omitempty"`
	Extended string `json:"extended,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapability struct {
	Dynamic string                                                               `json:"dynamic,omitempty"`
	Orf     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrf `json:"orf,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrfPrefixList struct {
	Receive string `json:"receive,omitempty"`
	Send    string `json:"send,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupTimers struct {
	Holdtime  EdgeOSInt `json:"holdtime,omitempty"`
	Keepalive EdgeOSInt `json:"keepalive,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupSoftReconfiguration struct {
	Inbound string `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs struct {
	NoPrepend string `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAttributeUnchanged struct {
	AsPath  string `json:"as-path,omitempty"`
	NextHop string `json:"next-hop,omitempty"`
	Med     string `json:"med,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupRouteMap struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupPrefixList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDistributeList struct {
	Export EdgeOSInt `json:"export,omitempty"`
	Import EdgeOSInt `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6Unicast struct {
	Network          *map[string]ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork          `json:"network,omitempty"`
	AggregateAddress *map[string]ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress `json:"aggregate-address,omitempty"`
	Redistribute     *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistribute                `json:"redistribute,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork struct {
	RouteMap  string    `json:"route-map,omitempty"`
	PathLimit EdgeOSInt `json:"path-limit,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress struct {
	SummaryOnly string `json:"summary-only,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistribute struct {
	Connected *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeConnected `json:"connected,omitempty"`
	Ripng     *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeRipng     `json:"ripng,omitempty"`
	Static    *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeStatic    `json:"static,omitempty"`
	Ospfv3    *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeOspfv3    `json:"ospfv3,omitempty"`
	Kernel    *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeRipng struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeOspfv3 struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeKernel struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpDampening struct {
	RouteMap string                                          `json:"route-map,omitempty"`
	HalfLife *map[string]ConfigProtocolsBgpDampeningHalfLife `json:"half-life,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLife struct {
	ReuseRoute *map[string]ConfigProtocolsBgpDampeningHalfLifeReuseRoute `json:"reuse-route,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLifeReuseRoute struct {
	SupRoute *map[string]ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute `json:"sup-route,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute struct {
	Time *map[string]ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime `json:"time,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime struct {
	HalfTime string `json:"half-time,omitempty"`
}

type ConfigProtocolsBgpParameters struct {
	ClusterId                  IPv4                                         `json:"cluster-id,omitempty"`
	DisableNetworkImportCheck  string                                       `json:"disable-network-import-check,omitempty"`
	NoClientToClientReflection string                                       `json:"no-client-to-client-reflection,omitempty"`
	EnforceFirstAs             string                                       `json:"enforce-first-as,omitempty"`
	RouterId                   IPv4                                         `json:"router-id,omitempty"`
	Distance                   *ConfigProtocolsBgpParametersDistance        `json:"distance,omitempty"`
	Default                    *ConfigProtocolsBgpParametersDefault         `json:"default,omitempty"`
	AlwaysCompareMed           string                                       `json:"always-compare-med,omitempty"`
	GracefulRestart            *ConfigProtocolsBgpParametersGracefulRestart `json:"graceful-restart,omitempty"`
	Dampening                  *ConfigProtocolsBgpParametersDampening       `json:"dampening,omitempty"`
	DeterministicMed           string                                       `json:"deterministic-med,omitempty"`
	Bestpath                   *ConfigProtocolsBgpParametersBestpath        `json:"bestpath,omitempty"`
	LogNeighborChanges         string                                       `json:"log-neighbor-changes,omitempty"`
	ScanTime                   EdgeOSInt                                    `json:"scan-time,omitempty"`
	Confederation              *ConfigProtocolsBgpParametersConfederation   `json:"confederation,omitempty"`
	NoFastExternalFailover     string                                       `json:"no-fast-external-failover,omitempty"`
}

type ConfigProtocolsBgpParametersDistance struct {
	Prefix *map[string]ConfigProtocolsBgpParametersDistancePrefix `json:"prefix,omitempty"`
	Global *ConfigProtocolsBgpParametersDistanceGlobal            `json:"global,omitempty"`
}

type ConfigProtocolsBgpParametersDistancePrefix struct {
	Distance EdgeOSInt `json:"distance,omitempty"`
}

type ConfigProtocolsBgpParametersDistanceGlobal struct {
	Internal EdgeOSInt `json:"internal,omitempty"`
	Local    EdgeOSInt `json:"local,omitempty"`
	External EdgeOSInt `json:"external,omitempty"`
}

type ConfigProtocolsBgpParametersDefault struct {
	NoIpv4Unicast string    `json:"no-ipv4-unicast,omitempty"`
	LocalPref     EdgeOSInt `json:"local-pref,omitempty"`
}

type ConfigProtocolsBgpParametersGracefulRestart struct {
	StalepathTime EdgeOSInt `json:"stalepath-time,omitempty"`
}

type ConfigProtocolsBgpParametersDampening struct {
	MaxSuppressTime   EdgeOSInt `json:"max-suppress-time,omitempty"`
	StartSuppressTime EdgeOSInt `json:"start-suppress-time,omitempty"`
	ReUse             EdgeOSInt `json:"re-use,omitempty"`
	HalfLife          EdgeOSInt `json:"half-life,omitempty"`
}

type ConfigProtocolsBgpParametersBestpath struct {
	AsPath          *ConfigProtocolsBgpParametersBestpathAsPath `json:"as-path,omitempty"`
	CompareRouterid string                                      `json:"compare-routerid,omitempty"`
	Med             *ConfigProtocolsBgpParametersBestpathMed    `json:"med,omitempty"`
}

type ConfigProtocolsBgpParametersBestpathAsPath struct {
	Confed string `json:"confed,omitempty"`
	Ignore string `json:"ignore,omitempty"`
}

type ConfigProtocolsBgpParametersBestpathMed struct {
	Confed         string `json:"confed,omitempty"`
	MissingAsWorst string `json:"missing-as-worst,omitempty"`
}

type ConfigProtocolsBgpParametersConfederation struct {
	Identifier EdgeOSInt `json:"identifier,omitempty"`
	Peers      []string  `json:"peers,omitempty"`
}

type ConfigProtocolsBgpRedistribute struct {
	Rip       *ConfigProtocolsBgpRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsBgpRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsBgpRedistributeStatic    `json:"static,omitempty"`
	Kernel    *ConfigProtocolsBgpRedistributeKernel    `json:"kernel,omitempty"`
	Ospf      *ConfigProtocolsBgpRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsBgpRedistributeRip struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeConnected struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeStatic struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeKernel struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeOspf struct {
	RouteMap string    `json:"route-map,omitempty"`
	Metric   EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsBgpPeerGroup struct {
	Weight                       EdgeOSInt                                        `json:"weight,omitempty"`
	EbgpMultihop                 EdgeOSInt                                        `json:"ebgp-multihop,omitempty"`
	Password                     string                                           `json:"password,omitempty"`
	MaximumPrefix                EdgeOSInt                                        `json:"maximum-prefix,omitempty"`
	FilterList                   *ConfigProtocolsBgpPeerGroupFilterList           `json:"filter-list,omitempty"`
	AllowasIn                    *ConfigProtocolsBgpPeerGroupAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient         string                                           `json:"route-reflector-client,omitempty"`
	OverrideCapability           string                                           `json:"override-capability,omitempty"`
	Shutdown                     string                                           `json:"shutdown,omitempty"`
	DisableSendCommunity         *ConfigProtocolsBgpPeerGroupDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate             *ConfigProtocolsBgpPeerGroupDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient            string                                           `json:"route-server-client,omitempty"`
	Capability                   *ConfigProtocolsBgpPeerGroupCapability           `json:"capability,omitempty"`
	UpdateSource                 string                                           `json:"update-source,omitempty"`
	TtlSecurity                  *ConfigProtocolsBgpPeerGroupTtlSecurity          `json:"ttl-security,omitempty"`
	UnsuppressMap                string                                           `json:"unsuppress-map,omitempty"`
	Passive                      string                                           `json:"passive,omitempty"`
	Timers                       *ConfigProtocolsBgpPeerGroupTimers               `json:".timers,omitempty"`
	AddressFamily                *ConfigProtocolsBgpPeerGroupAddressFamily        `json:"address-family,omitempty"`
	Description                  string                                           `json:"description,omitempty"`
	SoftReconfiguration          *ConfigProtocolsBgpPeerGroupSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	LocalAs                      *map[string]ConfigProtocolsBgpPeerGroupLocalAs   `json:"local-as,omitempty"`
	AttributeUnchanged           *ConfigProtocolsBgpPeerGroupAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap                     *ConfigProtocolsBgpPeerGroupRouteMap             `json:"route-map,omitempty"`
	RemoteAs                     EdgeOSInt                                        `json:"remote-as,omitempty"`
	NexthopSelf                  string                                           `json:"nexthop-self,omitempty"`
	DisableConnectedCheck        string                                           `json:"disable-connected-check,omitempty"`
	DisableCapabilityNegotiation string                                           `json:"disable-capability-negotiation,omitempty"`
	RemovePrivateAs              string                                           `json:"remove-private-as,omitempty"`
	PrefixList                   *ConfigProtocolsBgpPeerGroupPrefixList           `json:"prefix-list,omitempty"`
	DistributeList               *ConfigProtocolsBgpPeerGroupDistributeList       `json:"distribute-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAllowasIn struct {
	Number EdgeOSInt `json:"number,omitempty"`
}

type ConfigProtocolsBgpPeerGroupDisableSendCommunity struct {
	Standard string `json:"standard,omitempty"`
	Extended string `json:"extended,omitempty"`
}

type ConfigProtocolsBgpPeerGroupDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpPeerGroupCapability struct {
	Dynamic         string                                    `json:"dynamic,omitempty"`
	Orf             *ConfigProtocolsBgpPeerGroupCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart string                                    `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpPeerGroupCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpPeerGroupCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupCapabilityOrfPrefixList struct {
	Receive string `json:"receive,omitempty"`
	Send    string `json:"send,omitempty"`
}

type ConfigProtocolsBgpPeerGroupTtlSecurity struct {
	Hops EdgeOSInt `json:"hops,omitempty"`
}

type ConfigProtocolsBgpPeerGroupTimers struct {
	Holdtime  EdgeOSInt `json:"holdtime,omitempty"`
	Keepalive EdgeOSInt `json:"keepalive,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamily struct {
	Ipv6Unicast *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6Unicast `json:"ipv6-unicast,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6Unicast struct {
	MaximumPrefix        EdgeOSInt                                                                `json:"maximum-prefix,omitempty"`
	FilterList           *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastFilterList           `json:"filter-list,omitempty"`
	AllowasIn            *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient string                                                                   `json:"route-reflector-client,omitempty"`
	NexthopLocal         *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastNexthopLocal         `json:"nexthop-local,omitempty"`
	DisableSendCommunity *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate     *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient    string                                                                   `json:"route-server-client,omitempty"`
	Capability           *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapability           `json:"capability,omitempty"`
	UnsuppressMap        string                                                                   `json:"unsuppress-map,omitempty"`
	SoftReconfiguration  *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	AttributeUnchanged   *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap             *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastRouteMap             `json:"route-map,omitempty"`
	NexthopSelf          string                                                                   `json:"nexthop-self,omitempty"`
	RemovePrivateAs      string                                                                   `json:"remove-private-as,omitempty"`
	PrefixList           *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastPrefixList           `json:"prefix-list,omitempty"`
	DistributeList       *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDistributeList       `json:"distribute-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAllowasIn struct {
	Number EdgeOSInt `json:"number,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastNexthopLocal struct {
	Unchanged string `json:"unchanged,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDisableSendCommunity struct {
	Standard string `json:"standard,omitempty"`
	Extended string `json:"extended,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapability struct {
	Orf             *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart string                                                            `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrfPrefixList struct {
	Receive string `json:"receive,omitempty"`
	Send    string `json:"send,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastSoftReconfiguration struct {
	Inbound string `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAttributeUnchanged struct {
	AsPath  string `json:"as-path,omitempty"`
	NextHop string `json:"next-hop,omitempty"`
	Med     string `json:"med,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastRouteMap struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastPrefixList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDistributeList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupSoftReconfiguration struct {
	Inbound string `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpPeerGroupLocalAs struct {
	NoPrepend string `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAttributeUnchanged struct {
	AsPath  string `json:"as-path,omitempty"`
	NextHop string `json:"next-hop,omitempty"`
	Med     string `json:"med,omitempty"`
}

type ConfigProtocolsBgpPeerGroupRouteMap struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupPrefixList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupDistributeList struct {
	Export EdgeOSInt `json:"export,omitempty"`
	Import EdgeOSInt `json:"import,omitempty"`
}

type ConfigProtocolsOspfv3 struct {
	Bfd                     *ConfigProtocolsOspfv3Bfd                       `json:"bfd,omitempty"`
	Area                    *map[string]ConfigProtocolsOspfv3Area           `json:"area,omitempty"`
	Timers                  *ConfigProtocolsOspfv3Timers                    `json:"timers,omitempty"`
	Capability              *ConfigProtocolsOspfv3Capability                `json:"capability,omitempty"`
	DefaultMetric           EdgeOSInt                                       `json:"default-metric,omitempty"`
	Distance                *ConfigProtocolsOspfv3Distance                  `json:"distance,omitempty"`
	LogAdjacencyChanges     *ConfigProtocolsOspfv3LogAdjacencyChanges       `json:"log-adjacency-changes,omitempty"`
	SummaryAddress          IPv6Net                                         `json:"summary-address,omitempty"`
	Cspf                    *ConfigProtocolsOspfv3Cspf                      `json:"cspf,omitempty"`
	AutoCost                *ConfigProtocolsOspfv3AutoCost                  `json:"auto-cost,omitempty"`
	PassiveInterfaceExclude []string                                        `json:"passive-interface-exclude,omitempty"`
	Vrf                     *map[string]ConfigProtocolsOspfv3Vrf            `json:".vrf,omitempty"`
	Parameters              *ConfigProtocolsOspfv3Parameters                `json:"parameters,omitempty"`
	PassiveInterface        []string                                        `json:"passive-interface,omitempty"`
	MaxConcurrentDd         EdgeOSInt                                       `json:"max-concurrent-dd,omitempty"`
	Redistribute            *ConfigProtocolsOspfv3Redistribute              `json:"redistribute,omitempty"`
	DistributeList          *map[string]ConfigProtocolsOspfv3DistributeList `json:"distribute-list,omitempty"`
	DefaultInformation      *ConfigProtocolsOspfv3DefaultInformation        `json:"default-information,omitempty"`
}

type ConfigProtocolsOspfv3Bfd struct {
	Interface     []string `json:"interface,omitempty"`
	AllInterfaces string   `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfv3Area struct {
	ExportList  string                                           `json:"export-list,omitempty"`
	Interface   []string                                         `json:"interface,omitempty"`
	FilterList  *map[string]ConfigProtocolsOspfv3AreaFilterList  `json:".filter-list,omitempty"`
	ImportList  string                                           `json:"import-list,omitempty"`
	AreaType    *ConfigProtocolsOspfv3AreaAreaType               `json:"area-type,omitempty"`
	VirtualLink *map[string]ConfigProtocolsOspfv3AreaVirtualLink `json:"virtual-link,omitempty"`
	Range       *map[string]ConfigProtocolsOspfv3AreaRange       `json:"range,omitempty"`
}

type ConfigProtocolsOspfv3AreaFilterList struct {
}

type ConfigProtocolsOspfv3AreaAreaType struct {
	Stub   *ConfigProtocolsOspfv3AreaAreaTypeStub `json:"stub,omitempty"`
	Normal string                                 `json:"normal,omitempty"`
	Nssa   *ConfigProtocolsOspfv3AreaAreaTypeNssa `json:"nssa,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeStub struct {
	DefaultCost EdgeOSInt `json:"default-cost,omitempty"`
	NoSummary   string    `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeNssa struct {
	DefaultCost                 EdgeOSInt                                                         `json:"default-cost,omitempty"`
	Translate                   string                                                            `json:"translate,omitempty"`
	NoSummary                   string                                                            `json:"no-summary,omitempty"`
	StabilityInterval           EdgeOSInt                                                         `json:"stability-interval,omitempty"`
	DefaultInformationOriginate *ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginate `json:"default-information-originate,omitempty"`
	NoRedistribution            string                                                            `json:"no-redistribution,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginate struct {
	RouteMap string                                                                             `json:"route-map,omitempty"`
	Metric   *map[string]ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric `json:"metric,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric struct {
	Type string `json:"type,omitempty"`
}

type ConfigProtocolsOspfv3AreaVirtualLink struct {
	Bfd string `json:"bfd,omitempty"`
}

type ConfigProtocolsOspfv3AreaRange struct {
	NotAdvertise string `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfv3Timers struct {
	SfpExpDelay *ConfigProtocolsOspfv3TimersSfpExpDelay `json:"sfp-exp-delay,omitempty"`
}

type ConfigProtocolsOspfv3TimersSfpExpDelay struct {
	Min *map[string]ConfigProtocolsOspfv3TimersSfpExpDelayMin `json:"min,omitempty"`
}

type ConfigProtocolsOspfv3TimersSfpExpDelayMin struct {
	Max EdgeOSInt `json:"max,omitempty"`
}

type ConfigProtocolsOspfv3Capability struct {
	DbSummaryOpt    string `json:"db-summary-opt,omitempty"`
	Te              string `json:"te,omitempty"`
	Cspf            string `json:"cspf,omitempty"`
	GracefulRestart string `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsOspfv3Distance struct {
	Global EdgeOSInt                            `json:"global,omitempty"`
	Ospfv3 *ConfigProtocolsOspfv3DistanceOspfv3 `json:"ospfv3,omitempty"`
}

type ConfigProtocolsOspfv3DistanceOspfv3 struct {
	InterArea EdgeOSInt `json:"inter-area,omitempty"`
	External  EdgeOSInt `json:"external,omitempty"`
	IntraArea EdgeOSInt `json:"intra-area,omitempty"`
}

type ConfigProtocolsOspfv3LogAdjacencyChanges struct {
	Detail string `json:"detail,omitempty"`
}

type ConfigProtocolsOspfv3Cspf struct {
	TieBreak             string    `json:"tie-break,omitempty"`
	DefaultRetryInterval EdgeOSInt `json:"default-retry-interval,omitempty"`
}

type ConfigProtocolsOspfv3AutoCost struct {
	ReferenceBandwidth EdgeOSInt `json:"reference-bandwidth,omitempty"`
}

type ConfigProtocolsOspfv3Vrf struct {
	Bfd          *ConfigProtocolsOspfv3VrfBfd             `json:"bfd,omitempty"`
	Area         *map[string]ConfigProtocolsOspfv3VrfArea `json:"area,omitempty"`
	Parameters   *ConfigProtocolsOspfv3VrfParameters      `json:"parameters,omitempty"`
	Redistribute *ConfigProtocolsOspfv3VrfRedistribute    `json:"redistribute,omitempty"`
}

type ConfigProtocolsOspfv3VrfBfd struct {
	AllInterfaces string `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfv3VrfArea struct {
	ExportList  string                                              `json:"export-list,omitempty"`
	Interface   []string                                            `json:"interface,omitempty"`
	FilterList  *map[string]ConfigProtocolsOspfv3VrfAreaFilterList  `json:".filter-list,omitempty"`
	ImportList  string                                              `json:"import-list,omitempty"`
	VirtualLink *map[string]ConfigProtocolsOspfv3VrfAreaVirtualLink `json:"virtual-link,omitempty"`
	Range       *map[string]ConfigProtocolsOspfv3VrfAreaRange       `json:"range,omitempty"`
}

type ConfigProtocolsOspfv3VrfAreaFilterList struct {
}

type ConfigProtocolsOspfv3VrfAreaVirtualLink struct {
	Bfd string `json:"bfd,omitempty"`
}

type ConfigProtocolsOspfv3VrfAreaRange struct {
	Advertise    string `json:"advertise,omitempty"`
	NotAdvertise string `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfv3VrfParameters struct {
	RouterId IPv4 `json:"router-id,omitempty"`
}

type ConfigProtocolsOspfv3VrfRedistribute struct {
	Connected *ConfigProtocolsOspfv3VrfRedistributeConnected `json:"connected,omitempty"`
	Ripng     *ConfigProtocolsOspfv3VrfRedistributeRipng     `json:"ripng,omitempty"`
	Static    *ConfigProtocolsOspfv3VrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsOspfv3VrfRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsOspfv3VrfRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsOspfv3VrfRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3VrfRedistributeRipng struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3VrfRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3VrfRedistributeBgp struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3VrfRedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3Parameters struct {
	RouterId IPv4   `json:"router-id,omitempty"`
	AbrType  string `json:"abr-type,omitempty"`
}

type ConfigProtocolsOspfv3Redistribute struct {
	Connected *ConfigProtocolsOspfv3RedistributeConnected `json:"connected,omitempty"`
	Ripng     *ConfigProtocolsOspfv3RedistributeRipng     `json:"ripng,omitempty"`
	Static    *ConfigProtocolsOspfv3RedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsOspfv3RedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsOspfv3RedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsOspfv3RedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3RedistributeRipng struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3RedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3RedistributeBgp struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3RedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsOspfv3DistributeList struct {
	Out *ConfigProtocolsOspfv3DistributeListOut `json:"out,omitempty"`
	In  string                                  `json:"in,omitempty"`
}

type ConfigProtocolsOspfv3DistributeListOut struct {
	Rip       string `json:"rip,omitempty"`
	Connected string `json:"connected,omitempty"`
	Static    string `json:"static,omitempty"`
	Bgp       string `json:"bgp,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Ospf      string `json:"ospf,omitempty"`
	Isis      string `json:"isis,omitempty"`
}

type ConfigProtocolsOspfv3DefaultInformation struct {
	Originate *ConfigProtocolsOspfv3DefaultInformationOriginate `json:"originate,omitempty"`
}

type ConfigProtocolsOspfv3DefaultInformationOriginate struct {
	Always     string    `json:"always,omitempty"`
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType string    `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspf struct {
	Neighbor                *map[string]ConfigProtocolsOspfNeighbor   `json:"neighbor,omitempty"`
	Bfd                     *ConfigProtocolsOspfBfd                   `json:"bfd,omitempty"`
	Area                    *map[string]ConfigProtocolsOspfArea       `json:"area,omitempty"`
	Refresh                 *ConfigProtocolsOspfRefresh               `json:"refresh,omitempty"`
	Timers                  *ConfigProtocolsOspfTimers                `json:"timers,omitempty"`
	DefaultMetric           EdgeOSInt                                 `json:"default-metric,omitempty"`
	Distance                *ConfigProtocolsOspfDistance              `json:"distance,omitempty"`
	LogAdjacencyChanges     *ConfigProtocolsOspfLogAdjacencyChanges   `json:"log-adjacency-changes,omitempty"`
	MplsTe                  *ConfigProtocolsOspfMplsTe                `json:"mpls-te,omitempty"`
	AutoCost                *ConfigProtocolsOspfAutoCost              `json:"auto-cost,omitempty"`
	PassiveInterfaceExclude []string                                  `json:"passive-interface-exclude,omitempty"`
	AccessList              *map[string]ConfigProtocolsOspfAccessList `json:"access-list,omitempty"`
	InstanceId              *map[string]ConfigProtocolsOspfInstanceId `json:".instance-id,omitempty"`
	Parameters              *ConfigProtocolsOspfParameters            `json:"parameters,omitempty"`
	PassiveInterface        []string                                  `json:"passive-interface,omitempty"`
	Redistribute            *ConfigProtocolsOspfRedistribute          `json:"redistribute,omitempty"`
	MaxMetric               *ConfigProtocolsOspfMaxMetric             `json:"max-metric,omitempty"`
	DefaultInformation      *ConfigProtocolsOspfDefaultInformation    `json:"default-information,omitempty"`
}

type ConfigProtocolsOspfNeighbor struct {
	PollInterval EdgeOSInt `json:"poll-interval,omitempty"`
	Priority     EdgeOSInt `json:"priority,omitempty"`
}

type ConfigProtocolsOspfBfd struct {
	Interface     []string `json:"interface,omitempty"`
	AllInterfaces string   `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfArea struct {
	Shortcut       string                                         `json:"shortcut,omitempty"`
	Network        []string                                       `json:"network,omitempty"`
	AreaType       *ConfigProtocolsOspfAreaAreaType               `json:"area-type,omitempty"`
	VirtualLink    *map[string]ConfigProtocolsOspfAreaVirtualLink `json:"virtual-link,omitempty"`
	Range          *map[string]ConfigProtocolsOspfAreaRange       `json:"range,omitempty"`
	Authentication string                                         `json:"authentication,omitempty"`
}

type ConfigProtocolsOspfAreaAreaType struct {
	Stub   *ConfigProtocolsOspfAreaAreaTypeStub `json:"stub,omitempty"`
	Normal string                               `json:"normal,omitempty"`
	Nssa   *ConfigProtocolsOspfAreaAreaTypeNssa `json:"nssa,omitempty"`
}

type ConfigProtocolsOspfAreaAreaTypeStub struct {
	DefaultCost EdgeOSInt `json:"default-cost,omitempty"`
	NoSummary   string    `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfAreaAreaTypeNssa struct {
	DefaultCost EdgeOSInt `json:"default-cost,omitempty"`
	Translate   string    `json:"translate,omitempty"`
	NoSummary   string    `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLink struct {
	RetransmitInterval EdgeOSInt                                         `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                         `json:"transmit-delay,omitempty"`
	Bfd                string                                            `json:"bfd,omitempty"`
	DeadInterval       EdgeOSInt                                         `json:"dead-interval,omitempty"`
	Authentication     *ConfigProtocolsOspfAreaVirtualLinkAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                         `json:"hello-interval,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLinkAuthentication struct {
	Md5               *ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                               `json:"plaintext-password,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5 struct {
	KeyId *map[string]ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigProtocolsOspfAreaRange struct {
	Cost         EdgeOSInt `json:"cost,omitempty"`
	Substitute   IPv4Net   `json:"substitute,omitempty"`
	NotAdvertise string    `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfRefresh struct {
	Timers EdgeOSInt `json:"timers,omitempty"`
}

type ConfigProtocolsOspfTimers struct {
	Throttle *ConfigProtocolsOspfTimersThrottle `json:"throttle,omitempty"`
}

type ConfigProtocolsOspfTimersThrottle struct {
	Spf *ConfigProtocolsOspfTimersThrottleSpf `json:"spf,omitempty"`
}

type ConfigProtocolsOspfTimersThrottleSpf struct {
	MaxHoldtime     EdgeOSInt `json:"max-holdtime,omitempty"`
	Delay           EdgeOSInt `json:"delay,omitempty"`
	InitialHoldtime EdgeOSInt `json:"initial-holdtime,omitempty"`
}

type ConfigProtocolsOspfDistance struct {
	Global EdgeOSInt                        `json:"global,omitempty"`
	Ospf   *ConfigProtocolsOspfDistanceOspf `json:"ospf,omitempty"`
}

type ConfigProtocolsOspfDistanceOspf struct {
	InterArea EdgeOSInt `json:"inter-area,omitempty"`
	External  EdgeOSInt `json:"external,omitempty"`
	IntraArea EdgeOSInt `json:"intra-area,omitempty"`
}

type ConfigProtocolsOspfLogAdjacencyChanges struct {
	Detail string `json:"detail,omitempty"`
}

type ConfigProtocolsOspfMplsTe struct {
	Enable        string `json:"enable,omitempty"`
	RouterAddress IPv4   `json:"router-address,omitempty"`
}

type ConfigProtocolsOspfAutoCost struct {
	ReferenceBandwidth EdgeOSInt `json:"reference-bandwidth,omitempty"`
}

type ConfigProtocolsOspfAccessList struct {
	Export []string `json:"export,omitempty"`
	Import string   `json:"import,omitempty"`
}

type ConfigProtocolsOspfInstanceId struct {
	Vrf *map[string]ConfigProtocolsOspfInstanceIdVrf `json:"vrf,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrf struct {
	Neighbor                *map[string]ConfigProtocolsOspfInstanceIdVrfNeighbor   `json:"neighbor,omitempty"`
	Bfd                     *ConfigProtocolsOspfInstanceIdVrfBfd                   `json:"bfd,omitempty"`
	Area                    *map[string]ConfigProtocolsOspfInstanceIdVrfArea       `json:"area,omitempty"`
	Refresh                 *ConfigProtocolsOspfInstanceIdVrfRefresh               `json:"refresh,omitempty"`
	Timers                  *ConfigProtocolsOspfInstanceIdVrfTimers                `json:"timers,omitempty"`
	Capability              *ConfigProtocolsOspfInstanceIdVrfCapability            `json:"capability,omitempty"`
	DefaultMetric           EdgeOSInt                                              `json:"default-metric,omitempty"`
	Distance                *ConfigProtocolsOspfInstanceIdVrfDistance              `json:"distance,omitempty"`
	LogAdjacencyChanges     *ConfigProtocolsOspfInstanceIdVrfLogAdjacencyChanges   `json:"log-adjacency-changes,omitempty"`
	MplsTe                  *ConfigProtocolsOspfInstanceIdVrfMplsTe                `json:"mpls-te,omitempty"`
	AutoCost                *ConfigProtocolsOspfInstanceIdVrfAutoCost              `json:"auto-cost,omitempty"`
	PassiveInterfaceExclude []string                                               `json:"passive-interface-exclude,omitempty"`
	AccessList              *map[string]ConfigProtocolsOspfInstanceIdVrfAccessList `json:"access-list,omitempty"`
	Parameters              *ConfigProtocolsOspfInstanceIdVrfParameters            `json:"parameters,omitempty"`
	PassiveInterface        []string                                               `json:"passive-interface,omitempty"`
	Redistribute            *ConfigProtocolsOspfInstanceIdVrfRedistribute          `json:"redistribute,omitempty"`
	MaxMetric               *ConfigProtocolsOspfInstanceIdVrfMaxMetric             `json:"max-metric,omitempty"`
	DefaultInformation      *ConfigProtocolsOspfInstanceIdVrfDefaultInformation    `json:"default-information,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfNeighbor struct {
	PollInterval EdgeOSInt `json:"poll-interval,omitempty"`
	Priority     EdgeOSInt `json:"priority,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfBfd struct {
	AllInterfaces string `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfArea struct {
	Shortcut       string                                                      `json:"shortcut,omitempty"`
	Network        []string                                                    `json:"network,omitempty"`
	AreaType       *ConfigProtocolsOspfInstanceIdVrfAreaAreaType               `json:"area-type,omitempty"`
	VirtualLink    *map[string]ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink `json:"virtual-link,omitempty"`
	Range          *map[string]ConfigProtocolsOspfInstanceIdVrfAreaRange       `json:"range,omitempty"`
	Authentication string                                                      `json:"authentication,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaAreaType struct {
	Stub   *ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeStub `json:"stub,omitempty"`
	Normal string                                            `json:"normal,omitempty"`
	Nssa   *ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeNssa `json:"nssa,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeStub struct {
	DefaultCost EdgeOSInt `json:"default-cost,omitempty"`
	NoSummary   string    `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeNssa struct {
	DefaultCost EdgeOSInt `json:"default-cost,omitempty"`
	Translate   string    `json:"translate,omitempty"`
	NoSummary   string    `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink struct {
	RetransmitInterval EdgeOSInt                                                      `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                                      `json:"transmit-delay,omitempty"`
	Bfd                string                                                         `json:"bfd,omitempty"`
	DeadInterval       EdgeOSInt                                                      `json:"dead-interval,omitempty"`
	Authentication     *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                                      `json:"hello-interval,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthentication struct {
	Md5               *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                            `json:"plaintext-password,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5 struct {
	KeyId *map[string]ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaRange struct {
	Cost         EdgeOSInt `json:"cost,omitempty"`
	Substitute   IPv4Net   `json:"substitute,omitempty"`
	NotAdvertise string    `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRefresh struct {
	Timers EdgeOSInt `json:"timers,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfTimers struct {
	Throttle *ConfigProtocolsOspfInstanceIdVrfTimersThrottle `json:"throttle,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfTimersThrottle struct {
	Spf *ConfigProtocolsOspfInstanceIdVrfTimersThrottleSpf `json:"spf,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfTimersThrottleSpf struct {
	MaxHoldtime     EdgeOSInt `json:"max-holdtime,omitempty"`
	Delay           EdgeOSInt `json:"delay,omitempty"`
	InitialHoldtime EdgeOSInt `json:"initial-holdtime,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfCapability struct {
	Cspf               *ConfigProtocolsOspfInstanceIdVrfCapabilityCspf `json:"cspf,omitempty"`
	TrafficEngineering string                                          `json:"traffic-engineering,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfCapabilityCspf struct {
	EnableBetterProtection  string                                                  `json:"enable-better-protection,omitempty"`
	TieBreak                *ConfigProtocolsOspfInstanceIdVrfCapabilityCspfTieBreak `json:"tie-break,omitempty"`
	DisableBetterProtection string                                                  `json:"disable-better-protection,omitempty"`
	DefaultRetryInterval    string                                                  `json:"default-retry-interval,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfCapabilityCspfTieBreak struct {
	MostFill  string `json:"most-fill,omitempty"`
	LeastFill string `json:"least-fill,omitempty"`
	Random    string `json:"random,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDistance struct {
	Global EdgeOSInt                                     `json:"global,omitempty"`
	Ospf   *ConfigProtocolsOspfInstanceIdVrfDistanceOspf `json:"ospf,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDistanceOspf struct {
	InterArea EdgeOSInt `json:"inter-area,omitempty"`
	External  EdgeOSInt `json:"external,omitempty"`
	IntraArea EdgeOSInt `json:"intra-area,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfLogAdjacencyChanges struct {
	Detail string `json:"detail,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfMplsTe struct {
	Enable        string `json:"enable,omitempty"`
	RouterAddress IPv4   `json:"router-address,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAutoCost struct {
	ReferenceBandwidth EdgeOSInt `json:"reference-bandwidth,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAccessList struct {
	Export []string `json:"export,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfParameters struct {
	Rfc1583Compatibility string `json:"rfc1583-compatibility,omitempty"`
	RouterId             IPv4   `json:"router-id,omitempty"`
	AbrType              string `json:"abr-type,omitempty"`
	OpaqueLsa            string `json:"opaque-lsa,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistribute struct {
	Rip       *ConfigProtocolsOspfInstanceIdVrfRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsOspfInstanceIdVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsOspfInstanceIdVrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsOspfInstanceIdVrfRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsOspfInstanceIdVrfRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeRip struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeConnected struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeStatic struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeBgp struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeKernel struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfMaxMetric struct {
	RouterLsa *ConfigProtocolsOspfInstanceIdVrfMaxMetricRouterLsa `json:"router-lsa,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfMaxMetricRouterLsa struct {
	OnStartup      EdgeOSInt `json:"on-startup,omitempty"`
	Administrative string    `json:"administrative,omitempty"`
	OnShutdown     EdgeOSInt `json:"on-shutdown,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDefaultInformation struct {
	Originate *ConfigProtocolsOspfInstanceIdVrfDefaultInformationOriginate `json:"originate,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDefaultInformationOriginate struct {
	Always     string    `json:"always,omitempty"`
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfParameters struct {
	Rfc1583Compatibility string `json:"rfc1583-compatibility,omitempty"`
	RouterId             IPv4   `json:"router-id,omitempty"`
	AbrType              string `json:"abr-type,omitempty"`
	OpaqueLsa            string `json:"opaque-lsa,omitempty"`
}

type ConfigProtocolsOspfRedistribute struct {
	Rip       *ConfigProtocolsOspfRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsOspfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsOspfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsOspfRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsOspfRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsOspfRedistributeRip struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeConnected struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeStatic struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeBgp struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeKernel struct {
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigProtocolsOspfMaxMetric struct {
	RouterLsa *ConfigProtocolsOspfMaxMetricRouterLsa `json:"router-lsa,omitempty"`
}

type ConfigProtocolsOspfMaxMetricRouterLsa struct {
	OnStartup      EdgeOSInt `json:"on-startup,omitempty"`
	Administrative string    `json:"administrative,omitempty"`
	OnShutdown     EdgeOSInt `json:"on-shutdown,omitempty"`
}

type ConfigProtocolsOspfDefaultInformation struct {
	Originate *ConfigProtocolsOspfDefaultInformationOriginate `json:"originate,omitempty"`
}

type ConfigProtocolsOspfDefaultInformationOriginate struct {
	Always     string    `json:"always,omitempty"`
	RouteMap   string    `json:"route-map,omitempty"`
	MetricType EdgeOSInt `json:"metric-type,omitempty"`
	Metric     EdgeOSInt `json:"metric,omitempty"`
}

type ConfigPolicy struct {
	AsPathList       *map[string]ConfigPolicyAsPathList       `json:"as-path-list,omitempty"`
	AccessList       *map[string]ConfigPolicyAccessList       `json:"access-list,omitempty"`
	RouteMap         *map[string]ConfigPolicyRouteMap         `json:"route-map,omitempty"`
	AccessList6      *map[string]ConfigPolicyAccessList6      `json:"access-list6,omitempty"`
	PrefixList6      *map[string]ConfigPolicyPrefixList6      `json:"prefix-list6,omitempty"`
	CommunityList    *map[string]ConfigPolicyCommunityList    `json:"community-list,omitempty"`
	ExtcommunityList *map[string]ConfigPolicyExtcommunityList `json:"extcommunity-list,omitempty"`
	PrefixList       *map[string]ConfigPolicyPrefixList       `json:"prefix-list,omitempty"`
}

type ConfigPolicyAsPathList struct {
	Rule        *map[string]ConfigPolicyAsPathListRule `json:"rule,omitempty"`
	Description string                                 `json:"description,omitempty"`
}

type ConfigPolicyAsPathListRule struct {
	Regex       string `json:"regex,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigPolicyAccessList struct {
	Rule        *map[string]ConfigPolicyAccessListRule `json:"rule,omitempty"`
	Description string                                 `json:"description,omitempty"`
}

type ConfigPolicyAccessListRule struct {
	Source      *ConfigPolicyAccessListRuleSource      `json:"source,omitempty"`
	Destination *ConfigPolicyAccessListRuleDestination `json:"destination,omitempty"`
	Action      string                                 `json:"action,omitempty"`
	Description string                                 `json:"description,omitempty"`
}

type ConfigPolicyAccessListRuleSource struct {
	Host        IPv4   `json:"host,omitempty"`
	Network     IPv4   `json:"network,omitempty"`
	Any         string `json:"any,omitempty"`
	InverseMask IPv4   `json:"inverse-mask,omitempty"`
}

type ConfigPolicyAccessListRuleDestination struct {
	Host        IPv4   `json:"host,omitempty"`
	Network     IPv4   `json:"network,omitempty"`
	Any         string `json:"any,omitempty"`
	InverseMask IPv4   `json:"inverse-mask,omitempty"`
}

type ConfigPolicyRouteMap struct {
	Rule        *map[string]ConfigPolicyRouteMapRule `json:"rule,omitempty"`
	Description string                               `json:"description,omitempty"`
}

type ConfigPolicyRouteMapRule struct {
	Match       *ConfigPolicyRouteMapRuleMatch   `json:"match,omitempty"`
	OnMatch     *ConfigPolicyRouteMapRuleOnMatch `json:"on-match,omitempty"`
	Action      string                           `json:"action,omitempty"`
	Call        string                           `json:"call,omitempty"`
	Description string                           `json:"description,omitempty"`
	Set         *ConfigPolicyRouteMapRuleSet     `json:"set,omitempty"`
	Continue    EdgeOSInt                        `json:"continue,omitempty"`
}

type ConfigPolicyRouteMapRuleMatch struct {
	AsPath       string                                     `json:"as-path,omitempty"`
	Interface    string                                     `json:"interface,omitempty"`
	Extcommunity *ConfigPolicyRouteMapRuleMatchExtcommunity `json:"extcommunity,omitempty"`
	Peer         string                                     `json:"peer,omitempty"`
	Origin       string                                     `json:"origin,omitempty"`
	Community    *ConfigPolicyRouteMapRuleMatchCommunity    `json:"community,omitempty"`
	Ip           *ConfigPolicyRouteMapRuleMatchIp           `json:"ip,omitempty"`
	Metric       EdgeOSInt                                  `json:"metric,omitempty"`
	Ipv6         *ConfigPolicyRouteMapRuleMatchIpv6         `json:"ipv6,omitempty"`
	Tag          EdgeOSInt                                  `json:"tag,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchExtcommunity struct {
	ExactMatch       string    `json:"exact-match,omitempty"`
	ExtcommunityList EdgeOSInt `json:"extcommunity-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchCommunity struct {
	ExactMatch    string    `json:"exact-match,omitempty"`
	CommunityList EdgeOSInt `json:"community-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIp struct {
	RouteSource *ConfigPolicyRouteMapRuleMatchIpRouteSource `json:"route-source,omitempty"`
	Nexthop     *ConfigPolicyRouteMapRuleMatchIpNexthop     `json:"nexthop,omitempty"`
	Address     *ConfigPolicyRouteMapRuleMatchIpAddress     `json:"address,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpRouteSource struct {
	AccessList EdgeOSInt `json:"access-list,omitempty"`
	PrefixList string    `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpNexthop struct {
	AccessList EdgeOSInt `json:"access-list,omitempty"`
	PrefixList string    `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpAddress struct {
	AccessList EdgeOSInt `json:"access-list,omitempty"`
	PrefixList string    `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpv6 struct {
	Nexthop *ConfigPolicyRouteMapRuleMatchIpv6Nexthop `json:"nexthop,omitempty"`
	Address *ConfigPolicyRouteMapRuleMatchIpv6Address `json:"address,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpv6Nexthop struct {
	AccessList string `json:"access-list,omitempty"`
	PrefixList string `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpv6Address struct {
	AccessList string `json:"access-list,omitempty"`
	PrefixList string `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleOnMatch struct {
	Next string    `json:"next,omitempty"`
	Goto EdgeOSInt `json:"goto,omitempty"`
}

type ConfigPolicyRouteMapRuleSet struct {
	Weight          EdgeOSInt                                `json:"weight,omitempty"`
	AsPathPrepend   string                                   `json:"as-path-prepend,omitempty"`
	Ipv6NextHop     *ConfigPolicyRouteMapRuleSetIpv6NextHop  `json:"ipv6-next-hop,omitempty"`
	CommList        *ConfigPolicyRouteMapRuleSetCommList     `json:"comm-list,omitempty"`
	OriginatorId    IPv4                                     `json:"originator-id,omitempty"`
	Extcommunity    *ConfigPolicyRouteMapRuleSetExtcommunity `json:"extcommunity,omitempty"`
	Aggregator      *ConfigPolicyRouteMapRuleSetAggregator   `json:"aggregator,omitempty"`
	AtomicAggregate string                                   `json:"atomic-aggregate,omitempty"`
	LocalPreference EdgeOSInt                                `json:"local-preference,omitempty"`
	MetricType      string                                   `json:"metric-type,omitempty"`
	Origin          string                                   `json:"origin,omitempty"`
	Community       string                                   `json:"community,omitempty"`
	Metric          string                                   `json:"metric,omitempty"`
	IpNextHop       IPv4                                     `json:"ip-next-hop,omitempty"`
	Tag             EdgeOSInt                                `json:"tag,omitempty"`
}

type ConfigPolicyRouteMapRuleSetIpv6NextHop struct {
	Local  IPv6 `json:"local,omitempty"`
	Global IPv6 `json:"global,omitempty"`
}

type ConfigPolicyRouteMapRuleSetCommList struct {
	CommList EdgeOSInt `json:"comm-list,omitempty"`
	Delete   string    `json:"delete,omitempty"`
}

type ConfigPolicyRouteMapRuleSetExtcommunity struct {
	Rt string `json:"rt,omitempty"`
	Ro string `json:"ro,omitempty"`
}

type ConfigPolicyRouteMapRuleSetAggregator struct {
	As EdgeOSInt `json:"as,omitempty"`
	Ip IPv4      `json:"ip,omitempty"`
}

type ConfigPolicyAccessList6 struct {
	Rule        *map[string]ConfigPolicyAccessList6Rule `json:"rule,omitempty"`
	Description string                                  `json:"description,omitempty"`
}

type ConfigPolicyAccessList6Rule struct {
	Source      *ConfigPolicyAccessList6RuleSource `json:"source,omitempty"`
	Action      string                             `json:"action,omitempty"`
	Description string                             `json:"description,omitempty"`
}

type ConfigPolicyAccessList6RuleSource struct {
	Network    IPv6Net `json:"network,omitempty"`
	Any        string  `json:"any,omitempty"`
	ExactMatch string  `json:"exact-match,omitempty"`
}

type ConfigPolicyPrefixList6 struct {
	Rule        *map[string]ConfigPolicyPrefixList6Rule `json:"rule,omitempty"`
	Description string                                  `json:"description,omitempty"`
}

type ConfigPolicyPrefixList6Rule struct {
	Prefix      IPv6Net   `json:"prefix,omitempty"`
	Le          EdgeOSInt `json:"le,omitempty"`
	Action      string    `json:"action,omitempty"`
	Description string    `json:"description,omitempty"`
	Ge          EdgeOSInt `json:"ge,omitempty"`
}

type ConfigPolicyCommunityList struct {
	Rule        *map[string]ConfigPolicyCommunityListRule `json:"rule,omitempty"`
	Description string                                    `json:"description,omitempty"`
}

type ConfigPolicyCommunityListRule struct {
	Regex       string `json:"regex,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigPolicyExtcommunityList struct {
	Rule        *map[string]ConfigPolicyExtcommunityListRule `json:"rule,omitempty"`
	Description string                                       `json:"description,omitempty"`
}

type ConfigPolicyExtcommunityListRule struct {
	Rt          string `json:"rt,omitempty"`
	Regex       string `json:"regex,omitempty"`
	Ro          string `json:"ro,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigPolicyPrefixList struct {
	Rule        *map[string]ConfigPolicyPrefixListRule `json:"rule,omitempty"`
	Description string                                 `json:"description,omitempty"`
}

type ConfigPolicyPrefixListRule struct {
	Prefix      IPv4Net   `json:"prefix,omitempty"`
	Le          EdgeOSInt `json:"le,omitempty"`
	Action      string    `json:"action,omitempty"`
	Description string    `json:"description,omitempty"`
	Ge          EdgeOSInt `json:"ge,omitempty"`
}

type ConfigInterfaces struct {
	Wirelessmodem  *map[string]ConfigInterfacesWirelessmodem  `json:"wirelessmodem,omitempty"`
	Ipv6Tunnel     *map[string]ConfigInterfacesIpv6Tunnel     `json:"ipv6-tunnel,omitempty"`
	Bonding        *map[string]ConfigInterfacesBonding        `json:"bonding,omitempty"`
	L2tpv3         *map[string]ConfigInterfacesL2tpv3         `json:"l2tpv3,omitempty"`
	Vti            *map[string]ConfigInterfacesVti            `json:"vti,omitempty"`
	Input          *map[string]ConfigInterfacesInput          `json:"input,omitempty"`
	Bridge         *map[string]ConfigInterfacesBridge         `json:"bridge,omitempty"`
	L2tpClient     *map[string]ConfigInterfacesL2tpClient     `json:"l2tp-client,omitempty"`
	PptpClient     *map[string]ConfigInterfacesPptpClient     `json:"pptp-client,omitempty"`
	Ethernet       *map[string]ConfigInterfacesEthernet       `json:"ethernet,omitempty"`
	Tunnel         *map[string]ConfigInterfacesTunnel         `json:"tunnel,omitempty"`
	Openvpn        *map[string]ConfigInterfacesOpenvpn        `json:"openvpn,omitempty"`
	Loopback       *map[string]ConfigInterfacesLoopback       `json:"loopback,omitempty"`
	Switch         *map[string]ConfigInterfacesSwitch         `json:"switch,omitempty"`
	PseudoEthernet *map[string]ConfigInterfacesPseudoEthernet `json:"pseudo-ethernet,omitempty"`
}

type ConfigInterfacesWirelessmodem struct {
	Bandwidth         *ConfigInterfacesWirelessmodemBandwidth     `json:"bandwidth,omitempty"`
	Ondemand          string                                      `json:"ondemand,omitempty"`
	Mtu               EdgeOSInt                                   `json:"mtu,omitempty"`
	Network           string                                      `json:"network,omitempty"`
	TrafficPolicy     *ConfigInterfacesWirelessmodemTrafficPolicy `json:"traffic-policy,omitempty"`
	NoDns             string                                      `json:"no-dns,omitempty"`
	DisableLinkDetect string                                      `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesWirelessmodemFirewall      `json:"firewall,omitempty"`
	Description       string                                      `json:"description,omitempty"`
	Redirect          string                                      `json:"redirect,omitempty"`
	Device            string                                      `json:"device,omitempty"`
	Backup            *ConfigInterfacesWirelessmodemBackup        `json:"backup,omitempty"`
	Ip                *ConfigInterfacesWirelessmodemIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesWirelessmodemIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesWirelessmodemBandwidth struct {
	Maximum    string                                            `json:"maximum,omitempty"`
	Reservable string                                            `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesWirelessmodemBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesWirelessmodemBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesWirelessmodemBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesWirelessmodemBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesWirelessmodemTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesWirelessmodemFirewall struct {
	Out   *ConfigInterfacesWirelessmodemFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesWirelessmodemFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesWirelessmodemFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesWirelessmodemFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesWirelessmodemFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesWirelessmodemFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesWirelessmodemBackup struct {
	Distance EdgeOSInt `json:"distance,omitempty"`
}

type ConfigInterfacesWirelessmodemIp struct {
	Rip              *ConfigInterfacesWirelessmodemIpRip  `json:"rip,omitempty"`
	SourceValidation string                               `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesWirelessmodemIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesWirelessmodemIpRip struct {
	SplitHorizon   *ConfigInterfacesWirelessmodemIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesWirelessmodemIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesWirelessmodemIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesWirelessmodemIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesWirelessmodemIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesWirelessmodemIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspf struct {
	RetransmitInterval EdgeOSInt                                          `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                          `json:"transmit-delay,omitempty"`
	Network            string                                             `json:"network,omitempty"`
	Cost               EdgeOSInt                                          `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                          `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                          `json:"priority,omitempty"`
	MtuIgnore          string                                             `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesWirelessmodemIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                          `json:"hello-interval,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspfAuthentication struct {
	Md5               *ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                      `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                         `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesWirelessmodemIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesWirelessmodemIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesWirelessmodemIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesWirelessmodemIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesWirelessmodemIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6RouterAdvert struct {
	DefaultPreference string                                                          `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                       `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                       `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                       `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                          `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                       `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                            `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                        `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                            `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                            `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                       `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                       `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                       `json:"link-mtu,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesIpv6Tunnel struct {
	Disable           string                                   `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesIpv6TunnelBandwidth     `json:"bandwidth,omitempty"`
	Encapsulation     string                                   `json:"encapsulation,omitempty"`
	Multicast         string                                   `json:"multicast,omitempty"`
	Ttl               EdgeOSInt                                `json:"ttl,omitempty"`
	Mtu               EdgeOSInt                                `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesIpv6TunnelTrafficPolicy `json:"traffic-policy,omitempty"`
	Key               EdgeOSInt                                `json:"key,omitempty"`
	DisableLinkDetect string                                   `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesIpv6TunnelFirewall      `json:"firewall,omitempty"`
	Tos               EdgeOSInt                                `json:"tos,omitempty"`
	Description       string                                   `json:"description,omitempty"`
	Address           []string                                 `json:"address,omitempty"`
	Redirect          string                                   `json:"redirect,omitempty"`
	LocalIp           IPv6                                     `json:"local-ip,omitempty"`
	RemoteIp          IPv6                                     `json:"remote-ip,omitempty"`
	Ip                *ConfigInterfacesIpv6TunnelIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesIpv6TunnelIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesIpv6TunnelBandwidth struct {
	Maximum    string                                         `json:"maximum,omitempty"`
	Reservable string                                         `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesIpv6TunnelBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesIpv6TunnelBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesIpv6TunnelBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesIpv6TunnelBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesIpv6TunnelTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesIpv6TunnelFirewall struct {
	Out   *ConfigInterfacesIpv6TunnelFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesIpv6TunnelFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesIpv6TunnelFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesIpv6TunnelFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesIpv6TunnelFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesIpv6TunnelFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesIpv6TunnelIp struct {
	Rip              *ConfigInterfacesIpv6TunnelIpRip  `json:"rip,omitempty"`
	SourceValidation string                            `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesIpv6TunnelIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpRip struct {
	SplitHorizon   *ConfigInterfacesIpv6TunnelIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesIpv6TunnelIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                       `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspf struct {
	RetransmitInterval EdgeOSInt                                       `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                       `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               EdgeOSInt                                       `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                       `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                       `json:"priority,omitempty"`
	MtuIgnore          string                                          `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesIpv6TunnelIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                       `json:"hello-interval,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspfAuthentication struct {
	Md5               *ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpv6 struct {
	Ripng  *ConfigInterfacesIpv6TunnelIpv6Ripng  `json:"ripng,omitempty"`
	Ospfv3 *ConfigInterfacesIpv6TunnelIpv6Ospfv3 `json:"ospfv3,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesIpv6TunnelIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBonding struct {
	BridgeGroup       *ConfigInterfacesBondingBridgeGroup    `json:"bridge-group,omitempty"`
	HashPolicy        string                                 `json:"hash-policy,omitempty"`
	Disable           string                                 `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBondingBandwidth      `json:"bandwidth,omitempty"`
	Mode              string                                 `json:"mode,omitempty"`
	Mtu               EdgeOSInt                              `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesBondingTrafficPolicy  `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBondingVrrp           `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBondingDhcpv6Pd       `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect string                                 `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBondingFirewall       `json:"firewall,omitempty"`
	Mac               MacAddr                                `json:"mac,omitempty"`
	DhcpOptions       *ConfigInterfacesBondingDhcpOptions    `json:"dhcp-options,omitempty"`
	Description       string                                 `json:"description,omitempty"`
	Vif               *map[string]ConfigInterfacesBondingVif `json:"vif,omitempty"`
	Address           []string                               `json:"address,omitempty"`
	Redirect          string                                 `json:"redirect,omitempty"`
	ArpMonitor        *ConfigInterfacesBondingArpMonitor     `json:"arp-monitor,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBondingDhcpv6Options  `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesBondingIp             `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBondingIpv6           `json:"ipv6,omitempty"`
	Primary           string                                 `json:"primary,omitempty"`
}

type ConfigInterfacesBondingBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesBondingBandwidth struct {
	Maximum    string                                      `json:"maximum,omitempty"`
	Reservable string                                      `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBondingBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBondingBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesBondingBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBondingBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBondingTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBondingVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesBondingVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBondingVrrpVrrpGroup struct {
	Disable              string                                                    `json:"disable,omitempty"`
	VirtualAddress       []string                                                  `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                 `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                    `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                 `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBondingVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                      `json:"preempt,omitempty"`
	Description          string                                                    `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                      `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                 `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesBondingVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesBondingVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesBondingVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesBondingDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesBondingDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                        `json:"duid,omitempty"`
	NoDns       string                                        `json:"no-dns,omitempty"`
	RapidCommit string                                        `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                        `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBondingDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesBondingDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                 `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBondingDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                              `json:"no-dns,omitempty"`
	PrefixId      string                                                              `json:"prefix-id,omitempty"`
	HostAddress   string                                                              `json:"host-address,omitempty"`
	Service       string                                                              `json:"service,omitempty"`
}

type ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesBondingFirewall struct {
	Out   *ConfigInterfacesBondingFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesBondingFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesBondingFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesBondingFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBondingFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBondingFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBondingDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesBondingVif struct {
	BridgeGroup       *ConfigInterfacesBondingVifBridgeGroup   `json:"bridge-group,omitempty"`
	Disable           string                                   `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBondingVifBandwidth     `json:"bandwidth,omitempty"`
	Mtu               EdgeOSInt                                `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesBondingVifTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBondingVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBondingVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect string                                   `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBondingVifFirewall      `json:"firewall,omitempty"`
	DhcpOptions       *ConfigInterfacesBondingVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                   `json:"description,omitempty"`
	Address           []string                                 `json:"address,omitempty"`
	Redirect          string                                   `json:"redirect,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBondingVifDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesBondingVifIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBondingVifIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesBondingVifBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesBondingVifBandwidth struct {
	Maximum    string                                         `json:"maximum,omitempty"`
	Reservable string                                         `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBondingVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBondingVifBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesBondingVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBondingVifBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBondingVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBondingVifVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesBondingVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBondingVifVrrpVrrpGroup struct {
	Disable              string                                                       `json:"disable,omitempty"`
	VirtualAddress       []string                                                     `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                    `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                       `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                    `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBondingVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                         `json:"preempt,omitempty"`
	Description          string                                                       `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                         `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                    `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesBondingVifVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesBondingVifVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesBondingVifVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesBondingVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                           `json:"duid,omitempty"`
	NoDns       string                                           `json:"no-dns,omitempty"`
	RapidCommit string                                           `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                           `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesBondingVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                    `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                 `json:"no-dns,omitempty"`
	PrefixId      string                                                                 `json:"prefix-id,omitempty"`
	HostAddress   string                                                                 `json:"host-address,omitempty"`
	Service       string                                                                 `json:"service,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesBondingVifFirewall struct {
	Out   *ConfigInterfacesBondingVifFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesBondingVifFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesBondingVifFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesBondingVifFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBondingVifFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBondingVifFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBondingVifDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesBondingVifIp struct {
	Rip              *ConfigInterfacesBondingVifIpRip  `json:"rip,omitempty"`
	SourceValidation string                            `json:"source-validation,omitempty"`
	ProxyArpPvlan    string                            `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesBondingVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBondingVifIpRip struct {
	SplitHorizon   *ConfigInterfacesBondingVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBondingVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBondingVifIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingVifIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesBondingVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                       `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingVifIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBondingVifIpOspf struct {
	RetransmitInterval EdgeOSInt                                       `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                       `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               EdgeOSInt                                       `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                       `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                       `json:"priority,omitempty"`
	MtuIgnore          string                                          `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBondingVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                       `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBondingVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBondingVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingVifIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBondingVifIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                   `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                      `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBondingVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBondingVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBondingVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBondingVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBondingVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBondingVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBondingVifIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingVifIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesBondingVifIpv6RouterAdvert struct {
	DefaultPreference string                                                       `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                    `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                    `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                    `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesBondingVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                       `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                    `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                         `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                     `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                         `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                         `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                    `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                    `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                    `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBondingVifIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBondingVifIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBondingArpMonitor struct {
	Target   []string  `json:"target,omitempty"`
	Interval EdgeOSInt `json:"interval,omitempty"`
}

type ConfigInterfacesBondingDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesBondingIp struct {
	Rip              *ConfigInterfacesBondingIpRip  `json:"rip,omitempty"`
	EnableProxyArp   string                         `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                         `json:"source-validation,omitempty"`
	ProxyArpPvlan    string                         `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesBondingIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBondingIpRip struct {
	SplitHorizon   *ConfigInterfacesBondingIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBondingIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBondingIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesBondingIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                    `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBondingIpOspf struct {
	RetransmitInterval EdgeOSInt                                    `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                    `json:"transmit-delay,omitempty"`
	Network            string                                       `json:"network,omitempty"`
	Cost               EdgeOSInt                                    `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                    `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                    `json:"priority,omitempty"`
	MtuIgnore          string                                       `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBondingIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                    `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBondingIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBondingIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBondingIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                   `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBondingIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBondingIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBondingIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBondingIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBondingIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBondingIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBondingIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesBondingIpv6RouterAdvert struct {
	DefaultPreference string                                                    `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                 `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                 `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                 `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesBondingIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                    `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                 `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                      `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                  `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                      `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                      `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                 `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                 `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                 `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBondingIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBondingIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpv3 struct {
	BridgeGroup     *ConfigInterfacesL2tpv3BridgeGroup   `json:"bridge-group,omitempty"`
	Disable         string                               `json:"disable,omitempty"`
	PeerSessionId   string                               `json:"peer-session-id,omitempty"`
	Bandwidth       *ConfigInterfacesL2tpv3Bandwidth     `json:"bandwidth,omitempty"`
	Encapsulation   string                               `json:"encapsulation,omitempty"`
	Mtu             EdgeOSInt                            `json:"mtu,omitempty"`
	TrafficPolicy   *ConfigInterfacesL2tpv3TrafficPolicy `json:"traffic-policy,omitempty"`
	SourcePort      string                               `json:"source-port,omitempty"`
	Firewall        *ConfigInterfacesL2tpv3Firewall      `json:"firewall,omitempty"`
	PeerTunnelId    string                               `json:"peer-tunnel-id,omitempty"`
	Description     string                               `json:"description,omitempty"`
	Address         []string                             `json:"address,omitempty"`
	Redirect        string                               `json:"redirect,omitempty"`
	LocalIp         IP                                   `json:"local-ip,omitempty"`
	RemoteIp        IP                                   `json:"remote-ip,omitempty"`
	Ip              *ConfigInterfacesL2tpv3Ip            `json:"ip,omitempty"`
	DestinationPort string                               `json:"destination-port,omitempty"`
	Ipv6            *ConfigInterfacesL2tpv3Ipv6          `json:"ipv6,omitempty"`
	TunnelId        string                               `json:"tunnel-id,omitempty"`
	SessionId       string                               `json:"session-id,omitempty"`
}

type ConfigInterfacesL2tpv3BridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesL2tpv3Bandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesL2tpv3BandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesL2tpv3BandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesL2tpv3BandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesL2tpv3BandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesL2tpv3TrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesL2tpv3Firewall struct {
	Out   *ConfigInterfacesL2tpv3FirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesL2tpv3FirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesL2tpv3FirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesL2tpv3FirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesL2tpv3FirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesL2tpv3FirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesL2tpv3Ip struct {
	Rip              *ConfigInterfacesL2tpv3IpRip  `json:"rip,omitempty"`
	SourceValidation string                        `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesL2tpv3IpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesL2tpv3IpRip struct {
	SplitHorizon   *ConfigInterfacesL2tpv3IpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesL2tpv3IpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesL2tpv3IpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpv3IpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesL2tpv3IpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpv3IpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspf struct {
	RetransmitInterval EdgeOSInt                                   `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                   `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               EdgeOSInt                                   `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                   `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                   `json:"priority,omitempty"`
	MtuIgnore          string                                      `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesL2tpv3IpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                   `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspfAuthentication struct {
	Md5               *ConfigInterfacesL2tpv3IpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesL2tpv3Ipv6 struct {
	Ripng  *ConfigInterfacesL2tpv3Ipv6Ripng  `json:"ripng,omitempty"`
	Ospfv3 *ConfigInterfacesL2tpv3Ipv6Ospfv3 `json:"ospfv3,omitempty"`
}

type ConfigInterfacesL2tpv3Ipv6Ripng struct {
	SplitHorizon *ConfigInterfacesL2tpv3Ipv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesL2tpv3Ipv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpv3Ipv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesVti struct {
	Disable       string                            `json:"disable,omitempty"`
	Bandwidth     *ConfigInterfacesVtiBandwidth     `json:"bandwidth,omitempty"`
	Mtu           EdgeOSInt                         `json:"mtu,omitempty"`
	TrafficPolicy *ConfigInterfacesVtiTrafficPolicy `json:"traffic-policy,omitempty"`
	Firewall      *ConfigInterfacesVtiFirewall      `json:"firewall,omitempty"`
	Description   string                            `json:"description,omitempty"`
	Address       []string                          `json:"address,omitempty"`
	Redirect      string                            `json:"redirect,omitempty"`
	Ip            *ConfigInterfacesVtiIp            `json:"ip,omitempty"`
	Ipv6          *ConfigInterfacesVtiIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesVtiBandwidth struct {
	Maximum    string                                  `json:"maximum,omitempty"`
	Reservable string                                  `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesVtiBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesVtiBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesVtiBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesVtiBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesVtiTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesVtiFirewall struct {
	Out   *ConfigInterfacesVtiFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesVtiFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesVtiFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesVtiFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesVtiFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesVtiFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesVtiIp struct {
	Rip              *ConfigInterfacesVtiIpRip  `json:"rip,omitempty"`
	SourceValidation string                     `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesVtiIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesVtiIpRip struct {
	SplitHorizon   *ConfigInterfacesVtiIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesVtiIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesVtiIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesVtiIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesVtiIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesVtiIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesVtiIpOspf struct {
	RetransmitInterval EdgeOSInt                                `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                `json:"transmit-delay,omitempty"`
	Network            string                                   `json:"network,omitempty"`
	Cost               EdgeOSInt                                `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                `json:"priority,omitempty"`
	MtuIgnore          string                                   `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesVtiIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                `json:"hello-interval,omitempty"`
}

type ConfigInterfacesVtiIpOspfAuthentication struct {
	Md5               *ConfigInterfacesVtiIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                      `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesVtiIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesVtiIpv6 struct {
	Ripng  *ConfigInterfacesVtiIpv6Ripng  `json:"ripng,omitempty"`
	Ospfv3 *ConfigInterfacesVtiIpv6Ospfv3 `json:"ospfv3,omitempty"`
}

type ConfigInterfacesVtiIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesVtiIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesVtiIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesVtiIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesInput struct {
	TrafficPolicy *ConfigInterfacesInputTrafficPolicy `json:"traffic-policy,omitempty"`
	Firewall      *ConfigInterfacesInputFirewall      `json:"firewall,omitempty"`
	Description   string                              `json:"description,omitempty"`
	Redirect      string                              `json:"redirect,omitempty"`
}

type ConfigInterfacesInputTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesInputFirewall struct {
	Out   *ConfigInterfacesInputFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesInputFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesInputFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesInputFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesInputFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesInputFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridge struct {
	Disable           string                                  `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBridgeBandwidth        `json:"bandwidth,omitempty"`
	Multicast         string                                  `json:"multicast,omitempty"`
	Pppoe             *map[string]ConfigInterfacesBridgePppoe `json:"pppoe,omitempty"`
	TrafficPolicy     *ConfigInterfacesBridgeTrafficPolicy    `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBridgeVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBridgeDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	Stp               bool                                    `json:"stp,omitempty"`
	DisableLinkDetect string                                  `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBridgeFirewall         `json:"firewall,omitempty"`
	MaxAge            EdgeOSInt                               `json:"max-age,omitempty"`
	BridgedConntrack  string                                  `json:"bridged-conntrack,omitempty"`
	DhcpOptions       *ConfigInterfacesBridgeDhcpOptions      `json:"dhcp-options,omitempty"`
	HelloTime         EdgeOSInt                               `json:"hello-time,omitempty"`
	Description       string                                  `json:"description,omitempty"`
	Vif               *map[string]ConfigInterfacesBridgeVif   `json:"vif,omitempty"`
	Address           []string                                `json:"address,omitempty"`
	Redirect          string                                  `json:"redirect,omitempty"`
	ForwardingDelay   EdgeOSInt                               `json:"forwarding-delay,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBridgeDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Priority          EdgeOSInt                               `json:"priority,omitempty"`
	Promiscuous       string                                  `json:"promiscuous,omitempty"`
	Ip                *ConfigInterfacesBridgeIp               `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBridgeIpv6             `json:"ipv6,omitempty"`
	Aging             EdgeOSInt                               `json:"aging,omitempty"`
}

type ConfigInterfacesBridgeBandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesBridgeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgePppoe struct {
	ServiceName        string                                    `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesBridgePppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                    `json:"password,omitempty"`
	RemoteAddress      string                                    `json:"remote-address,omitempty"`
	HostUniq           string                                    `json:"host-uniq,omitempty"`
	Mtu                string                                    `json:"mtu,omitempty"`
	NameServer         string                                    `json:"name-server,omitempty"`
	DefaultRoute       string                                    `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesBridgePppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        string                                    `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesBridgePppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                    `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesBridgePppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                    `json:"user-id,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	LocalAddress       string                                    `json:"local-address,omitempty"`
	Redirect           string                                    `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesBridgePppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesBridgePppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          string                                    `json:"multilink,omitempty"`
	AccessConcentrator string                                    `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesBridgePppoeBandwidth struct {
	Maximum    string                                          `json:"maximum,omitempty"`
	Reservable string                                          `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgePppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgePppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesBridgePppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgePppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgePppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesBridgePppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                            `json:"duid,omitempty"`
	NoDns       string                                            `json:"no-dns,omitempty"`
	RapidCommit string                                            `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                            `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesBridgePppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                     `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                  `json:"no-dns,omitempty"`
	PrefixId      string                                                                  `json:"prefix-id,omitempty"`
	HostAddress   string                                                                  `json:"host-address,omitempty"`
	Service       string                                                                  `json:"service,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesBridgePppoeFirewall struct {
	Out   *ConfigInterfacesBridgePppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesBridgePppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesBridgePppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesBridgePppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgePppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgePppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgePppoeIp struct {
	Rip              *ConfigInterfacesBridgePppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                             `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesBridgePppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBridgePppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesBridgePppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBridgePppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBridgePppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgePppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesBridgePppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgePppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                        `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                        `json:"transmit-delay,omitempty"`
	Network            string                                           `json:"network,omitempty"`
	Cost               EdgeOSInt                                        `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                        `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                        `json:"priority,omitempty"`
	MtuIgnore          string                                           `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgePppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                        `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6 struct {
	Enable                 *ConfigInterfacesBridgePppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                    `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                       `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgePppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgePppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgePppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgePppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgePppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                        `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                     `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                     `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                     `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                        `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                     `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                          `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                      `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                          `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                          `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                     `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                     `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                     `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgeVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesBridgeVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBridgeVrrpVrrpGroup struct {
	Disable              string                                                   `json:"disable,omitempty"`
	VirtualAddress       []string                                                 `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                   `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBridgeVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                     `json:"preempt,omitempty"`
	Description          string                                                   `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                     `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesBridgeVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesBridgeVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesBridgeVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesBridgeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                       `json:"duid,omitempty"`
	NoDns       string                                       `json:"no-dns,omitempty"`
	RapidCommit string                                       `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                       `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesBridgeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                             `json:"no-dns,omitempty"`
	PrefixId      string                                                             `json:"prefix-id,omitempty"`
	HostAddress   string                                                             `json:"host-address,omitempty"`
	Service       string                                                             `json:"service,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesBridgeFirewall struct {
	Out   *ConfigInterfacesBridgeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesBridgeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesBridgeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesBridgeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesBridgeVif struct {
	Disable           string                                     `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBridgeVifBandwidth        `json:"bandwidth,omitempty"`
	Pppoe             *map[string]ConfigInterfacesBridgeVifPppoe `json:"pppoe,omitempty"`
	TrafficPolicy     *ConfigInterfacesBridgeVifTrafficPolicy    `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBridgeVifVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBridgeVifDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect string                                     `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBridgeVifFirewall         `json:"firewall,omitempty"`
	DhcpOptions       *ConfigInterfacesBridgeVifDhcpOptions      `json:"dhcp-options,omitempty"`
	Description       string                                     `json:"description,omitempty"`
	Address           []string                                   `json:"address,omitempty"`
	Redirect          string                                     `json:"redirect,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBridgeVifDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesBridgeVifIp               `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBridgeVifIpv6             `json:"ipv6,omitempty"`
}

type ConfigInterfacesBridgeVifBandwidth struct {
	Maximum    string                                        `json:"maximum,omitempty"`
	Reservable string                                        `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgeVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgeVifBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesBridgeVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgeVifBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgeVifPppoe struct {
	ServiceName        string                                       `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesBridgeVifPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                       `json:"password,omitempty"`
	RemoteAddress      string                                       `json:"remote-address,omitempty"`
	HostUniq           string                                       `json:"host-uniq,omitempty"`
	Mtu                string                                       `json:"mtu,omitempty"`
	NameServer         string                                       `json:"name-server,omitempty"`
	DefaultRoute       string                                       `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesBridgeVifPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        string                                       `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesBridgeVifPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                       `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesBridgeVifPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                       `json:"user-id,omitempty"`
	Description        string                                       `json:"description,omitempty"`
	LocalAddress       string                                       `json:"local-address,omitempty"`
	Redirect           string                                       `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesBridgeVifPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesBridgeVifPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          string                                       `json:"multilink,omitempty"`
	AccessConcentrator string                                       `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeBandwidth struct {
	Maximum    string                                             `json:"maximum,omitempty"`
	Reservable string                                             `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgeVifPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesBridgeVifPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                               `json:"duid,omitempty"`
	NoDns       string                                               `json:"no-dns,omitempty"`
	RapidCommit string                                               `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                               `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                        `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                     `json:"no-dns,omitempty"`
	PrefixId      string                                                                     `json:"prefix-id,omitempty"`
	HostAddress   string                                                                     `json:"host-address,omitempty"`
	Service       string                                                                     `json:"service,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeFirewall struct {
	Out   *ConfigInterfacesBridgeVifPppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesBridgeVifPppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesBridgeVifPppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIp struct {
	Rip              *ConfigInterfacesBridgeVifPppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                                `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesBridgeVifPppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesBridgeVifPppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBridgeVifPppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                           `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                           `json:"transmit-delay,omitempty"`
	Network            string                                              `json:"network,omitempty"`
	Cost               EdgeOSInt                                           `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                           `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                           `json:"priority,omitempty"`
	MtuIgnore          string                                              `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgeVifPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                           `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                 `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6 struct {
	Enable                 *ConfigInterfacesBridgeVifPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                       `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                          `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgeVifPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgeVifPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgeVifPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgeVifPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgeVifPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                           `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                        `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                        `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                        `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                           `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                        `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                             `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                         `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                             `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                             `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                        `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                        `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                        `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgeVifVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesBridgeVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBridgeVifVrrpVrrpGroup struct {
	Disable              string                                                      `json:"disable,omitempty"`
	VirtualAddress       []string                                                    `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                   `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                      `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                   `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBridgeVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                        `json:"preempt,omitempty"`
	Description          string                                                      `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                        `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                   `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesBridgeVifVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesBridgeVifVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesBridgeVifVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesBridgeVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                          `json:"duid,omitempty"`
	NoDns       string                                          `json:"no-dns,omitempty"`
	RapidCommit string                                          `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                          `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesBridgeVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                   `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                `json:"no-dns,omitempty"`
	PrefixId      string                                                                `json:"prefix-id,omitempty"`
	HostAddress   string                                                                `json:"host-address,omitempty"`
	Service       string                                                                `json:"service,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesBridgeVifFirewall struct {
	Out   *ConfigInterfacesBridgeVifFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesBridgeVifFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesBridgeVifFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesBridgeVifFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeVifFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeVifFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesBridgeVifIp struct {
	Rip              *ConfigInterfacesBridgeVifIpRip  `json:"rip,omitempty"`
	SourceValidation string                           `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesBridgeVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBridgeVifIpRip struct {
	SplitHorizon   *ConfigInterfacesBridgeVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBridgeVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBridgeVifIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesBridgeVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                      `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspf struct {
	RetransmitInterval EdgeOSInt                                      `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                      `json:"transmit-delay,omitempty"`
	Network            string                                         `json:"network,omitempty"`
	Cost               EdgeOSInt                                      `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                      `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                      `json:"priority,omitempty"`
	MtuIgnore          string                                         `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgeVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                      `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgeVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                  `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                     `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgeVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgeVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgeVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgeVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgeVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6RouterAdvert struct {
	DefaultPreference string                                                      `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                   `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                   `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                   `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                      `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                   `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                        `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                    `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                        `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                        `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                   `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                   `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                   `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesBridgeIp struct {
	Rip              *ConfigInterfacesBridgeIpRip  `json:"rip,omitempty"`
	SourceValidation string                        `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesBridgeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBridgeIpRip struct {
	SplitHorizon   *ConfigInterfacesBridgeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBridgeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBridgeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesBridgeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgeIpOspf struct {
	RetransmitInterval EdgeOSInt                                   `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                   `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               EdgeOSInt                                   `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                   `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                   `json:"priority,omitempty"`
	MtuIgnore          string                                      `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                   `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgeIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                               `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                  `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesBridgeIpv6RouterAdvert struct {
	DefaultPreference string                                                   `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesBridgeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                   `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                     `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                 `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                     `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                     `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpClient struct {
	Disable        string                                    `json:"disable,omitempty"`
	Bandwidth      *ConfigInterfacesL2tpClientBandwidth      `json:"bandwidth,omitempty"`
	Mtu            EdgeOSInt                                 `json:"mtu,omitempty"`
	NameServer     string                                    `json:"name-server,omitempty"`
	DefaultRoute   string                                    `json:"default-route,omitempty"`
	TrafficPolicy  *ConfigInterfacesL2tpClientTrafficPolicy  `json:"traffic-policy,omitempty"`
	Firewall       *ConfigInterfacesL2tpClientFirewall       `json:"firewall,omitempty"`
	ServerIp       string                                    `json:"server-ip,omitempty"`
	Description    string                                    `json:"description,omitempty"`
	Compression    *ConfigInterfacesL2tpClientCompression    `json:"compression,omitempty"`
	Redirect       string                                    `json:"redirect,omitempty"`
	RequireIpsec   string                                    `json:"require-ipsec,omitempty"`
	Ip             *ConfigInterfacesL2tpClientIp             `json:"ip,omitempty"`
	Ipv6           *ConfigInterfacesL2tpClientIpv6           `json:"ipv6,omitempty"`
	Authentication *ConfigInterfacesL2tpClientAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesL2tpClientBandwidth struct {
	Maximum    string                                         `json:"maximum,omitempty"`
	Reservable string                                         `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesL2tpClientBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesL2tpClientBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesL2tpClientBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesL2tpClientBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesL2tpClientTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesL2tpClientFirewall struct {
	Out   *ConfigInterfacesL2tpClientFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesL2tpClientFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesL2tpClientFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesL2tpClientFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesL2tpClientFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesL2tpClientFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesL2tpClientCompression struct {
	ProtocolField string `json:"protocol-field,omitempty"`
	Bsd           string `json:"bsd,omitempty"`
	TcpHeader     string `json:"tcp-header,omitempty"`
	Deflate       string `json:"deflate,omitempty"`
	Control       string `json:"control,omitempty"`
}

type ConfigInterfacesL2tpClientIp struct {
	Rip              *ConfigInterfacesL2tpClientIpRip  `json:"rip,omitempty"`
	SourceValidation string                            `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesL2tpClientIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesL2tpClientIpRip struct {
	SplitHorizon   *ConfigInterfacesL2tpClientIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesL2tpClientIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesL2tpClientIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpClientIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesL2tpClientIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                       `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpClientIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspf struct {
	RetransmitInterval EdgeOSInt                                       `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                       `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               EdgeOSInt                                       `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                       `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                       `json:"priority,omitempty"`
	MtuIgnore          string                                          `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesL2tpClientIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                       `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspfAuthentication struct {
	Md5               *ConfigInterfacesL2tpClientIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesL2tpClientIpv6 struct {
	Ripng  *ConfigInterfacesL2tpClientIpv6Ripng  `json:"ripng,omitempty"`
	Ospfv3 *ConfigInterfacesL2tpClientIpv6Ospfv3 `json:"ospfv3,omitempty"`
}

type ConfigInterfacesL2tpClientIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesL2tpClientIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesL2tpClientIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpClientIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpClientAuthentication struct {
	Password    string   `json:"password,omitempty"`
	Refuse      []string `json:"refuse,omitempty"`
	UserId      string   `json:"user-id,omitempty"`
	RequireMppe string   `json:"require-mppe,omitempty"`
}

type ConfigInterfacesPptpClient struct {
	Bandwidth       *ConfigInterfacesPptpClientBandwidth     `json:"bandwidth,omitempty"`
	Password        string                                   `json:"password,omitempty"`
	RemoteAddress   string                                   `json:"remote-address,omitempty"`
	Mtu             string                                   `json:"mtu,omitempty"`
	NameServer      string                                   `json:"name-server,omitempty"`
	DefaultRoute    string                                   `json:"default-route,omitempty"`
	TrafficPolicy   *ConfigInterfacesPptpClientTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout     string                                   `json:"idle-timeout,omitempty"`
	ConnectOnDemand string                                   `json:".connect-on-demand,omitempty"`
	Firewall        *ConfigInterfacesPptpClientFirewall      `json:"firewall,omitempty"`
	UserId          string                                   `json:"user-id,omitempty"`
	ServerIp        string                                   `json:"server-ip,omitempty"`
	Description     string                                   `json:"description,omitempty"`
	LocalAddress    string                                   `json:"local-address,omitempty"`
	RequireMppe     string                                   `json:"require-mppe,omitempty"`
	Redirect        string                                   `json:"redirect,omitempty"`
	Ip              *ConfigInterfacesPptpClientIp            `json:"ip,omitempty"`
	Ipv6            *ConfigInterfacesPptpClientIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesPptpClientBandwidth struct {
	Maximum    string                                         `json:"maximum,omitempty"`
	Reservable string                                         `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesPptpClientBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesPptpClientBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesPptpClientBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPptpClientBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPptpClientTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesPptpClientFirewall struct {
	Out   *ConfigInterfacesPptpClientFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesPptpClientFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesPptpClientFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesPptpClientFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPptpClientFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPptpClientFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPptpClientIp struct {
	Rip              *ConfigInterfacesPptpClientIpRip  `json:"rip,omitempty"`
	SourceValidation string                            `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesPptpClientIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesPptpClientIpRip struct {
	SplitHorizon   *ConfigInterfacesPptpClientIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesPptpClientIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesPptpClientIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPptpClientIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesPptpClientIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                       `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPptpClientIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPptpClientIpOspf struct {
	RetransmitInterval EdgeOSInt                                       `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                       `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               EdgeOSInt                                       `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                       `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                       `json:"priority,omitempty"`
	MtuIgnore          string                                          `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPptpClientIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                       `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPptpClientIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPptpClientIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPptpClientIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPptpClientIpv6 struct {
	Enable                 *ConfigInterfacesPptpClientIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                   `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                      `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesPptpClientIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesPptpClientIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesPptpClientIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesPptpClientIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPptpClientIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPptpClientIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesPptpClientIpv6RouterAdvert struct {
	DefaultPreference string                                                       `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                    `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                    `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                    `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesPptpClientIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                       `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                    `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                         `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                     `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                         `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                         `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                    `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                    `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                    `json:"link-mtu,omitempty"`
}

type ConfigInterfacesPptpClientIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernet struct {
	BridgeGroup        *ConfigInterfacesEthernetBridgeGroup      `json:"bridge-group,omitempty"`
	Poe                *ConfigInterfacesEthernetPoe              `json:"poe,omitempty"`
	Disable            string                                    `json:"disable,omitempty"`
	Bandwidth          *ConfigInterfacesEthernetBandwidth        `json:"bandwidth,omitempty"`
	Pppoe              *map[string]ConfigInterfacesEthernetPppoe `json:"pppoe,omitempty"`
	Speed              string                                    `json:"speed,omitempty"`
	Mtu                EdgeOSInt                                 `json:"mtu,omitempty"`
	TrafficPolicy      *ConfigInterfacesEthernetTrafficPolicy    `json:"traffic-policy,omitempty"`
	Vrrp               *ConfigInterfacesEthernetVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesEthernetDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect  string                                    `json:"disable-link-detect,omitempty"`
	Duplex             string                                    `json:"duplex,omitempty"`
	Firewall           *ConfigInterfacesEthernetFirewall         `json:"firewall,omitempty"`
	DisableFlowControl string                                    `json:".disable-flow-control,omitempty"`
	Mac                MacAddr                                   `json:"mac,omitempty"`
	DhcpOptions        *ConfigInterfacesEthernetDhcpOptions      `json:"dhcp-options,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	BondGroup          string                                    `json:"bond-group,omitempty"`
	Vif                *map[string]ConfigInterfacesEthernetVif   `json:"vif,omitempty"`
	Address            []string                                  `json:"address,omitempty"`
	Redirect           string                                    `json:"redirect,omitempty"`
	SmpAffinity        string                                    `json:".smp_affinity,omitempty"`
	Dhcpv6Options      *ConfigInterfacesEthernetDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Ip                 *ConfigInterfacesEthernetIp               `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesEthernetIpv6             `json:"ipv6,omitempty"`
	Mirror             string                                    `json:"mirror,omitempty"`
}

type ConfigInterfacesEthernetBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesEthernetPoe struct {
	Output   string                               `json:"output,omitempty"`
	Watchdog *ConfigInterfacesEthernetPoeWatchdog `json:"watchdog,omitempty"`
}

type ConfigInterfacesEthernetPoeWatchdog struct {
	Disable      string    `json:"disable,omitempty"`
	FailureCount EdgeOSInt `json:"failure-count,omitempty"`
	OffDelay     EdgeOSInt `json:"off-delay,omitempty"`
	Interval     EdgeOSInt `json:"interval,omitempty"`
	StartDelay   EdgeOSInt `json:"start-delay,omitempty"`
	Address      IP        `json:"address,omitempty"`
}

type ConfigInterfacesEthernetBandwidth struct {
	Maximum    string                                       `json:"maximum,omitempty"`
	Reservable string                                       `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesEthernetBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetPppoe struct {
	ServiceName        string                                      `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesEthernetPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                      `json:"password,omitempty"`
	RemoteAddress      string                                      `json:"remote-address,omitempty"`
	HostUniq           string                                      `json:"host-uniq,omitempty"`
	Mtu                string                                      `json:"mtu,omitempty"`
	NameServer         string                                      `json:"name-server,omitempty"`
	DefaultRoute       string                                      `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesEthernetPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        string                                      `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesEthernetPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                      `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesEthernetPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                      `json:"user-id,omitempty"`
	Description        string                                      `json:"description,omitempty"`
	LocalAddress       string                                      `json:"local-address,omitempty"`
	Redirect           string                                      `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesEthernetPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesEthernetPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          string                                      `json:"multilink,omitempty"`
	AccessConcentrator string                                      `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesEthernetPppoeBandwidth struct {
	Maximum    string                                            `json:"maximum,omitempty"`
	Reservable string                                            `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetPppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesEthernetPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetPppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesEthernetPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                              `json:"duid,omitempty"`
	NoDns       string                                              `json:"no-dns,omitempty"`
	RapidCommit string                                              `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                              `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                       `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                    `json:"no-dns,omitempty"`
	PrefixId      string                                                                    `json:"prefix-id,omitempty"`
	HostAddress   string                                                                    `json:"host-address,omitempty"`
	Service       string                                                                    `json:"service,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesEthernetPppoeFirewall struct {
	Out   *ConfigInterfacesEthernetPppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesEthernetPppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesEthernetPppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesEthernetPppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetPppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetPppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetPppoeIp struct {
	Rip              *ConfigInterfacesEthernetPppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                               `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesEthernetPppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesEthernetPppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesEthernetPppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                          `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                          `json:"transmit-delay,omitempty"`
	Network            string                                             `json:"network,omitempty"`
	Cost               EdgeOSInt                                          `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                          `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                          `json:"priority,omitempty"`
	MtuIgnore          string                                             `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                          `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6 struct {
	Enable                 *ConfigInterfacesEthernetPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                      `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                         `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                          `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                       `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                       `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                       `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                          `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                       `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                            `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                        `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                            `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                            `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                       `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                       `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                       `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesEthernetVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesEthernetVrrpVrrpGroup struct {
	Disable              string                                                     `json:"disable,omitempty"`
	VirtualAddress       []string                                                   `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                  `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                     `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                  `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesEthernetVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                       `json:"preempt,omitempty"`
	Description          string                                                     `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                       `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                  `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesEthernetVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesEthernetVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesEthernetDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                         `json:"duid,omitempty"`
	NoDns       string                                         `json:"no-dns,omitempty"`
	RapidCommit string                                         `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                         `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesEthernetDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                  `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                               `json:"no-dns,omitempty"`
	PrefixId      string                                                               `json:"prefix-id,omitempty"`
	HostAddress   string                                                               `json:"host-address,omitempty"`
	Service       string                                                               `json:"service,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesEthernetFirewall struct {
	Out   *ConfigInterfacesEthernetFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesEthernetFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesEthernetFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesEthernetFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesEthernetVif struct {
	BridgeGroup       *ConfigInterfacesEthernetVifBridgeGroup      `json:"bridge-group,omitempty"`
	Disable           string                                       `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesEthernetVifBandwidth        `json:"bandwidth,omitempty"`
	EgressQos         string                                       `json:"egress-qos,omitempty"`
	Pppoe             *map[string]ConfigInterfacesEthernetVifPppoe `json:"pppoe,omitempty"`
	Mtu               EdgeOSInt                                    `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesEthernetVifTrafficPolicy    `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesEthernetVifVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesEthernetVifDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect string                                       `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesEthernetVifFirewall         `json:"firewall,omitempty"`
	Mac               MacAddr                                      `json:"mac,omitempty"`
	DhcpOptions       *ConfigInterfacesEthernetVifDhcpOptions      `json:"dhcp-options,omitempty"`
	Description       string                                       `json:"description,omitempty"`
	Address           []string                                     `json:"address,omitempty"`
	Redirect          string                                       `json:"redirect,omitempty"`
	Dhcpv6Options     *ConfigInterfacesEthernetVifDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesEthernetVifIp               `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesEthernetVifIpv6             `json:"ipv6,omitempty"`
}

type ConfigInterfacesEthernetVifBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesEthernetVifBandwidth struct {
	Maximum    string                                          `json:"maximum,omitempty"`
	Reservable string                                          `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetVifBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesEthernetVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetVifBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetVifPppoe struct {
	ServiceName        string                                         `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesEthernetVifPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                         `json:"password,omitempty"`
	RemoteAddress      string                                         `json:"remote-address,omitempty"`
	HostUniq           string                                         `json:"host-uniq,omitempty"`
	Mtu                string                                         `json:"mtu,omitempty"`
	NameServer         string                                         `json:"name-server,omitempty"`
	DefaultRoute       string                                         `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesEthernetVifPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        string                                         `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesEthernetVifPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                         `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesEthernetVifPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                         `json:"user-id,omitempty"`
	Description        string                                         `json:"description,omitempty"`
	LocalAddress       string                                         `json:"local-address,omitempty"`
	Redirect           string                                         `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesEthernetVifPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesEthernetVifPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          string                                         `json:"multilink,omitempty"`
	AccessConcentrator string                                         `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeBandwidth struct {
	Maximum    string                                               `json:"maximum,omitempty"`
	Reservable string                                               `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetVifPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesEthernetVifPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                                 `json:"duid,omitempty"`
	NoDns       string                                                 `json:"no-dns,omitempty"`
	RapidCommit string                                                 `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                                 `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                          `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                       `json:"no-dns,omitempty"`
	PrefixId      string                                                                       `json:"prefix-id,omitempty"`
	HostAddress   string                                                                       `json:"host-address,omitempty"`
	Service       string                                                                       `json:"service,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeFirewall struct {
	Out   *ConfigInterfacesEthernetVifPppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesEthernetVifPppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesEthernetVifPppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIp struct {
	Rip              *ConfigInterfacesEthernetVifPppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                                  `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesEthernetVifPppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesEthernetVifPppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesEthernetVifPppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                             `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                             `json:"transmit-delay,omitempty"`
	Network            string                                                `json:"network,omitempty"`
	Cost               EdgeOSInt                                             `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                             `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                             `json:"priority,omitempty"`
	MtuIgnore          string                                                `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetVifPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6 struct {
	Enable                 *ConfigInterfacesEthernetVifPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                         `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                            `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetVifPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetVifPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetVifPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetVifPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetVifPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                             `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                          `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                          `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                          `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                             `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                          `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                               `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                           `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                               `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                               `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                          `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                          `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                          `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetVifVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesEthernetVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesEthernetVifVrrpVrrpGroup struct {
	Disable              string                                                        `json:"disable,omitempty"`
	VirtualAddress       []string                                                      `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                     `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                        `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                     `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesEthernetVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                          `json:"preempt,omitempty"`
	Description          string                                                        `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                          `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                     `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesEthernetVifVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetVifVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesEthernetVifVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesEthernetVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                            `json:"duid,omitempty"`
	NoDns       string                                            `json:"no-dns,omitempty"`
	RapidCommit string                                            `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                            `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesEthernetVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                     `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                  `json:"no-dns,omitempty"`
	PrefixId      string                                                                  `json:"prefix-id,omitempty"`
	HostAddress   string                                                                  `json:"host-address,omitempty"`
	Service       string                                                                  `json:"service,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesEthernetVifFirewall struct {
	Out   *ConfigInterfacesEthernetVifFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesEthernetVifFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesEthernetVifFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesEthernetVifFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetVifFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetVifFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesEthernetVifIp struct {
	Rip              *ConfigInterfacesEthernetVifIpRip  `json:"rip,omitempty"`
	EnableProxyArp   string                             `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                             `json:"source-validation,omitempty"`
	ProxyArpPvlan    string                             `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesEthernetVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesEthernetVifIpRip struct {
	SplitHorizon   *ConfigInterfacesEthernetVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesEthernetVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetVifIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesEthernetVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspf struct {
	RetransmitInterval EdgeOSInt                                        `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                        `json:"transmit-delay,omitempty"`
	Network            string                                           `json:"network,omitempty"`
	Cost               EdgeOSInt                                        `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                        `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                        `json:"priority,omitempty"`
	MtuIgnore          string                                           `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                        `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                    `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                       `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6RouterAdvert struct {
	DefaultPreference string                                                        `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                     `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                     `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                     `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                        `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                     `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                          `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                      `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                          `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                          `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                     `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                     `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                     `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesEthernetIp struct {
	Rip              *ConfigInterfacesEthernetIpRip  `json:"rip,omitempty"`
	EnableProxyArp   string                          `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                          `json:"source-validation,omitempty"`
	ProxyArpPvlan    string                          `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesEthernetIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesEthernetIpRip struct {
	SplitHorizon   *ConfigInterfacesEthernetIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesEthernetIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesEthernetIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                     `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetIpOspf struct {
	RetransmitInterval EdgeOSInt                                     `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                     `json:"transmit-delay,omitempty"`
	Network            string                                        `json:"network,omitempty"`
	Cost               EdgeOSInt                                     `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                     `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                     `json:"priority,omitempty"`
	MtuIgnore          string                                        `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                     `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                 `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                    `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesEthernetIpv6RouterAdvert struct {
	DefaultPreference string                                                     `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                  `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                  `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                  `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesEthernetIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                     `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                  `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                       `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                   `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                       `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                       `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                  `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                  `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                  `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesTunnel struct {
	BridgeGroup       *ConfigInterfacesTunnelBridgeGroup   `json:"bridge-group,omitempty"`
	Disable           string                               `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesTunnelBandwidth     `json:"bandwidth,omitempty"`
	Encapsulation     string                               `json:"encapsulation,omitempty"`
	Multicast         string                               `json:"multicast,omitempty"`
	Ttl               EdgeOSInt                            `json:"ttl,omitempty"`
	Mtu               EdgeOSInt                            `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesTunnelTrafficPolicy `json:"traffic-policy,omitempty"`
	Key               EdgeOSInt                            `json:"key,omitempty"`
	DisableLinkDetect string                               `json:"disable-link-detect,omitempty"`
	SixrdPrefix       IPv6Net                              `json:"6rd-prefix,omitempty"`
	Firewall          *ConfigInterfacesTunnelFirewall      `json:"firewall,omitempty"`
	Tos               EdgeOSInt                            `json:"tos,omitempty"`
	SixrdRelayPrefix  IPv4Net                              `json:"6rd-relay_prefix,omitempty"`
	Description       string                               `json:"description,omitempty"`
	Address           []string                             `json:"address,omitempty"`
	Redirect          string                               `json:"redirect,omitempty"`
	LocalIp           IPv4                                 `json:"local-ip,omitempty"`
	RemoteIp          IPv4                                 `json:"remote-ip,omitempty"`
	SixrdDefaultGw    string                               `json:"6rd-default-gw,omitempty"`
	Ip                *ConfigInterfacesTunnelIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesTunnelIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesTunnelBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesTunnelBandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesTunnelBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesTunnelBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesTunnelBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesTunnelBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesTunnelTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesTunnelFirewall struct {
	Out   *ConfigInterfacesTunnelFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesTunnelFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesTunnelFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesTunnelFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesTunnelFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesTunnelFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesTunnelIp struct {
	Rip              *ConfigInterfacesTunnelIpRip  `json:"rip,omitempty"`
	SourceValidation string                        `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesTunnelIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesTunnelIpRip struct {
	SplitHorizon   *ConfigInterfacesTunnelIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesTunnelIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesTunnelIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesTunnelIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesTunnelIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesTunnelIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesTunnelIpOspf struct {
	RetransmitInterval EdgeOSInt                                   `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                   `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               EdgeOSInt                                   `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                   `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                   `json:"priority,omitempty"`
	MtuIgnore          string                                      `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesTunnelIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                   `json:"hello-interval,omitempty"`
}

type ConfigInterfacesTunnelIpOspfAuthentication struct {
	Md5               *ConfigInterfacesTunnelIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesTunnelIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesTunnelIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                               `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                  `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesTunnelIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesTunnelIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesTunnelIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesTunnelIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesTunnelIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesTunnelIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesTunnelIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesTunnelIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesTunnelIpv6RouterAdvert struct {
	DefaultPreference string                                                   `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesTunnelIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                   `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                     `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                 `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                     `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                     `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                `json:"link-mtu,omitempty"`
}

type ConfigInterfacesTunnelIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesTunnelIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesOpenvpn struct {
	BridgeGroup         *ConfigInterfacesOpenvpnBridgeGroup             `json:"bridge-group,omitempty"`
	Encryption          string                                          `json:"encryption,omitempty"`
	Disable             string                                          `json:"disable,omitempty"`
	RemoteHost          []string                                        `json:"remote-host,omitempty"`
	Bandwidth           *ConfigInterfacesOpenvpnBandwidth               `json:"bandwidth,omitempty"`
	ReplaceDefaultRoute *ConfigInterfacesOpenvpnReplaceDefaultRoute     `json:"replace-default-route,omitempty"`
	OpenvpnOption       []string                                        `json:"openvpn-option,omitempty"`
	RemoteAddress       IPv4                                            `json:"remote-address,omitempty"`
	Mode                string                                          `json:"mode,omitempty"`
	Hash                string                                          `json:"hash,omitempty"`
	DeviceType          string                                          `json:"device-type,omitempty"`
	SharedSecretKeyFile string                                          `json:"shared-secret-key-file,omitempty"`
	LocalHost           IPv4                                            `json:"local-host,omitempty"`
	TrafficPolicy       *ConfigInterfacesOpenvpnTrafficPolicy           `json:"traffic-policy,omitempty"`
	Server              *ConfigInterfacesOpenvpnServer                  `json:"server,omitempty"`
	Protocol            string                                          `json:"protocol,omitempty"`
	Firewall            *ConfigInterfacesOpenvpnFirewall                `json:"firewall,omitempty"`
	Tls                 *ConfigInterfacesOpenvpnTls                     `json:"tls,omitempty"`
	Description         string                                          `json:"description,omitempty"`
	LocalAddress        *map[string]ConfigInterfacesOpenvpnLocalAddress `json:"local-address,omitempty"`
	LocalPort           EdgeOSInt                                       `json:"local-port,omitempty"`
	Redirect            string                                          `json:"redirect,omitempty"`
	Ip                  *ConfigInterfacesOpenvpnIp                      `json:"ip,omitempty"`
	Ipv6                *ConfigInterfacesOpenvpnIpv6                    `json:"ipv6,omitempty"`
	RemotePort          EdgeOSInt                                       `json:"remote-port,omitempty"`
	ConfigFile          string                                          `json:"config-file,omitempty"`
}

type ConfigInterfacesOpenvpnBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesOpenvpnBandwidth struct {
	Maximum    string                                      `json:"maximum,omitempty"`
	Reservable string                                      `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesOpenvpnBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesOpenvpnBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesOpenvpnBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesOpenvpnBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesOpenvpnReplaceDefaultRoute struct {
	Local string `json:"local,omitempty"`
}

type ConfigInterfacesOpenvpnTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesOpenvpnServer struct {
	PushRoute      []string                                        `json:"push-route,omitempty"`
	Topology       string                                          `json:"topology,omitempty"`
	NameServer     []string                                        `json:"name-server,omitempty"`
	DomainName     string                                          `json:"domain-name,omitempty"`
	MaxConnections EdgeOSInt                                       `json:"max-connections,omitempty"`
	Subnet         IPv4Net                                         `json:"subnet,omitempty"`
	Client         *map[string]ConfigInterfacesOpenvpnServerClient `json:"client,omitempty"`
}

type ConfigInterfacesOpenvpnServerClient struct {
	PushRoute []string `json:"push-route,omitempty"`
	Disable   string   `json:"disable,omitempty"`
	Ip        IPv4     `json:"ip,omitempty"`
	Subnet    []string `json:"subnet,omitempty"`
}

type ConfigInterfacesOpenvpnFirewall struct {
	Out   *ConfigInterfacesOpenvpnFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesOpenvpnFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesOpenvpnFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesOpenvpnFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesOpenvpnFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesOpenvpnFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesOpenvpnTls struct {
	CrlFile    string `json:"crl-file,omitempty"`
	Role       string `json:"role,omitempty"`
	KeyFile    string `json:"key-file,omitempty"`
	DhFile     string `json:"dh-file,omitempty"`
	CaCertFile string `json:"ca-cert-file,omitempty"`
	CertFile   string `json:"cert-file,omitempty"`
}

type ConfigInterfacesOpenvpnLocalAddress struct {
	SubnetMask IPv4 `json:"subnet-mask,omitempty"`
}

type ConfigInterfacesOpenvpnIp struct {
	Rip              *ConfigInterfacesOpenvpnIpRip  `json:"rip,omitempty"`
	SourceValidation string                         `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesOpenvpnIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesOpenvpnIpRip struct {
	SplitHorizon   *ConfigInterfacesOpenvpnIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesOpenvpnIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesOpenvpnIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesOpenvpnIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesOpenvpnIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                    `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesOpenvpnIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspf struct {
	RetransmitInterval EdgeOSInt                                    `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                    `json:"transmit-delay,omitempty"`
	Network            string                                       `json:"network,omitempty"`
	Cost               EdgeOSInt                                    `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                    `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                    `json:"priority,omitempty"`
	MtuIgnore          string                                       `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesOpenvpnIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                    `json:"hello-interval,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspfAuthentication struct {
	Md5               *ConfigInterfacesOpenvpnIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                   `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesOpenvpnIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesOpenvpnIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesOpenvpnIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesOpenvpnIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesOpenvpnIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6RouterAdvert struct {
	DefaultPreference string                                                    `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                 `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                 `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                 `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                    `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                 `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                      `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                  `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                      `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                      `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                 `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                 `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                 `json:"link-mtu,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesLoopback struct {
	Bandwidth     *ConfigInterfacesLoopbackBandwidth     `json:"bandwidth,omitempty"`
	TrafficPolicy *ConfigInterfacesLoopbackTrafficPolicy `json:"traffic-policy,omitempty"`
	Description   string                                 `json:"description,omitempty"`
	Address       []string                               `json:"address,omitempty"`
	Redirect      string                                 `json:"redirect,omitempty"`
	Ip            *ConfigInterfacesLoopbackIp            `json:"ip,omitempty"`
	Ipv6          *ConfigInterfacesLoopbackIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesLoopbackBandwidth struct {
	Maximum    string                                       `json:"maximum,omitempty"`
	Reservable string                                       `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesLoopbackBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesLoopbackBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesLoopbackBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesLoopbackBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesLoopbackTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesLoopbackIp struct {
	Rip              *ConfigInterfacesLoopbackIpRip  `json:"rip,omitempty"`
	SourceValidation string                          `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesLoopbackIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesLoopbackIpRip struct {
	SplitHorizon   *ConfigInterfacesLoopbackIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesLoopbackIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesLoopbackIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesLoopbackIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesLoopbackIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                     `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesLoopbackIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesLoopbackIpOspf struct {
	RetransmitInterval EdgeOSInt                                     `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                     `json:"transmit-delay,omitempty"`
	Network            string                                        `json:"network,omitempty"`
	Cost               EdgeOSInt                                     `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                     `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                     `json:"priority,omitempty"`
	MtuIgnore          string                                        `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesLoopbackIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                     `json:"hello-interval,omitempty"`
}

type ConfigInterfacesLoopbackIpOspfAuthentication struct {
	Md5               *ConfigInterfacesLoopbackIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesLoopbackIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesLoopbackIpv6 struct {
	Ripng  *ConfigInterfacesLoopbackIpv6Ripng  `json:"ripng,omitempty"`
	Ospfv3 *ConfigInterfacesLoopbackIpv6Ospfv3 `json:"ospfv3,omitempty"`
}

type ConfigInterfacesLoopbackIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesLoopbackIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesLoopbackIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesLoopbackIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitch struct {
	BridgeGroup   *ConfigInterfacesSwitchBridgeGroup      `json:"bridge-group,omitempty"`
	Bandwidth     *ConfigInterfacesSwitchBandwidth        `json:"bandwidth,omitempty"`
	Pppoe         *map[string]ConfigInterfacesSwitchPppoe `json:"pppoe,omitempty"`
	Mtu           EdgeOSInt                               `json:"mtu,omitempty"`
	SwitchPort    *ConfigInterfacesSwitchSwitchPort       `json:"switch-port,omitempty"`
	TrafficPolicy *ConfigInterfacesSwitchTrafficPolicy    `json:"traffic-policy,omitempty"`
	Vrrp          *ConfigInterfacesSwitchVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd      *ConfigInterfacesSwitchDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	Firewall      *ConfigInterfacesSwitchFirewall         `json:"firewall,omitempty"`
	DhcpOptions   *ConfigInterfacesSwitchDhcpOptions      `json:"dhcp-options,omitempty"`
	Description   string                                  `json:"description,omitempty"`
	Vif           *map[string]ConfigInterfacesSwitchVif   `json:"vif,omitempty"`
	Address       []string                                `json:"address,omitempty"`
	Redirect      string                                  `json:"redirect,omitempty"`
	Dhcpv6Options *ConfigInterfacesSwitchDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Ip            *ConfigInterfacesSwitchIp               `json:"ip,omitempty"`
	Ipv6          *ConfigInterfacesSwitchIpv6             `json:"ipv6,omitempty"`
}

type ConfigInterfacesSwitchBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesSwitchBandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesSwitchBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchPppoe struct {
	ServiceName        string                                    `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesSwitchPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                    `json:"password,omitempty"`
	RemoteAddress      string                                    `json:"remote-address,omitempty"`
	HostUniq           string                                    `json:"host-uniq,omitempty"`
	Mtu                string                                    `json:"mtu,omitempty"`
	NameServer         string                                    `json:"name-server,omitempty"`
	DefaultRoute       string                                    `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesSwitchPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        string                                    `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesSwitchPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                    `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesSwitchPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                    `json:"user-id,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	LocalAddress       string                                    `json:"local-address,omitempty"`
	Redirect           string                                    `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesSwitchPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesSwitchPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          string                                    `json:"multilink,omitempty"`
	AccessConcentrator string                                    `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesSwitchPppoeBandwidth struct {
	Maximum    string                                          `json:"maximum,omitempty"`
	Reservable string                                          `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchPppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesSwitchPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchPppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesSwitchPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                            `json:"duid,omitempty"`
	NoDns       string                                            `json:"no-dns,omitempty"`
	RapidCommit string                                            `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                            `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                     `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                  `json:"no-dns,omitempty"`
	PrefixId      string                                                                  `json:"prefix-id,omitempty"`
	HostAddress   string                                                                  `json:"host-address,omitempty"`
	Service       string                                                                  `json:"service,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesSwitchPppoeFirewall struct {
	Out   *ConfigInterfacesSwitchPppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesSwitchPppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesSwitchPppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesSwitchPppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchPppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchPppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchPppoeIp struct {
	Rip              *ConfigInterfacesSwitchPppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                             `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesSwitchPppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesSwitchPppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesSwitchPppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                        `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                        `json:"transmit-delay,omitempty"`
	Network            string                                           `json:"network,omitempty"`
	Cost               EdgeOSInt                                        `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                        `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                        `json:"priority,omitempty"`
	MtuIgnore          string                                           `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                        `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6 struct {
	Enable                 *ConfigInterfacesSwitchPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                    `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                       `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                        `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                     `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                     `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                     `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                        `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                     `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                          `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                      `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                          `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                          `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                     `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                     `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                     `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchSwitchPort struct {
	Interface *map[string]ConfigInterfacesSwitchSwitchPortInterface `json:"interface,omitempty"`
	VlanAware string                                                `json:"vlan-aware,omitempty"`
}

type ConfigInterfacesSwitchSwitchPortInterface struct {
	Vlan *ConfigInterfacesSwitchSwitchPortInterfaceVlan `json:"vlan,omitempty"`
}

type ConfigInterfacesSwitchSwitchPortInterfaceVlan struct {
	Vid  []string  `json:"vid,omitempty"`
	Pvid EdgeOSInt `json:"pvid,omitempty"`
}

type ConfigInterfacesSwitchTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesSwitchVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesSwitchVrrpVrrpGroup struct {
	Disable              string                                                   `json:"disable,omitempty"`
	VirtualAddress       []string                                                 `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                   `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesSwitchVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                     `json:"preempt,omitempty"`
	Description          string                                                   `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                     `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesSwitchVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesSwitchVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesSwitchDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                       `json:"duid,omitempty"`
	NoDns       string                                       `json:"no-dns,omitempty"`
	RapidCommit string                                       `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                       `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesSwitchDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                             `json:"no-dns,omitempty"`
	PrefixId      string                                                             `json:"prefix-id,omitempty"`
	HostAddress   string                                                             `json:"host-address,omitempty"`
	Service       string                                                             `json:"service,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesSwitchFirewall struct {
	Out   *ConfigInterfacesSwitchFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesSwitchFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesSwitchFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesSwitchFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesSwitchVif struct {
	BridgeGroup   *ConfigInterfacesSwitchVifBridgeGroup      `json:"bridge-group,omitempty"`
	Disable       string                                     `json:"disable,omitempty"`
	Bandwidth     *ConfigInterfacesSwitchVifBandwidth        `json:"bandwidth,omitempty"`
	Pppoe         *map[string]ConfigInterfacesSwitchVifPppoe `json:"pppoe,omitempty"`
	Mtu           EdgeOSInt                                  `json:"mtu,omitempty"`
	TrafficPolicy *ConfigInterfacesSwitchVifTrafficPolicy    `json:"traffic-policy,omitempty"`
	Vrrp          *ConfigInterfacesSwitchVifVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd      *ConfigInterfacesSwitchVifDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	Firewall      *ConfigInterfacesSwitchVifFirewall         `json:"firewall,omitempty"`
	Mac           MacAddr                                    `json:"mac,omitempty"`
	DhcpOptions   *ConfigInterfacesSwitchVifDhcpOptions      `json:"dhcp-options,omitempty"`
	Description   string                                     `json:"description,omitempty"`
	Address       []string                                   `json:"address,omitempty"`
	Redirect      string                                     `json:"redirect,omitempty"`
	Dhcpv6Options *ConfigInterfacesSwitchVifDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Ip            *ConfigInterfacesSwitchVifIp               `json:"ip,omitempty"`
	Ipv6          *ConfigInterfacesSwitchVifIpv6             `json:"ipv6,omitempty"`
}

type ConfigInterfacesSwitchVifBridgeGroup struct {
	Bridge   string    `json:"bridge,omitempty"`
	Cost     EdgeOSInt `json:"cost,omitempty"`
	Priority EdgeOSInt `json:"priority,omitempty"`
}

type ConfigInterfacesSwitchVifBandwidth struct {
	Maximum    string                                        `json:"maximum,omitempty"`
	Reservable string                                        `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchVifBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesSwitchVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchVifBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchVifPppoe struct {
	ServiceName        string                                       `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesSwitchVifPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                       `json:"password,omitempty"`
	RemoteAddress      string                                       `json:"remote-address,omitempty"`
	HostUniq           string                                       `json:"host-uniq,omitempty"`
	Mtu                string                                       `json:"mtu,omitempty"`
	NameServer         string                                       `json:"name-server,omitempty"`
	DefaultRoute       string                                       `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesSwitchVifPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        string                                       `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesSwitchVifPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                       `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesSwitchVifPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                       `json:"user-id,omitempty"`
	Description        string                                       `json:"description,omitempty"`
	LocalAddress       string                                       `json:"local-address,omitempty"`
	Redirect           string                                       `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesSwitchVifPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesSwitchVifPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          string                                       `json:"multilink,omitempty"`
	AccessConcentrator string                                       `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeBandwidth struct {
	Maximum    string                                             `json:"maximum,omitempty"`
	Reservable string                                             `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchVifPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesSwitchVifPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                               `json:"duid,omitempty"`
	NoDns       string                                               `json:"no-dns,omitempty"`
	RapidCommit string                                               `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                               `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                        `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                     `json:"no-dns,omitempty"`
	PrefixId      string                                                                     `json:"prefix-id,omitempty"`
	HostAddress   string                                                                     `json:"host-address,omitempty"`
	Service       string                                                                     `json:"service,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeFirewall struct {
	Out   *ConfigInterfacesSwitchVifPppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesSwitchVifPppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesSwitchVifPppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIp struct {
	Rip              *ConfigInterfacesSwitchVifPppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                                `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesSwitchVifPppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesSwitchVifPppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesSwitchVifPppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                           `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                           `json:"transmit-delay,omitempty"`
	Network            string                                              `json:"network,omitempty"`
	Cost               EdgeOSInt                                           `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                           `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                           `json:"priority,omitempty"`
	MtuIgnore          string                                              `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchVifPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                           `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                 `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6 struct {
	Enable                 *ConfigInterfacesSwitchVifPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                       `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                          `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchVifPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchVifPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchVifPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchVifPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchVifPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                           `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                        `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                        `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                        `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                           `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                        `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                             `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                         `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                             `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                             `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                        `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                        `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                        `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchVifVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesSwitchVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesSwitchVifVrrpVrrpGroup struct {
	Disable              string                                                      `json:"disable,omitempty"`
	VirtualAddress       []string                                                    `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                   `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                      `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                   `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesSwitchVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                        `json:"preempt,omitempty"`
	Description          string                                                      `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                        `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                   `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesSwitchVifVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchVifVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesSwitchVifVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesSwitchVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                          `json:"duid,omitempty"`
	NoDns       string                                          `json:"no-dns,omitempty"`
	RapidCommit string                                          `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                          `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesSwitchVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                   `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                `json:"no-dns,omitempty"`
	PrefixId      string                                                                `json:"prefix-id,omitempty"`
	HostAddress   string                                                                `json:"host-address,omitempty"`
	Service       string                                                                `json:"service,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesSwitchVifFirewall struct {
	Out   *ConfigInterfacesSwitchVifFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesSwitchVifFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesSwitchVifFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesSwitchVifFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchVifFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchVifFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesSwitchVifIp struct {
	Rip              *ConfigInterfacesSwitchVifIpRip  `json:"rip,omitempty"`
	EnableProxyArp   string                           `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                           `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesSwitchVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesSwitchVifIpRip struct {
	SplitHorizon   *ConfigInterfacesSwitchVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesSwitchVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchVifIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesSwitchVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                      `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspf struct {
	RetransmitInterval EdgeOSInt                                      `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                      `json:"transmit-delay,omitempty"`
	Network            string                                         `json:"network,omitempty"`
	Cost               EdgeOSInt                                      `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                      `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                      `json:"priority,omitempty"`
	MtuIgnore          string                                         `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                      `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                  `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                     `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6RouterAdvert struct {
	DefaultPreference string                                                      `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                   `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                   `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                   `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                      `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                   `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                        `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                    `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                        `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                        `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                   `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                   `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                   `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesSwitchIp struct {
	Rip              *ConfigInterfacesSwitchIpRip  `json:"rip,omitempty"`
	EnableProxyArp   string                        `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                        `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesSwitchIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesSwitchIpRip struct {
	SplitHorizon   *ConfigInterfacesSwitchIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesSwitchIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesSwitchIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchIpOspf struct {
	RetransmitInterval EdgeOSInt                                   `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                   `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               EdgeOSInt                                   `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                   `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                   `json:"priority,omitempty"`
	MtuIgnore          string                                      `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                   `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                               `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                  `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesSwitchIpv6RouterAdvert struct {
	DefaultPreference string                                                   `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesSwitchIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                   `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                     `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                 `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                     `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                     `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernet struct {
	Disable           string                                          `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesPseudoEthernetBandwidth        `json:"bandwidth,omitempty"`
	Pppoe             *map[string]ConfigInterfacesPseudoEthernetPppoe `json:"pppoe,omitempty"`
	Vrrp              *ConfigInterfacesPseudoEthernetVrrp             `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesPseudoEthernetDhcpv6Pd         `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect string                                          `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesPseudoEthernetFirewall         `json:"firewall,omitempty"`
	Mac               MacAddr                                         `json:"mac,omitempty"`
	DhcpOptions       *ConfigInterfacesPseudoEthernetDhcpOptions      `json:"dhcp-options,omitempty"`
	Link              string                                          `json:"link,omitempty"`
	Description       string                                          `json:"description,omitempty"`
	Vif               *map[string]ConfigInterfacesPseudoEthernetVif   `json:"vif,omitempty"`
	Address           []string                                        `json:"address,omitempty"`
	Dhcpv6Options     *ConfigInterfacesPseudoEthernetDhcpv6Options    `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesPseudoEthernetIp               `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesPseudoEthernetIpv6             `json:"ipv6,omitempty"`
}

type ConfigInterfacesPseudoEthernetBandwidth struct {
	Maximum    string                                             `json:"maximum,omitempty"`
	Reservable string                                             `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesPseudoEthernetBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesPseudoEthernetBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesPseudoEthernetBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPseudoEthernetBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoe struct {
	ServiceName        string                                        `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesPseudoEthernetPppoeBandwidth `json:"bandwidth,omitempty"`
	Password           string                                        `json:"password,omitempty"`
	RemoteAddress      string                                        `json:"remote-address,omitempty"`
	HostUniq           string                                        `json:"host-uniq,omitempty"`
	Mtu                string                                        `json:"mtu,omitempty"`
	NameServer         string                                        `json:"name-server,omitempty"`
	DefaultRoute       string                                        `json:"default-route,omitempty"`
	IdleTimeout        string                                        `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesPseudoEthernetPppoeDhcpv6Pd  `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    string                                        `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesPseudoEthernetPppoeFirewall  `json:"firewall,omitempty"`
	UserId             string                                        `json:"user-id,omitempty"`
	Description        string                                        `json:"description,omitempty"`
	LocalAddress       string                                        `json:"local-address,omitempty"`
	Ip                 *ConfigInterfacesPseudoEthernetPppoeIp        `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesPseudoEthernetPppoeIpv6      `json:"ipv6,omitempty"`
	Multilink          string                                        `json:"multilink,omitempty"`
	AccessConcentrator string                                        `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeBandwidth struct {
	Maximum    string                                                  `json:"maximum,omitempty"`
	Reservable string                                                  `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesPseudoEthernetPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                                    `json:"duid,omitempty"`
	NoDns       string                                                    `json:"no-dns,omitempty"`
	RapidCommit string                                                    `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                                    `json:"prefix-only,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                             `json:"prefix-length,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                          `json:"no-dns,omitempty"`
	PrefixId      string                                                                          `json:"prefix-id,omitempty"`
	HostAddress   string                                                                          `json:"host-address,omitempty"`
	Service       string                                                                          `json:"service,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeFirewall struct {
	Out   *ConfigInterfacesPseudoEthernetPppoeFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesPseudoEthernetPppoeFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesPseudoEthernetPppoeFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIp struct {
	Rip              *ConfigInterfacesPseudoEthernetPppoeIpRip  `json:"rip,omitempty"`
	SourceValidation string                                     `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesPseudoEthernetPppoeIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpRip struct {
	SplitHorizon   *ConfigInterfacesPseudoEthernetPppoeIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesPseudoEthernetPppoeIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspf struct {
	RetransmitInterval EdgeOSInt                                                `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                                `json:"transmit-delay,omitempty"`
	Network            string                                                   `json:"network,omitempty"`
	Cost               EdgeOSInt                                                `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                                `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                                `json:"priority,omitempty"`
	MtuIgnore          string                                                   `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPseudoEthernetPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                                `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                      `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6 struct {
	Enable                 *ConfigInterfacesPseudoEthernetPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits EdgeOSInt                                            `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                               `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesPseudoEthernetPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesPseudoEthernetPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesPseudoEthernetPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Enable struct {
	RemoteIdentifier string `json:"remote-identifier,omitempty"`
	LocalIdentifier  string `json:"local-identifier,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPseudoEthernetPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Address struct {
	Eui64     []string `json:"eui64,omitempty"`
	Autoconf  string   `json:"autoconf,omitempty"`
	Secondary string   `json:"secondary,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                                `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                             `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                             `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                             `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                                `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                             `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                                  `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                              `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                                  `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                                  `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                             `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                             `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                             `json:"link-mtu,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesPseudoEthernetVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesPseudoEthernetVrrpVrrpGroup struct {
	Disable              string                                                           `json:"disable,omitempty"`
	VirtualAddress       []string                                                         `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                        `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                           `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                        `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesPseudoEthernetVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                             `json:"preempt,omitempty"`
	Description          string                                                           `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                             `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                        `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesPseudoEthernetVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesPseudoEthernetVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesPseudoEthernetDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                               `json:"duid,omitempty"`
	NoDns       string                                               `json:"no-dns,omitempty"`
	RapidCommit string                                               `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                               `json:"prefix-only,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                        `json:"prefix-length,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                     `json:"no-dns,omitempty"`
	PrefixId      string                                                                     `json:"prefix-id,omitempty"`
	HostAddress   string                                                                     `json:"host-address,omitempty"`
	Service       string                                                                     `json:"service,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesPseudoEthernetFirewall struct {
	Out   *ConfigInterfacesPseudoEthernetFirewallOut   `json:"out,omitempty"`
	In    *ConfigInterfacesPseudoEthernetFirewallIn    `json:"in,omitempty"`
	Local *ConfigInterfacesPseudoEthernetFirewallLocal `json:"local,omitempty"`
}

type ConfigInterfacesPseudoEthernetFirewallOut struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPseudoEthernetFirewallIn struct {
	Modify     string `json:"modify,omitempty"`
	Ipv6Modify string `json:"ipv6-modify,omitempty"`
	Name       string `json:"name,omitempty"`
	Ipv6Name   string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPseudoEthernetFirewallLocal struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesPseudoEthernetVif struct {
	Disable           string                                          `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesPseudoEthernetVifBandwidth     `json:"bandwidth,omitempty"`
	Vrrp              *ConfigInterfacesPseudoEthernetVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesPseudoEthernetVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect string                                          `json:"disable-link-detect,omitempty"`
	DhcpOptions       *ConfigInterfacesPseudoEthernetVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                          `json:"description,omitempty"`
	Address           []string                                        `json:"address,omitempty"`
	Dhcpv6Options     *ConfigInterfacesPseudoEthernetVifDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesPseudoEthernetVifIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesPseudoEthernetVifIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifBandwidth struct {
	Maximum    string                                                `json:"maximum,omitempty"`
	Reservable string                                                `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesPseudoEthernetVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifBandwidthConstraint struct {
	ClassType *map[string]ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifVrrp struct {
	VrrpGroup *map[string]ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup struct {
	Disable              string                                                              `json:"disable,omitempty"`
	VirtualAddress       []string                                                            `json:"virtual-address,omitempty"`
	AdvertiseInterval    EdgeOSInt                                                           `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                              `json:"sync-group,omitempty"`
	PreemptDelay         EdgeOSInt                                                           `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesPseudoEthernetVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                                `json:"preempt,omitempty"`
	Description          string                                                              `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                                `json:"hello-source-address,omitempty"`
	Priority             EdgeOSInt                                                           `json:"priority,omitempty"`
	Authentication       *ConfigInterfacesPseudoEthernetVifVrrpVrrpGroupAuthentication       `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifVrrpVrrpGroupRunTransitionScripts struct {
	Master string `json:"master,omitempty"`
	Fault  string `json:"fault,omitempty"`
	Backup string `json:"backup,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifVrrpVrrpGroupAuthentication struct {
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6Pd struct {
	Pd          *map[string]ConfigInterfacesPseudoEthernetVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                                  `json:"duid,omitempty"`
	NoDns       string                                                  `json:"no-dns,omitempty"`
	RapidCommit string                                                  `json:"rapid-commit,omitempty"`
	PrefixOnly  string                                                  `json:"prefix-only,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6PdPd struct {
	Interface    *map[string]ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                           `json:"prefix-length,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface struct {
	StaticMapping *map[string]ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         string                                                                        `json:"no-dns,omitempty"`
	PrefixId      string                                                                        `json:"prefix-id,omitempty"`
	HostAddress   string                                                                        `json:"host-address,omitempty"`
	Service       string                                                                        `json:"service,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpOptions struct {
	NameServer           string    `json:"name-server,omitempty"`
	DefaultRoute         string    `json:"default-route,omitempty"`
	ClientOption         []string  `json:"client-option,omitempty"`
	DefaultRouteDistance EdgeOSInt `json:"default-route-distance,omitempty"`
	GlobalOption         []string  `json:"global-option,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIp struct {
	Rip              *ConfigInterfacesPseudoEthernetVifIpRip  `json:"rip,omitempty"`
	SourceValidation string                                   `json:"source-validation,omitempty"`
	ProxyArpPvlan    string                                   `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesPseudoEthernetVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRip struct {
	SplitHorizon   *ConfigInterfacesPseudoEthernetVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesPseudoEthernetVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspf struct {
	RetransmitInterval EdgeOSInt                                              `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                              `json:"transmit-delay,omitempty"`
	Network            string                                                 `json:"network,omitempty"`
	Cost               EdgeOSInt                                              `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                              `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                              `json:"priority,omitempty"`
	MtuIgnore          string                                                 `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPseudoEthernetVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                              `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                    `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpv6 struct {
	Ripng  *ConfigInterfacesPseudoEthernetVifIpv6Ripng  `json:"ripng,omitempty"`
	Ospfv3 *ConfigInterfacesPseudoEthernetVifIpv6Ospfv3 `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPseudoEthernetVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6Options struct {
	ParametersOnly string `json:"parameters-only,omitempty"`
	Temporary      string `json:"temporary,omitempty"`
}

type ConfigInterfacesPseudoEthernetIp struct {
	Rip              *ConfigInterfacesPseudoEthernetIpRip  `json:"rip,omitempty"`
	SourceValidation string                                `json:"source-validation,omitempty"`
	ProxyArpPvlan    string                                `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesPseudoEthernetIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRip struct {
	SplitHorizon   *ConfigInterfacesPseudoEthernetIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesPseudoEthernetIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRipSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRipAuthentication struct {
	Md5               *map[string]ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5 struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspf struct {
	RetransmitInterval EdgeOSInt                                           `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt                                           `json:"transmit-delay,omitempty"`
	Network            string                                              `json:"network,omitempty"`
	Cost               EdgeOSInt                                           `json:"cost,omitempty"`
	DeadInterval       EdgeOSInt                                           `json:"dead-interval,omitempty"`
	Priority           EdgeOSInt                                           `json:"priority,omitempty"`
	MtuIgnore          string                                              `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPseudoEthernetIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      EdgeOSInt                                           `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                 `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5 struct {
	KeyId *map[string]ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6 struct {
	DupAddrDetectTransmits EdgeOSInt                                       `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      string                                          `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesPseudoEthernetIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesPseudoEthernetIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesPseudoEthernetIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesPseudoEthernetIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPseudoEthernetIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6RipngSplitHorizon struct {
	Disable       string `json:"disable,omitempty"`
	PoisonReverse string `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6Address struct {
	Eui64    []string `json:"eui64,omitempty"`
	Autoconf string   `json:"autoconf,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6RouterAdvert struct {
	DefaultPreference string                                                           `json:"default-preference,omitempty"`
	MinInterval       EdgeOSInt                                                        `json:"min-interval,omitempty"`
	MaxInterval       EdgeOSInt                                                        `json:"max-interval,omitempty"`
	ReachableTime     EdgeOSInt                                                        `json:"reachable-time,omitempty"`
	Prefix            *map[string]ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        string                                                           `json:"name-server,omitempty"`
	RetransTimer      EdgeOSInt                                                        `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                             `json:"send-advert,omitempty"`
	RadvdOptions      []string                                                         `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                             `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                             `json:"other-config-flag,omitempty"`
	DefaultLifetime   EdgeOSInt                                                        `json:"default-lifetime,omitempty"`
	CurHopLimit       EdgeOSInt                                                        `json:"cur-hop-limit,omitempty"`
	LinkMtu           EdgeOSInt                                                        `json:"link-mtu,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6Ospfv3 struct {
	RetransmitInterval EdgeOSInt `json:"retransmit-interval,omitempty"`
	TransmitDelay      EdgeOSInt `json:"transmit-delay,omitempty"`
	Cost               EdgeOSInt `json:"cost,omitempty"`
	Passive            string    `json:"passive,omitempty"`
	DeadInterval       EdgeOSInt `json:"dead-interval,omitempty"`
	InstanceId         EdgeOSInt `json:"instance-id,omitempty"`
	Ifmtu              EdgeOSInt `json:"ifmtu,omitempty"`
	Priority           EdgeOSInt `json:"priority,omitempty"`
	MtuIgnore          string    `json:"mtu-ignore,omitempty"`
	HelloInterval      EdgeOSInt `json:"hello-interval,omitempty"`
}

type ConfigCustomAttribute struct {
	NodeTag *ConfigCustomAttributeNodeTag `json:"node.tag,omitempty"`
}

type ConfigCustomAttributeNodeTag struct {
	Value string `json:"value,omitempty"`
}

type Config struct {
	ZonePolicy      *ConfigZonePolicy      `json:"zone-policy,omitempty"`
	LoadBalance     *ConfigLoadBalance     `json:"load-balance,omitempty"`
	PortForward     *ConfigPortForward     `json:"port-forward,omitempty"`
	Vpn             *ConfigVpn             `json:"vpn,omitempty"`
	TrafficPolicy   *ConfigTrafficPolicy   `json:"traffic-policy,omitempty"`
	Firewall        *ConfigFirewall        `json:"firewall,omitempty"`
	System          *ConfigSystem          `json:"system,omitempty"`
	TrafficControl  *ConfigTrafficControl  `json:"traffic-control,omitempty"`
	Service         *ConfigService         `json:"service,omitempty"`
	Protocols       *ConfigProtocols       `json:"protocols,omitempty"`
	Policy          *ConfigPolicy          `json:"policy,omitempty"`
	Interfaces      *ConfigInterfaces      `json:"interfaces,omitempty"`
	CustomAttribute *ConfigCustomAttribute `json:"custom-attribute,omitempty"`
}

func (e *ConfigZonePolicy) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigZonePolicy{}
		return nil
	}
	type t ConfigZonePolicy
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigZonePolicyZone) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigZonePolicyZone{}
		return nil
	}
	type t ConfigZonePolicyZone
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigZonePolicyZoneFrom) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigZonePolicyZoneFrom{}
		return nil
	}
	type t ConfigZonePolicyZoneFrom
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigLoadBalance) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigLoadBalance{}
		return nil
	}
	type t ConfigLoadBalance
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigLoadBalanceGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigLoadBalanceGroup{}
		return nil
	}
	type t ConfigLoadBalanceGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigLoadBalanceGroupInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigLoadBalanceGroupInterface{}
		return nil
	}
	type t ConfigLoadBalanceGroupInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPortForward) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPortForward{}
		return nil
	}
	type t ConfigPortForward
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPortForwardRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPortForwardRule{}
		return nil
	}
	type t ConfigPortForwardRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpn) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpn{}
		return nil
	}
	type t ConfigVpn
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnRsaKeysRsaKeyName) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnRsaKeysRsaKeyName{}
		return nil
	}
	type t ConfigVpnRsaKeysRsaKeyName
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecIkeGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecIkeGroup{}
		return nil
	}
	type t ConfigVpnIpsecIkeGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecEspGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecEspGroup{}
		return nil
	}
	type t ConfigVpnIpsecEspGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecNatNetworksAllowedNetwork) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecNatNetworksAllowedNetwork{}
		return nil
	}
	type t ConfigVpnIpsecNatNetworksAllowedNetwork
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecSiteToSitePeer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecSiteToSitePeer{}
		return nil
	}
	type t ConfigVpnIpsecSiteToSitePeer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecSiteToSitePeerTunnel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecSiteToSitePeerTunnel{}
		return nil
	}
	type t ConfigVpnIpsecSiteToSitePeerTunnel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecRemoteAccessIkeSettingsProposal) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecRemoteAccessIkeSettingsProposal{}
		return nil
	}
	type t ConfigVpnIpsecRemoteAccessIkeSettingsProposal
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecRemoteAccessEspSettingsProposal) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecRemoteAccessEspSettingsProposal{}
		return nil
	}
	type t ConfigVpnIpsecRemoteAccessEspSettingsProposal
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer{}
		return nil
	}
	type t ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername{}
		return nil
	}
	type t ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecIkeGroupProposal) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecIkeGroupProposal{}
		return nil
	}
	type t ConfigVpnIpsecIkeGroupProposal
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnIpsecEspGroupProposal) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnIpsecEspGroupProposal{}
		return nil
	}
	type t ConfigVpnIpsecEspGroupProposal
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnPptpRemoteAccessAccountingRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnPptpRemoteAccessAccountingRadiusServer{}
		return nil
	}
	type t ConfigVpnPptpRemoteAccessAccountingRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnPptpRemoteAccessAuthenticationRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnPptpRemoteAccessAuthenticationRadiusServer{}
		return nil
	}
	type t ConfigVpnPptpRemoteAccessAuthenticationRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername{}
		return nil
	}
	type t ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnL2tpRemoteAccessAccountingRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnL2tpRemoteAccessAccountingRadiusServer{}
		return nil
	}
	type t ConfigVpnL2tpRemoteAccessAccountingRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer{}
		return nil
	}
	type t ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername{}
		return nil
	}
	type t ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicy) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicy{}
		return nil
	}
	type t ConfigTrafficPolicy
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyNetworkEmulator) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyNetworkEmulator{}
		return nil
	}
	type t ConfigTrafficPolicyNetworkEmulator
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyDropTail) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyDropTail{}
		return nil
	}
	type t ConfigTrafficPolicyDropTail
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyRoundRobin) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyRoundRobin{}
		return nil
	}
	type t ConfigTrafficPolicyRoundRobin
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyLimiter) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyLimiter{}
		return nil
	}
	type t ConfigTrafficPolicyLimiter
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyFairQueue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyFairQueue{}
		return nil
	}
	type t ConfigTrafficPolicyFairQueue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyRateControl) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyRateControl{}
		return nil
	}
	type t ConfigTrafficPolicyRateControl
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyShaper) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyShaper{}
		return nil
	}
	type t ConfigTrafficPolicyShaper
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyPriorityQueue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyPriorityQueue{}
		return nil
	}
	type t ConfigTrafficPolicyPriorityQueue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyRandomDetect) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyRandomDetect{}
		return nil
	}
	type t ConfigTrafficPolicyRandomDetect
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyRoundRobinClass) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyRoundRobinClass{}
		return nil
	}
	type t ConfigTrafficPolicyRoundRobinClass
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyRoundRobinClassMatch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyRoundRobinClassMatch{}
		return nil
	}
	type t ConfigTrafficPolicyRoundRobinClassMatch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyLimiterClass) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyLimiterClass{}
		return nil
	}
	type t ConfigTrafficPolicyLimiterClass
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyLimiterClassMatch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyLimiterClassMatch{}
		return nil
	}
	type t ConfigTrafficPolicyLimiterClassMatch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyShaperClass) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyShaperClass{}
		return nil
	}
	type t ConfigTrafficPolicyShaperClass
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyShaperClassMatch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyShaperClassMatch{}
		return nil
	}
	type t ConfigTrafficPolicyShaperClassMatch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyPriorityQueueClass) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyPriorityQueueClass{}
		return nil
	}
	type t ConfigTrafficPolicyPriorityQueueClass
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyPriorityQueueClassMatch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyPriorityQueueClassMatch{}
		return nil
	}
	type t ConfigTrafficPolicyPriorityQueueClassMatch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficPolicyRandomDetectPrecedence) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficPolicyRandomDetectPrecedence{}
		return nil
	}
	type t ConfigTrafficPolicyRandomDetectPrecedence
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewall) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewall{}
		return nil
	}
	type t ConfigFirewall
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallModify) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallModify{}
		return nil
	}
	type t ConfigFirewallModify
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallIpv6Modify) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallIpv6Modify{}
		return nil
	}
	type t ConfigFirewallIpv6Modify
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallName) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallName{}
		return nil
	}
	type t ConfigFirewallName
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallIpv6Name) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallIpv6Name{}
		return nil
	}
	type t ConfigFirewallIpv6Name
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallGroupAddressGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallGroupAddressGroup{}
		return nil
	}
	type t ConfigFirewallGroupAddressGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallGroupPortGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallGroupPortGroup{}
		return nil
	}
	type t ConfigFirewallGroupPortGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallGroupNetworkGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallGroupNetworkGroup{}
		return nil
	}
	type t ConfigFirewallGroupNetworkGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallGroupIpv6AddressGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallGroupIpv6AddressGroup{}
		return nil
	}
	type t ConfigFirewallGroupIpv6AddressGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallGroupIpv6NetworkGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallGroupIpv6NetworkGroup{}
		return nil
	}
	type t ConfigFirewallGroupIpv6NetworkGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallModifyRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallModifyRule{}
		return nil
	}
	type t ConfigFirewallModifyRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallIpv6ModifyRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallIpv6ModifyRule{}
		return nil
	}
	type t ConfigFirewallIpv6ModifyRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallNameRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallNameRule{}
		return nil
	}
	type t ConfigFirewallNameRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigFirewallIpv6NameRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigFirewallIpv6NameRule{}
		return nil
	}
	type t ConfigFirewallIpv6NameRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystem) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystem{}
		return nil
	}
	type t ConfigSystem
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogHost) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogHost{}
		return nil
	}
	type t ConfigSystemSyslogHost
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogFile) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogFile{}
		return nil
	}
	type t ConfigSystemSyslogFile
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogUser) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogUser{}
		return nil
	}
	type t ConfigSystemSyslogUser
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogHostFacility) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogHostFacility{}
		return nil
	}
	type t ConfigSystemSyslogHostFacility
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogFileFacility) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogFileFacility{}
		return nil
	}
	type t ConfigSystemSyslogFileFacility
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogUserFacility) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogUserFacility{}
		return nil
	}
	type t ConfigSystemSyslogUserFacility
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogGlobalFacility) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogGlobalFacility{}
		return nil
	}
	type t ConfigSystemSyslogGlobalFacility
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemSyslogConsoleFacility) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemSyslogConsoleFacility{}
		return nil
	}
	type t ConfigSystemSyslogConsoleFacility
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemFlowAccountingNetflowServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemFlowAccountingNetflowServer{}
		return nil
	}
	type t ConfigSystemFlowAccountingNetflowServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemFlowAccountingSflowServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemFlowAccountingSflowServer{}
		return nil
	}
	type t ConfigSystemFlowAccountingSflowServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemTaskSchedulerTask) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemTaskSchedulerTask{}
		return nil
	}
	type t ConfigSystemTaskSchedulerTask
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemConntrackIgnoreRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemConntrackIgnoreRule{}
		return nil
	}
	type t ConfigSystemConntrackIgnoreRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemConntrackTimeoutCustomRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemConntrackTimeoutCustomRule{}
		return nil
	}
	type t ConfigSystemConntrackTimeoutCustomRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemStaticHostMappingHostName) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemStaticHostMappingHostName{}
		return nil
	}
	type t ConfigSystemStaticHostMappingHostName
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemNtpServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemNtpServer{}
		return nil
	}
	type t ConfigSystemNtpServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemTrafficAnalysisCustomCategory) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemTrafficAnalysisCustomCategory{}
		return nil
	}
	type t ConfigSystemTrafficAnalysisCustomCategory
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemLoginRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemLoginRadiusServer{}
		return nil
	}
	type t ConfigSystemLoginRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemLoginUser) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemLoginUser{}
		return nil
	}
	type t ConfigSystemLoginUser
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemLoginUserAuthenticationPublicKeys) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemLoginUserAuthenticationPublicKeys{}
		return nil
	}
	type t ConfigSystemLoginUserAuthenticationPublicKeys
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigSystemPackageRepository) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigSystemPackageRepository{}
		return nil
	}
	type t ConfigSystemPackageRepository
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControl) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControl{}
		return nil
	}
	type t ConfigTrafficControl
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlSmartQueue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlSmartQueue{}
		return nil
	}
	type t ConfigTrafficControlSmartQueue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueFiltersMatch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueFiltersMatch{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueFiltersMatch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueLeafQueue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueLeafQueue{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueLeafQueue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueBranchQueue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueBranchQueue{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueBranchQueue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueQueueTypePfifo) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueQueueTypePfifo{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueQueueTypePfifo
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueQueueTypeHfq) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueQueueTypeHfq{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueQueueTypeHfq
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueQueueTypeFqCodel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueQueueTypeFqCodel{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueQueueTypeFqCodel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueQueueTypeSfq) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueQueueTypeSfq{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueQueueTypeSfq
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigTrafficControlAdvancedQueueRootQueue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigTrafficControlAdvancedQueueRootQueue{}
		return nil
	}
	type t ConfigTrafficControlAdvancedQueueRootQueue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigService) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigService{}
		return nil
	}
	type t ConfigService
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceUbntDiscoverInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceUbntDiscoverInterface{}
		return nil
	}
	type t ConfigServiceUbntDiscoverInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpListenAddress) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpListenAddress{}
		return nil
	}
	type t ConfigServiceSnmpListenAddress
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpTrapTarget) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpTrapTarget{}
		return nil
	}
	type t ConfigServiceSnmpTrapTarget
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpCommunity) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpCommunity{}
		return nil
	}
	type t ConfigServiceSnmpCommunity
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpV3Group) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpV3Group{}
		return nil
	}
	type t ConfigServiceSnmpV3Group
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpV3User) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpV3User{}
		return nil
	}
	type t ConfigServiceSnmpV3User
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpV3View) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpV3View{}
		return nil
	}
	type t ConfigServiceSnmpV3View
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpV3TrapTarget) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpV3TrapTarget{}
		return nil
	}
	type t ConfigServiceSnmpV3TrapTarget
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceSnmpV3ViewOid) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceSnmpV3ViewOid{}
		return nil
	}
	type t ConfigServiceSnmpV3ViewOid
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkName) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkName{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkName
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkNameSubnet) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkNameSubnet{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkNameSubnet
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart{}
		return nil
	}
	type t ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceUpnpListenOn) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceUpnpListenOn{}
		return nil
	}
	type t ConfigServiceUpnpListenOn
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceLldpInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceLldpInterface{}
		return nil
	}
	type t ConfigServiceLldpInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceLldpInterfaceLocationCivicBasedCaType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceLldpInterfaceLocationCivicBasedCaType{}
		return nil
	}
	type t ConfigServiceLldpInterfaceLocationCivicBasedCaType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceNatRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceNatRule{}
		return nil
	}
	type t ConfigServiceNatRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceWebproxyListenAddress) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceWebproxyListenAddress{}
		return nil
	}
	type t ConfigServiceWebproxyListenAddress
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup{}
		return nil
	}
	type t ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod{}
		return nil
	}
	type t ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceWebproxyUrlFilteringSquidguardRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceWebproxyUrlFilteringSquidguardRule{}
		return nil
	}
	type t ConfigServiceWebproxyUrlFilteringSquidguardRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays{}
		return nil
	}
	type t ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpServerSharedNetworkName) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpServerSharedNetworkName{}
		return nil
	}
	type t ConfigServiceDhcpServerSharedNetworkName
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpServerSharedNetworkNameSubnet) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpServerSharedNetworkNameSubnet{}
		return nil
	}
	type t ConfigServiceDhcpServerSharedNetworkNameSubnet
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping{}
		return nil
	}
	type t ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpServerSharedNetworkNameSubnetStart) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpServerSharedNetworkNameSubnetStart{}
		return nil
	}
	type t ConfigServiceDhcpServerSharedNetworkNameSubnetStart
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServicePppoeServerAuthenticationRadiusServer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServicePppoeServerAuthenticationRadiusServer{}
		return nil
	}
	type t ConfigServicePppoeServerAuthenticationRadiusServer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServicePppoeServerAuthenticationLocalUsersUsername) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServicePppoeServerAuthenticationLocalUsersUsername{}
		return nil
	}
	type t ConfigServicePppoeServerAuthenticationLocalUsersUsername
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDnsDynamicInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDnsDynamicInterface{}
		return nil
	}
	type t ConfigServiceDnsDynamicInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDnsDynamicInterfaceService) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDnsDynamicInterfaceService{}
		return nil
	}
	type t ConfigServiceDnsDynamicInterfaceService
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceUpnp2AclRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceUpnp2AclRule{}
		return nil
	}
	type t ConfigServiceUpnp2AclRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6RelayListenInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6RelayListenInterface{}
		return nil
	}
	type t ConfigServiceDhcpv6RelayListenInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigServiceDhcpv6RelayUpstreamInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigServiceDhcpv6RelayUpstreamInterface{}
		return nil
	}
	type t ConfigServiceDhcpv6RelayUpstreamInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocols) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocols{}
		return nil
	}
	type t ConfigProtocols
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVrf{}
		return nil
	}
	type t ConfigProtocolsVrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgp{}
		return nil
	}
	type t ConfigProtocolsBgp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipVrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipVrf{}
		return nil
	}
	type t ConfigProtocolsRipVrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipNetworkDistance) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipNetworkDistance{}
		return nil
	}
	type t ConfigProtocolsRipNetworkDistance
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipBfdNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipBfdNeighbor{}
		return nil
	}
	type t ConfigProtocolsRipBfdNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipVrfNetworkDistance) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipVrfNetworkDistance{}
		return nil
	}
	type t ConfigProtocolsRipVrfNetworkDistance
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipVrfBfdNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipVrfBfdNeighbor{}
		return nil
	}
	type t ConfigProtocolsRipVrfBfdNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipVrfDistributeListInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipVrfDistributeListInterface{}
		return nil
	}
	type t ConfigProtocolsRipVrfDistributeListInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipDistributeListInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipDistributeListInterface{}
		return nil
	}
	type t ConfigProtocolsRipDistributeListInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsAcGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsAcGroup{}
		return nil
	}
	type t ConfigProtocolsMplsAcGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsInterface{}
		return nil
	}
	type t ConfigProtocolsMplsInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntry) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntry{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntry
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMsPw) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMsPw{}
		return nil
	}
	type t ConfigProtocolsMplsMsPw
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsTeClass) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsTeClass{}
		return nil
	}
	type t ConfigProtocolsMplsTeClass
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsClassToExp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsClassToExp{}
		return nil
	}
	type t ConfigProtocolsMplsClassToExp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2Circuit) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2Circuit{}
		return nil
	}
	type t ConfigProtocolsMplsL2Circuit
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMinLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMinLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsMinLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsAdminGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsAdminGroup{}
		return nil
	}
	type t ConfigProtocolsMplsAdminGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMsPwStitch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMsPwStitch{}
		return nil
	}
	type t ConfigProtocolsMplsMsPwStitch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsClassType{}
		return nil
	}
	type t ConfigProtocolsMplsClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsIlmEntry) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsIlmEntry{}
		return nil
	}
	type t ConfigProtocolsMplsIlmEntry
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMapRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMapRoute{}
		return nil
	}
	type t ConfigProtocolsMplsMapRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMaxLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMaxLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsMaxLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsLspTunnelingInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsLspTunnelingInterface{}
		return nil
	}
	type t ConfigProtocolsMplsLspTunnelingInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsLspTunnelingInterfaceInLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsLspTunnelingInterfaceInLabel{}
		return nil
	}
	type t ConfigProtocolsMplsLspTunnelingInterfaceInLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel{}
		return nil
	}
	type t ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsInterfaceL2Circuit) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsInterfaceL2Circuit{}
		return nil
	}
	type t ConfigProtocolsMplsInterfaceL2Circuit
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntryInLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntryInLabel{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntryInLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsTeClassName) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsTeClassName{}
		return nil
	}
	type t ConfigProtocolsMplsTeClassName
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelId{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIp{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpMask) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpMask{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpMask
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface{}
		return nil
	}
	type t ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitId{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4Agi) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4Agi{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4Agi
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4AgiSaii) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4AgiSaii{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4AgiSaii
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIdIpv4) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIdIpv4{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIdIpv4
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIdIpv6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIdIpv6{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIdIpv6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIdIpv4Groupname) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIdIpv4Groupname{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIdIpv4Groupname
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIdIpv4TunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIdIpv4TunnelId{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIdIpv4TunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId{}
		return nil
	}
	type t ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMsPwStitchVc1) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMsPwStitchVc1{}
		return nil
	}
	type t ConfigProtocolsMplsMsPwStitchVc1
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMsPwStitchVc1Vc2) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMsPwStitchVc1Vc2{}
		return nil
	}
	type t ConfigProtocolsMplsMsPwStitchVc1Vc2
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu{}
		return nil
	}
	type t ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsIlmEntryInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsIlmEntryInterface{}
		return nil
	}
	type t ConfigProtocolsMplsIlmEntryInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsIlmEntryInterfaceSwap) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsIlmEntryInterfaceSwap{}
		return nil
	}
	type t ConfigProtocolsMplsIlmEntryInterfaceSwap
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsIlmEntryInterfaceSwapInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsIlmEntryInterfaceSwapInterface{}
		return nil
	}
	type t ConfigProtocolsMplsIlmEntryInterfaceSwapInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp{}
		return nil
	}
	type t ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec{}
		return nil
	}
	type t ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsRsvpMinLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsRsvpMinLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsRsvpMinLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsRsvpMaxLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsRsvpMaxLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsRsvpMaxLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsLdpMinLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsLdpMinLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsLdpMinLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsLdpMaxLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsLdpMaxLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsLdpMaxLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsBgpMinLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsBgpMinLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsBgpMinLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsMplsBgpMaxLabelValue) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsMplsBgpMaxLabelValue{}
		return nil
	}
	type t ConfigProtocolsMplsBgpMaxLabelValue
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdInterface{}
		return nil
	}
	type t ConfigProtocolsBfdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdMultihopPeer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdMultihopPeer{}
		return nil
	}
	type t ConfigProtocolsBfdMultihopPeer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdInterfaceInterval) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdInterfaceInterval{}
		return nil
	}
	type t ConfigProtocolsBfdInterfaceInterval
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdInterfaceIntervalMinrx) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdInterfaceIntervalMinrx{}
		return nil
	}
	type t ConfigProtocolsBfdInterfaceIntervalMinrx
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdInterfaceSessionSource) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdInterfaceSessionSource{}
		return nil
	}
	type t ConfigProtocolsBfdInterfaceSessionSource
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdInterfaceSessionSourceDest) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdInterfaceSessionSourceDest{}
		return nil
	}
	type t ConfigProtocolsBfdInterfaceSessionSourceDest
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdMultihopPeerInterval) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdMultihopPeerInterval{}
		return nil
	}
	type t ConfigProtocolsBfdMultihopPeerInterval
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBfdMultihopPeerIntervalMinrx) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBfdMultihopPeerIntervalMinrx{}
		return nil
	}
	type t ConfigProtocolsBfdMultihopPeerIntervalMinrx
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipngVrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipngVrf{}
		return nil
	}
	type t ConfigProtocolsRipngVrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipngVrfDistributeListInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipngVrfDistributeListInterface{}
		return nil
	}
	type t ConfigProtocolsRipngVrfDistributeListInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRipngDistributeListInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRipngDistributeListInterface{}
		return nil
	}
	type t ConfigProtocolsRipngDistributeListInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticInterfaceRoute6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticInterfaceRoute6{}
		return nil
	}
	type t ConfigProtocolsStaticInterfaceRoute6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticRoute{}
		return nil
	}
	type t ConfigProtocolsStaticRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrf{}
		return nil
	}
	type t ConfigProtocolsStaticVrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTable) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTable{}
		return nil
	}
	type t ConfigProtocolsStaticTable
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticInterfaceRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticInterfaceRoute{}
		return nil
	}
	type t ConfigProtocolsStaticInterfaceRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticArp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticArp{}
		return nil
	}
	type t ConfigProtocolsStaticArp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticRoute6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticRoute6{}
		return nil
	}
	type t ConfigProtocolsStaticRoute6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticInterfaceRoute6NextHopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticInterfaceRoute6NextHopInterface{}
		return nil
	}
	type t ConfigProtocolsStaticInterfaceRoute6NextHopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticRouteNextHop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticRouteNextHop{}
		return nil
	}
	type t ConfigProtocolsStaticRouteNextHop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticBfdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticBfdInterface{}
		return nil
	}
	type t ConfigProtocolsStaticBfdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfInterfaceRoute6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfInterfaceRoute6{}
		return nil
	}
	type t ConfigProtocolsStaticVrfInterfaceRoute6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfRoute{}
		return nil
	}
	type t ConfigProtocolsStaticVrfRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfInterfaceRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfInterfaceRoute{}
		return nil
	}
	type t ConfigProtocolsStaticVrfInterfaceRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfRoute6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfRoute6{}
		return nil
	}
	type t ConfigProtocolsStaticVrfRoute6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface{}
		return nil
	}
	type t ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw{}
		return nil
	}
	type t ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfRouteNextHop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfRouteNextHop{}
		return nil
	}
	type t ConfigProtocolsStaticVrfRouteNextHop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface{}
		return nil
	}
	type t ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticVrfRoute6NextHop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticVrfRoute6NextHop{}
		return nil
	}
	type t ConfigProtocolsStaticVrfRoute6NextHop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableInterfaceRoute6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableInterfaceRoute6{}
		return nil
	}
	type t ConfigProtocolsStaticTableInterfaceRoute6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableRoute{}
		return nil
	}
	type t ConfigProtocolsStaticTableRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableInterfaceRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableInterfaceRoute{}
		return nil
	}
	type t ConfigProtocolsStaticTableInterfaceRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableRoute6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableRoute6{}
		return nil
	}
	type t ConfigProtocolsStaticTableRoute6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface{}
		return nil
	}
	type t ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableRouteNextHop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableRouteNextHop{}
		return nil
	}
	type t ConfigProtocolsStaticTableRouteNextHop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableInterfaceRouteNextHopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableInterfaceRouteNextHopInterface{}
		return nil
	}
	type t ConfigProtocolsStaticTableInterfaceRouteNextHopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticTableRoute6NextHop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticTableRoute6NextHop{}
		return nil
	}
	type t ConfigProtocolsStaticTableRoute6NextHop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticInterfaceRouteNextHopInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticInterfaceRouteNextHopInterface{}
		return nil
	}
	type t ConfigProtocolsStaticInterfaceRouteNextHopInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsStaticRoute6NextHop) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsStaticRoute6NextHop{}
		return nil
	}
	type t ConfigProtocolsStaticRoute6NextHop
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpInterface{}
		return nil
	}
	type t ConfigProtocolsRsvpInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpPath) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpPath{}
		return nil
	}
	type t ConfigProtocolsRsvpPath
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunk) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunk{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunk
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpPathMplsUnnumbered) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpPathMplsUnnumbered{}
		return nil
	}
	type t ConfigProtocolsRsvpPathMplsUnnumbered
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpPathGmplsUnnumbered) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpPathGmplsUnnumbered{}
		return nil
	}
	type t ConfigProtocolsRsvpPathGmplsUnnumbered
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4MapRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4MapRoute{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4MapRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6MapRouteMask) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6MapRouteMask{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6MapRouteMask
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange{}
		return nil
	}
	type t ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInterface{}
		return nil
	}
	type t ConfigProtocolsVplsInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntry) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntry{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntry
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstance) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstance{}
		return nil
	}
	type t ConfigProtocolsVplsInstance
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInterfaceVlanInstance) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInterfaceVlanInstance{}
		return nil
	}
	type t ConfigProtocolsVplsInterfaceVlanInstance
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInterfaceVlanInstanceVlan) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInterfaceVlanInstanceVlan{}
		return nil
	}
	type t ConfigProtocolsVplsInterfaceVlanInstanceVlan
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntryPeer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntryPeer{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntryPeer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntrySpokeVc) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntrySpokeVc{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntrySpokeVc
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntryPeerInLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntryPeerInLabel{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntryPeerInLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntryPeerInLabelOutInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntryPeerInLabelOutInterface{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntryPeerInLabelOutInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntrySpokeVcInLabel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntrySpokeVcInLabel{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntrySpokeVcInLabel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface{}
		return nil
	}
	type t ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceId{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdVplsPeer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdVplsPeer{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdVplsPeer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdVplsVc) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdVplsVc{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdVplsVc
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdVplsPeerTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdVplsPeerTunnelId{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdVplsPeerTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId{}
		return nil
	}
	type t ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpInterface{}
		return nil
	}
	type t ConfigProtocolsLdpInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpNeighbor{}
		return nil
	}
	type t ConfigProtocolsLdpNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpNeighborAuthMd5Password) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpNeighborAuthMd5Password{}
		return nil
	}
	type t ConfigProtocolsLdpNeighborAuthMd5Password
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpAdvertiseLabelsForAcl) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpAdvertiseLabelsForAcl{}
		return nil
	}
	type t ConfigProtocolsLdpAdvertiseLabelsForAcl
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpAdvertiseLabelsForPeerAcl) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpAdvertiseLabelsForPeerAcl{}
		return nil
	}
	type t ConfigProtocolsLdpAdvertiseLabelsForPeerAcl
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpTransportAddressIpv4) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpTransportAddressIpv4{}
		return nil
	}
	type t ConfigProtocolsLdpTransportAddressIpv4
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpTransportAddressIpv6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpTransportAddressIpv6{}
		return nil
	}
	type t ConfigProtocolsLdpTransportAddressIpv6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsLdpTargetedPeerIpv4) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsLdpTargetedPeerIpv4{}
		return nil
	}
	type t ConfigProtocolsLdpTargetedPeerIpv4
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsIgmpProxyInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsIgmpProxyInterface{}
		return nil
	}
	type t ConfigProtocolsIgmpProxyInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpNeighbor{}
		return nil
	}
	type t ConfigProtocolsBgpNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpNetwork) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpNetwork{}
		return nil
	}
	type t ConfigProtocolsBgpNetwork
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAggregateAddress) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAggregateAddress{}
		return nil
	}
	type t ConfigProtocolsBgpAggregateAddress
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpPeerGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpPeerGroup{}
		return nil
	}
	type t ConfigProtocolsBgpPeerGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpNeighborLocalAs) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpNeighborLocalAs{}
		return nil
	}
	type t ConfigProtocolsBgpNeighborLocalAs
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpNeighborDistributeListWord) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpNeighborDistributeListWord{}
		return nil
	}
	type t ConfigProtocolsBgpNeighborDistributeListWord
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress{}
		return nil
	}
	type t ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpDampeningHalfLife) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpDampeningHalfLife{}
		return nil
	}
	type t ConfigProtocolsBgpDampeningHalfLife
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpDampeningHalfLifeReuseRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpDampeningHalfLifeReuseRoute{}
		return nil
	}
	type t ConfigProtocolsBgpDampeningHalfLifeReuseRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute{}
		return nil
	}
	type t ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime{}
		return nil
	}
	type t ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpParametersDistancePrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpParametersDistancePrefix{}
		return nil
	}
	type t ConfigProtocolsBgpParametersDistancePrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsBgpPeerGroupLocalAs) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsBgpPeerGroupLocalAs{}
		return nil
	}
	type t ConfigProtocolsBgpPeerGroupLocalAs
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3Area) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3Area{}
		return nil
	}
	type t ConfigProtocolsOspfv3Area
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3Vrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3Vrf{}
		return nil
	}
	type t ConfigProtocolsOspfv3Vrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3DistributeList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3DistributeList{}
		return nil
	}
	type t ConfigProtocolsOspfv3DistributeList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3AreaFilterList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3AreaFilterList{}
		return nil
	}
	type t ConfigProtocolsOspfv3AreaFilterList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3AreaVirtualLink) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3AreaVirtualLink{}
		return nil
	}
	type t ConfigProtocolsOspfv3AreaVirtualLink
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3AreaRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3AreaRange{}
		return nil
	}
	type t ConfigProtocolsOspfv3AreaRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric{}
		return nil
	}
	type t ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3TimersSfpExpDelayMin) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3TimersSfpExpDelayMin{}
		return nil
	}
	type t ConfigProtocolsOspfv3TimersSfpExpDelayMin
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3VrfArea) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3VrfArea{}
		return nil
	}
	type t ConfigProtocolsOspfv3VrfArea
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3VrfAreaFilterList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3VrfAreaFilterList{}
		return nil
	}
	type t ConfigProtocolsOspfv3VrfAreaFilterList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3VrfAreaVirtualLink) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3VrfAreaVirtualLink{}
		return nil
	}
	type t ConfigProtocolsOspfv3VrfAreaVirtualLink
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfv3VrfAreaRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfv3VrfAreaRange{}
		return nil
	}
	type t ConfigProtocolsOspfv3VrfAreaRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfNeighbor{}
		return nil
	}
	type t ConfigProtocolsOspfNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfArea) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfArea{}
		return nil
	}
	type t ConfigProtocolsOspfArea
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfAccessList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfAccessList{}
		return nil
	}
	type t ConfigProtocolsOspfAccessList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceId{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfAreaVirtualLink) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfAreaVirtualLink{}
		return nil
	}
	type t ConfigProtocolsOspfAreaVirtualLink
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfAreaRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfAreaRange{}
		return nil
	}
	type t ConfigProtocolsOspfAreaRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrf) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrf{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrf
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrfNeighbor) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrfNeighbor{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrfNeighbor
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrfArea) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrfArea{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrfArea
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrfAccessList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrfAccessList{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrfAccessList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrfAreaRange) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrfAreaRange{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrfAreaRange
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicy) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicy{}
		return nil
	}
	type t ConfigPolicy
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyAsPathList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyAsPathList{}
		return nil
	}
	type t ConfigPolicyAsPathList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyAccessList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyAccessList{}
		return nil
	}
	type t ConfigPolicyAccessList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyRouteMap) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyRouteMap{}
		return nil
	}
	type t ConfigPolicyRouteMap
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyAccessList6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyAccessList6{}
		return nil
	}
	type t ConfigPolicyAccessList6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyPrefixList6) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyPrefixList6{}
		return nil
	}
	type t ConfigPolicyPrefixList6
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyCommunityList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyCommunityList{}
		return nil
	}
	type t ConfigPolicyCommunityList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyExtcommunityList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyExtcommunityList{}
		return nil
	}
	type t ConfigPolicyExtcommunityList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyPrefixList) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyPrefixList{}
		return nil
	}
	type t ConfigPolicyPrefixList
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyAsPathListRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyAsPathListRule{}
		return nil
	}
	type t ConfigPolicyAsPathListRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyAccessListRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyAccessListRule{}
		return nil
	}
	type t ConfigPolicyAccessListRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyRouteMapRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyRouteMapRule{}
		return nil
	}
	type t ConfigPolicyRouteMapRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyAccessList6Rule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyAccessList6Rule{}
		return nil
	}
	type t ConfigPolicyAccessList6Rule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyPrefixList6Rule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyPrefixList6Rule{}
		return nil
	}
	type t ConfigPolicyPrefixList6Rule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyCommunityListRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyCommunityListRule{}
		return nil
	}
	type t ConfigPolicyCommunityListRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyExtcommunityListRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyExtcommunityListRule{}
		return nil
	}
	type t ConfigPolicyExtcommunityListRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigPolicyPrefixListRule) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigPolicyPrefixListRule{}
		return nil
	}
	type t ConfigPolicyPrefixListRule
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfaces) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfaces{}
		return nil
	}
	type t ConfigInterfaces
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesWirelessmodem) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesWirelessmodem{}
		return nil
	}
	type t ConfigInterfacesWirelessmodem
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesIpv6Tunnel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesIpv6Tunnel{}
		return nil
	}
	type t ConfigInterfacesIpv6Tunnel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBonding) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBonding{}
		return nil
	}
	type t ConfigInterfacesBonding
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpv3) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpv3{}
		return nil
	}
	type t ConfigInterfacesL2tpv3
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesVti) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesVti{}
		return nil
	}
	type t ConfigInterfacesVti
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesInput) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesInput{}
		return nil
	}
	type t ConfigInterfacesInput
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridge) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridge{}
		return nil
	}
	type t ConfigInterfacesBridge
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpClient) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpClient{}
		return nil
	}
	type t ConfigInterfacesL2tpClient
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPptpClient) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPptpClient{}
		return nil
	}
	type t ConfigInterfacesPptpClient
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernet) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernet{}
		return nil
	}
	type t ConfigInterfacesEthernet
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesTunnel) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesTunnel{}
		return nil
	}
	type t ConfigInterfacesTunnel
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpn) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpn{}
		return nil
	}
	type t ConfigInterfacesOpenvpn
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesLoopback) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesLoopback{}
		return nil
	}
	type t ConfigInterfacesLoopback
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitch) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitch{}
		return nil
	}
	type t ConfigInterfacesSwitch
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernet) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernet{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernet
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesWirelessmodemBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesWirelessmodemBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesWirelessmodemBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesWirelessmodemIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesWirelessmodemIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesWirelessmodemIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesIpv6TunnelBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesIpv6TunnelBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesIpv6TunnelBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVif) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVif{}
		return nil
	}
	type t ConfigInterfacesBondingVif
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesBondingBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesBondingVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesBondingDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesBondingDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesBondingVifBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesBondingVifVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesBondingVifDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesBondingVifDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesBondingVifIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingVifIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingVifIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesBondingVifIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesBondingIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBondingIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBondingIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesBondingIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpv3BandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpv3BandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesL2tpv3BandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpv3IpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpv3IpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesL2tpv3IpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesVtiBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesVtiBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesVtiBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesVtiIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesVtiIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesVtiIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoe{}
		return nil
	}
	type t ConfigInterfacesBridgePppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVif) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVif{}
		return nil
	}
	type t ConfigInterfacesBridgeVif
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesBridgeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesBridgeVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesBridgeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesBridgeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoe{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesBridgeVifBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesBridgeVifVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesBridgeVifDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesBridgeVifDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesBridgeVifIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesBridgeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesBridgeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesBridgeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesBridgeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpClientBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpClientBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesL2tpClientBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpClientIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpClientIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesL2tpClientIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPptpClientBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPptpClientBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesPptpClientBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPptpClientIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPptpClientIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesPptpClientIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPptpClientIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPptpClientIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesPptpClientIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoe{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVif) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVif{}
		return nil
	}
	type t ConfigInterfacesEthernetVif
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesEthernetBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesEthernetVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesEthernetDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesEthernetDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoe{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesEthernetVifBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesEthernetVifVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesEthernetVifDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesEthernetVifDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesEthernetVifIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesEthernetIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesEthernetIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesEthernetIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesEthernetIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesTunnelBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesTunnelBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesTunnelBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesTunnelIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesTunnelIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesTunnelIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesTunnelIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesTunnelIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesTunnelIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpnLocalAddress) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpnLocalAddress{}
		return nil
	}
	type t ConfigInterfacesOpenvpnLocalAddress
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpnBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpnBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesOpenvpnBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpnServerClient) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpnServerClient{}
		return nil
	}
	type t ConfigInterfacesOpenvpnServerClient
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpnIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpnIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesOpenvpnIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesLoopbackBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesLoopbackBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesLoopbackBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesLoopbackIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesLoopbackIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesLoopbackIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoe{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVif) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVif{}
		return nil
	}
	type t ConfigInterfacesSwitchVif
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesSwitchBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchSwitchPortInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchSwitchPortInterface{}
		return nil
	}
	type t ConfigInterfacesSwitchSwitchPortInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesSwitchVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesSwitchDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesSwitchDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoe{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesSwitchVifBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesSwitchVifVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesSwitchVifDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesSwitchVifDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesSwitchVifIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesSwitchIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesSwitchIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesSwitchIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesSwitchIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoe) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoe{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoe
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVif) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVif{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVif
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifDhcpv6PdPd) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifDhcpv6PdPd{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifDhcpv6PdPd
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix{}
		return nil
	}
	type t ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}

func (e *ConfigCustomAttribute) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, emptyString) {
		*e = ConfigCustomAttribute{}
		return nil
	}
	type t ConfigCustomAttribute
	if err := json.Unmarshal(b, (*t)(e)); err != nil {
		return fmt.Errorf("failed to parse nested structure: %w", err)
	}
	return nil
}
