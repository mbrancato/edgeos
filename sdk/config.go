package sdk

import "encoding/json"

type ConfigZonePolicy *struct {
	Zone *ConfigZonePolicyZone `json:"zone,omitempty"`
}

type ConfigZonePolicyZone map[string]struct {
	DefaultAction string                    `json:"default-action,omitempty"`
	Interface     string                    `json:"interface,omitempty"`
	LocalZone     json.RawMessage           `json:"local-zone,omitempty"`
	From          *ConfigZonePolicyZoneFrom `json:"from,omitempty"`
	Description   string                    `json:"description,omitempty"`
}

type ConfigZonePolicyZoneFrom map[string]struct {
	ContentInspection *ConfigZonePolicyZoneFromContentInspection `json:".content-inspection,omitempty"`
	Firewall          *ConfigZonePolicyZoneFromFirewall          `json:"firewall,omitempty"`
}

type ConfigZonePolicyZoneFromContentInspection struct {
	Enable     json.RawMessage `json:"enable,omitempty"`
	Ipv6Enable json.RawMessage `json:".ipv6-enable,omitempty"`
}

type ConfigZonePolicyZoneFromFirewall struct {
	Name     string `json:"name,omitempty"`
	Ipv6Name string `json:"ipv6-name,omitempty"`
}

type ConfigLoadBalance *struct {
	Group *ConfigLoadBalanceGroup `json:"group,omitempty"`
}

type ConfigLoadBalanceGroup map[string]struct {
	Interface             *ConfigLoadBalanceGroupInterface `json:"interface,omitempty"`
	LbLocal               string                           `json:"lb-local,omitempty"`
	GatewayUpdateInterval int                              `json:"gateway-update-interval,omitempty"`
	LbLocalMetricChange   string                           `json:"lb-local-metric-change,omitempty"`
	Sticky                *ConfigLoadBalanceGroupSticky    `json:"sticky,omitempty"`
	FlushOnActive         string                           `json:"flush-on-active,omitempty"`
	TransitionScript      string                           `json:"transition-script,omitempty"`
	ExcludeLocalDns       string                           `json:"exclude-local-dns,omitempty"`
	ReachabilityScript    string                           `json:"reachability-script,omitempty"`
}

type ConfigLoadBalanceGroupInterface map[string]struct {
	Weight           int                                       `json:"weight,omitempty"`
	RouteTest        *ConfigLoadBalanceGroupInterfaceRouteTest `json:"route-test,omitempty"`
	Route            *ConfigLoadBalanceGroupInterfaceRoute     `json:"route,omitempty"`
	FailoverOnly     json.RawMessage                           `json:"failover-only,omitempty"`
	FailoverPriority int                                       `json:"failover-priority,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTest struct {
	Interval     int                                            `json:"interval,omitempty"`
	Count        *ConfigLoadBalanceGroupInterfaceRouteTestCount `json:"count,omitempty"`
	InitialDelay int                                            `json:"initial-delay,omitempty"`
	Type         *ConfigLoadBalanceGroupInterfaceRouteTestType  `json:"type,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTestCount struct {
	Success int `json:"success,omitempty"`
	Failure int `json:"failure,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTestType struct {
	Ping    *ConfigLoadBalanceGroupInterfaceRouteTestTypePing `json:"ping,omitempty"`
	Default json.RawMessage                                   `json:"default,omitempty"`
	Script  string                                            `json:"script,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRouteTestTypePing struct {
	Target IP `json:"target,omitempty"`
}

type ConfigLoadBalanceGroupInterfaceRoute struct {
	Default json.RawMessage `json:"default,omitempty"`
	Table   int             `json:"table,omitempty"`
}

type ConfigLoadBalanceGroupSticky struct {
	Proto      string `json:"proto,omitempty"`
	SourceAddr string `json:"source-addr,omitempty"`
	SourcePort string `json:"source-port,omitempty"`
	DestPort   string `json:"dest-port,omitempty"`
	DestAddr   string `json:"dest-addr,omitempty"`
}

type ConfigPortForward *struct {
	LanInterface string                 `json:"lan-interface,omitempty"`
	AutoFirewall string                 `json:"auto-firewall,omitempty"`
	Rule         *ConfigPortForwardRule `json:"rule,omitempty"`
	WanInterface string                 `json:"wan-interface,omitempty"`
	HairpinNat   string                 `json:"hairpin-nat,omitempty"`
}

type ConfigPortForwardRule map[string]struct {
	ForwardTo    *ConfigPortForwardRuleForwardTo `json:"forward-to,omitempty"`
	OriginalPort string                          `json:"original-port,omitempty"`
	Protocol     string                          `json:"protocol,omitempty"`
	Description  string                          `json:"description,omitempty"`
}

type ConfigPortForwardRuleForwardTo struct {
	Address IPv4   `json:"address,omitempty"`
	Port    string `json:"port,omitempty"`
}

type ConfigVpn *struct {
	RsaKeys *ConfigVpnRsaKeys `json:"rsa-keys,omitempty"`
	Ipsec   *ConfigVpnIpsec   `json:"ipsec,omitempty"`
	Pptp    *ConfigVpnPptp    `json:"pptp,omitempty"`
	L2tp    *ConfigVpnL2tp    `json:"l2tp,omitempty"`
}

type ConfigVpnRsaKeys struct {
	LocalKey   *ConfigVpnRsaKeysLocalKey   `json:"local-key,omitempty"`
	RsaKeyName *ConfigVpnRsaKeysRsaKeyName `json:"rsa-key-name,omitempty"`
}

type ConfigVpnRsaKeysLocalKey struct {
	File string `json:"file,omitempty"`
}

type ConfigVpnRsaKeysRsaKeyName map[string]struct {
	RsaKey string `json:"rsa-key,omitempty"`
}

type ConfigVpnIpsec struct {
	AutoUpdate                  int                            `json:"auto-update,omitempty"`
	NatNetworks                 *ConfigVpnIpsecNatNetworks     `json:"nat-networks,omitempty"`
	AllowAccessToLocalInterface string                         `json:"allow-access-to-local-interface,omitempty"`
	AutoFirewallNatExclude      string                         `json:"auto-firewall-nat-exclude,omitempty"`
	DisableUniqreqids           json.RawMessage                `json:"disable-uniqreqids,omitempty"`
	SiteToSite                  *ConfigVpnIpsecSiteToSite      `json:"site-to-site,omitempty"`
	RemoteAccess                *ConfigVpnIpsecRemoteAccess    `json:"remote-access,omitempty"`
	IpsecInterfaces             *ConfigVpnIpsecIpsecInterfaces `json:"ipsec-interfaces,omitempty"`
	GlobalConfig                string                         `json:"global-config,omitempty"`
	IkeGroup                    *ConfigVpnIpsecIkeGroup        `json:"ike-group,omitempty"`
	EspGroup                    *ConfigVpnIpsecEspGroup        `json:"esp-group,omitempty"`
	IncludeIpsecSecrets         string                         `json:"include-ipsec-secrets,omitempty"`
	IncludeIpsecConf            string                         `json:"include-ipsec-conf,omitempty"`
	Logging                     *ConfigVpnIpsecLogging         `json:"logging,omitempty"`
	NatTraversal                string                         `json:"nat-traversal,omitempty"`
}

type ConfigVpnIpsecNatNetworks struct {
	AllowedNetwork *ConfigVpnIpsecNatNetworksAllowedNetwork `json:"allowed-network,omitempty"`
}

type ConfigVpnIpsecNatNetworksAllowedNetwork map[string]struct {
	Exclude IPv4Net `json:"exclude,omitempty"`
}

type ConfigVpnIpsecSiteToSite struct {
	Peer *ConfigVpnIpsecSiteToSitePeer `json:"peer,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeer map[string]struct {
	DefaultEspGroup    string                                      `json:"default-esp-group,omitempty"`
	ForceEncapsulation string                                      `json:"force-encapsulation,omitempty"`
	Vti                *ConfigVpnIpsecSiteToSitePeerVti            `json:"vti,omitempty"`
	ConnectionType     string                                      `json:"connection-type,omitempty"`
	Ikev2Reauth        string                                      `json:"ikev2-reauth,omitempty"`
	Tunnel             *ConfigVpnIpsecSiteToSitePeerTunnel         `json:"tunnel,omitempty"`
	Description        string                                      `json:"description,omitempty"`
	LocalAddress       json.RawMessage                             `json:"local-address,omitempty"`
	IkeGroup           string                                      `json:"ike-group,omitempty"`
	Authentication     *ConfigVpnIpsecSiteToSitePeerAuthentication `json:"authentication,omitempty"`
	DhcpInterface      string                                      `json:"dhcp-interface,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerVti struct {
	EspGroup string `json:"esp-group,omitempty"`
	Bind     string `json:"bind,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerTunnel map[string]struct {
	Disable             json.RawMessage                           `json:"disable,omitempty"`
	AllowPublicNetworks string                                    `json:"allow-public-networks,omitempty"`
	Protocol            string                                    `json:"protocol,omitempty"`
	Local               *ConfigVpnIpsecSiteToSitePeerTunnelLocal  `json:"local,omitempty"`
	EspGroup            string                                    `json:"esp-group,omitempty"`
	AllowNatNetworks    string                                    `json:"allow-nat-networks,omitempty"`
	Remote              *ConfigVpnIpsecSiteToSitePeerTunnelRemote `json:"remote,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerTunnelLocal struct {
	Prefix IPNet  `json:"prefix,omitempty"`
	Port   string `json:"port,omitempty"`
}

type ConfigVpnIpsecSiteToSitePeerTunnelRemote struct {
	Prefix IPNet  `json:"prefix,omitempty"`
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
	OutsideAddress    IPv4                                      `json:"outside-address,omitempty"`
	WinsServers       *ConfigVpnIpsecRemoteAccessWinsServers    `json:"wins-servers,omitempty"`
	UpdownScript      string                                    `json:"updown-script,omitempty"`
	Inactivity        int                                       `json:"inactivity,omitempty"`
	DnsServers        *ConfigVpnIpsecRemoteAccessDnsServers     `json:"dns-servers,omitempty"`
	IkeSettings       *ConfigVpnIpsecRemoteAccessIkeSettings    `json:"ike-settings,omitempty"`
	ClientIpPool      *ConfigVpnIpsecRemoteAccessClientIpPool   `json:"client-ip-pool,omitempty"`
	Description       string                                    `json:"description,omitempty"`
	LocalIp           IPv4                                      `json:"local-ip,omitempty"`
	CompatibilityMode string                                    `json:"compatibility-mode,omitempty"`
	EspSettings       *ConfigVpnIpsecRemoteAccessEspSettings    `json:"esp-settings,omitempty"`
	Authentication    *ConfigVpnIpsecRemoteAccessAuthentication `json:"authentication,omitempty"`
	DhcpInterface     string                                    `json:"dhcp-interface,omitempty"`
}

type ConfigVpnIpsecRemoteAccessWinsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigVpnIpsecRemoteAccessDnsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigVpnIpsecRemoteAccessIkeSettings struct {
	Proposal       *ConfigVpnIpsecRemoteAccessIkeSettingsProposal       `json:"proposal,omitempty"`
	EspGroup       string                                               `json:"esp-group,omitempty"`
	IkeLifetime    int                                                  `json:"ike-lifetime,omitempty"`
	Authentication *ConfigVpnIpsecRemoteAccessIkeSettingsAuthentication `json:"authentication,omitempty"`
	OperatingMode  string                                               `json:"operating-mode,omitempty"`
	Fragmentation  string                                               `json:"fragmentation,omitempty"`
}

type ConfigVpnIpsecRemoteAccessIkeSettingsProposal map[string]struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DhGroup    int    `json:"dh-group,omitempty"`
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
	Subnet  IPv4Net `json:"subnet,omitempty"`
	Subnet6 IPv6Net `json:"subnet6,omitempty"`
}

type ConfigVpnIpsecRemoteAccessEspSettings struct {
	Proposal *ConfigVpnIpsecRemoteAccessEspSettingsProposal `json:"proposal,omitempty"`
}

type ConfigVpnIpsecRemoteAccessEspSettingsProposal map[string]struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DhGroup    int    `json:"dh-group,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthentication struct {
	Mode         string                                                `json:"mode,omitempty"`
	LocalUsers   *ConfigVpnIpsecRemoteAccessAuthenticationLocalUsers   `json:"local-users,omitempty"`
	RadiusServer *ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthenticationLocalUsers struct {
	Username *ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthenticationLocalUsersUsername map[string]struct {
	Disable  json.RawMessage `json:"disable,omitempty"`
	Password string          `json:"password,omitempty"`
}

type ConfigVpnIpsecRemoteAccessAuthenticationRadiusServer map[string]struct {
	Key string `json:"key,omitempty"`
}

type ConfigVpnIpsecIpsecInterfaces struct {
	Interface string `json:"interface,omitempty"`
}

type ConfigVpnIpsecIkeGroup map[string]struct {
	Mode              string                                   `json:"mode,omitempty"`
	DeadPeerDetection *ConfigVpnIpsecIkeGroupDeadPeerDetection `json:"dead-peer-detection,omitempty"`
	KeyExchange       string                                   `json:"key-exchange,omitempty"`
	Ikev2Reauth       string                                   `json:"ikev2-reauth,omitempty"`
	Lifetime          int                                      `json:"lifetime,omitempty"`
	Proposal          *ConfigVpnIpsecIkeGroupProposal          `json:"proposal,omitempty"`
}

type ConfigVpnIpsecIkeGroupDeadPeerDetection struct {
	Interval int    `json:"interval,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
	Action   string `json:"action,omitempty"`
}

type ConfigVpnIpsecIkeGroupProposal map[string]struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
	DhGroup    int    `json:"dh-group,omitempty"`
}

type ConfigVpnIpsecEspGroup map[string]struct {
	Mode        string                          `json:"mode,omitempty"`
	Pfs         string                          `json:"pfs,omitempty"`
	Lifetime    int                             `json:"lifetime,omitempty"`
	Proposal    *ConfigVpnIpsecEspGroupProposal `json:"proposal,omitempty"`
	Compression string                          `json:"compression,omitempty"`
}

type ConfigVpnIpsecEspGroupProposal map[string]struct {
	Encryption string `json:"encryption,omitempty"`
	Hash       string `json:"hash,omitempty"`
}

type ConfigVpnIpsecLogging struct {
	LogModes string `json:"log-modes,omitempty"`
	LogLevel int    `json:"log-level,omitempty"`
}

type ConfigVpnPptp struct {
	RemoteAccess *ConfigVpnPptpRemoteAccess `json:"remote-access,omitempty"`
}

type ConfigVpnPptpRemoteAccess struct {
	Accounting     *ConfigVpnPptpRemoteAccessAccounting     `json:"accounting,omitempty"`
	OutsideAddress IPv4                                     `json:"outside-address,omitempty"`
	WinsServers    *ConfigVpnPptpRemoteAccessWinsServers    `json:"wins-servers,omitempty"`
	DnsServers     *ConfigVpnPptpRemoteAccessDnsServers     `json:"dns-servers,omitempty"`
	Mtu            int                                      `json:"mtu,omitempty"`
	ClientIpPool   *ConfigVpnPptpRemoteAccessClientIpPool   `json:"client-ip-pool,omitempty"`
	LocalIp        IPv4                                     `json:"local-ip,omitempty"`
	Authentication *ConfigVpnPptpRemoteAccessAuthentication `json:"authentication,omitempty"`
	DhcpInterface  string                                   `json:"dhcp-interface,omitempty"`
}

type ConfigVpnPptpRemoteAccessAccounting struct {
	RadiusServer *ConfigVpnPptpRemoteAccessAccountingRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnPptpRemoteAccessAccountingRadiusServer map[string]struct {
	Key  string `json:"key,omitempty"`
	Port int    `json:"port,omitempty"`
}

type ConfigVpnPptpRemoteAccessWinsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigVpnPptpRemoteAccessDnsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigVpnPptpRemoteAccessClientIpPool struct {
	Start IPv4 `json:"start,omitempty"`
	Stop  IPv4 `json:"stop,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthentication struct {
	Mode         string                                               `json:"mode,omitempty"`
	LocalUsers   *ConfigVpnPptpRemoteAccessAuthenticationLocalUsers   `json:"local-users,omitempty"`
	RadiusServer *ConfigVpnPptpRemoteAccessAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthenticationLocalUsers struct {
	Username *ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthenticationLocalUsersUsername map[string]struct {
	Disable  json.RawMessage `json:"disable,omitempty"`
	Password string          `json:"password,omitempty"`
	StaticIp IPv4            `json:"static-ip,omitempty"`
}

type ConfigVpnPptpRemoteAccessAuthenticationRadiusServer map[string]struct {
	Key  string `json:"key,omitempty"`
	Port int    `json:"port,omitempty"`
}

type ConfigVpnL2tp struct {
	RemoteAccess *ConfigVpnL2tpRemoteAccess `json:"remote-access,omitempty"`
}

type ConfigVpnL2tpRemoteAccess struct {
	OutsideNexthop                  IPv4                                     `json:"outside-nexthop,omitempty"`
	Accounting                      *ConfigVpnL2tpRemoteAccessAccounting     `json:"accounting,omitempty"`
	OutsideAddress                  IPv4                                     `json:"outside-address,omitempty"`
	Idle                            int                                      `json:"idle,omitempty"`
	WinsServers                     *ConfigVpnL2tpRemoteAccessWinsServers    `json:"wins-servers,omitempty"`
	DnsServers                      *ConfigVpnL2tpRemoteAccessDnsServers     `json:"dns-servers,omitempty"`
	Mtu                             int                                      `json:"mtu,omitempty"`
	ClientIpPool                    *ConfigVpnL2tpRemoteAccessClientIpPool   `json:"client-ip-pool,omitempty"`
	IpsecSettings                   *ConfigVpnL2tpRemoteAccessIpsecSettings  `json:"ipsec-settings,omitempty"`
	Description                     string                                   `json:"description,omitempty"`
	AllowMultipleClientsFromSameNat string                                   `json:"allow-multiple-clients-from-same-nat,omitempty"`
	LocalIp                         IPv4                                     `json:"local-ip,omitempty"`
	Authentication                  *ConfigVpnL2tpRemoteAccessAuthentication `json:"authentication,omitempty"`
	DhcpInterface                   string                                   `json:"dhcp-interface,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAccounting struct {
	RadiusServer *ConfigVpnL2tpRemoteAccessAccountingRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAccountingRadiusServer map[string]struct {
	Key  string `json:"key,omitempty"`
	Port int    `json:"port,omitempty"`
}

type ConfigVpnL2tpRemoteAccessWinsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigVpnL2tpRemoteAccessDnsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigVpnL2tpRemoteAccessClientIpPool struct {
	Start IPv4 `json:"start,omitempty"`
	Stop  IPv4 `json:"stop,omitempty"`
}

type ConfigVpnL2tpRemoteAccessIpsecSettings struct {
	Lifetime       int                                                   `json:"lifetime,omitempty"`
	IkeLifetime    int                                                   `json:"ike-lifetime,omitempty"`
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
	Mode         string                                               `json:"mode,omitempty"`
	Require      string                                               `json:"require,omitempty"`
	LocalUsers   *ConfigVpnL2tpRemoteAccessAuthenticationLocalUsers   `json:"local-users,omitempty"`
	RadiusServer *ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthenticationLocalUsers struct {
	Username *ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthenticationLocalUsersUsername map[string]struct {
	Disable  json.RawMessage `json:"disable,omitempty"`
	Password string          `json:"password,omitempty"`
	StaticIp IPv4            `json:"static-ip,omitempty"`
}

type ConfigVpnL2tpRemoteAccessAuthenticationRadiusServer map[string]struct {
	Key  string `json:"key,omitempty"`
	Port int    `json:"port,omitempty"`
}

type ConfigTrafficPolicy *struct {
	NetworkEmulator *ConfigTrafficPolicyNetworkEmulator `json:"network-emulator,omitempty"`
	DropTail        *ConfigTrafficPolicyDropTail        `json:"drop-tail,omitempty"`
	RoundRobin      *ConfigTrafficPolicyRoundRobin      `json:"round-robin,omitempty"`
	Limiter         *ConfigTrafficPolicyLimiter         `json:"limiter,omitempty"`
	FairQueue       *ConfigTrafficPolicyFairQueue       `json:"fair-queue,omitempty"`
	RateControl     *ConfigTrafficPolicyRateControl     `json:"rate-control,omitempty"`
	Shaper          *ConfigTrafficPolicyShaper          `json:"shaper,omitempty"`
	PriorityQueue   *ConfigTrafficPolicyPriorityQueue   `json:"priority-queue,omitempty"`
	RandomDetect    *ConfigTrafficPolicyRandomDetect    `json:"random-detect,omitempty"`
}

type ConfigTrafficPolicyNetworkEmulator map[string]struct {
	PacketCorruption string `json:"packet-corruption,omitempty"`
	Bandwidth        string `json:"bandwidth,omitempty"`
	Burst            string `json:"burst,omitempty"`
	Description      string `json:"description,omitempty"`
	QueueLimit       int    `json:"queue-limit,omitempty"`
	NetworkDelay     string `json:"network-delay,omitempty"`
	PacketReordering string `json:"packet-reordering,omitempty"`
	PacketLoss       string `json:"packet-loss,omitempty"`
}

type ConfigTrafficPolicyDropTail map[string]struct {
	Description string `json:"description,omitempty"`
	QueueLimit  int    `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyRoundRobin map[string]struct {
	Default     *ConfigTrafficPolicyRoundRobinDefault `json:"default,omitempty"`
	Description string                                `json:"description,omitempty"`
	Class       *ConfigTrafficPolicyRoundRobinClass   `json:"class,omitempty"`
}

type ConfigTrafficPolicyRoundRobinDefault struct {
	QueueType  string `json:"queue-type,omitempty"`
	QueueLimit int    `json:"queue-limit,omitempty"`
	Quantum    int    `json:"quantum,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClass map[string]struct {
	Match       *ConfigTrafficPolicyRoundRobinClassMatch `json:"match,omitempty"`
	QueueType   string                                   `json:"queue-type,omitempty"`
	Description string                                   `json:"description,omitempty"`
	QueueLimit  int                                      `json:"queue-limit,omitempty"`
	Quantum     int                                      `json:"quantum,omitempty"`
}

type ConfigTrafficPolicyRoundRobinClassMatch map[string]struct {
	Interface   string                                        `json:"interface,omitempty"`
	Mark        int                                           `json:"mark,omitempty"`
	Ether       *ConfigTrafficPolicyRoundRobinClassMatchEther `json:"ether,omitempty"`
	Description string                                        `json:"description,omitempty"`
	Vif         int                                           `json:"vif,omitempty"`
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

type ConfigTrafficPolicyLimiter map[string]struct {
	Default     *ConfigTrafficPolicyLimiterDefault `json:"default,omitempty"`
	Description string                             `json:"description,omitempty"`
	Class       *ConfigTrafficPolicyLimiterClass   `json:"class,omitempty"`
}

type ConfigTrafficPolicyLimiterDefault struct {
	Bandwidth string `json:"bandwidth,omitempty"`
	Burst     string `json:"burst,omitempty"`
}

type ConfigTrafficPolicyLimiterClass map[string]struct {
	Bandwidth   string                                `json:"bandwidth,omitempty"`
	Match       *ConfigTrafficPolicyLimiterClassMatch `json:"match,omitempty"`
	Burst       string                                `json:"burst,omitempty"`
	Description string                                `json:"description,omitempty"`
	Priority    int                                   `json:"priority,omitempty"`
}

type ConfigTrafficPolicyLimiterClassMatch map[string]struct {
	Ether       *ConfigTrafficPolicyLimiterClassMatchEther `json:"ether,omitempty"`
	Description string                                     `json:"description,omitempty"`
	Vif         int                                        `json:"vif,omitempty"`
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

type ConfigTrafficPolicyFairQueue map[string]struct {
	HashInterval int    `json:"hash-interval,omitempty"`
	Description  string `json:"description,omitempty"`
	QueueLimit   int    `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyRateControl map[string]struct {
	Bandwidth   string `json:"bandwidth,omitempty"`
	Burst       string `json:"burst,omitempty"`
	Latency     string `json:"latency,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigTrafficPolicyShaper map[string]struct {
	Bandwidth   string                            `json:"bandwidth,omitempty"`
	Default     *ConfigTrafficPolicyShaperDefault `json:"default,omitempty"`
	Description string                            `json:"description,omitempty"`
	Class       *ConfigTrafficPolicyShaperClass   `json:"class,omitempty"`
}

type ConfigTrafficPolicyShaperDefault struct {
	Bandwidth  string `json:"bandwidth,omitempty"`
	Burst      string `json:"burst,omitempty"`
	Ceiling    string `json:"ceiling,omitempty"`
	QueueType  string `json:"queue-type,omitempty"`
	Priority   int    `json:"priority,omitempty"`
	QueueLimit int    `json:"queue-limit,omitempty"`
	SetDscp    string `json:".set-dscp,omitempty"`
}

type ConfigTrafficPolicyShaperClass map[string]struct {
	Bandwidth   string                               `json:"bandwidth,omitempty"`
	Match       *ConfigTrafficPolicyShaperClassMatch `json:"match,omitempty"`
	Burst       string                               `json:"burst,omitempty"`
	Ceiling     string                               `json:"ceiling,omitempty"`
	QueueType   string                               `json:"queue-type,omitempty"`
	Description string                               `json:"description,omitempty"`
	Priority    int                                  `json:"priority,omitempty"`
	QueueLimit  int                                  `json:"queue-limit,omitempty"`
	SetDscp     string                               `json:".set-dscp,omitempty"`
}

type ConfigTrafficPolicyShaperClassMatch map[string]struct {
	Interface   string                                    `json:"interface,omitempty"`
	Mark        string                                    `json:"mark,omitempty"`
	Ether       *ConfigTrafficPolicyShaperClassMatchEther `json:"ether,omitempty"`
	Description string                                    `json:"description,omitempty"`
	Vif         int                                       `json:"vif,omitempty"`
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

type ConfigTrafficPolicyPriorityQueue map[string]struct {
	Default     *ConfigTrafficPolicyPriorityQueueDefault `json:"default,omitempty"`
	Description string                                   `json:"description,omitempty"`
	Class       *ConfigTrafficPolicyPriorityQueueClass   `json:"class,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueDefault struct {
	QueueType  string `json:"queue-type,omitempty"`
	QueueLimit int    `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClass map[string]struct {
	Match       *ConfigTrafficPolicyPriorityQueueClassMatch `json:"match,omitempty"`
	QueueType   string                                      `json:"queue-type,omitempty"`
	Description string                                      `json:"description,omitempty"`
	QueueLimit  int                                         `json:"queue-limit,omitempty"`
}

type ConfigTrafficPolicyPriorityQueueClassMatch map[string]struct {
	Interface   string                                           `json:"interface,omitempty"`
	Mark        int                                              `json:"mark,omitempty"`
	Ether       *ConfigTrafficPolicyPriorityQueueClassMatchEther `json:"ether,omitempty"`
	Description string                                           `json:"description,omitempty"`
	Vif         int                                              `json:"vif,omitempty"`
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

type ConfigTrafficPolicyRandomDetect map[string]struct {
	Bandwidth   string                                     `json:"bandwidth,omitempty"`
	Description string                                     `json:"description,omitempty"`
	Precedence  *ConfigTrafficPolicyRandomDetectPrecedence `json:"precedence,omitempty"`
}

type ConfigTrafficPolicyRandomDetectPrecedence map[string]struct {
	MarkProbability  int `json:"mark-probability,omitempty"`
	MinimumThreshold int `json:"minimum-threshold,omitempty"`
	AveragePacket    int `json:"average-packet,omitempty"`
	QueueLimit       int `json:"queue-limit,omitempty"`
	MaximumThreshold int `json:"maximum-threshold,omitempty"`
}

type ConfigFirewall *struct {
	Options              *ConfigFirewallOptions    `json:"options,omitempty"`
	IpSrcRoute           string                    `json:"ip-src-route,omitempty"`
	SendRedirects        string                    `json:"send-redirects,omitempty"`
	Group                *ConfigFirewallGroup      `json:"group,omitempty"`
	Ipv6ReceiveRedirects string                    `json:"ipv6-receive-redirects,omitempty"`
	AllPing              string                    `json:"all-ping,omitempty"`
	SynCookies           string                    `json:"syn-cookies,omitempty"`
	Modify               *ConfigFirewallModify     `json:"modify,omitempty"`
	BroadcastPing        string                    `json:"broadcast-ping,omitempty"`
	LogMartians          string                    `json:"log-martians,omitempty"`
	Ipv6Modify           *ConfigFirewallIpv6Modify `json:"ipv6-modify,omitempty"`
	SourceValidation     string                    `json:"source-validation,omitempty"`
	Name                 *ConfigFirewallName       `json:"name,omitempty"`
	Ipv6SrcRoute         string                    `json:"ipv6-src-route,omitempty"`
	ReceiveRedirects     string                    `json:"receive-redirects,omitempty"`
	Ipv6Name             *ConfigFirewallIpv6Name   `json:"ipv6-name,omitempty"`
}

type ConfigFirewallOptions struct {
	MssClamp  *ConfigFirewallOptionsMssClamp  `json:"mss-clamp,omitempty"`
	MssClamp6 *ConfigFirewallOptionsMssClamp6 `json:"mss-clamp6,omitempty"`
}

type ConfigFirewallOptionsMssClamp struct {
	Mss           int    `json:"mss,omitempty"`
	InterfaceType string `json:"interface-type,omitempty"`
}

type ConfigFirewallOptionsMssClamp6 struct {
	Mss           int    `json:"mss,omitempty"`
	InterfaceType string `json:"interface-type,omitempty"`
}

type ConfigFirewallGroup struct {
	AddressGroup     *ConfigFirewallGroupAddressGroup     `json:"address-group,omitempty"`
	PortGroup        *ConfigFirewallGroupPortGroup        `json:"port-group,omitempty"`
	NetworkGroup     *ConfigFirewallGroupNetworkGroup     `json:"network-group,omitempty"`
	Ipv6AddressGroup *ConfigFirewallGroupIpv6AddressGroup `json:"ipv6-address-group,omitempty"`
	Ipv6NetworkGroup *ConfigFirewallGroupIpv6NetworkGroup `json:"ipv6-network-group,omitempty"`
}

type ConfigFirewallGroupAddressGroup map[string]struct {
	Description string `json:"description,omitempty"`
	Address     string `json:"address,omitempty"`
}

type ConfigFirewallGroupPortGroup map[string]struct {
	Description string `json:"description,omitempty"`
	Port        string `json:"port,omitempty"`
}

type ConfigFirewallGroupNetworkGroup map[string]struct {
	Network     IPv4Net `json:"network,omitempty"`
	Description string  `json:"description,omitempty"`
}

type ConfigFirewallGroupIpv6AddressGroup map[string]struct {
	Ipv6Address IPv6Net `json:"ipv6-address,omitempty"`
	Description string  `json:"description,omitempty"`
}

type ConfigFirewallGroupIpv6NetworkGroup map[string]struct {
	Description string  `json:"description,omitempty"`
	Ipv6Network IPv6Net `json:"ipv6-network,omitempty"`
}

type ConfigFirewallModify map[string]struct {
	Rule             *ConfigFirewallModifyRule `json:"rule,omitempty"`
	Description      string                    `json:"description,omitempty"`
	EnableDefaultLog json.RawMessage           `json:"enable-default-log,omitempty"`
}

type ConfigFirewallModifyRule map[string]struct {
	Disable     json.RawMessage                      `json:"disable,omitempty"`
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
	Dscp        int                                  `json:"dscp,omitempty"`
	Statistic   *ConfigFirewallModifyRuleStatistic   `json:"statistic,omitempty"`
	Recent      *ConfigFirewallModifyRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallModifyRuleLimit struct {
	Rate  string `json:"rate,omitempty"`
	Burst int    `json:"burst,omitempty"`
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
	Dscp     int                                     `json:"dscp,omitempty"`
	LbGroup  string                                  `json:"lb-group,omitempty"`
}

type ConfigFirewallModifyRuleModifyConnmark struct {
	SaveMark    json.RawMessage `json:"save-mark,omitempty"`
	RestoreMark json.RawMessage `json:"restore-mark,omitempty"`
	SetMark     int             `json:"set-mark,omitempty"`
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
	Stopdate   string          `json:"stopdate,omitempty"`
	Contiguous json.RawMessage `json:"contiguous,omitempty"`
	Starttime  string          `json:"starttime,omitempty"`
	Stoptime   string          `json:"stoptime,omitempty"`
	Weekdays   string          `json:"weekdays,omitempty"`
	Utc        json.RawMessage `json:"utc,omitempty"`
	Startdate  string          `json:"startdate,omitempty"`
	Monthdays  string          `json:"monthdays,omitempty"`
}

type ConfigFirewallModifyRuleIpsec struct {
	MatchNone  json.RawMessage `json:"match-none,omitempty"`
	MatchIpsec json.RawMessage `json:"match-ipsec,omitempty"`
}

type ConfigFirewallModifyRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallModifyRuleFragment struct {
	MatchNonFrag json.RawMessage `json:"match-non-frag,omitempty"`
	MatchFrag    json.RawMessage `json:"match-frag,omitempty"`
}

type ConfigFirewallModifyRuleIcmp struct {
	Code     int    `json:"code,omitempty"`
	TypeName string `json:"type-name,omitempty"`
	Type     int    `json:"type,omitempty"`
}

type ConfigFirewallModifyRuleP2p struct {
	Bittorrent    json.RawMessage `json:"bittorrent,omitempty"`
	Gnutella      json.RawMessage `json:"gnutella,omitempty"`
	All           json.RawMessage `json:"all,omitempty"`
	Applejuice    json.RawMessage `json:"applejuice,omitempty"`
	Edonkey       json.RawMessage `json:"edonkey,omitempty"`
	Kazaa         json.RawMessage `json:"kazaa,omitempty"`
	Directconnect json.RawMessage `json:"directconnect,omitempty"`
}

type ConfigFirewallModifyRuleApplication struct {
	Category       string `json:"category,omitempty"`
	CustomCategory string `json:"custom-category,omitempty"`
}

type ConfigFirewallModifyRuleStatistic struct {
	Probability string `json:"probability,omitempty"`
}

type ConfigFirewallModifyRuleRecent struct {
	Count int `json:"count,omitempty"`
	Time  int `json:"time,omitempty"`
}

type ConfigFirewallIpv6Modify map[string]struct {
	Rule             *ConfigFirewallIpv6ModifyRule `json:"rule,omitempty"`
	Description      string                        `json:"description,omitempty"`
	EnableDefaultLog json.RawMessage               `json:"enable-default-log,omitempty"`
}

type ConfigFirewallIpv6ModifyRule map[string]struct {
	Disable     json.RawMessage                          `json:"disable,omitempty"`
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
	Dscp        int                                      `json:"dscp,omitempty"`
	Recent      *ConfigFirewallIpv6ModifyRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleIcmpv6 struct {
	Type string `json:"type,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleLimit struct {
	Rate  string `json:"rate,omitempty"`
	Burst int    `json:"burst,omitempty"`
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
	Dscp     int                                         `json:"dscp,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleModifyConnmark struct {
	SaveMark    json.RawMessage `json:"save-mark,omitempty"`
	RestoreMark json.RawMessage `json:"restore-mark,omitempty"`
	SetMark     int             `json:"set-mark,omitempty"`
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
	Stopdate   string          `json:"stopdate,omitempty"`
	Contiguous json.RawMessage `json:"contiguous,omitempty"`
	Starttime  string          `json:"starttime,omitempty"`
	Stoptime   string          `json:"stoptime,omitempty"`
	Weekdays   string          `json:"weekdays,omitempty"`
	Utc        json.RawMessage `json:"utc,omitempty"`
	Startdate  string          `json:"startdate,omitempty"`
	Monthdays  string          `json:"monthdays,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleIpsec struct {
	MatchNone  json.RawMessage `json:"match-none,omitempty"`
	MatchIpsec json.RawMessage `json:"match-ipsec,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleP2p struct {
	Bittorrent    json.RawMessage `json:"bittorrent,omitempty"`
	Gnutella      json.RawMessage `json:"gnutella,omitempty"`
	All           json.RawMessage `json:"all,omitempty"`
	Applejuice    json.RawMessage `json:"applejuice,omitempty"`
	Edonkey       json.RawMessage `json:"edonkey,omitempty"`
	Kazaa         json.RawMessage `json:"kazaa,omitempty"`
	Directconnect json.RawMessage `json:"directconnect,omitempty"`
}

type ConfigFirewallIpv6ModifyRuleRecent struct {
	Count int `json:"count,omitempty"`
	Time  int `json:"time,omitempty"`
}

type ConfigFirewallName map[string]struct {
	DefaultAction    string                  `json:"default-action,omitempty"`
	Rule             *ConfigFirewallNameRule `json:"rule,omitempty"`
	Description      string                  `json:"description,omitempty"`
	EnableDefaultLog json.RawMessage         `json:"enable-default-log,omitempty"`
}

type ConfigFirewallNameRule map[string]struct {
	Disable     json.RawMessage                    `json:"disable,omitempty"`
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
	Dscp        int                                `json:"dscp,omitempty"`
	Recent      *ConfigFirewallNameRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallNameRuleLimit struct {
	Rate  string `json:"rate,omitempty"`
	Burst int    `json:"burst,omitempty"`
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
	Stopdate   string          `json:"stopdate,omitempty"`
	Contiguous json.RawMessage `json:"contiguous,omitempty"`
	Starttime  string          `json:"starttime,omitempty"`
	Stoptime   string          `json:"stoptime,omitempty"`
	Weekdays   string          `json:"weekdays,omitempty"`
	Utc        json.RawMessage `json:"utc,omitempty"`
	Startdate  string          `json:"startdate,omitempty"`
	Monthdays  string          `json:"monthdays,omitempty"`
}

type ConfigFirewallNameRuleIpsec struct {
	MatchNone  json.RawMessage `json:"match-none,omitempty"`
	MatchIpsec json.RawMessage `json:"match-ipsec,omitempty"`
}

type ConfigFirewallNameRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallNameRuleFragment struct {
	MatchNonFrag json.RawMessage `json:"match-non-frag,omitempty"`
	MatchFrag    json.RawMessage `json:"match-frag,omitempty"`
}

type ConfigFirewallNameRuleIcmp struct {
	Code     int    `json:"code,omitempty"`
	TypeName string `json:"type-name,omitempty"`
	Type     int    `json:"type,omitempty"`
}

type ConfigFirewallNameRuleP2p struct {
	Bittorrent    json.RawMessage `json:"bittorrent,omitempty"`
	Gnutella      json.RawMessage `json:"gnutella,omitempty"`
	All           json.RawMessage `json:"all,omitempty"`
	Applejuice    json.RawMessage `json:"applejuice,omitempty"`
	Edonkey       json.RawMessage `json:"edonkey,omitempty"`
	Kazaa         json.RawMessage `json:"kazaa,omitempty"`
	Directconnect json.RawMessage `json:"directconnect,omitempty"`
}

type ConfigFirewallNameRuleApplication struct {
	Category       string `json:"category,omitempty"`
	CustomCategory string `json:"custom-category,omitempty"`
}

type ConfigFirewallNameRuleRecent struct {
	Count int `json:"count,omitempty"`
	Time  int `json:"time,omitempty"`
}

type ConfigFirewallIpv6Name map[string]struct {
	DefaultAction    string                      `json:"default-action,omitempty"`
	Rule             *ConfigFirewallIpv6NameRule `json:"rule,omitempty"`
	Description      string                      `json:"description,omitempty"`
	EnableDefaultLog json.RawMessage             `json:"enable-default-log,omitempty"`
}

type ConfigFirewallIpv6NameRule map[string]struct {
	Disable     json.RawMessage                        `json:"disable,omitempty"`
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
	Dscp        int                                    `json:"dscp,omitempty"`
	Recent      *ConfigFirewallIpv6NameRuleRecent      `json:"recent,omitempty"`
}

type ConfigFirewallIpv6NameRuleIcmpv6 struct {
	Type string `json:"type,omitempty"`
}

type ConfigFirewallIpv6NameRuleLimit struct {
	Rate  string `json:"rate,omitempty"`
	Burst int    `json:"burst,omitempty"`
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
	Stopdate   string          `json:"stopdate,omitempty"`
	Contiguous json.RawMessage `json:"contiguous,omitempty"`
	Starttime  string          `json:"starttime,omitempty"`
	Stoptime   string          `json:"stoptime,omitempty"`
	Weekdays   string          `json:"weekdays,omitempty"`
	Utc        json.RawMessage `json:"utc,omitempty"`
	Startdate  string          `json:"startdate,omitempty"`
	Monthdays  string          `json:"monthdays,omitempty"`
}

type ConfigFirewallIpv6NameRuleIpsec struct {
	MatchNone  json.RawMessage `json:"match-none,omitempty"`
	MatchIpsec json.RawMessage `json:"match-ipsec,omitempty"`
}

type ConfigFirewallIpv6NameRuleTcp struct {
	Flags string `json:"flags,omitempty"`
}

type ConfigFirewallIpv6NameRuleP2p struct {
	Bittorrent    json.RawMessage `json:"bittorrent,omitempty"`
	Gnutella      json.RawMessage `json:"gnutella,omitempty"`
	All           json.RawMessage `json:"all,omitempty"`
	Applejuice    json.RawMessage `json:"applejuice,omitempty"`
	Edonkey       json.RawMessage `json:"edonkey,omitempty"`
	Kazaa         json.RawMessage `json:"kazaa,omitempty"`
	Directconnect json.RawMessage `json:"directconnect,omitempty"`
}

type ConfigFirewallIpv6NameRuleRecent struct {
	Count int `json:"count,omitempty"`
	Time  int `json:"time,omitempty"`
}

type ConfigSystem *struct {
	Options           *ConfigSystemOptions           `json:"options,omitempty"`
	Syslog            *ConfigSystemSyslog            `json:"syslog,omitempty"`
	FlowAccounting    *ConfigSystemFlowAccounting    `json:"flow-accounting,omitempty"`
	GatewayAddress    IPv4                           `json:"gateway-address,omitempty"`
	TaskScheduler     *ConfigSystemTaskScheduler     `json:"task-scheduler,omitempty"`
	AnalyticsHandler  *ConfigSystemAnalyticsHandler  `json:"analytics-handler,omitempty"`
	TimeZone          string                         `json:"time-zone,omitempty"`
	Systemd           *ConfigSystemSystemd           `json:"systemd,omitempty"`
	Conntrack         *ConfigSystemConntrack         `json:"conntrack,omitempty"`
	NameServer        IP                             `json:"name-server,omitempty"`
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
	Host    *ConfigSystemSyslogHost    `json:"host,omitempty"`
	File    *ConfigSystemSyslogFile    `json:"file,omitempty"`
	User    *ConfigSystemSyslogUser    `json:"user,omitempty"`
	Global  *ConfigSystemSyslogGlobal  `json:"global,omitempty"`
	Console *ConfigSystemSyslogConsole `json:"console,omitempty"`
}

type ConfigSystemSyslogHost map[string]struct {
	Facility *ConfigSystemSyslogHostFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogHostFacility map[string]struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogFile map[string]struct {
	Archive  *ConfigSystemSyslogFileArchive  `json:"archive,omitempty"`
	Facility *ConfigSystemSyslogFileFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogFileArchive struct {
	Files int `json:"files,omitempty"`
	Size  int `json:"size,omitempty"`
}

type ConfigSystemSyslogFileFacility map[string]struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogUser map[string]struct {
	Facility *ConfigSystemSyslogUserFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogUserFacility map[string]struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogGlobal struct {
	Archive  *ConfigSystemSyslogGlobalArchive  `json:"archive,omitempty"`
	Facility *ConfigSystemSyslogGlobalFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogGlobalArchive struct {
	Files int `json:"files,omitempty"`
	Size  int `json:"size,omitempty"`
}

type ConfigSystemSyslogGlobalFacility map[string]struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemSyslogConsole struct {
	Facility *ConfigSystemSyslogConsoleFacility `json:"facility,omitempty"`
}

type ConfigSystemSyslogConsoleFacility map[string]struct {
	Level string `json:"level,omitempty"`
}

type ConfigSystemFlowAccounting struct {
	Netflow            *ConfigSystemFlowAccountingNetflow   `json:"netflow,omitempty"`
	Interface          string                               `json:"interface,omitempty"`
	Sflow              *ConfigSystemFlowAccountingSflow     `json:"sflow,omitempty"`
	Aggregate          *ConfigSystemFlowAccountingAggregate `json:"aggregate,omitempty"`
	Unms               *ConfigSystemFlowAccountingUnms      `json:"unms,omitempty"`
	IngressCapture     string                               `json:"ingress-capture,omitempty"`
	SyslogFacility     string                               `json:"syslog-facility,omitempty"`
	DisableMemoryTable json.RawMessage                      `json:"disable-memory-table,omitempty"`
}

type ConfigSystemFlowAccountingNetflow struct {
	EngineId     int                                            `json:"engine-id,omitempty"`
	SamplingRate int                                            `json:"sampling-rate,omitempty"`
	Mode         string                                         `json:"mode,omitempty"`
	Timeout      *ConfigSystemFlowAccountingNetflowTimeout      `json:"timeout,omitempty"`
	Server       *ConfigSystemFlowAccountingNetflowServer       `json:"server,omitempty"`
	Version      string                                         `json:"version,omitempty"`
	EnableEgress *ConfigSystemFlowAccountingNetflowEnableEgress `json:"enable-egress,omitempty"`
}

type ConfigSystemFlowAccountingNetflowTimeout struct {
	TcpFin         int `json:"tcp-fin,omitempty"`
	Udp            int `json:"udp,omitempty"`
	FlowGeneric    int `json:"flow-generic,omitempty"`
	MaxActiveLife  int `json:"max-active-life,omitempty"`
	TcpRst         int `json:"tcp-rst,omitempty"`
	Icmp           int `json:"icmp,omitempty"`
	TcpGeneric     int `json:"tcp-generic,omitempty"`
	ExpiryInterval int `json:"expiry-interval,omitempty"`
}

type ConfigSystemFlowAccountingNetflowServer map[string]struct {
	Port int `json:"port,omitempty"`
}

type ConfigSystemFlowAccountingNetflowEnableEgress struct {
	EngineId int `json:"engine-id,omitempty"`
}

type ConfigSystemFlowAccountingSflow struct {
	SamplingRate int                                    `json:"sampling-rate,omitempty"`
	AgentAddress string                                 `json:"agent-address,omitempty"`
	Agentid      int                                    `json:".agentid,omitempty"`
	Server       *ConfigSystemFlowAccountingSflowServer `json:"server,omitempty"`
}

type ConfigSystemFlowAccountingSflowServer map[string]struct {
	Port int `json:"port,omitempty"`
}

type ConfigSystemFlowAccountingAggregate struct {
	Egress  string `json:"egress,omitempty"`
	Ingress string `json:"ingress,omitempty"`
}

type ConfigSystemFlowAccountingUnms struct {
	Exclude string `json:"exclude,omitempty"`
	Subnets string `json:"subnets,omitempty"`
}

type ConfigSystemTaskScheduler struct {
	Task *ConfigSystemTaskSchedulerTask `json:"task,omitempty"`
}

type ConfigSystemTaskSchedulerTask map[string]struct {
	Executable  *ConfigSystemTaskSchedulerTaskExecutable `json:"executable,omitempty"`
	CrontabSpec string                                   `json:"crontab-spec,omitempty"`
	Interval    string                                   `json:"interval,omitempty"`
}

type ConfigSystemTaskSchedulerTaskExecutable struct {
	Path      string `json:"path,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

type ConfigSystemAnalyticsHandler struct {
	SendAnalyticsReport bool `json:"send-analytics-report,omitempty"`
}

type ConfigSystemSystemd struct {
	Journal *ConfigSystemSystemdJournal `json:"journal,omitempty"`
}

type ConfigSystemSystemdJournal struct {
	RateLimitBurst    int    `json:"rate-limit-burst,omitempty"`
	MaxRetention      int    `json:"max-retention,omitempty"`
	RuntimeMaxUse     int    `json:"runtime-max-use,omitempty"`
	Storage           string `json:"storage,omitempty"`
	RateLimitInterval int    `json:"rate-limit-interval,omitempty"`
}

type ConfigSystemConntrack struct {
	Ignore          *ConfigSystemConntrackIgnore  `json:"ignore,omitempty"`
	Timeout         *ConfigSystemConntrackTimeout `json:"timeout,omitempty"`
	Tcp             *ConfigSystemConntrackTcp     `json:"tcp,omitempty"`
	Log             *ConfigSystemConntrackLog     `json:"log,omitempty"`
	Modules         *ConfigSystemConntrackModules `json:"modules,omitempty"`
	HashSize        int                           `json:"hash-size,omitempty"`
	TableSize       int                           `json:"table-size,omitempty"`
	ExpectTableSize int                           `json:"expect-table-size,omitempty"`
}

type ConfigSystemConntrackIgnore struct {
	Rule *ConfigSystemConntrackIgnoreRule `json:"rule,omitempty"`
}

type ConfigSystemConntrackIgnoreRule map[string]struct {
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
	Other  int                                 `json:"other,omitempty"`
	Tcp    *ConfigSystemConntrackTimeoutTcp    `json:"tcp,omitempty"`
	Icmp   int                                 `json:"icmp,omitempty"`
	Custom *ConfigSystemConntrackTimeoutCustom `json:".custom,omitempty"`
}

type ConfigSystemConntrackTimeoutUdp struct {
	Stream int `json:"stream,omitempty"`
	Other  int `json:"other,omitempty"`
}

type ConfigSystemConntrackTimeoutTcp struct {
	FinWait     int `json:"fin-wait,omitempty"`
	TimeWait    int `json:"time-wait,omitempty"`
	Close       int `json:"close,omitempty"`
	SynSent     int `json:"syn-sent,omitempty"`
	Established int `json:"established,omitempty"`
	SynRecv     int `json:"syn-recv,omitempty"`
	LastAck     int `json:"last-ack,omitempty"`
	CloseWait   int `json:"close-wait,omitempty"`
}

type ConfigSystemConntrackTimeoutCustom struct {
	Rule *ConfigSystemConntrackTimeoutCustomRule `json:"rule,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRule map[string]struct {
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
	Other int                                                `json:"other,omitempty"`
	Tcp   *ConfigSystemConntrackTimeoutCustomRuleProtocolTcp `json:"tcp,omitempty"`
	Icmp  int                                                `json:"icmp,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleProtocolUdp struct {
	Stream int `json:"stream,omitempty"`
	Other  int `json:"other,omitempty"`
}

type ConfigSystemConntrackTimeoutCustomRuleProtocolTcp struct {
	FinWait     int `json:"fin-wait,omitempty"`
	TimeWait    int `json:"time-wait,omitempty"`
	Close       int `json:"close,omitempty"`
	SynSent     int `json:"syn-sent,omitempty"`
	Established int `json:"established,omitempty"`
	SynRecv     int `json:"syn-recv,omitempty"`
	LastAck     int `json:"last-ack,omitempty"`
	CloseWait   int `json:"close-wait,omitempty"`
}

type ConfigSystemConntrackTcp struct {
	Loose               string `json:"loose,omitempty"`
	HalfOpenConnections int    `json:"half-open-connections,omitempty"`
	MaxRetrans          int    `json:"max-retrans,omitempty"`
}

type ConfigSystemConntrackLog struct {
	Udp   *ConfigSystemConntrackLogUdp   `json:"udp,omitempty"`
	Other *ConfigSystemConntrackLogOther `json:"other,omitempty"`
	Tcp   *ConfigSystemConntrackLogTcp   `json:"tcp,omitempty"`
	Icmp  *ConfigSystemConntrackLogIcmp  `json:"icmp,omitempty"`
}

type ConfigSystemConntrackLogUdp struct {
	Destroy json.RawMessage `json:"destroy,omitempty"`
	Update  json.RawMessage `json:"update,omitempty"`
	New     json.RawMessage `json:"new,omitempty"`
}

type ConfigSystemConntrackLogOther struct {
	Destroy json.RawMessage `json:"destroy,omitempty"`
	Update  json.RawMessage `json:"update,omitempty"`
	New     json.RawMessage `json:"new,omitempty"`
}

type ConfigSystemConntrackLogTcp struct {
	Destroy json.RawMessage                    `json:"destroy,omitempty"`
	Update  *ConfigSystemConntrackLogTcpUpdate `json:"update,omitempty"`
	New     json.RawMessage                    `json:"new,omitempty"`
}

type ConfigSystemConntrackLogTcpUpdate struct {
	FinWait     json.RawMessage `json:"fin-wait,omitempty"`
	TimeWait    json.RawMessage `json:"time-wait,omitempty"`
	Established json.RawMessage `json:"established,omitempty"`
	SynReceived json.RawMessage `json:"syn-received,omitempty"`
	LastAck     json.RawMessage `json:"last-ack,omitempty"`
	CloseWait   json.RawMessage `json:"close-wait,omitempty"`
}

type ConfigSystemConntrackLogIcmp struct {
	Destroy json.RawMessage `json:"destroy,omitempty"`
	Update  json.RawMessage `json:"update,omitempty"`
	New     json.RawMessage `json:"new,omitempty"`
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
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesNfs struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesRtsp struct {
	Enable json.RawMessage `json:"enable,omitempty"`
}

type ConfigSystemConntrackModulesGre struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesTftp struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesPptp struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesSqlnet struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemConntrackModulesSip struct {
	Disable                  json.RawMessage `json:"disable,omitempty"`
	EnableIndirectSignalling json.RawMessage `json:"enable-indirect-signalling,omitempty"`
	EnableIndirectMedia      json.RawMessage `json:"enable-indirect-media,omitempty"`
	Port                     int             `json:"port,omitempty"`
}

type ConfigSystemConntrackModulesH323 struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigSystemStaticHostMapping struct {
	HostName *ConfigSystemStaticHostMappingHostName `json:"host-name,omitempty"`
}

type ConfigSystemStaticHostMappingHostName map[string]struct {
	Alias string `json:"alias,omitempty"`
	Inet  IP     `json:"inet,omitempty"`
}

type ConfigSystemNtp struct {
	Server *ConfigSystemNtpServer `json:"server,omitempty"`
}

type ConfigSystemNtpServer map[string]struct {
	Prefer   json.RawMessage `json:"prefer,omitempty"`
	Preempt  json.RawMessage `json:"preempt,omitempty"`
	Noselect json.RawMessage `json:"noselect,omitempty"`
}

type ConfigSystemCoredump struct {
	Enabled bool `json:"enabled,omitempty"`
}

type ConfigSystemDomainSearch struct {
	Domain string `json:"domain,omitempty"`
}

type ConfigSystemConfigManagement struct {
	CommitRevisions int                                        `json:"commit-revisions,omitempty"`
	CommitArchive   *ConfigSystemConfigManagementCommitArchive `json:"commit-archive,omitempty"`
}

type ConfigSystemConfigManagementCommitArchive struct {
	Location string `json:"location,omitempty"`
}

type ConfigSystemTrafficAnalysis struct {
	SignatureUpdate *ConfigSystemTrafficAnalysisSignatureUpdate `json:"signature-update,omitempty"`
	Dpi             string                                      `json:"dpi,omitempty"`
	CustomCategory  *ConfigSystemTrafficAnalysisCustomCategory  `json:"custom-category,omitempty"`
	Export          string                                      `json:"export,omitempty"`
}

type ConfigSystemTrafficAnalysisSignatureUpdate struct {
	Disable    json.RawMessage `json:"disable,omitempty"`
	UpdateHour int             `json:"update-hour,omitempty"`
}

type ConfigSystemTrafficAnalysisCustomCategory map[string]struct {
	Name string `json:"name,omitempty"`
}

type ConfigSystemCrashHandler struct {
	SaveCoreFile    bool `json:"save-core-file,omitempty"`
	SendCrashReport bool `json:"send-crash-report,omitempty"`
}

type ConfigSystemIp struct {
	DisableForwarding  json.RawMessage    `json:"disable-forwarding,omitempty"`
	OverrideHostnameIp IPv4               `json:"override-hostname-ip,omitempty"`
	Arp                *ConfigSystemIpArp `json:"arp,omitempty"`
}

type ConfigSystemIpArp struct {
	StaleTime         int `json:"stale-time,omitempty"`
	BaseReachableTime int `json:"base-reachable-time,omitempty"`
	TableSize         int `json:"table-size,omitempty"`
}

type ConfigSystemIpv6 struct {
	Disable           json.RawMessage           `json:"disable,omitempty"`
	Neighbor          *ConfigSystemIpv6Neighbor `json:"neighbor,omitempty"`
	DisableForwarding json.RawMessage           `json:"disable-forwarding,omitempty"`
	Blacklist         json.RawMessage           `json:"blacklist,omitempty"`
	StrictDad         json.RawMessage           `json:"strict-dad,omitempty"`
}

type ConfigSystemIpv6Neighbor struct {
	StaleTime         int `json:"stale-time,omitempty"`
	BaseReachableTime int `json:"base-reachable-time,omitempty"`
	TableSize         int `json:"table-size,omitempty"`
}

type ConfigSystemLogin struct {
	RadiusServer *ConfigSystemLoginRadiusServer `json:"radius-server,omitempty"`
	User         *ConfigSystemLoginUser         `json:"user,omitempty"`
	Banner       *ConfigSystemLoginBanner       `json:"banner,omitempty"`
}

type ConfigSystemLoginRadiusServer map[string]struct {
	Timeout int    `json:"timeout,omitempty"`
	Secret  string `json:"secret,omitempty"`
	Port    int    `json:"port,omitempty"`
}

type ConfigSystemLoginUser map[string]struct {
	Group          string                               `json:"group,omitempty"`
	HomeDirectory  string                               `json:"home-directory,omitempty"`
	Level          string                               `json:"level,omitempty"`
	FullName       string                               `json:"full-name,omitempty"`
	Authentication *ConfigSystemLoginUserAuthentication `json:"authentication,omitempty"`
}

type ConfigSystemLoginUserAuthentication struct {
	EncryptedPassword string                                         `json:"encrypted-password,omitempty"`
	PublicKeys        *ConfigSystemLoginUserAuthenticationPublicKeys `json:"public-keys,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigSystemLoginUserAuthenticationPublicKeys map[string]struct {
	Options string `json:"options,omitempty"`
	Key     string `json:"key,omitempty"`
	Type    string `json:"type,omitempty"`
}

type ConfigSystemLoginBanner struct {
	PostLogin string `json:"post-login,omitempty"`
	PreLogin  string `json:"pre-login,omitempty"`
}

type ConfigSystemPackage struct {
	Repository *ConfigSystemPackageRepository `json:"repository,omitempty"`
	AutoSync   int                            `json:".auto-sync,omitempty"`
}

type ConfigSystemPackageRepository map[string]struct {
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
	FlowLifetime int                      `json:"flow-lifetime,omitempty"`
	Ipv6         *ConfigSystemOffloadIpv6 `json:"ipv6,omitempty"`
}

type ConfigSystemOffloadIpv4 struct {
	DisableFlowFlushingUponFibChanges json.RawMessage `json:"disable-flow-flushing-upon-fib-changes,omitempty"`
	Bonding                           string          `json:"bonding,omitempty"`
	Pppoe                             string          `json:"pppoe,omitempty"`
	Forwarding                        string          `json:"forwarding,omitempty"`
	Gre                               string          `json:"gre,omitempty"`
	Vlan                              string          `json:"vlan,omitempty"`
	TableSize                         int             `json:"table-size,omitempty"`
}

type ConfigSystemOffloadIpv6 struct {
	DisableFlowFlushingUponFibChanges json.RawMessage `json:"disable-flow-flushing-upon-fib-changes,omitempty"`
	Bonding                           string          `json:"bonding,omitempty"`
	Pppoe                             string          `json:"pppoe,omitempty"`
	Forwarding                        string          `json:"forwarding,omitempty"`
	Vlan                              string          `json:"vlan,omitempty"`
	TableSize                         int             `json:"table-size,omitempty"`
}

type ConfigTrafficControl *struct {
	OptimizedQueue *ConfigTrafficControlOptimizedQueue `json:"optimized-queue,omitempty"`
	SmartQueue     *ConfigTrafficControlSmartQueue     `json:"smart-queue,omitempty"`
	AdvancedQueue  *ConfigTrafficControlAdvancedQueue  `json:"advanced-queue,omitempty"`
}

type ConfigTrafficControlOptimizedQueue struct {
	Policy string `json:"policy,omitempty"`
}

type ConfigTrafficControlSmartQueue map[string]struct {
	WanInterface string                                  `json:"wan-interface,omitempty"`
	Download     *ConfigTrafficControlSmartQueueDownload `json:"download,omitempty"`
	Upload       *ConfigTrafficControlSmartQueueUpload   `json:"upload,omitempty"`
}

type ConfigTrafficControlSmartQueueDownload struct {
	Rate       string `json:"rate,omitempty"`
	HtbQuantum int    `json:"htb-quantum,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Target     string `json:"target,omitempty"`
	Interval   string `json:"interval,omitempty"`
	Burst      string `json:"burst,omitempty"`
	Ecn        string `json:"ecn,omitempty"`
	FqQuantum  int    `json:"fq-quantum,omitempty"`
	Flows      int    `json:"flows,omitempty"`
}

type ConfigTrafficControlSmartQueueUpload struct {
	Rate       string `json:"rate,omitempty"`
	HtbQuantum int    `json:"htb-quantum,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Target     string `json:"target,omitempty"`
	Interval   string `json:"interval,omitempty"`
	Burst      string `json:"burst,omitempty"`
	Ecn        string `json:"ecn,omitempty"`
	FqQuantum  int    `json:"fq-quantum,omitempty"`
	Flows      int    `json:"flows,omitempty"`
}

type ConfigTrafficControlAdvancedQueue struct {
	Filters   *ConfigTrafficControlAdvancedQueueFilters   `json:"filters,omitempty"`
	Leaf      *ConfigTrafficControlAdvancedQueueLeaf      `json:"leaf,omitempty"`
	Branch    *ConfigTrafficControlAdvancedQueueBranch    `json:"branch,omitempty"`
	QueueType *ConfigTrafficControlAdvancedQueueQueueType `json:"queue-type,omitempty"`
	Root      *ConfigTrafficControlAdvancedQueueRoot      `json:"root,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFilters struct {
	Match *ConfigTrafficControlAdvancedQueueFiltersMatch `json:"match,omitempty"`
}

type ConfigTrafficControlAdvancedQueueFiltersMatch map[string]struct {
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
	Protocol    int                                                         `json:"protocol,omitempty"`
	Dscp        int                                                         `json:"dscp,omitempty"`
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
	Queue *ConfigTrafficControlAdvancedQueueLeafQueue `json:"queue,omitempty"`
}

type ConfigTrafficControlAdvancedQueueLeafQueue map[string]struct {
	Bandwidth   string                                           `json:"bandwidth,omitempty"`
	Burst       *ConfigTrafficControlAdvancedQueueLeafQueueBurst `json:"burst,omitempty"`
	Ceiling     string                                           `json:"ceiling,omitempty"`
	QueueType   string                                           `json:"queue-type,omitempty"`
	Description string                                           `json:"description,omitempty"`
	Parent      string                                           `json:"parent,omitempty"`
	Priority    int                                              `json:"priority,omitempty"`
}

type ConfigTrafficControlAdvancedQueueLeafQueueBurst struct {
	BurstRate string `json:"burst-rate,omitempty"`
	BurstSize string `json:"burst-size,omitempty"`
}

type ConfigTrafficControlAdvancedQueueBranch struct {
	Queue *ConfigTrafficControlAdvancedQueueBranchQueue `json:"queue,omitempty"`
}

type ConfigTrafficControlAdvancedQueueBranchQueue map[string]struct {
	Bandwidth   string `json:"bandwidth,omitempty"`
	Description string `json:"description,omitempty"`
	Parent      string `json:"parent,omitempty"`
	Priority    int    `json:"priority,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueType struct {
	Pfifo   *ConfigTrafficControlAdvancedQueueQueueTypePfifo   `json:"pfifo,omitempty"`
	Hfq     *ConfigTrafficControlAdvancedQueueQueueTypeHfq     `json:"hfq,omitempty"`
	FqCodel *ConfigTrafficControlAdvancedQueueQueueTypeFqCodel `json:"fq-codel,omitempty"`
	Sfq     *ConfigTrafficControlAdvancedQueueQueueTypeSfq     `json:"sfq,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypePfifo map[string]struct {
	Limit int `json:"limit,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypeHfq map[string]struct {
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

type ConfigTrafficControlAdvancedQueueQueueTypeFqCodel map[string]struct {
	Limit    int    `json:"limit,omitempty"`
	Target   string `json:"target,omitempty"`
	Interval string `json:"interval,omitempty"`
	Ecn      string `json:"ecn,omitempty"`
	Flows    int    `json:"flows,omitempty"`
	Quantum  int    `json:"quantum,omitempty"`
}

type ConfigTrafficControlAdvancedQueueQueueTypeSfq map[string]struct {
	HashInterval int    `json:"hash-interval,omitempty"`
	Description  string `json:"description,omitempty"`
	QueueLimit   int    `json:"queue-limit,omitempty"`
}

type ConfigTrafficControlAdvancedQueueRoot struct {
	Queue *ConfigTrafficControlAdvancedQueueRootQueue `json:"queue,omitempty"`
}

type ConfigTrafficControlAdvancedQueueRootQueue map[string]struct {
	Bandwidth   string `json:"bandwidth,omitempty"`
	Default     int    `json:"default,omitempty"`
	Description string `json:"description,omitempty"`
	AttachTo    string `json:"attach-to,omitempty"`
}

type ConfigService *struct {
	UbntDiscover       *ConfigServiceUbntDiscover       `json:"ubnt-discover,omitempty"`
	UdapiServer        json.RawMessage                  `json:"udapi-server,omitempty"`
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
	Disable   json.RawMessage                     `json:"disable,omitempty"`
	Interface *ConfigServiceUbntDiscoverInterface `json:"interface,omitempty"`
}

type ConfigServiceUbntDiscoverInterface map[string]struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigServiceSnmp struct {
	Contact         string                          `json:"contact,omitempty"`
	Location        string                          `json:"location,omitempty"`
	ListenAddress   *ConfigServiceSnmpListenAddress `json:"listen-address,omitempty"`
	Description     string                          `json:"description,omitempty"`
	V3              *ConfigServiceSnmpV3            `json:"v3,omitempty"`
	TrapSource      IP                              `json:"trap-source,omitempty"`
	TrapTarget      *ConfigServiceSnmpTrapTarget    `json:"trap-target,omitempty"`
	Community       *ConfigServiceSnmpCommunity     `json:"community,omitempty"`
	IgnoreInterface string                          `json:"ignore-interface,omitempty"`
}

type ConfigServiceSnmpListenAddress map[string]struct {
	Interface string `json:"interface,omitempty"`
	Port      int    `json:"port,omitempty"`
}

type ConfigServiceSnmpV3 struct {
	Group      *ConfigServiceSnmpV3Group      `json:"group,omitempty"`
	Tsm        *ConfigServiceSnmpV3Tsm        `json:"tsm,omitempty"`
	User       *ConfigServiceSnmpV3User       `json:"user,omitempty"`
	View       *ConfigServiceSnmpV3View       `json:"view,omitempty"`
	TrapTarget *ConfigServiceSnmpV3TrapTarget `json:"trap-target,omitempty"`
	Engineid   string                         `json:"engineid,omitempty"`
}

type ConfigServiceSnmpV3Group map[string]struct {
	Mode     string `json:"mode,omitempty"`
	View     string `json:"view,omitempty"`
	Seclevel string `json:"seclevel,omitempty"`
}

type ConfigServiceSnmpV3Tsm struct {
	LocalKey string `json:"local-key,omitempty"`
	Port     int    `json:"port,omitempty"`
}

type ConfigServiceSnmpV3User map[string]struct {
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

type ConfigServiceSnmpV3View map[string]struct {
	Oid *ConfigServiceSnmpV3ViewOid `json:"oid,omitempty"`
}

type ConfigServiceSnmpV3ViewOid map[string]struct {
	Exclude json.RawMessage `json:"exclude,omitempty"`
	Mask    string          `json:"mask,omitempty"`
}

type ConfigServiceSnmpV3TrapTarget map[string]struct {
	Privacy  *ConfigServiceSnmpV3TrapTargetPrivacy `json:"privacy,omitempty"`
	Auth     *ConfigServiceSnmpV3TrapTargetAuth    `json:"auth,omitempty"`
	User     string                                `json:"user,omitempty"`
	Protocol string                                `json:"protocol,omitempty"`
	Type     string                                `json:"type,omitempty"`
	Port     int                                   `json:"port,omitempty"`
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

type ConfigServiceSnmpTrapTarget map[string]struct {
	Port      int    `json:"port,omitempty"`
	Community string `json:"community,omitempty"`
}

type ConfigServiceSnmpCommunity map[string]struct {
	Network       IPNet  `json:"network,omitempty"`
	Authorization string `json:"authorization,omitempty"`
	Client        IP     `json:"client,omitempty"`
}

type ConfigServiceDhcpv6Server struct {
	Preference        int                                         `json:"preference,omitempty"`
	SharedNetworkName *ConfigServiceDhcpv6ServerSharedNetworkName `json:"shared-network-name,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkName map[string]struct {
	NameServer IPv6                                              `json:"name-server,omitempty"`
	Subnet     *ConfigServiceDhcpv6ServerSharedNetworkNameSubnet `json:"subnet,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnet map[string]struct {
	NisServer        IPv6                                                              `json:"nis-server,omitempty"`
	StaticMapping    *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping    `json:"static-mapping,omitempty"`
	SntpServer       IPv6                                                              `json:"sntp-server,omitempty"`
	PrefixDelegation *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegation `json:"prefix-delegation,omitempty"`
	NisplusDomain    string                                                            `json:"nisplus-domain,omitempty"`
	SipServerAddress IPv6                                                              `json:"sip-server-address,omitempty"`
	SipServerName    string                                                            `json:"sip-server-name,omitempty"`
	NameServer       IPv6                                                              `json:"name-server,omitempty"`
	NisDomain        string                                                            `json:"nis-domain,omitempty"`
	DomainSearch     string                                                            `json:"domain-search,omitempty"`
	LeaseTime        *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetLeaseTime        `json:"lease-time,omitempty"`
	NisplusServer    IPv6                                                              `json:"nisplus-server,omitempty"`
	AddressRange     *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRange     `json:"address-range,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetStaticMapping map[string]struct {
	Ipv6Address IPv6   `json:"ipv6-address,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegation struct {
	Start *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart `json:"start,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStart map[string]struct {
	Stop *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop `json:"stop,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetPrefixDelegationStartStop map[string]struct {
	PrefixLength string `json:"prefix-length,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetLeaseTime struct {
	Maximum int `json:"maximum,omitempty"`
	Default int `json:"default,omitempty"`
	Minimum int `json:"minimum,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRange struct {
	Prefix *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix `json:"prefix,omitempty"`
	Start  *ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart  `json:"start,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangePrefix map[string]struct {
	Temporary json.RawMessage `json:"temporary,omitempty"`
}

type ConfigServiceDhcpv6ServerSharedNetworkNameSubnetAddressRangeStart map[string]struct {
	Stop IPv6 `json:"stop,omitempty"`
}

type ConfigServiceUpnp struct {
	ListenOn *ConfigServiceUpnpListenOn `json:"listen-on,omitempty"`
}

type ConfigServiceUpnpListenOn map[string]struct {
	OutboundInterface string `json:"outbound-interface,omitempty"`
}

type ConfigServiceLldp struct {
	LegacyProtocols   *ConfigServiceLldpLegacyProtocols `json:"legacy-protocols,omitempty"`
	Interface         *ConfigServiceLldpInterface       `json:"interface,omitempty"`
	ManagementAddress IPv4                              `json:"management-address,omitempty"`
	ListenVlan        json.RawMessage                   `json:".listen-vlan,omitempty"`
}

type ConfigServiceLldpLegacyProtocols struct {
	Cdp   json.RawMessage `json:"cdp,omitempty"`
	Sonmp json.RawMessage `json:"sonmp,omitempty"`
	Edp   json.RawMessage `json:"edp,omitempty"`
	Fdp   json.RawMessage `json:"fdp,omitempty"`
}

type ConfigServiceLldpInterface map[string]struct {
	Disable  json.RawMessage                     `json:"disable,omitempty"`
	Location *ConfigServiceLldpInterfaceLocation `json:"location,omitempty"`
}

type ConfigServiceLldpInterfaceLocation struct {
	CivicBased      *ConfigServiceLldpInterfaceLocationCivicBased      `json:"civic-based,omitempty"`
	Elin            string                                             `json:"elin,omitempty"`
	CoordinateBased *ConfigServiceLldpInterfaceLocationCoordinateBased `json:"coordinate-based,omitempty"`
}

type ConfigServiceLldpInterfaceLocationCivicBased struct {
	CountryCode string                                              `json:"country-code,omitempty"`
	CaType      *ConfigServiceLldpInterfaceLocationCivicBasedCaType `json:"ca-type,omitempty"`
}

type ConfigServiceLldpInterfaceLocationCivicBasedCaType map[string]struct {
	CaValue string `json:"ca-value,omitempty"`
}

type ConfigServiceLldpInterfaceLocationCoordinateBased struct {
	Datum     string `json:"datum,omitempty"`
	Longitude string `json:"longitude,omitempty"`
	Altitude  string `json:"altitude,omitempty"`
	Latitude  string `json:"latitude,omitempty"`
}

type ConfigServiceNat struct {
	Rule *ConfigServiceNatRule `json:"rule,omitempty"`
}

type ConfigServiceNatRule map[string]struct {
	OutsideAddress    *ConfigServiceNatRuleOutsideAddress `json:"outside-address,omitempty"`
	Disable           json.RawMessage                     `json:"disable,omitempty"`
	InboundInterface  string                              `json:"inbound-interface,omitempty"`
	Exclude           json.RawMessage                     `json:"exclude,omitempty"`
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
	DomainBlock       string                              `json:"domain-block,omitempty"`
	MinimumObjectSize int                                 `json:"minimum-object-size,omitempty"`
	ProxyBypass       string                              `json:"proxy-bypass,omitempty"`
	ProxyBypassSource string                              `json:"proxy-bypass-source,omitempty"`
	ListenAddress     *ConfigServiceWebproxyListenAddress `json:"listen-address,omitempty"`
	DomainNoncache    string                              `json:"domain-noncache,omitempty"`
	MemCacheSize      int                                 `json:"mem-cache-size,omitempty"`
	MaximumObjectSize int                                 `json:"maximum-object-size,omitempty"`
	DefaultPort       int                                 `json:"default-port,omitempty"`
	AppendDomain      string                              `json:"append-domain,omitempty"`
	UrlFiltering      *ConfigServiceWebproxyUrlFiltering  `json:"url-filtering,omitempty"`
	EnableAccessLog   json.RawMessage                     `json:"enable-access-log,omitempty"`
	Administrator     string                              `json:"administrator,omitempty"`
	CacheSize         int                                 `json:"cache-size,omitempty"`
	ReplyBlockMime    string                              `json:"reply-block-mime,omitempty"`
	ReplyBodyMaxSize  int                                 `json:"reply-body-max-size,omitempty"`
}

type ConfigServiceWebproxyListenAddress map[string]struct {
	DisableTransparent json.RawMessage `json:"disable-transparent,omitempty"`
	Port               int             `json:"port,omitempty"`
}

type ConfigServiceWebproxyUrlFiltering struct {
	Disable    json.RawMessage                              `json:"disable,omitempty"`
	Squidguard *ConfigServiceWebproxyUrlFilteringSquidguard `json:"squidguard,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguard struct {
	AutoUpdate        *ConfigServiceWebproxyUrlFilteringSquidguardAutoUpdate  `json:"auto-update,omitempty"`
	DefaultAction     string                                                  `json:"default-action,omitempty"`
	EnableSafeSearch  json.RawMessage                                         `json:"enable-safe-search,omitempty"`
	SourceGroup       *ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup `json:"source-group,omitempty"`
	RedirectUrl       string                                                  `json:"redirect-url,omitempty"`
	LocalBlock        string                                                  `json:"local-block,omitempty"`
	BlockCategory     string                                                  `json:"block-category,omitempty"`
	LocalOk           string                                                  `json:"local-ok,omitempty"`
	TimePeriod        *ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod  `json:"time-period,omitempty"`
	LocalOkUrl        string                                                  `json:"local-ok-url,omitempty"`
	AllowIpaddrUrl    json.RawMessage                                         `json:"allow-ipaddr-url,omitempty"`
	Rule              *ConfigServiceWebproxyUrlFilteringSquidguardRule        `json:"rule,omitempty"`
	LocalBlockKeyword string                                                  `json:"local-block-keyword,omitempty"`
	AllowCategory     string                                                  `json:"allow-category,omitempty"`
	Log               string                                                  `json:"log,omitempty"`
	LocalBlockUrl     string                                                  `json:"local-block-url,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardAutoUpdate struct {
	UpdateHour int `json:"update-hour,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardSourceGroup map[string]struct {
	Description string `json:"description,omitempty"`
	Address     string `json:"address,omitempty"`
	Domain      string `json:"domain,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardTimePeriod map[string]struct {
	Description string                                                     `json:"description,omitempty"`
	Days        *ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays `json:"days,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardTimePeriodDays map[string]struct {
	Time string `json:"time,omitempty"`
}

type ConfigServiceWebproxyUrlFilteringSquidguardRule map[string]struct {
	DefaultAction     string          `json:"default-action,omitempty"`
	EnableSafeSearch  json.RawMessage `json:"enable-safe-search,omitempty"`
	SourceGroup       string          `json:"source-group,omitempty"`
	RedirectUrl       string          `json:"redirect-url,omitempty"`
	LocalBlock        string          `json:"local-block,omitempty"`
	BlockCategory     string          `json:"block-category,omitempty"`
	LocalOk           string          `json:"local-ok,omitempty"`
	TimePeriod        string          `json:"time-period,omitempty"`
	LocalOkUrl        string          `json:"local-ok-url,omitempty"`
	AllowIpaddrUrl    json.RawMessage `json:"allow-ipaddr-url,omitempty"`
	Description       string          `json:"description,omitempty"`
	LocalBlockKeyword string          `json:"local-block-keyword,omitempty"`
	AllowCategory     string          `json:"allow-category,omitempty"`
	Log               string          `json:"log,omitempty"`
	LocalBlockUrl     string          `json:"local-block-url,omitempty"`
}

type ConfigServiceSuspend struct {
	ForwardTo   *ConfigServiceSuspendForwardTo `json:"forward-to,omitempty"`
	AllowDomain string                         `json:"allow-domain,omitempty"`
	UserIp      IPv4                           `json:"user-ip,omitempty"`
	Redirect    *ConfigServiceSuspendRedirect  `json:"redirect,omitempty"`
	AllowIp     IPv4                           `json:"allow-ip,omitempty"`
}

type ConfigServiceSuspendForwardTo struct {
	HttpPort  int  `json:"http-port,omitempty"`
	Address   IPv4 `json:"address,omitempty"`
	HttpsPort int  `json:"https-port,omitempty"`
}

type ConfigServiceSuspendRedirect struct {
	HttpPort  int    `json:"http-port,omitempty"`
	Url       string `json:"url,omitempty"`
	HttpsPort int    `json:"https-port,omitempty"`
}

type ConfigServiceUnms struct {
	Disable    json.RawMessage           `json:"disable,omitempty"`
	Connection string                    `json:"connection,omitempty"`
	Lldp       *ConfigServiceUnmsLldp    `json:"lldp,omitempty"`
	RestApi    *ConfigServiceUnmsRestApi `json:"rest-api,omitempty"`
}

type ConfigServiceUnmsLldp struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigServiceUnmsRestApi struct {
	Interface string `json:"interface,omitempty"`
	Port      int    `json:"port,omitempty"`
}

type ConfigServiceMdns struct {
	Reflector json.RawMessage            `json:"reflector,omitempty"`
	Repeater  *ConfigServiceMdnsRepeater `json:"repeater,omitempty"`
}

type ConfigServiceMdnsRepeater struct {
	Interface string `json:"interface,omitempty"`
}

type ConfigServiceUbntDiscoverServer struct {
	Disable  json.RawMessage `json:"disable,omitempty"`
	Protocol string          `json:"protocol,omitempty"`
}

type ConfigServiceDhcpServer struct {
	UseDnsmasq        string                                    `json:"use-dnsmasq,omitempty"`
	StaticArp         string                                    `json:"static-arp,omitempty"`
	HostfileUpdate    string                                    `json:"hostfile-update,omitempty"`
	SharedNetworkName *ConfigServiceDhcpServerSharedNetworkName `json:"shared-network-name,omitempty"`
	Disabled          bool                                      `json:"disabled,omitempty"`
	DynamicDnsUpdate  *ConfigServiceDhcpServerDynamicDnsUpdate  `json:"dynamic-dns-update,omitempty"`
	GlobalParameters  string                                    `json:"global-parameters,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkName map[string]struct {
	Disable                 json.RawMessage                                 `json:"disable,omitempty"`
	SharedNetworkParameters string                                          `json:"shared-network-parameters,omitempty"`
	Authoritative           string                                          `json:"authoritative,omitempty"`
	Description             string                                          `json:"description,omitempty"`
	Subnet                  *ConfigServiceDhcpServerSharedNetworkNameSubnet `json:"subnet,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnet map[string]struct {
	StaticMapping      *ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping `json:"static-mapping,omitempty"`
	BootfileName       string                                                       `json:"bootfile-name,omitempty"`
	BootfileServer     string                                                       `json:"bootfile-server,omitempty"`
	PopServer          IPv4                                                         `json:"pop-server,omitempty"`
	Exclude            IPv4                                                         `json:"exclude,omitempty"`
	DomainName         string                                                       `json:"domain-name,omitempty"`
	StaticRoute        *ConfigServiceDhcpServerSharedNetworkNameSubnetStaticRoute   `json:"static-route,omitempty"`
	SubnetParameters   string                                                       `json:"subnet-parameters,omitempty"`
	Start              *ConfigServiceDhcpServerSharedNetworkNameSubnetStart         `json:"start,omitempty"`
	TimeServer         IPv4                                                         `json:"time-server,omitempty"`
	WpadUrl            string                                                       `json:"wpad-url,omitempty"`
	UnifiController    IPv4                                                         `json:"unifi-controller,omitempty"`
	Lease              int                                                          `json:"lease,omitempty"`
	DefaultRouter      IPv4                                                         `json:"default-router,omitempty"`
	TftpServerName     string                                                       `json:"tftp-server-name,omitempty"`
	IpForwarding       *ConfigServiceDhcpServerSharedNetworkNameSubnetIpForwarding  `json:"ip-forwarding,omitempty"`
	DnsServer          IPv4                                                         `json:"dns-server,omitempty"`
	NtpServer          IPv4                                                         `json:"ntp-server,omitempty"`
	TimeOffset         string                                                       `json:"time-offset,omitempty"`
	SmtpServer         IPv4                                                         `json:"smtp-server,omitempty"`
	WinsServer         IPv4                                                         `json:"wins-server,omitempty"`
	ClientPrefixLength int                                                          `json:"client-prefix-length,omitempty"`
	Failover           *ConfigServiceDhcpServerSharedNetworkNameSubnetFailover      `json:"failover,omitempty"`
	ServerIdentifier   IPv4                                                         `json:"server-identifier,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetStaticMapping map[string]struct {
	Disable                 json.RawMessage `json:"disable,omitempty"`
	IpAddress               IPv4            `json:"ip-address,omitempty"`
	StaticMappingParameters string          `json:"static-mapping-parameters,omitempty"`
	MacAddress              MacAddr         `json:"mac-address,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetStaticRoute struct {
	DestinationSubnet IPv4Net `json:"destination-subnet,omitempty"`
	Router            IPv4    `json:"router,omitempty"`
}

type ConfigServiceDhcpServerSharedNetworkNameSubnetStart map[string]struct {
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
	DisablePasswordAuthentication json.RawMessage `json:"disable-password-authentication,omitempty"`
	ListenAddress                 IP              `json:"listen-address,omitempty"`
	AllowRoot                     json.RawMessage `json:"allow-root,omitempty"`
	ProtocolVersion               string          `json:"protocol-version,omitempty"`
	DisableHostValidation         json.RawMessage `json:"disable-host-validation,omitempty"`
	Port                          int             `json:"port,omitempty"`
}

type ConfigServiceGui struct {
	CaFile        string          `json:"ca-file,omitempty"`
	HttpPort      int             `json:"http-port,omitempty"`
	ListenAddress IP              `json:"listen-address,omitempty"`
	HttpsPort     int             `json:"https-port,omitempty"`
	DhFile        string          `json:"dh-file,omitempty"`
	CertFile      string          `json:"cert-file,omitempty"`
	OlderCiphers  string          `json:"older-ciphers,omitempty"`
	Debug         json.RawMessage `json:"debug,omitempty"`
}

type ConfigServicePppoeServer struct {
	Encryption         string                                  `json:"encryption,omitempty"`
	ServiceName        string                                  `json:"service-name,omitempty"`
	WinsServers        *ConfigServicePppoeServerWinsServers    `json:"wins-servers,omitempty"`
	Interface          string                                  `json:"interface,omitempty"`
	DnsServers         *ConfigServicePppoeServerDnsServers     `json:"dns-servers,omitempty"`
	Mtu                int                                     `json:"mtu,omitempty"`
	ClientIpPool       *ConfigServicePppoeServerClientIpPool   `json:"client-ip-pool,omitempty"`
	Radius             *ConfigServicePppoeServerRadius         `json:"radius,omitempty"`
	LocalIp            IPv4                                    `json:"local-ip,omitempty"`
	Authentication     *ConfigServicePppoeServerAuthentication `json:"authentication,omitempty"`
	AccessConcentrator string                                  `json:"access-concentrator,omitempty"`
}

type ConfigServicePppoeServerWinsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigServicePppoeServerDnsServers struct {
	Server2 IPv4 `json:"server-2,omitempty"`
	Server1 IPv4 `json:"server-1,omitempty"`
}

type ConfigServicePppoeServerClientIpPool struct {
	Start IPv4 `json:"start,omitempty"`
	Stop  IPv4 `json:"stop,omitempty"`
}

type ConfigServicePppoeServerRadius struct {
	DefaultInterimInterval int `json:"default-interim-interval,omitempty"`
}

type ConfigServicePppoeServerAuthentication struct {
	Mode         string                                              `json:"mode,omitempty"`
	LocalUsers   *ConfigServicePppoeServerAuthenticationLocalUsers   `json:"local-users,omitempty"`
	RadiusServer *ConfigServicePppoeServerAuthenticationRadiusServer `json:"radius-server,omitempty"`
}

type ConfigServicePppoeServerAuthenticationLocalUsers struct {
	Username *ConfigServicePppoeServerAuthenticationLocalUsersUsername `json:"username,omitempty"`
}

type ConfigServicePppoeServerAuthenticationLocalUsersUsername map[string]struct {
	Disable  json.RawMessage `json:"disable,omitempty"`
	Password string          `json:"password,omitempty"`
	StaticIp IPv4            `json:"static-ip,omitempty"`
}

type ConfigServicePppoeServerAuthenticationRadiusServer map[string]struct {
	Key string `json:"key,omitempty"`
}

type ConfigServiceSshRecovery struct {
	ListenOn string          `json:"listen-on,omitempty"`
	Lifetime string          `json:"lifetime,omitempty"`
	Disabled json.RawMessage `json:"disabled,omitempty"`
	Port     int             `json:"port,omitempty"`
}

type ConfigServiceDns struct {
	Dynamic    *ConfigServiceDnsDynamic    `json:"dynamic,omitempty"`
	Forwarding *ConfigServiceDnsForwarding `json:"forwarding,omitempty"`
}

type ConfigServiceDnsDynamic struct {
	Interface *ConfigServiceDnsDynamicInterface `json:"interface,omitempty"`
}

type ConfigServiceDnsDynamicInterface map[string]struct {
	Web     string                                   `json:"web,omitempty"`
	WebSkip string                                   `json:"web-skip,omitempty"`
	Service *ConfigServiceDnsDynamicInterfaceService `json:"service,omitempty"`
}

type ConfigServiceDnsDynamicInterfaceService map[string]struct {
	Options  string `json:"options,omitempty"`
	Password string `json:"password,omitempty"`
	Server   string `json:"server,omitempty"`
	HostName string `json:"host-name,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Login    string `json:"login,omitempty"`
}

type ConfigServiceDnsForwarding struct {
	Options             string          `json:"options,omitempty"`
	ExceptInterface     string          `json:"except-interface,omitempty"`
	ForcePublicDnsBoost json.RawMessage `json:"force-public-dns-boost,omitempty"`
	ListenOn            string          `json:"listen-on,omitempty"`
	NameServer          IP              `json:"name-server,omitempty"`
	System              json.RawMessage `json:"system,omitempty"`
	Dhcp                string          `json:"dhcp,omitempty"`
	CacheSize           int             `json:"cache-size,omitempty"`
}

type ConfigServiceDhcpRelay struct {
	Interface    string                              `json:"interface,omitempty"`
	RelayOptions *ConfigServiceDhcpRelayRelayOptions `json:"relay-options,omitempty"`
	Server       IPv4                                `json:"server,omitempty"`
}

type ConfigServiceDhcpRelayRelayOptions struct {
	HopCount           int    `json:"hop-count,omitempty"`
	MaxSize            int    `json:"max-size,omitempty"`
	Port               int    `json:"port,omitempty"`
	RelayAgentsPackets string `json:"relay-agents-packets,omitempty"`
}

type ConfigServiceUpnp2 struct {
	ListenOn   string                     `json:"listen-on,omitempty"`
	NatPmp     string                     `json:"nat-pmp,omitempty"`
	BitRate    *ConfigServiceUpnp2BitRate `json:"bit-rate,omitempty"`
	Wan        string                     `json:"wan,omitempty"`
	Port       int                        `json:"port,omitempty"`
	SecureMode string                     `json:"secure-mode,omitempty"`
	Acl        *ConfigServiceUpnp2Acl     `json:"acl,omitempty"`
}

type ConfigServiceUpnp2BitRate struct {
	Up   int `json:"up,omitempty"`
	Down int `json:"down,omitempty"`
}

type ConfigServiceUpnp2Acl struct {
	Rule *ConfigServiceUpnp2AclRule `json:"rule,omitempty"`
}

type ConfigServiceUpnp2AclRule map[string]struct {
	Action       string  `json:"action,omitempty"`
	Description  string  `json:"description,omitempty"`
	ExternalPort string  `json:"external-port,omitempty"`
	LocalPort    string  `json:"local-port,omitempty"`
	Subnet       IPv4Net `json:"subnet,omitempty"`
}

type ConfigServiceTelnet struct {
	ListenAddress IP              `json:"listen-address,omitempty"`
	AllowRoot     json.RawMessage `json:"allow-root,omitempty"`
	Port          int             `json:"port,omitempty"`
}

type ConfigServiceDhcpv6Relay struct {
	ListenInterface      *ConfigServiceDhcpv6RelayListenInterface   `json:"listen-interface,omitempty"`
	MaxHopCount          int                                        `json:"max-hop-count,omitempty"`
	UseInterfaceIdOption json.RawMessage                            `json:"use-interface-id-option,omitempty"`
	UpstreamInterface    *ConfigServiceDhcpv6RelayUpstreamInterface `json:"upstream-interface,omitempty"`
	ListenPort           int                                        `json:"listen-port,omitempty"`
}

type ConfigServiceDhcpv6RelayListenInterface map[string]struct {
	Address IPv6 `json:"address,omitempty"`
}

type ConfigServiceDhcpv6RelayUpstreamInterface map[string]struct {
	Address IPv6 `json:"address,omitempty"`
}

type ConfigProtocols *struct {
	Rip       *ConfigProtocolsRip       `json:"rip,omitempty"`
	Mpls      *ConfigProtocolsMpls      `json:"mpls,omitempty"`
	Bfd       *ConfigProtocolsBfd       `json:"bfd,omitempty"`
	Ripng     *ConfigProtocolsRipng     `json:"ripng,omitempty"`
	Vrf       *ConfigProtocolsVrf       `json:".vrf,omitempty"`
	Static    *ConfigProtocolsStatic    `json:"static,omitempty"`
	Rsvp      *ConfigProtocolsRsvp      `json:"rsvp,omitempty"`
	Vpls      *ConfigProtocolsVpls      `json:"vpls,omitempty"`
	Ldp       *ConfigProtocolsLdp       `json:"ldp,omitempty"`
	IgmpProxy *ConfigProtocolsIgmpProxy `json:"igmp-proxy,omitempty"`
	Bgp       *ConfigProtocolsBgp       `json:"bgp,omitempty"`
	Ospfv3    *ConfigProtocolsOspfv3    `json:"ospfv3,omitempty"`
	Ospf      *ConfigProtocolsOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsRip struct {
	Interface          string                                `json:"interface,omitempty"`
	Neighbor           IPv4                                  `json:"neighbor,omitempty"`
	Route              IPv4Net                               `json:"route,omitempty"`
	Bfd                *ConfigProtocolsRipBfd                `json:"bfd,omitempty"`
	DefaultDistance    int                                   `json:"default-distance,omitempty"`
	Timers             *ConfigProtocolsRipTimers             `json:"timers,omitempty"`
	Network            IPv4Net                               `json:"network,omitempty"`
	DefaultMetric      int                                   `json:"default-metric,omitempty"`
	Vrf                *ConfigProtocolsRipVrf                `json:".vrf,omitempty"`
	NetworkDistance    *ConfigProtocolsRipNetworkDistance    `json:"network-distance,omitempty"`
	PassiveInterface   string                                `json:"passive-interface,omitempty"`
	Redistribute       *ConfigProtocolsRipRedistribute       `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipDistributeList     `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipDefaultInformation `json:"default-information,omitempty"`
}

type ConfigProtocolsRipBfd struct {
	Neighbor      *ConfigProtocolsRipBfdNeighbor `json:"neighbor,omitempty"`
	AllInterfaces json.RawMessage                `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsRipBfdNeighbor map[string]struct {
	FallOver json.RawMessage `json:"fall-over,omitempty"`
}

type ConfigProtocolsRipTimers struct {
	Update            int `json:"update,omitempty"`
	Timeout           int `json:"timeout,omitempty"`
	GarbageCollection int `json:"garbage-collection,omitempty"`
}

type ConfigProtocolsRipVrf map[string]struct {
	Interface          string                                   `json:"interface,omitempty"`
	Bfd                *ConfigProtocolsRipVrfBfd                `json:"bfd,omitempty"`
	DefaultDistance    int                                      `json:"default-distance,omitempty"`
	Network            IPv4Net                                  `json:"network,omitempty"`
	DefaultMetric      int                                      `json:"default-metric,omitempty"`
	NetworkDistance    *ConfigProtocolsRipVrfNetworkDistance    `json:"network-distance,omitempty"`
	Redistribute       *ConfigProtocolsRipVrfRedistribute       `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipVrfDistributeList     `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipVrfDefaultInformation `json:"default-information,omitempty"`
}

type ConfigProtocolsRipVrfBfd struct {
	Neighbor      *ConfigProtocolsRipVrfBfdNeighbor `json:"neighbor,omitempty"`
	AllInterfaces json.RawMessage                   `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsRipVrfBfdNeighbor map[string]struct {
	FallOver json.RawMessage `json:"fall-over,omitempty"`
}

type ConfigProtocolsRipVrfNetworkDistance map[string]struct {
	Distance   int    `json:"distance,omitempty"`
	AccessList string `json:"access-list,omitempty"`
}

type ConfigProtocolsRipVrfRedistribute struct {
	Connected *ConfigProtocolsRipVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipVrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipVrfRedistributeBgp       `json:"bgp,omitempty"`
	Ospf      *ConfigProtocolsRipVrfRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeBgp struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfRedistributeOspf struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipVrfDistributeList struct {
	Interface  *ConfigProtocolsRipVrfDistributeListInterface  `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipVrfDistributeListAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipVrfDistributeListPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListInterface map[string]struct {
	AccessList *ConfigProtocolsRipVrfDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipVrfDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListInterfaceAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipVrfDefaultInformation struct {
	Originate json.RawMessage `json:"originate,omitempty"`
}

type ConfigProtocolsRipNetworkDistance map[string]struct {
	Distance   int    `json:"distance,omitempty"`
	AccessList string `json:"access-list,omitempty"`
}

type ConfigProtocolsRipRedistribute struct {
	Connected *ConfigProtocolsRipRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsRipRedistributeKernel    `json:"kernel,omitempty"`
	Ospf      *ConfigProtocolsRipRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsRipRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeBgp struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipRedistributeOspf struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipDistributeList struct {
	Interface  *ConfigProtocolsRipDistributeListInterface  `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipDistributeListAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipDistributeListPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipDistributeListInterface map[string]struct {
	AccessList *ConfigProtocolsRipDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipDistributeListInterfaceAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipDistributeListAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipDefaultInformation struct {
	Originate json.RawMessage `json:"originate,omitempty"`
}

type ConfigProtocolsMpls struct {
	LspTunneling         *ConfigProtocolsMplsLspTunneling      `json:"lsp-tunneling,omitempty"`
	AcGroup              *ConfigProtocolsMplsAcGroup           `json:"ac-group,omitempty"`
	LocalPacketHandling  json.RawMessage                       `json:"local-packet-handling,omitempty"`
	Interface            *ConfigProtocolsMplsInterface         `json:"interface,omitempty"`
	L2CircuitFibEntry    *ConfigProtocolsMplsL2CircuitFibEntry `json:".l2-circuit-fib-entry,omitempty"`
	EnableAllInterfaces  json.RawMessage                       `json:"enable-all-interfaces,omitempty"`
	MsPw                 *ConfigProtocolsMplsMsPw              `json:"ms-pw,omitempty"`
	IngressTtl           int                                   `json:"ingress-ttl,omitempty"`
	TeClass              *ConfigProtocolsMplsTeClass           `json:"te-class,omitempty"`
	LspModel             *ConfigProtocolsMplsLspModel          `json:"lsp-model,omitempty"`
	FtnEntry             *ConfigProtocolsMplsFtnEntry          `json:"ftn-entry,omitempty"`
	ClassToExp           *ConfigProtocolsMplsClassToExp        `json:"class-to-exp,omitempty"`
	L2Circuit            *ConfigProtocolsMplsL2Circuit         `json:".l2-circuit,omitempty"`
	EgressTtl            int                                   `json:"egress-ttl,omitempty"`
	MinLabelValue        *ConfigProtocolsMplsMinLabelValue     `json:"min-label-value,omitempty"`
	AdminGroup           *ConfigProtocolsMplsAdminGroup        `json:"admin-group,omitempty"`
	MsPwStitch           *ConfigProtocolsMplsMsPwStitch        `json:"ms-pw-stitch,omitempty"`
	ClassType            *ConfigProtocolsMplsClassType         `json:"class-type,omitempty"`
	IlmEntry             *ConfigProtocolsMplsIlmEntry          `json:"ilm-entry,omitempty"`
	SupportDiffservClass string                                `json:"support-diffserv-class,omitempty"`
	MapRoute             *ConfigProtocolsMplsMapRoute          `json:"map-route,omitempty"`
	Rsvp                 *ConfigProtocolsMplsRsvp              `json:"rsvp,omitempty"`
	Ldp                  *ConfigProtocolsMplsLdp               `json:"ldp,omitempty"`
	Bgp                  *ConfigProtocolsMplsBgp               `json:"bgp,omitempty"`
	MaxLabelValue        *ConfigProtocolsMplsMaxLabelValue     `json:"max-label-value,omitempty"`
	PropagateTtl         json.RawMessage                       `json:"propagate-ttl,omitempty"`
	DisableAllInterfaces json.RawMessage                       `json:"disable-all-interfaces,omitempty"`
}

type ConfigProtocolsMplsLspTunneling struct {
	Interface *ConfigProtocolsMplsLspTunnelingInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsLspTunnelingInterface map[string]struct {
	InLabel *ConfigProtocolsMplsLspTunnelingInterfaceInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsMplsLspTunnelingInterfaceInLabel map[string]struct {
	OutLabel *ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsLspTunnelingInterfaceInLabelOutLabel map[string]struct {
	NetworkFec IPv4Net `json:"network-fec,omitempty"`
}

type ConfigProtocolsMplsAcGroup map[string]struct {
	GroupId int `json:"group-id,omitempty"`
}

type ConfigProtocolsMplsInterface map[string]struct {
	MulticastHellos    json.RawMessage                                 `json:"multicast-hellos,omitempty"`
	KeepaliveTimeout   int                                             `json:"keepalive-timeout,omitempty"`
	VcMode             *ConfigProtocolsMplsInterfaceVcMode             `json:"vc-mode,omitempty"`
	LdpIgp             *ConfigProtocolsMplsInterfaceLdpIgp             `json:"ldp-igp,omitempty"`
	MaxPduLength       int                                             `json:"max-pdu-length,omitempty"`
	LabelRetentionMode *ConfigProtocolsMplsInterfaceLabelRetentionMode `json:"label-retention-mode,omitempty"`
	AdminGroup         string                                          `json:"admin-group,omitempty"`
	L2Circuit          *ConfigProtocolsMplsInterfaceL2Circuit          `json:"l2-circuit,omitempty"`
	LabelSwitching     json.RawMessage                                 `json:"label-switching,omitempty"`
	HoldTime           int                                             `json:"hold-time,omitempty"`
	KeepaliveInterval  int                                             `json:"keepalive-interval,omitempty"`
	AdvertisementMode  *ConfigProtocolsMplsInterfaceAdvertisementMode  `json:"advertisement-mode,omitempty"`
	HelloInterval      int                                             `json:"hello-interval,omitempty"`
}

type ConfigProtocolsMplsInterfaceVcMode struct {
	Standby   json.RawMessage `json:"standby,omitempty"`
	Revertive json.RawMessage `json:"revertive,omitempty"`
}

type ConfigProtocolsMplsInterfaceLdpIgp struct {
	Sync      *ConfigProtocolsMplsInterfaceLdpIgpSync `json:"sync,omitempty"`
	SyncDelay int                                     `json:"sync-delay,omitempty"`
}

type ConfigProtocolsMplsInterfaceLdpIgpSync struct {
	Ospf *ConfigProtocolsMplsInterfaceLdpIgpSyncOspf `json:"ospf,omitempty"`
}

type ConfigProtocolsMplsInterfaceLdpIgpSyncOspf struct {
	HolddownTimer int `json:"holddown-timer,omitempty"`
}

type ConfigProtocolsMplsInterfaceLabelRetentionMode struct {
	Liberal      json.RawMessage `json:"liberal,omitempty"`
	Conservative json.RawMessage `json:"conservative,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2Circuit map[string]struct {
	Hdlc     *ConfigProtocolsMplsInterfaceL2CircuitHdlc     `json:".hdlc,omitempty"`
	Ppp      *ConfigProtocolsMplsInterfaceL2CircuitPpp      `json:".ppp,omitempty"`
	Ethernet *ConfigProtocolsMplsInterfaceL2CircuitEthernet `json:".ethernet,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2CircuitHdlc struct {
	Primary   json.RawMessage `json:"primary,omitempty"`
	Secondary json.RawMessage `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2CircuitPpp struct {
	Primary   json.RawMessage `json:"primary,omitempty"`
	Secondary json.RawMessage `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsInterfaceL2CircuitEthernet struct {
	Primary   json.RawMessage `json:"primary,omitempty"`
	Secondary json.RawMessage `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsInterfaceAdvertisementMode struct {
	DownstreamOnDemand    json.RawMessage `json:"downstream-on-demand,omitempty"`
	DownstreamUnsolicited json.RawMessage `json:"downstream-unsolicited,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntry map[string]struct {
	InLabel *ConfigProtocolsMplsL2CircuitFibEntryInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabel map[string]struct {
	OutLabel *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabel map[string]struct {
	Ipv4 *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4 `json:"ipv4,omitempty"`
	Ipv6 *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6 `json:"ipv6,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4 map[string]struct {
	Int *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int `json:"int,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv4Int map[string]struct {
	Int string `json:"int,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6 map[string]struct {
	Int *ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int `json:"int,omitempty"`
}

type ConfigProtocolsMplsL2CircuitFibEntryInLabelOutLabelIpv6Int map[string]struct {
	Int string `json:"int,omitempty"`
}

type ConfigProtocolsMplsMsPw map[string]struct {
	Description string `json:"description,omitempty"`
}

type ConfigProtocolsMplsTeClass map[string]struct {
	Name *ConfigProtocolsMplsTeClassName `json:"name,omitempty"`
}

type ConfigProtocolsMplsTeClassName map[string]struct {
	Priority int `json:"priority,omitempty"`
}

type ConfigProtocolsMplsLspModel struct {
	Pipe json.RawMessage `json:"pipe,omitempty"`
}

type ConfigProtocolsMplsFtnEntry struct {
	TunnelId *ConfigProtocolsMplsFtnEntryTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelId map[string]struct {
	Ip       *ConfigProtocolsMplsFtnEntryTunnelIdIp       `json:"ip,omitempty"`
	Ipv6mask *ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask `json:"ipv6mask,omitempty"`
	Ipv4mask *ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask `json:"ipv4mask,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIp map[string]struct {
	Mask *ConfigProtocolsMplsFtnEntryTunnelIdIpMask `json:"mask,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMask map[string]struct {
	OutLabel *ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabel map[string]struct {
	Nexthop *ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop `json:"nexthop,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthop map[string]struct {
	Interface *ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpMaskOutLabelNexthopInterface map[string]struct {
	Primary   json.RawMessage `json:"primary,omitempty"`
	Secondary json.RawMessage `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6mask map[string]struct {
	OutLabel *ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabel map[string]struct {
	Nexthop *ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop `json:"nexthop,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthop map[string]struct {
	Interface *ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv6maskOutLabelNexthopInterface map[string]struct {
	Primary   json.RawMessage `json:"primary,omitempty"`
	Secondary json.RawMessage `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4mask map[string]struct {
	OutLabel *ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel `json:"out-label,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabel map[string]struct {
	Nexthop *ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop `json:"nexthop,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthop map[string]struct {
	Interface *ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsFtnEntryTunnelIdIpv4maskOutLabelNexthopInterface map[string]struct {
	Primary   json.RawMessage `json:"primary,omitempty"`
	Secondary json.RawMessage `json:"secondary,omitempty"`
}

type ConfigProtocolsMplsClassToExp map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsMplsL2Circuit map[string]struct {
	Ipv4 *ConfigProtocolsMplsL2CircuitIpv4 `json:"ipv4,omitempty"`
	Id   *ConfigProtocolsMplsL2CircuitId   `json:"id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4 map[string]struct {
	Agi *ConfigProtocolsMplsL2CircuitIpv4Agi `json:"agi,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4Agi map[string]struct {
	Saii *ConfigProtocolsMplsL2CircuitIpv4AgiSaii `json:"saii,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaii map[string]struct {
	Taii *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii `json:"taii,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaii map[string]struct {
	Manual      json.RawMessage                                         `json:"manual,omitempty"`
	Groupname   *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname   `json:"groupname,omitempty"`
	ControlWord *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWord `json:"control-word,omitempty"`
	TunnelId    *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId    `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiGroupname map[string]struct {
	GroupId int `json:"group-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWord struct {
	Manual   json.RawMessage                                                 `json:"manual,omitempty"`
	TunnelId *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelId map[string]struct {
	Passive json.RawMessage                                                        `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdReverse `json:"reverse,omitempty"`
	Manual  json.RawMessage                                                        `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdReverse struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiControlWordTunnelIdForward struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelId map[string]struct {
	Passive json.RawMessage                                             `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdReverse `json:"reverse,omitempty"`
	Manual  json.RawMessage                                             `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdReverse struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIpv4AgiSaiiTaiiTunnelIdForward struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitId map[string]struct {
	Ipv4 *ConfigProtocolsMplsL2CircuitIdIpv4 `json:"ipv4,omitempty"`
	Ipv6 *ConfigProtocolsMplsL2CircuitIdIpv6 `json:"ipv6,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4 map[string]struct {
	Passive     json.RawMessage                                `json:"passive,omitempty"`
	Manual      json.RawMessage                                `json:"manual,omitempty"`
	Groupname   *ConfigProtocolsMplsL2CircuitIdIpv4Groupname   `json:"groupname,omitempty"`
	ControlWord *ConfigProtocolsMplsL2CircuitIdIpv4ControlWord `json:"control-word,omitempty"`
	TunnelId    *ConfigProtocolsMplsL2CircuitIdIpv4TunnelId    `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4Groupname map[string]struct {
	ControlWord *ConfigProtocolsMplsL2CircuitIdIpv4GroupnameControlWord `json:"control-word,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4GroupnameControlWord struct {
	Manual json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWord struct {
	Passive  json.RawMessage                                        `json:"passive,omitempty"`
	Manual   json.RawMessage                                        `json:"manual,omitempty"`
	TunnelId *ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelId map[string]struct {
	Passive json.RawMessage                                               `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdReverse `json:"reverse,omitempty"`
	Manual  json.RawMessage                                               `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdReverse struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4ControlWordTunnelIdForward struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4TunnelId map[string]struct {
	Passive json.RawMessage                                    `json:"passive,omitempty"`
	Reverse *ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdReverse `json:"reverse,omitempty"`
	Manual  json.RawMessage                                    `json:"manual,omitempty"`
	Forward *ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdReverse struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv4TunnelIdForward struct {
	Passive json.RawMessage `json:"passive,omitempty"`
	Manual  json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsL2CircuitIdIpv6 map[string]struct {
	Manual json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsMplsMinLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsAdminGroup map[string]struct {
	Value int `json:"value,omitempty"`
}

type ConfigProtocolsMplsMsPwStitch map[string]struct {
	Vc1 *ConfigProtocolsMplsMsPwStitchVc1 `json:"vc1,omitempty"`
}

type ConfigProtocolsMplsMsPwStitchVc1 map[string]struct {
	Vc2 *ConfigProtocolsMplsMsPwStitchVc1Vc2 `json:"vc2,omitempty"`
}

type ConfigProtocolsMplsMsPwStitchVc1Vc2 map[string]struct {
	Mtu *ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu `json:"mtu,omitempty"`
}

type ConfigProtocolsMplsMsPwStitchVc1Vc2Mtu map[string]struct {
	Ethernet json.RawMessage `json:"ethernet,omitempty"`
	Vlan     int             `json:"vlan,omitempty"`
}

type ConfigProtocolsMplsClassType map[string]struct {
	Name string `json:"name,omitempty"`
}

type ConfigProtocolsMplsIlmEntry map[string]struct {
	Interface *ConfigProtocolsMplsIlmEntryInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterface map[string]struct {
	Pop  json.RawMessage                           `json:"pop,omitempty"`
	Swap *ConfigProtocolsMplsIlmEntryInterfaceSwap `json:"swap,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwap map[string]struct {
	Interface *ConfigProtocolsMplsIlmEntryInterfaceSwapInterface `json:"interface,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwapInterface map[string]struct {
	Ip *ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp `json:"ip,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIp map[string]struct {
	Fec *ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec `json:"fec,omitempty"`
}

type ConfigProtocolsMplsIlmEntryInterfaceSwapInterfaceIpFec map[string]struct {
	Mask IPv4 `json:"mask,omitempty"`
}

type ConfigProtocolsMplsMapRoute map[string]struct {
	Fec IPv4Net `json:"fec,omitempty"`
}

type ConfigProtocolsMplsRsvp struct {
	MinLabelValue *ConfigProtocolsMplsRsvpMinLabelValue `json:"min-label-value,omitempty"`
	MaxLabelValue *ConfigProtocolsMplsRsvpMaxLabelValue `json:"max-label-value,omitempty"`
}

type ConfigProtocolsMplsRsvpMinLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsRsvpMaxLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsLdp struct {
	MinLabelValue *ConfigProtocolsMplsLdpMinLabelValue `json:"min-label-value,omitempty"`
	MaxLabelValue *ConfigProtocolsMplsLdpMaxLabelValue `json:"max-label-value,omitempty"`
}

type ConfigProtocolsMplsLdpMinLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsLdpMaxLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsBgp struct {
	MinLabelValue *ConfigProtocolsMplsBgpMinLabelValue `json:"min-label-value,omitempty"`
	MaxLabelValue *ConfigProtocolsMplsBgpMaxLabelValue `json:"max-label-value,omitempty"`
}

type ConfigProtocolsMplsBgpMinLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsBgpMaxLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsMplsMaxLabelValue map[string]struct {
	LabelSpace int `json:"label-space,omitempty"`
}

type ConfigProtocolsBfd struct {
	Interface    *ConfigProtocolsBfdInterface    `json:"interface,omitempty"`
	Echo         json.RawMessage                 `json:"echo,omitempty"`
	Notification *ConfigProtocolsBfdNotification `json:"notification,omitempty"`
	SlowTimer    int                             `json:"slow-timer,omitempty"`
	Gtsm         *ConfigProtocolsBfdGtsm         `json:"gtsm,omitempty"`
	MultihopPeer *ConfigProtocolsBfdMultihopPeer `json:"multihop-peer,omitempty"`
}

type ConfigProtocolsBfdInterface map[string]struct {
	Enable   json.RawMessage                      `json:"enable,omitempty"`
	Echo     *ConfigProtocolsBfdInterfaceEcho     `json:"echo,omitempty"`
	Auth     *ConfigProtocolsBfdInterfaceAuth     `json:"auth,omitempty"`
	Interval *ConfigProtocolsBfdInterfaceInterval `json:"interval,omitempty"`
	Session  *ConfigProtocolsBfdInterfaceSession  `json:"session,omitempty"`
}

type ConfigProtocolsBfdInterfaceEcho struct {
	Interval int `json:"interval,omitempty"`
}

type ConfigProtocolsBfdInterfaceAuth struct {
	Key  string `json:"key,omitempty"`
	Type string `json:"type,omitempty"`
}

type ConfigProtocolsBfdInterfaceInterval map[string]struct {
	Minrx *ConfigProtocolsBfdInterfaceIntervalMinrx `json:"minrx,omitempty"`
}

type ConfigProtocolsBfdInterfaceIntervalMinrx map[string]struct {
	Multiplier int `json:"multiplier,omitempty"`
}

type ConfigProtocolsBfdInterfaceSession struct {
	Source *ConfigProtocolsBfdInterfaceSessionSource `json:"source,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSource map[string]struct {
	Dest *ConfigProtocolsBfdInterfaceSessionSourceDest `json:"dest,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDest map[string]struct {
	Multihop      *ConfigProtocolsBfdInterfaceSessionSourceDestMultihop      `json:"multihop,omitempty"`
	AdminDown     json.RawMessage                                            `json:"admin-down,omitempty"`
	DemandMode    *ConfigProtocolsBfdInterfaceSessionSourceDestDemandMode    `json:"demand-mode,omitempty"`
	NonPersistent *ConfigProtocolsBfdInterfaceSessionSourceDestNonPersistent `json:"non-persistent,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestMultihop struct {
	AdminDown  json.RawMessage                                                 `json:"admin-down,omitempty"`
	DemandMode *ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandMode `json:"demand-mode,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandMode struct {
	AdminDown     json.RawMessage                                                              `json:"admin-down,omitempty"`
	NonPersistent *ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandModeNonPersistent `json:"non-persistent,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestMultihopDemandModeNonPersistent struct {
	AdminDown json.RawMessage `json:"admin-down,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestDemandMode struct {
	AdminDown     json.RawMessage                                                      `json:"admin-down,omitempty"`
	NonPersistent *ConfigProtocolsBfdInterfaceSessionSourceDestDemandModeNonPersistent `json:"non-persistent,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestDemandModeNonPersistent struct {
	AdminDown json.RawMessage `json:"admin-down,omitempty"`
}

type ConfigProtocolsBfdInterfaceSessionSourceDestNonPersistent struct {
	AdminDown json.RawMessage `json:"admin-down,omitempty"`
}

type ConfigProtocolsBfdNotification struct {
	Enable json.RawMessage `json:"enable,omitempty"`
}

type ConfigProtocolsBfdGtsm struct {
	Enable json.RawMessage `json:"enable,omitempty"`
	Ttl    int             `json:"ttl,omitempty"`
}

type ConfigProtocolsBfdMultihopPeer map[string]struct {
	Auth     *ConfigProtocolsBfdMultihopPeerAuth     `json:"auth,omitempty"`
	Interval *ConfigProtocolsBfdMultihopPeerInterval `json:"interval,omitempty"`
}

type ConfigProtocolsBfdMultihopPeerAuth struct {
	Key  string `json:"key,omitempty"`
	Type string `json:"type,omitempty"`
}

type ConfigProtocolsBfdMultihopPeerInterval map[string]struct {
	Minrx *ConfigProtocolsBfdMultihopPeerIntervalMinrx `json:"minrx,omitempty"`
}

type ConfigProtocolsBfdMultihopPeerIntervalMinrx map[string]struct {
	Multiplier int `json:"multiplier,omitempty"`
}

type ConfigProtocolsRipng struct {
	Interface          string                                  `json:"interface,omitempty"`
	Route              IPv6Net                                 `json:"route,omitempty"`
	Timers             *ConfigProtocolsRipngTimers             `json:"timers,omitempty"`
	Network            IPv6Net                                 `json:"network,omitempty"`
	DefaultMetric      int                                     `json:"default-metric,omitempty"`
	AggregateAddress   IPv6Net                                 `json:"aggregate-address,omitempty"`
	Vrf                *ConfigProtocolsRipngVrf                `json:".vrf,omitempty"`
	PassiveInterface   string                                  `json:"passive-interface,omitempty"`
	Redistribute       *ConfigProtocolsRipngRedistribute       `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipngDistributeList     `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipngDefaultInformation `json:"default-information,omitempty"`
}

type ConfigProtocolsRipngTimers struct {
	Update            int `json:"update,omitempty"`
	Timeout           int `json:"timeout,omitempty"`
	GarbageCollection int `json:"garbage-collection,omitempty"`
}

type ConfigProtocolsRipngVrf map[string]struct {
	Interface          string                                     `json:"interface,omitempty"`
	Route              IPv6Net                                    `json:"route,omitempty"`
	Timers             *ConfigProtocolsRipngVrfTimers             `json:"timers,omitempty"`
	Network            IPv6Net                                    `json:"network,omitempty"`
	DefaultMetric      int                                        `json:"default-metric,omitempty"`
	AggregateAddress   IPv6Net                                    `json:"aggregate-address,omitempty"`
	PassiveInterface   string                                     `json:"passive-interface,omitempty"`
	Redistribute       *ConfigProtocolsRipngVrfRedistribute       `json:"redistribute,omitempty"`
	DistributeList     *ConfigProtocolsRipngVrfDistributeList     `json:"distribute-list,omitempty"`
	DefaultInformation *ConfigProtocolsRipngVrfDefaultInformation `json:"default-information,omitempty"`
}

type ConfigProtocolsRipngVrfTimers struct {
	Update            int `json:"update,omitempty"`
	Timeout           int `json:"timeout,omitempty"`
	GarbageCollection int `json:"garbage-collection,omitempty"`
}

type ConfigProtocolsRipngVrfRedistribute struct {
	Connected *ConfigProtocolsRipngVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipngVrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipngVrfRedistributeBgp       `json:"bgp,omitempty"`
	Ospfv3    *ConfigProtocolsRipngVrfRedistributeOspfv3    `json:"ospfv3,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeBgp struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfRedistributeOspfv3 struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeList struct {
	Interface  *ConfigProtocolsRipngVrfDistributeListInterface  `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipngVrfDistributeListAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngVrfDistributeListPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListInterface map[string]struct {
	AccessList *ConfigProtocolsRipngVrfDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngVrfDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListInterfaceAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngVrfDefaultInformation struct {
	Originate json.RawMessage `json:"originate,omitempty"`
}

type ConfigProtocolsRipngRedistribute struct {
	Connected *ConfigProtocolsRipngRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsRipngRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsRipngRedistributeBgp       `json:"bgp,omitempty"`
	Ospfv3    *ConfigProtocolsRipngRedistributeOspfv3    `json:"ospfv3,omitempty"`
	Kernel    *ConfigProtocolsRipngRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsRipngRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeBgp struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeOspfv3 struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngRedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsRipngDistributeList struct {
	Interface  *ConfigProtocolsRipngDistributeListInterface  `json:"interface,omitempty"`
	AccessList *ConfigProtocolsRipngDistributeListAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngDistributeListPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngDistributeListInterface map[string]struct {
	AccessList *ConfigProtocolsRipngDistributeListInterfaceAccessList `json:"access-list,omitempty"`
	PrefixList *ConfigProtocolsRipngDistributeListInterfacePrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsRipngDistributeListInterfaceAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipngDistributeListInterfacePrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngDistributeListAccessList struct {
	Out int `json:"out,omitempty"`
	In  int `json:"in,omitempty"`
}

type ConfigProtocolsRipngDistributeListPrefixList struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigProtocolsRipngDefaultInformation struct {
	Originate json.RawMessage `json:"originate,omitempty"`
}

type ConfigProtocolsVrf map[string]struct {
	Interface   string                         `json:"interface,omitempty"`
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
	InterfaceRoute6 *ConfigProtocolsStaticInterfaceRoute6 `json:"interface-route6,omitempty"`
	Route           *ConfigProtocolsStaticRoute           `json:"route,omitempty"`
	Bfd             *ConfigProtocolsStaticBfd             `json:"bfd,omitempty"`
	Vrf             *ConfigProtocolsStaticVrf             `json:".vrf,omitempty"`
	Table           *ConfigProtocolsStaticTable           `json:"table,omitempty"`
	InterfaceRoute  *ConfigProtocolsStaticInterfaceRoute  `json:"interface-route,omitempty"`
	Arp             *ConfigProtocolsStaticArp             `json:"arp,omitempty"`
	Route6          *ConfigProtocolsStaticRoute6          `json:"route6,omitempty"`
}

type ConfigProtocolsStaticInterfaceRoute6 map[string]struct {
	NextHopInterface *ConfigProtocolsStaticInterfaceRoute6NextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticInterfaceRoute6NextHopInterface map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticRoute map[string]struct {
	NextHop   *ConfigProtocolsStaticRouteNextHop   `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticRouteBlackhole `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticRouteNextHop map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Bfd         json.RawMessage `json:"bfd,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticRouteBlackhole struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticBfd struct {
	Interface     *ConfigProtocolsStaticBfdInterface     `json:"interface,omitempty"`
	AllInterfaces *ConfigProtocolsStaticBfdAllInterfaces `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsStaticBfdInterface map[string]struct {
	Ipv4 json.RawMessage `json:"ipv4,omitempty"`
	Ipv6 json.RawMessage `json:"ipv6,omitempty"`
}

type ConfigProtocolsStaticBfdAllInterfaces struct {
	Ipv4 json.RawMessage `json:"ipv4,omitempty"`
	Ipv6 json.RawMessage `json:"ipv6,omitempty"`
}

type ConfigProtocolsStaticVrf map[string]struct {
	InterfaceRoute6 *ConfigProtocolsStaticVrfInterfaceRoute6 `json:"interface-route6,omitempty"`
	Route           *ConfigProtocolsStaticVrfRoute           `json:"route,omitempty"`
	InterfaceRoute  *ConfigProtocolsStaticVrfInterfaceRoute  `json:"interface-route,omitempty"`
	Ip              *ConfigProtocolsStaticVrfIp              `json:"ip,omitempty"`
	Route6          *ConfigProtocolsStaticVrfRoute6          `json:"route6,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute6 map[string]struct {
	NextHopInterface *ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterface map[string]struct {
	Gw *ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw `json:"gw,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute6NextHopInterfaceGw map[string]struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigProtocolsStaticVrfRoute map[string]struct {
	NextHop   *ConfigProtocolsStaticVrfRouteNextHop   `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticVrfRouteBlackhole `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticVrfRouteNextHop map[string]struct {
	Disable   string `json:"disable,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type ConfigProtocolsStaticVrfRouteBlackhole struct {
	Disable   string `json:"disable,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRoute map[string]struct {
	NextHopInterface *ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticVrfInterfaceRouteNextHopInterface map[string]struct {
	Disable json.RawMessage `json:"disable,omitempty"`
}

type ConfigProtocolsStaticVrfIp struct {
	Forwarding json.RawMessage `json:"forwarding,omitempty"`
}

type ConfigProtocolsStaticVrfRoute6 map[string]struct {
	NextHop *ConfigProtocolsStaticVrfRoute6NextHop `json:"next-hop,omitempty"`
}

type ConfigProtocolsStaticVrfRoute6NextHop map[string]struct {
	Disable   string `json:"disable,omitempty"`
	Interface string `json:"interface,omitempty"`
}

type ConfigProtocolsStaticTable map[string]struct {
	InterfaceRoute6 *ConfigProtocolsStaticTableInterfaceRoute6 `json:"interface-route6,omitempty"`
	Route           *ConfigProtocolsStaticTableRoute           `json:"route,omitempty"`
	Mark            int                                        `json:"mark,omitempty"`
	Description     string                                     `json:"description,omitempty"`
	InterfaceRoute  *ConfigProtocolsStaticTableInterfaceRoute  `json:"interface-route,omitempty"`
	Route6          *ConfigProtocolsStaticTableRoute6          `json:"route6,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRoute6 map[string]struct {
	NextHopInterface *ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRoute6NextHopInterface map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRoute map[string]struct {
	NextHop   *ConfigProtocolsStaticTableRouteNextHop   `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticTableRouteBlackhole `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticTableRouteNextHop map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRouteBlackhole struct {
	Distance    int    `json:"distance,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRoute map[string]struct {
	NextHopInterface *ConfigProtocolsStaticTableInterfaceRouteNextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticTableInterfaceRouteNextHopInterface map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRoute6 map[string]struct {
	NextHop   *ConfigProtocolsStaticTableRoute6NextHop   `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticTableRoute6Blackhole `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticTableRoute6NextHop map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticTableRoute6Blackhole struct {
	Distance    int    `json:"distance,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigProtocolsStaticInterfaceRoute map[string]struct {
	NextHopInterface *ConfigProtocolsStaticInterfaceRouteNextHopInterface `json:"next-hop-interface,omitempty"`
}

type ConfigProtocolsStaticInterfaceRouteNextHopInterface map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticArp map[string]struct {
	Hwaddr MacAddr `json:"hwaddr,omitempty"`
}

type ConfigProtocolsStaticRoute6 map[string]struct {
	NextHop   *ConfigProtocolsStaticRoute6NextHop   `json:"next-hop,omitempty"`
	Blackhole *ConfigProtocolsStaticRoute6Blackhole `json:"blackhole,omitempty"`
}

type ConfigProtocolsStaticRoute6NextHop map[string]struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Interface   string          `json:"interface,omitempty"`
	Bfd         json.RawMessage `json:"bfd,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsStaticRoute6Blackhole struct {
	Disable     json.RawMessage `json:"disable,omitempty"`
	Distance    int             `json:"distance,omitempty"`
	Description string          `json:"description,omitempty"`
}

type ConfigProtocolsRsvp struct {
	HelloTimeout             int                                 `json:"hello-timeout,omitempty"`
	Interface                *ConfigProtocolsRsvpInterface       `json:"interface,omitempty"`
	Neighbor                 IP                                  `json:"neighbor,omitempty"`
	BundleSend               json.RawMessage                     `json:"bundle-send,omitempty"`
	ExplicitNull             json.RawMessage                     `json:"explicit-null,omitempty"`
	OverrideDiffserv         json.RawMessage                     `json:"override-diffserv,omitempty"`
	PreprogramSuggestedLabel json.RawMessage                     `json:"preprogram-suggested-label,omitempty"`
	Notification             json.RawMessage                     `json:"notification,omitempty"`
	Path                     *ConfigProtocolsRsvpPath            `json:"path,omitempty"`
	From                     IP                                  `json:"from,omitempty"`
	AckWaitTimeout           int                                 `json:"ack-wait-timeout,omitempty"`
	RefreshPathParsing       json.RawMessage                     `json:"refresh-path-parsing,omitempty"`
	Cspf                     json.RawMessage                     `json:"cspf,omitempty"`
	GracefulRestart          *ConfigProtocolsRsvpGracefulRestart `json:"graceful-restart,omitempty"`
	RefreshResvParsing       json.RawMessage                     `json:"refresh-resv-parsing,omitempty"`
	MessageAck               json.RawMessage                     `json:"message-ack,omitempty"`
	RefreshReduction         json.RawMessage                     `json:"refresh-reduction,omitempty"`
	LocalProtection          json.RawMessage                     `json:"local-protection,omitempty"`
	RefreshTime              int                                 `json:"refresh-time,omitempty"`
	NoPhp                    json.RawMessage                     `json:"no-php,omitempty"`
	HelloReceipt             json.RawMessage                     `json:"hello-receipt,omitempty"`
	KeepMultiplier           int                                 `json:"keep-multiplier,omitempty"`
	LoopDetection            json.RawMessage                     `json:"loop-detection,omitempty"`
	HelloInterval            int                                 `json:"hello-interval,omitempty"`
	Trunk                    *ConfigProtocolsRsvpTrunk           `json:"trunk,omitempty"`
}

type ConfigProtocolsRsvpInterface map[string]struct {
	HelloTimeout     int             `json:"hello-timeout,omitempty"`
	Disable          json.RawMessage `json:"disable,omitempty"`
	AckWaitTimeout   int             `json:"ack-wait-timeout,omitempty"`
	MessageAck       json.RawMessage `json:"message-ack,omitempty"`
	RefreshReduction json.RawMessage `json:"refresh-reduction,omitempty"`
	RefreshTime      int             `json:"refresh-time,omitempty"`
	HelloReceipt     json.RawMessage `json:"hello-receipt,omitempty"`
	KeepMultiplier   int             `json:"keep-multiplier,omitempty"`
	NonIANAHello     json.RawMessage `json:"non-IANA-hello,omitempty"`
	HelloInterval    int             `json:"hello-interval,omitempty"`
}

type ConfigProtocolsRsvpPath map[string]struct {
	Mpls  *ConfigProtocolsRsvpPathMpls  `json:"mpls,omitempty"`
	Gmpls *ConfigProtocolsRsvpPathGmpls `json:".gmpls,omitempty"`
}

type ConfigProtocolsRsvpPathMpls struct {
	Loose      IP                                     `json:"loose,omitempty"`
	Unnumbered *ConfigProtocolsRsvpPathMplsUnnumbered `json:".unnumbered,omitempty"`
	Strict     IP                                     `json:"strict,omitempty"`
	StrictHop  IP                                     `json:".strict-hop,omitempty"`
}

type ConfigProtocolsRsvpPathMplsUnnumbered map[string]struct {
	LinkId IPv4 `json:"link-id,omitempty"`
}

type ConfigProtocolsRsvpPathGmpls struct {
	StrictHop  IP                                      `json:"strict-hop,omitempty"`
	Unnumbered *ConfigProtocolsRsvpPathGmplsUnnumbered `json:"unnumbered,omitempty"`
	Strict     IP                                      `json:".strict,omitempty"`
	Loose      IP                                      `json:".loose,omitempty"`
}

type ConfigProtocolsRsvpPathGmplsUnnumbered map[string]struct {
	LinkId IPv4 `json:"link-id,omitempty"`
}

type ConfigProtocolsRsvpGracefulRestart struct {
	Enable       json.RawMessage `json:"enable,omitempty"`
	RestartTime  int             `json:"restart-time,omitempty"`
	RecoveryTime int             `json:"recovery-time,omitempty"`
}

type ConfigProtocolsRsvpTrunk map[string]struct {
	Gmpls *ConfigProtocolsRsvpTrunkGmpls `json:".gmpls,omitempty"`
	Ipv4  *ConfigProtocolsRsvpTrunkIpv4  `json:"ipv4,omitempty"`
	Ipv6  *ConfigProtocolsRsvpTrunkIpv6  `json:".ipv6,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmpls struct {
	ExtTunnelId        IP                                          `json:"ext-tunnel-id,omitempty"`
	LspMetric          *ConfigProtocolsRsvpTrunkGmplsLspMetric     `json:"lsp-metric,omitempty"`
	EnableIgpShortcut  json.RawMessage                             `json:".enable-igp-shortcut,omitempty"`
	Capability         *ConfigProtocolsRsvpTrunkGmplsCapability    `json:"capability,omitempty"`
	From               IP                                          `json:"from,omitempty"`
	Gpid               *ConfigProtocolsRsvpTrunkGmplsGpid          `json:"gpid,omitempty"`
	RsvpTrunkRestart   json.RawMessage                             `json:"rsvp-trunk-restart,omitempty"`
	GmplsLabelSet      *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSet `json:"gmpls-label-set,omitempty"`
	Direction          *ConfigProtocolsRsvpTrunkGmplsDirection     `json:"direction,omitempty"`
	UpdateType         *ConfigProtocolsRsvpTrunkGmplsUpdateType    `json:"update-type,omitempty"`
	DisableIgpShortcut json.RawMessage                             `json:".disable-igp-shortcut,omitempty"`
	Primary            *ConfigProtocolsRsvpTrunkGmplsPrimary       `json:"primary,omitempty"`
	To                 IP                                          `json:"to,omitempty"`
	Secondary          *ConfigProtocolsRsvpTrunkGmplsSecondary     `json:"secondary,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsLspMetric struct {
	Relative int `json:"relative,omitempty"`
	Absolute int `json:"absolute,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsCapability struct {
	Psc1  json.RawMessage `json:"psc-1,omitempty"`
	PbbTe json.RawMessage `json:"pbb-te,omitempty"`
	Psc4  json.RawMessage `json:"psc-4,omitempty"`
	Psc3  json.RawMessage `json:"psc-3,omitempty"`
	Psc2  json.RawMessage `json:"psc-2,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGpid struct {
	Ethernet json.RawMessage `json:"ethernet,omitempty"`
	Ipv4     json.RawMessage `json:"ipv4,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSet struct {
	Range  *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRange  `json:"range,omitempty"`
	Packet *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacket `json:"packet,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRange struct {
	StartRange *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetRangeStartRange map[string]struct {
	EndRange int `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacket struct {
	Range *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRange `json:"range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRange struct {
	StartRange *ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsGmplsLabelSetPacketRangeStartRange map[string]struct {
	EndRange int `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsDirection struct {
	Bidirectional  json.RawMessage `json:"bidirectional,omitempty"`
	Unidirectional json.RawMessage `json:"unidirectional,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsUpdateType struct {
	MakeBeforeBreak json.RawMessage `json:"make-before-break,omitempty"`
	BreakBeforeMake json.RawMessage `json:"break-before-make,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimary struct {
	Traffic           *ConfigProtocolsRsvpTrunkGmplsPrimaryTraffic       `json:"traffic,omitempty"`
	Bandwidth         int                                                `json:"bandwidth,omitempty"`
	SetupPriority     int                                                `json:"setup-priority,omitempty"`
	Record            json.RawMessage                                    `json:"record,omitempty"`
	IncludeAny        string                                             `json:"include-any,omitempty"`
	Affinity          json.RawMessage                                    `json:"affinity,omitempty"`
	ReuseRouteRecord  json.RawMessage                                    `json:"reuse-route-record,omitempty"`
	ElspPreconfigured json.RawMessage                                    `json:"elsp-preconfigured,omitempty"`
	Path              string                                             `json:"path,omitempty"`
	HoldPriority      int                                                `json:"hold-priority,omitempty"`
	HopLimit          int                                                `json:"hop-limit,omitempty"`
	Cspf              json.RawMessage                                    `json:"cspf,omitempty"`
	LabelRecord       json.RawMessage                                    `json:"label-record,omitempty"`
	NoAffinity        json.RawMessage                                    `json:"no-affinity,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkGmplsPrimaryProtection    `json:"protection,omitempty"`
	RetryLimit        int                                                `json:"retry-limit,omitempty"`
	CspfRetryTimer    int                                                `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                             `json:"class-type,omitempty"`
	ElspSignaled      json.RawMessage                                    `json:"elsp-signaled,omitempty"`
	LocalProtection   json.RawMessage                                    `json:"local-protection,omitempty"`
	ClassToExpBit     *ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkGmplsPrimaryFilter        `json:"filter,omitempty"`
	ExplicitLabel     *ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel `json:"explicit-label,omitempty"`
	CspfRetryLimit    int                                                `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                             `json:"exclude-any,omitempty"`
	RetryTimer        int                                                `json:"retry-timer,omitempty"`
	NoRecord          json.RawMessage                                    `json:"no-record,omitempty"`
	Llsp              string                                             `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryTraffic struct {
	ControlledLoad json.RawMessage `json:"controlled-load,omitempty"`
	Guaranteed     json.RawMessage `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryProtection struct {
	Unprotected         json.RawMessage `json:"unprotected,omitempty"`
	DedicatedOneToOne   json.RawMessage `json:"dedicated-one-to-one,omitempty"`
	Shared              json.RawMessage `json:"shared,omitempty"`
	ExtraTraffic        json.RawMessage `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne json.RawMessage `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             json.RawMessage `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryClassToExpBit map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryFilter struct {
	SharedExplicit json.RawMessage `json:"shared-explicit,omitempty"`
	Fixed          json.RawMessage `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabel map[string]struct {
	Reverse json.RawMessage                                          `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward json.RawMessage                                          `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsPrimaryExplicitLabelPacket struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondary struct {
	Traffic           *ConfigProtocolsRsvpTrunkGmplsSecondaryTraffic       `json:"traffic,omitempty"`
	Bandwidth         int                                                  `json:"bandwidth,omitempty"`
	SetupPriority     int                                                  `json:"setup-priority,omitempty"`
	Record            json.RawMessage                                      `json:"record,omitempty"`
	IncludeAny        string                                               `json:"include-any,omitempty"`
	Affinity          json.RawMessage                                      `json:"affinity,omitempty"`
	ReuseRouteRecord  json.RawMessage                                      `json:"reuse-route-record,omitempty"`
	ElspPreconfigured json.RawMessage                                      `json:"elsp-preconfigured,omitempty"`
	Path              string                                               `json:"path,omitempty"`
	HoldPriority      int                                                  `json:"hold-priority,omitempty"`
	HopLimit          int                                                  `json:"hop-limit,omitempty"`
	Cspf              json.RawMessage                                      `json:"cspf,omitempty"`
	LabelRecord       json.RawMessage                                      `json:"label-record,omitempty"`
	NoAffinity        json.RawMessage                                      `json:"no-affinity,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkGmplsSecondaryProtection    `json:"protection,omitempty"`
	RetryLimit        int                                                  `json:"retry-limit,omitempty"`
	CspfRetryTimer    int                                                  `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                               `json:"class-type,omitempty"`
	ElspSignaled      json.RawMessage                                      `json:"elsp-signaled,omitempty"`
	LocalProtection   json.RawMessage                                      `json:"local-protection,omitempty"`
	ClassToExpBit     *ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkGmplsSecondaryFilter        `json:"filter,omitempty"`
	ExplicitLabel     *ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel `json:"explicit-label,omitempty"`
	CspfRetryLimit    int                                                  `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                               `json:"exclude-any,omitempty"`
	RetryTimer        int                                                  `json:"retry-timer,omitempty"`
	NoRecord          json.RawMessage                                      `json:"no-record,omitempty"`
	Llsp              string                                               `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryTraffic struct {
	ControlledLoad json.RawMessage `json:"controlled-load,omitempty"`
	Guaranteed     json.RawMessage `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryProtection struct {
	Unprotected         json.RawMessage `json:"unprotected,omitempty"`
	DedicatedOneToOne   json.RawMessage `json:"dedicated-one-to-one,omitempty"`
	Shared              json.RawMessage `json:"shared,omitempty"`
	ExtraTraffic        json.RawMessage `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne json.RawMessage `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             json.RawMessage `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryClassToExpBit map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryFilter struct {
	SharedExplicit json.RawMessage `json:"shared-explicit,omitempty"`
	Fixed          json.RawMessage `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabel map[string]struct {
	Reverse json.RawMessage                                            `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward json.RawMessage                                            `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkGmplsSecondaryExplicitLabelPacket struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4 struct {
	ExtTunnelId       IP                                         `json:"ext-tunnel-id,omitempty"`
	LspMetric         *ConfigProtocolsRsvpTrunkIpv4LspMetric     `json:"lsp-metric,omitempty"`
	From              IPv4                                       `json:"from,omitempty"`
	RsvpTrunkRestart  json.RawMessage                            `json:".rsvp-trunk-restart,omitempty"`
	Capability        *ConfigProtocolsRsvpTrunkIpv4Capability    `json:".capability,omitempty"`
	Direction         *ConfigProtocolsRsvpTrunkIpv4Direction     `json:".direction,omitempty"`
	MapRoute          *ConfigProtocolsRsvpTrunkIpv4MapRoute      `json:"map-route,omitempty"`
	UpdateType        string                                     `json:"update-type,omitempty"`
	Primary           *ConfigProtocolsRsvpTrunkIpv4Primary       `json:"primary,omitempty"`
	To                IPv4                                       `json:"to,omitempty"`
	EnableIgpShortcut json.RawMessage                            `json:"enable-igp-shortcut,omitempty"`
	Secondary         *ConfigProtocolsRsvpTrunkIpv4Secondary     `json:"secondary,omitempty"`
	GmplsLabelSet     *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSet `json:".gmpls-label-set,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4LspMetric struct {
	Relative int `json:"relative,omitempty"`
	Absolute int `json:"absolute,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Capability struct {
	Psc1 json.RawMessage `json:"psc-1,omitempty"`
	Psc4 json.RawMessage `json:"psc-4,omitempty"`
	Psc3 json.RawMessage `json:"psc-3,omitempty"`
	Psc2 json.RawMessage `json:"psc-2,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Direction struct {
	Bidirectional  json.RawMessage `json:"bidirectional,omitempty"`
	Unidirectional json.RawMessage `json:"unidirectional,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4MapRoute map[string]struct {
	Class string `json:"class,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Primary struct {
	Traffic           string                                            `json:"traffic,omitempty"`
	Bandwidth         string                                            `json:"bandwidth,omitempty"`
	SetupPriority     int                                               `json:"setup-priority,omitempty"`
	Record            json.RawMessage                                   `json:"record,omitempty"`
	IncludeAny        string                                            `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv4PrimaryProtection    `json:".protection,omitempty"`
	ReuseRouteRecord  json.RawMessage                                   `json:"reuse-route-record,omitempty"`
	ElspPreconfigured json.RawMessage                                   `json:"elsp-preconfigured,omitempty"`
	Path              string                                            `json:"path,omitempty"`
	ExplicitLabel     *ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel `json:".explicit-label,omitempty"`
	ClassToExp        *ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp    `json:"class-to-exp,omitempty"`
	HoldPriority      int                                               `json:"hold-priority,omitempty"`
	HopLimit          int                                               `json:"hop-limit,omitempty"`
	Cspf              json.RawMessage                                   `json:"cspf,omitempty"`
	LabelRecord       json.RawMessage                                   `json:"label-record,omitempty"`
	NoAffinity        json.RawMessage                                   `json:"no-affinity,omitempty"`
	RetryLimit        int                                               `json:"retry-limit,omitempty"`
	CspfRetryTimer    int                                               `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                            `json:"class-type,omitempty"`
	NoRecord          json.RawMessage                                   `json:".no-record,omitempty"`
	ElspSignaled      json.RawMessage                                   `json:"elsp-signaled,omitempty"`
	LocalProtection   json.RawMessage                                   `json:"local-protection,omitempty"`
	Filter            string                                            `json:"filter,omitempty"`
	CspfRetryLimit    int                                               `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                            `json:"exclude-any,omitempty"`
	RetryTimer        int                                               `json:"retry-timer,omitempty"`
	Llsp              string                                            `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryProtection struct {
	Unprotected         json.RawMessage `json:"unprotected,omitempty"`
	DedicatedOneToOne   json.RawMessage `json:"dedicated-one-to-one,omitempty"`
	Shared              json.RawMessage `json:"shared,omitempty"`
	ExtraTraffic        json.RawMessage `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne json.RawMessage `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             json.RawMessage `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabel map[string]struct {
	Reverse json.RawMessage                                         `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward json.RawMessage                                         `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryExplicitLabelPacket struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4PrimaryClassToExp map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4Secondary struct {
	Traffic           string                                              `json:"traffic,omitempty"`
	Bandwidth         string                                              `json:"bandwidth,omitempty"`
	SetupPriority     int                                                 `json:"setup-priority,omitempty"`
	Record            json.RawMessage                                     `json:"record,omitempty"`
	IncludeAny        string                                              `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv4SecondaryProtection    `json:".protection,omitempty"`
	ReuseRouteRecord  json.RawMessage                                     `json:"reuse-route-record,omitempty"`
	ElspPreconfigured json.RawMessage                                     `json:"elsp-preconfigured,omitempty"`
	Path              string                                              `json:"path,omitempty"`
	ExplicitLabel     *ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel `json:".explicit-label,omitempty"`
	ClassToExp        *ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp    `json:"class-to-exp,omitempty"`
	HoldPriority      int                                                 `json:"hold-priority,omitempty"`
	HopLimit          int                                                 `json:"hop-limit,omitempty"`
	Cspf              json.RawMessage                                     `json:"cspf,omitempty"`
	LabelRecord       json.RawMessage                                     `json:"label-record,omitempty"`
	NoAffinity        json.RawMessage                                     `json:"no-affinity,omitempty"`
	RetryLimit        int                                                 `json:"retry-limit,omitempty"`
	CspfRetryTimer    int                                                 `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                              `json:"class-type,omitempty"`
	NoRecord          json.RawMessage                                     `json:".no-record,omitempty"`
	ElspSignaled      json.RawMessage                                     `json:"elsp-signaled,omitempty"`
	LocalProtection   json.RawMessage                                     `json:"local-protection,omitempty"`
	Filter            string                                              `json:"filter,omitempty"`
	CspfRetryLimit    int                                                 `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                              `json:"exclude-any,omitempty"`
	RetryTimer        int                                                 `json:"retry-timer,omitempty"`
	Llsp              string                                              `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryProtection struct {
	Unprotected         json.RawMessage `json:"unprotected,omitempty"`
	DedicatedOneToOne   json.RawMessage `json:"dedicated-one-to-one,omitempty"`
	Shared              json.RawMessage `json:"shared,omitempty"`
	ExtraTraffic        json.RawMessage `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne json.RawMessage `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             json.RawMessage `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabel map[string]struct {
	Reverse json.RawMessage                                           `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward json.RawMessage                                           `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryExplicitLabelPacket struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4SecondaryClassToExp map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSet struct {
	Range  *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRange  `json:"range,omitempty"`
	Packet *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacket `json:"packet,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRange struct {
	StartRange *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetRangeStartRange map[string]struct {
	EndRange int `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacket struct {
	Range *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRange `json:"range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRange struct {
	StartRange *ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv4GmplsLabelSetPacketRangeStartRange map[string]struct {
	EndRange int `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6 struct {
	ExtTunnelId        IP                                         `json:"ext-tunnel-id,omitempty"`
	LspMetric          *ConfigProtocolsRsvpTrunkIpv6LspMetric     `json:"lsp-metric,omitempty"`
	From               IP                                         `json:"from,omitempty"`
	Ethernet           json.RawMessage                            `json:"ethernet,omitempty"`
	RsvpTrunkRestart   json.RawMessage                            `json:"rsvp-trunk-restart,omitempty"`
	Capability         *ConfigProtocolsRsvpTrunkIpv6Capability    `json:".capability,omitempty"`
	Direction          *ConfigProtocolsRsvpTrunkIpv6Direction     `json:".direction,omitempty"`
	MapRoute           *ConfigProtocolsRsvpTrunkIpv6MapRoute      `json:"map-route,omitempty"`
	DisableIgpShortcut json.RawMessage                            `json:"disable-igp-shortcut,omitempty"`
	UpdateType         *ConfigProtocolsRsvpTrunkIpv6UpdateType    `json:"update-type,omitempty"`
	Primary            *ConfigProtocolsRsvpTrunkIpv6Primary       `json:"primary,omitempty"`
	To                 IP                                         `json:"to,omitempty"`
	EnableIgpShortcut  json.RawMessage                            `json:"enable-igp-shortcut,omitempty"`
	Secondary          *ConfigProtocolsRsvpTrunkIpv6Secondary     `json:"secondary,omitempty"`
	GmplsLabelSet      *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSet `json:".gmpls-label-set,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6LspMetric struct {
	Relative int `json:"relative,omitempty"`
	Absolute int `json:"absolute,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Capability struct {
	Psc1 json.RawMessage `json:"psc-1,omitempty"`
	Psc4 json.RawMessage `json:"psc-4,omitempty"`
	Psc3 json.RawMessage `json:"psc-3,omitempty"`
	Psc2 json.RawMessage `json:"psc-2,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Direction struct {
	Bidirectional  json.RawMessage `json:"bidirectional,omitempty"`
	Unidirectional json.RawMessage `json:"unidirectional,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRoute struct {
	Prefix *ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix `json:"prefix,omitempty"`
	Mask   *ConfigProtocolsRsvpTrunkIpv6MapRouteMask   `json:"mask,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRoutePrefix map[string]struct {
	Mask *ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask `json:"mask,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRoutePrefixMask map[string]struct {
	Class string `json:"class,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6MapRouteMask map[string]struct {
	Class string `json:"class,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6UpdateType struct {
	MakeBeforeBreak json.RawMessage `json:"make-before-break,omitempty"`
	BreakBeforeMake json.RawMessage `json:"break-before-make,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Primary struct {
	Traffic           *ConfigProtocolsRsvpTrunkIpv6PrimaryTraffic       `json:"traffic,omitempty"`
	Bandwidth         int                                               `json:"bandwidth,omitempty"`
	SetupPriority     int                                               `json:"setup-priority,omitempty"`
	Record            json.RawMessage                                   `json:"record,omitempty"`
	IncludeAny        string                                            `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv6PrimaryProtection    `json:".protection,omitempty"`
	Affinity          json.RawMessage                                   `json:"affinity,omitempty"`
	ReuseRouteRecord  json.RawMessage                                   `json:"reuse-route-record,omitempty"`
	ElspPreconfigured json.RawMessage                                   `json:"elsp-preconfigured,omitempty"`
	Path              string                                            `json:"path,omitempty"`
	ExplicitLabel     *ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel `json:".explicit-label,omitempty"`
	HoldPriority      int                                               `json:"hold-priority,omitempty"`
	HopLimit          int                                               `json:"hop-limit,omitempty"`
	Cspf              json.RawMessage                                   `json:"cspf,omitempty"`
	LabelRecord       json.RawMessage                                   `json:"label-record,omitempty"`
	RetryLimit        int                                               `json:"retry-limit,omitempty"`
	CspfRetryTimer    int                                               `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                            `json:"class-type,omitempty"`
	NoRecord          json.RawMessage                                   `json:".no-record,omitempty"`
	ElspSignaled      json.RawMessage                                   `json:"elsp-signaled,omitempty"`
	NoAffinity        json.RawMessage                                   `json:".no-affinity,omitempty"`
	LocalProtection   json.RawMessage                                   `json:"local-protection,omitempty"`
	ClassToExpBit     *ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkIpv6PrimaryFilter        `json:"filter,omitempty"`
	CspfRetryLimit    int                                               `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                            `json:"exclude-any,omitempty"`
	RetryTimer        int                                               `json:"retry-timer,omitempty"`
	Llsp              string                                            `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryTraffic struct {
	ControlledLoad json.RawMessage `json:"controlled-load,omitempty"`
	Guaranteed     json.RawMessage `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryProtection struct {
	Unprotected         json.RawMessage `json:"unprotected,omitempty"`
	DedicatedOneToOne   json.RawMessage `json:"dedicated-one-to-one,omitempty"`
	Shared              json.RawMessage `json:"shared,omitempty"`
	ExtraTraffic        json.RawMessage `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne json.RawMessage `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             json.RawMessage `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabel map[string]struct {
	Reverse json.RawMessage                                         `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward json.RawMessage                                         `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryExplicitLabelPacket struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryClassToExpBit map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6PrimaryFilter struct {
	SharedExplicit json.RawMessage `json:"shared-explicit,omitempty"`
	Fixed          json.RawMessage `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6Secondary struct {
	Traffic           *ConfigProtocolsRsvpTrunkIpv6SecondaryTraffic       `json:"traffic,omitempty"`
	Bandwidth         int                                                 `json:"bandwidth,omitempty"`
	SetupPriority     int                                                 `json:"setup-priority,omitempty"`
	Record            json.RawMessage                                     `json:"record,omitempty"`
	IncludeAny        string                                              `json:"include-any,omitempty"`
	Protection        *ConfigProtocolsRsvpTrunkIpv6SecondaryProtection    `json:".protection,omitempty"`
	Affinity          json.RawMessage                                     `json:"affinity,omitempty"`
	ReuseRouteRecord  json.RawMessage                                     `json:"reuse-route-record,omitempty"`
	ElspPreconfigured json.RawMessage                                     `json:"elsp-preconfigured,omitempty"`
	Path              string                                              `json:"path,omitempty"`
	ExplicitLabel     *ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel `json:".explicit-label,omitempty"`
	HoldPriority      int                                                 `json:"hold-priority,omitempty"`
	HopLimit          int                                                 `json:"hop-limit,omitempty"`
	Cspf              json.RawMessage                                     `json:"cspf,omitempty"`
	LabelRecord       json.RawMessage                                     `json:"label-record,omitempty"`
	RetryLimit        int                                                 `json:"retry-limit,omitempty"`
	CspfRetryTimer    int                                                 `json:"cspf-retry-timer,omitempty"`
	ClassType         string                                              `json:"class-type,omitempty"`
	NoRecord          json.RawMessage                                     `json:".no-record,omitempty"`
	ElspSignaled      json.RawMessage                                     `json:"elsp-signaled,omitempty"`
	NoAffinity        json.RawMessage                                     `json:".no-affinity,omitempty"`
	LocalProtection   json.RawMessage                                     `json:"local-protection,omitempty"`
	ClassToExpBit     *ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit `json:"class-to-exp-bit,omitempty"`
	Filter            *ConfigProtocolsRsvpTrunkIpv6SecondaryFilter        `json:"filter,omitempty"`
	CspfRetryLimit    int                                                 `json:"cspf-retry-limit,omitempty"`
	ExcludeAny        string                                              `json:"exclude-any,omitempty"`
	RetryTimer        int                                                 `json:"retry-timer,omitempty"`
	Llsp              string                                              `json:"llsp,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryTraffic struct {
	ControlledLoad json.RawMessage `json:"controlled-load,omitempty"`
	Guaranteed     json.RawMessage `json:"guaranteed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryProtection struct {
	Unprotected         json.RawMessage `json:"unprotected,omitempty"`
	DedicatedOneToOne   json.RawMessage `json:"dedicated-one-to-one,omitempty"`
	Shared              json.RawMessage `json:"shared,omitempty"`
	ExtraTraffic        json.RawMessage `json:"extra-traffic,omitempty"`
	DedicatedOnePlusOne json.RawMessage `json:"dedicated-one-plus-one,omitempty"`
	Ehanced             json.RawMessage `json:"ehanced,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabel map[string]struct {
	Reverse json.RawMessage                                           `json:"reverse,omitempty"`
	Packet  *ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabelPacket `json:"packet,omitempty"`
	Forward json.RawMessage                                           `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryExplicitLabelPacket struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryClassToExpBit map[string]struct {
	Bit int `json:"bit,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6SecondaryFilter struct {
	SharedExplicit json.RawMessage `json:"shared-explicit,omitempty"`
	Fixed          json.RawMessage `json:"fixed,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSet struct {
	Range  *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRange  `json:"range,omitempty"`
	Packet *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacket `json:"packet,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRange struct {
	StartRange *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetRangeStartRange map[string]struct {
	EndRange int `json:"end_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacket struct {
	Range *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRange `json:"range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRange struct {
	StartRange *ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange `json:"start_range,omitempty"`
}

type ConfigProtocolsRsvpTrunkIpv6GmplsLabelSetPacketRangeStartRange map[string]struct {
	EndRange int `json:"end_range,omitempty"`
}

type ConfigProtocolsVpls struct {
	Interface *ConfigProtocolsVplsInterface `json:"interface,omitempty"`
	FibEntry  *ConfigProtocolsVplsFibEntry  `json:"fib-entry,omitempty"`
	Instance  *ConfigProtocolsVplsInstance  `json:"instance,omitempty"`
}

type ConfigProtocolsVplsInterface map[string]struct {
	VlanInstance *ConfigProtocolsVplsInterfaceVlanInstance `json:"vlan-instance,omitempty"`
	Instance     string                                    `json:"instance,omitempty"`
}

type ConfigProtocolsVplsInterfaceVlanInstance map[string]struct {
	Vlan *ConfigProtocolsVplsInterfaceVlanInstanceVlan `json:"vlan,omitempty"`
}

type ConfigProtocolsVplsInterfaceVlanInstanceVlan map[string]struct {
}

type ConfigProtocolsVplsFibEntry map[string]struct {
	Peer    *ConfigProtocolsVplsFibEntryPeer    `json:"peer,omitempty"`
	SpokeVc *ConfigProtocolsVplsFibEntrySpokeVc `json:".spoke-vc,omitempty"`
}

type ConfigProtocolsVplsFibEntryPeer map[string]struct {
	InLabel *ConfigProtocolsVplsFibEntryPeerInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsVplsFibEntryPeerInLabel map[string]struct {
	OutInterface *ConfigProtocolsVplsFibEntryPeerInLabelOutInterface `json:"out-interface,omitempty"`
}

type ConfigProtocolsVplsFibEntryPeerInLabelOutInterface map[string]struct {
	OutLabel int `json:"out-label,omitempty"`
}

type ConfigProtocolsVplsFibEntrySpokeVc map[string]struct {
	InLabel *ConfigProtocolsVplsFibEntrySpokeVcInLabel `json:"in-label,omitempty"`
}

type ConfigProtocolsVplsFibEntrySpokeVcInLabel map[string]struct {
	OutInterface *ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface `json:"out-interface,omitempty"`
}

type ConfigProtocolsVplsFibEntrySpokeVcInLabelOutInterface map[string]struct {
	OutLabel int `json:"out-label,omitempty"`
}

type ConfigProtocolsVplsInstance map[string]struct {
	Id *ConfigProtocolsVplsInstanceId `json:"id,omitempty"`
}

type ConfigProtocolsVplsInstanceId map[string]struct {
	VplsAcGroup     string                                  `json:"vpls-ac-group,omitempty"`
	VplsPeer        *ConfigProtocolsVplsInstanceIdVplsPeer  `json:"vpls-peer,omitempty"`
	Learning        *ConfigProtocolsVplsInstanceIdLearning  `json:"learning,omitempty"`
	VplsVc          *ConfigProtocolsVplsInstanceIdVplsVc    `json:"vpls-vc,omitempty"`
	VplsDescription string                                  `json:"vpls-description,omitempty"`
	Signaling       *ConfigProtocolsVplsInstanceIdSignaling `json:"signaling,omitempty"`
	VplsType        string                                  `json:"vpls-type,omitempty"`
	VplsMtu         int                                     `json:"vpls-mtu,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeer map[string]struct {
	Manual   json.RawMessage                                `json:"manual,omitempty"`
	TunnelId *ConfigProtocolsVplsInstanceIdVplsPeerTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeerTunnelId map[string]struct {
	Reverse *ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdReverse `json:"reverse,omitempty"`
	Manual  json.RawMessage                                       `json:"manual,omitempty"`
	Forward *ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdForward `json:"forward,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdReverse struct {
	Manual json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsPeerTunnelIdForward struct {
	Manual json.RawMessage `json:"manual,omitempty"`
}

type ConfigProtocolsVplsInstanceIdLearning struct {
	Disable json.RawMessage `json:"disable,omitempty"`
	Limit   int             `json:"limit,omitempty"`
}

type ConfigProtocolsVplsInstanceIdVplsVc map[string]struct {
	Ethernet json.RawMessage `json:"ethernet,omitempty"`
	Vlan     json.RawMessage `json:"vlan,omitempty"`
	Normal   json.RawMessage `json:"normal,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignaling struct {
	Ldp *ConfigProtocolsVplsInstanceIdSignalingLdp `json:"ldp,omitempty"`
	Bgp *ConfigProtocolsVplsInstanceIdSignalingBgp `json:"bgp,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdp struct {
	VplsPeer *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer `json:"vpls-peer,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeer map[string]struct {
	Agi      *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi      `json:"agi,omitempty"`
	TunnelId *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgi map[string]struct {
	Saii *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii `json:"saii,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaii map[string]struct {
	Taii *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii `json:"taii,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaii map[string]struct {
	Normal   json.RawMessage                                                       `json:"normal,omitempty"`
	TunnelId *ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId `json:"tunnel-id,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerAgiSaiiTaiiTunnelId map[string]struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Normal  json.RawMessage `json:"normal,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingLdpVplsPeerTunnelId map[string]struct {
	Reverse json.RawMessage `json:"reverse,omitempty"`
	Forward json.RawMessage `json:"forward,omitempty"`
}

type ConfigProtocolsVplsInstanceIdSignalingBgp struct {
	VeRange     int    `json:"ve-range,omitempty"`
	VeId        int    `json:"ve-id,omitempty"`
	RouteTarget string `json:"route-target,omitempty"`
	Rd          string `json:"rd,omitempty"`
}

type ConfigProtocolsLdp struct {
	LdpOptimization           json.RawMessage                          `json:"ldp-optimization,omitempty"`
	TargetedPeerHelloInterval int                                      `json:"targeted-peer-hello-interval,omitempty"`
	Interface                 *ConfigProtocolsLdpInterface             `json:"interface,omitempty"`
	Neighbor                  *ConfigProtocolsLdpNeighbor              `json:"neighbor,omitempty"`
	MulticastHellos           json.RawMessage                          `json:"multicast-hellos,omitempty"`
	ExplicitNull              json.RawMessage                          `json:"explicit-null,omitempty"`
	ImportBgpRoutes           json.RawMessage                          `json:"import-bgp-routes,omitempty"`
	AdvertiseLabels           *ConfigProtocolsLdpAdvertiseLabels       `json:"advertise-labels,omitempty"`
	KeepaliveTimeout          int                                      `json:"keepalive-timeout,omitempty"`
	PropagateRelease          json.RawMessage                          `json:"propagate-release,omitempty"`
	TransportAddress          *ConfigProtocolsLdpTransportAddress      `json:"transport-address,omitempty"`
	RouterId                  IP                                       `json:"router-id,omitempty"`
	ControlMode               *ConfigProtocolsLdpControlMode           `json:"control-mode,omitempty"`
	LabelRetentionMode        *ConfigProtocolsLdpLabelRetentionMode    `json:"label-retention-mode,omitempty"`
	RequestRetryTimeout       int                                      `json:"request-retry-timeout,omitempty"`
	GracefulRestart           *ConfigProtocolsLdpGracefulRestart       `json:"graceful-restart,omitempty"`
	TargetedPeerHoldTime      int                                      `json:"targeted-peer-hold-time,omitempty"`
	LoopDetectionPathVecCount int                                      `json:"loop-detection-path-vec-count,omitempty"`
	HoldTime                  int                                      `json:"hold-time,omitempty"`
	RequestRetry              json.RawMessage                          `json:"request-retry,omitempty"`
	LoopDetection             json.RawMessage                          `json:"loop-detection,omitempty"`
	TargetedPeer              *ConfigProtocolsLdpTargetedPeer          `json:"targeted-peer,omitempty"`
	GlobalMergeCapability     *ConfigProtocolsLdpGlobalMergeCapability `json:"global-merge-capability,omitempty"`
	KeepaliveInterval         int                                      `json:"keepalive-interval,omitempty"`
	AdvertisementMode         *ConfigProtocolsLdpAdvertisementMode     `json:"advertisement-mode,omitempty"`
	LoopDetectionHopCount     int                                      `json:"loop-detection-hop-count,omitempty"`
	HelloInterval             int                                      `json:"hello-interval,omitempty"`
	PwStatusTlv               json.RawMessage                          `json:"pw-status-tlv,omitempty"`
}

type ConfigProtocolsLdpInterface map[string]struct {
	Enable             *ConfigProtocolsLdpInterfaceEnable             `json:"enable,omitempty"`
	KeepaliveTimeout   int                                            `json:"keepalive-timeout,omitempty"`
	LabelRetentionMode *ConfigProtocolsLdpInterfaceLabelRetentionMode `json:"label-retention-mode,omitempty"`
	HoldTime           int                                            `json:"hold-time,omitempty"`
	KeepaliveInterval  int                                            `json:"keepalive-interval,omitempty"`
	AdvertisementMode  *ConfigProtocolsLdpInterfaceAdvertisementMode  `json:"advertisement-mode,omitempty"`
	HelloInterval      int                                            `json:"hello-interval,omitempty"`
}

type ConfigProtocolsLdpInterfaceEnable struct {
	Both json.RawMessage `json:"both,omitempty"`
	Ipv4 json.RawMessage `json:"ipv4,omitempty"`
	Ipv6 json.RawMessage `json:"ipv6,omitempty"`
}

type ConfigProtocolsLdpInterfaceLabelRetentionMode struct {
	Liberal      json.RawMessage `json:"liberal,omitempty"`
	Conservative json.RawMessage `json:"conservative,omitempty"`
}

type ConfigProtocolsLdpInterfaceAdvertisementMode struct {
	DownstreamOnDemand    json.RawMessage `json:"downstream-on-demand,omitempty"`
	DownstreamUnsolicited json.RawMessage `json:"downstream-unsolicited,omitempty"`
}

type ConfigProtocolsLdpNeighbor map[string]struct {
	Auth *ConfigProtocolsLdpNeighborAuth `json:"auth,omitempty"`
}

type ConfigProtocolsLdpNeighborAuth struct {
	Md5 *ConfigProtocolsLdpNeighborAuthMd5 `json:"md5,omitempty"`
}

type ConfigProtocolsLdpNeighborAuthMd5 struct {
	Password *ConfigProtocolsLdpNeighborAuthMd5Password `json:"password,omitempty"`
}

type ConfigProtocolsLdpNeighborAuthMd5Password map[string]struct {
	Type int `json:"type,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabels struct {
	ForAcl *ConfigProtocolsLdpAdvertiseLabelsForAcl `json:"for-acl,omitempty"`
	For    *ConfigProtocolsLdpAdvertiseLabelsFor    `json:"for,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAcl map[string]struct {
	To *ConfigProtocolsLdpAdvertiseLabelsForAclTo `json:"to,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAclTo struct {
	Any json.RawMessage `json:"any,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsFor struct {
	PeerAcl *ConfigProtocolsLdpAdvertiseLabelsForPeerAcl `json:"peer-acl,omitempty"`
	Any     *ConfigProtocolsLdpAdvertiseLabelsForAny     `json:"any,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForPeerAcl map[string]struct {
	To *ConfigProtocolsLdpAdvertiseLabelsForPeerAclTo `json:"to,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForPeerAclTo struct {
	PeerAcl string          `json:"peer-acl,omitempty"`
	Any     json.RawMessage `json:"any,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAny struct {
	To *ConfigProtocolsLdpAdvertiseLabelsForAnyTo `json:"to,omitempty"`
}

type ConfigProtocolsLdpAdvertiseLabelsForAnyTo struct {
	None json.RawMessage `json:"none,omitempty"`
}

type ConfigProtocolsLdpTransportAddress struct {
	Ipv4 *ConfigProtocolsLdpTransportAddressIpv4 `json:"ipv4,omitempty"`
	Ipv6 *ConfigProtocolsLdpTransportAddressIpv6 `json:".ipv6,omitempty"`
}

type ConfigProtocolsLdpTransportAddressIpv4 map[string]struct {
	Labelspace string `json:"labelspace,omitempty"`
}

type ConfigProtocolsLdpTransportAddressIpv6 map[string]struct {
	Labelspace string `json:"labelspace,omitempty"`
}

type ConfigProtocolsLdpControlMode struct {
	Independent json.RawMessage `json:"independent,omitempty"`
	Ordered     json.RawMessage `json:"ordered,omitempty"`
}

type ConfigProtocolsLdpLabelRetentionMode struct {
	Liberal      json.RawMessage `json:"liberal,omitempty"`
	Conservative json.RawMessage `json:"conservative,omitempty"`
}

type ConfigProtocolsLdpGracefulRestart struct {
	Enable  json.RawMessage                          `json:"enable,omitempty"`
	Disable json.RawMessage                          `json:"disable,omitempty"`
	Timers  *ConfigProtocolsLdpGracefulRestartTimers `json:"timers,omitempty"`
}

type ConfigProtocolsLdpGracefulRestartTimers struct {
	MaxRecovery      int `json:"max-recovery,omitempty"`
	NeighborLiveness int `json:"neighbor-liveness,omitempty"`
}

type ConfigProtocolsLdpTargetedPeer struct {
	Ipv4 *ConfigProtocolsLdpTargetedPeerIpv4 `json:"ipv4,omitempty"`
	Ipv6 IPv6                                `json:".ipv6,omitempty"`
}

type ConfigProtocolsLdpTargetedPeerIpv4 map[string]struct {
}

type ConfigProtocolsLdpGlobalMergeCapability struct {
	NonMergeCapable json.RawMessage `json:"non-merge-capable,omitempty"`
	MergeCapable    json.RawMessage `json:"merge-capable,omitempty"`
}

type ConfigProtocolsLdpAdvertisementMode struct {
	DownstreamOnDemand    json.RawMessage `json:"downstream-on-demand,omitempty"`
	DownstreamUnsolicited json.RawMessage `json:"downstream-unsolicited,omitempty"`
}

type ConfigProtocolsIgmpProxy struct {
	Disable           json.RawMessage                    `json:"disable,omitempty"`
	Interface         *ConfigProtocolsIgmpProxyInterface `json:"interface,omitempty"`
	DisableQuickleave json.RawMessage                    `json:"disable-quickleave,omitempty"`
}

type ConfigProtocolsIgmpProxyInterface map[string]struct {
	Whitelist IPv4Net `json:"whitelist,omitempty"`
	Role      string  `json:"role,omitempty"`
	AltSubnet IPv4Net `json:"alt-subnet,omitempty"`
	Threshold int     `json:"threshold,omitempty"`
}

type ConfigProtocolsBgp map[string]struct {
	Neighbor         *ConfigProtocolsBgpNeighbor         `json:"neighbor,omitempty"`
	Timers           *ConfigProtocolsBgpTimers           `json:"timers,omitempty"`
	MaximumPaths     *ConfigProtocolsBgpMaximumPaths     `json:"maximum-paths,omitempty"`
	Network          *ConfigProtocolsBgpNetwork          `json:"network,omitempty"`
	AggregateAddress *ConfigProtocolsBgpAggregateAddress `json:"aggregate-address,omitempty"`
	AddressFamily    *ConfigProtocolsBgpAddressFamily    `json:"address-family,omitempty"`
	Dampening        *ConfigProtocolsBgpDampening        `json:"dampening,omitempty"`
	Parameters       *ConfigProtocolsBgpParameters       `json:"parameters,omitempty"`
	Redistribute     *ConfigProtocolsBgpRedistribute     `json:"redistribute,omitempty"`
	PeerGroup        *ConfigProtocolsBgpPeerGroup        `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpNeighbor map[string]struct {
	Weight                       int                                             `json:"weight,omitempty"`
	NoActivate                   json.RawMessage                                 `json:"no-activate,omitempty"`
	EbgpMultihop                 int                                             `json:"ebgp-multihop,omitempty"`
	Password                     string                                          `json:"password,omitempty"`
	MaximumPrefix                int                                             `json:"maximum-prefix,omitempty"`
	FilterList                   *ConfigProtocolsBgpNeighborFilterList           `json:"filter-list,omitempty"`
	AllowasIn                    *ConfigProtocolsBgpNeighborAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient         json.RawMessage                                 `json:"route-reflector-client,omitempty"`
	OverrideCapability           json.RawMessage                                 `json:"override-capability,omitempty"`
	Shutdown                     json.RawMessage                                 `json:"shutdown,omitempty"`
	StrictCapabilityMatch        json.RawMessage                                 `json:"strict-capability-match,omitempty"`
	DisableSendCommunity         *ConfigProtocolsBgpNeighborDisableSendCommunity `json:"disable-send-community,omitempty"`
	Timers                       *ConfigProtocolsBgpNeighborTimers               `json:"timers,omitempty"`
	DefaultOriginate             *ConfigProtocolsBgpNeighborDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient            json.RawMessage                                 `json:"route-server-client,omitempty"`
	Capability                   *ConfigProtocolsBgpNeighborCapability           `json:"capability,omitempty"`
	UpdateSource                 string                                          `json:"update-source,omitempty"`
	TtlSecurity                  *ConfigProtocolsBgpNeighborTtlSecurity          `json:"ttl-security,omitempty"`
	UnsuppressMap                string                                          `json:"unsuppress-map,omitempty"`
	FallOver                     *ConfigProtocolsBgpNeighborFallOver             `json:"fall-over,omitempty"`
	Passive                      json.RawMessage                                 `json:"passive,omitempty"`
	AddressFamily                *ConfigProtocolsBgpNeighborAddressFamily        `json:"address-family,omitempty"`
	Description                  string                                          `json:"description,omitempty"`
	SoftReconfiguration          *ConfigProtocolsBgpNeighborSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	LocalAs                      *ConfigProtocolsBgpNeighborLocalAs              `json:"local-as,omitempty"`
	AttributeUnchanged           *ConfigProtocolsBgpNeighborAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap                     *ConfigProtocolsBgpNeighborRouteMap             `json:"route-map,omitempty"`
	RemoteAs                     int                                             `json:"remote-as,omitempty"`
	NexthopSelf                  json.RawMessage                                 `json:"nexthop-self,omitempty"`
	DisableConnectedCheck        json.RawMessage                                 `json:"disable-connected-check,omitempty"`
	DisableCapabilityNegotiation json.RawMessage                                 `json:"disable-capability-negotiation,omitempty"`
	Port                         int                                             `json:"port,omitempty"`
	AdvertisementInterval        int                                             `json:"advertisement-interval,omitempty"`
	RemovePrivateAs              json.RawMessage                                 `json:"remove-private-as,omitempty"`
	PrefixList                   *ConfigProtocolsBgpNeighborPrefixList           `json:"prefix-list,omitempty"`
	DistributeList               *ConfigProtocolsBgpNeighborDistributeList       `json:"distribute-list,omitempty"`
	PeerGroup                    string                                          `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpNeighborFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborAllowasIn struct {
	Number int `json:"number,omitempty"`
}

type ConfigProtocolsBgpNeighborDisableSendCommunity struct {
	Standard json.RawMessage `json:"standard,omitempty"`
	Extended json.RawMessage `json:"extended,omitempty"`
}

type ConfigProtocolsBgpNeighborTimers struct {
	Holdtime  int `json:"holdtime,omitempty"`
	Keepalive int `json:"keepalive,omitempty"`
	Connect   int `json:"connect,omitempty"`
}

type ConfigProtocolsBgpNeighborDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpNeighborCapability struct {
	Dynamic         json.RawMessage                          `json:"dynamic,omitempty"`
	Orf             *ConfigProtocolsBgpNeighborCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart json.RawMessage                          `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpNeighborCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpNeighborCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpNeighborCapabilityOrfPrefixList struct {
	Both    json.RawMessage `json:"both,omitempty"`
	Receive json.RawMessage `json:"receive,omitempty"`
	Send    json.RawMessage `json:"send,omitempty"`
}

type ConfigProtocolsBgpNeighborTtlSecurity struct {
	Hops int `json:"hops,omitempty"`
}

type ConfigProtocolsBgpNeighborFallOver struct {
	Bfd *ConfigProtocolsBgpNeighborFallOverBfd `json:"bfd,omitempty"`
}

type ConfigProtocolsBgpNeighborFallOverBfd struct {
	Multihop json.RawMessage `json:"multihop,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamily struct {
	Ipv6Unicast *ConfigProtocolsBgpNeighborAddressFamilyIpv6Unicast `json:"ipv6-unicast,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6Unicast struct {
	MaximumPrefix        int                                                                     `json:"maximum-prefix,omitempty"`
	FilterList           *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastFilterList           `json:"filter-list,omitempty"`
	AllowasIn            *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient json.RawMessage                                                         `json:"route-reflector-client,omitempty"`
	NexthopLocal         *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastNexthopLocal         `json:"nexthop-local,omitempty"`
	DisableSendCommunity *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate     *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient    json.RawMessage                                                         `json:"route-server-client,omitempty"`
	Capability           *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapability           `json:"capability,omitempty"`
	UnsuppressMap        string                                                                  `json:"unsuppress-map,omitempty"`
	SoftReconfiguration  *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	AttributeUnchanged   *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap             *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastRouteMap             `json:"route-map,omitempty"`
	NexthopSelf          json.RawMessage                                                         `json:"nexthop-self,omitempty"`
	RemovePrivateAs      json.RawMessage                                                         `json:"remove-private-as,omitempty"`
	PrefixList           *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastPrefixList           `json:"prefix-list,omitempty"`
	DistributeList       *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDistributeList       `json:"distribute-list,omitempty"`
	PeerGroup            string                                                                  `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAllowasIn struct {
	Number int `json:"number,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastNexthopLocal struct {
	Unchanged json.RawMessage `json:"unchanged,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDisableSendCommunity struct {
	Standard json.RawMessage `json:"standard,omitempty"`
	Extended json.RawMessage `json:"extended,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapability struct {
	Orf             *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart json.RawMessage                                                  `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastCapabilityOrfPrefixList struct {
	Receive json.RawMessage `json:"receive,omitempty"`
	Send    json.RawMessage `json:"send,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastSoftReconfiguration struct {
	Inbound json.RawMessage `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpNeighborAddressFamilyIpv6UnicastAttributeUnchanged struct {
	AsPath  json.RawMessage `json:"as-path,omitempty"`
	NextHop json.RawMessage `json:"next-hop,omitempty"`
	Med     json.RawMessage `json:"med,omitempty"`
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
	Inbound json.RawMessage `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpNeighborLocalAs map[string]struct {
	NoPrepend json.RawMessage `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpNeighborAttributeUnchanged struct {
	AsPath  json.RawMessage `json:"as-path,omitempty"`
	NextHop json.RawMessage `json:"next-hop,omitempty"`
	Med     json.RawMessage `json:"med,omitempty"`
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
	Word   *ConfigProtocolsBgpNeighborDistributeListWord `json:"word,omitempty"`
	Export int                                           `json:"export,omitempty"`
	Import int                                           `json:"import,omitempty"`
}

type ConfigProtocolsBgpNeighborDistributeListWord map[string]struct {
	Out json.RawMessage `json:"out,omitempty"`
	In  json.RawMessage `json:"in,omitempty"`
}

type ConfigProtocolsBgpTimers struct {
	Holdtime  int `json:"holdtime,omitempty"`
	Keepalive int `json:"keepalive,omitempty"`
}

type ConfigProtocolsBgpMaximumPaths struct {
	Ibgp int `json:"ibgp,omitempty"`
	Ebgp int `json:"ebgp,omitempty"`
}

type ConfigProtocolsBgpNetwork map[string]struct {
	Backdoor json.RawMessage `json:"backdoor,omitempty"`
	RouteMap string          `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAggregateAddress map[string]struct {
	SummaryOnly json.RawMessage `json:"summary-only,omitempty"`
	AsSet       json.RawMessage `json:"as-set,omitempty"`
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
	Ipv4 *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4 `json:"ipv4,omitempty"`
	Ipv6 *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6 `json:"ipv6,omitempty"`
	Tag  *ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag  `json:"tag,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv4 map[string]struct {
	Activate json.RawMessage `json:"activate,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborIpv6 map[string]struct {
	Activate json.RawMessage `json:"activate,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyL2vpnVplsNeighborTag map[string]struct {
	Activate json.RawMessage `json:"activate,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4Unicast struct {
	Vrf *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf `json:"vrf,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrf map[string]struct {
	Neighbor     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor     `json:"neighbor,omitempty"`
	Network      *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork      `json:"network,omitempty"`
	Parameters   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParameters   `json:"parameters,omitempty"`
	Redistribute *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistribute `json:"redistribute,omitempty"`
	PeerGroup    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup    `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighbor map[string]struct {
	Weight                int                                                                       `json:"weight,omitempty"`
	EbgpMultihop          int                                                                       `json:"ebgp-multihop,omitempty"`
	MaximumPrefix         int                                                                       `json:"maximum-prefix,omitempty"`
	FilterList            *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborFilterList          `json:"filter-list,omitempty"`
	AllowasIn             *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAllowasIn           `json:"allowas-in,omitempty"`
	RouteReflectorClient  json.RawMessage                                                           `json:"route-reflector-client,omitempty"`
	Shutdown              json.RawMessage                                                           `json:"shutdown,omitempty"`
	Timers                *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborTimers              `json:"timers,omitempty"`
	DefaultOriginate      *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDefaultOriginate    `json:"default-originate,omitempty"`
	Capability            *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapability          `json:"capability,omitempty"`
	UpdateSource          string                                                                    `json:"update-source,omitempty"`
	UnsuppressMap         string                                                                    `json:"unsuppress-map,omitempty"`
	Passive               json.RawMessage                                                           `json:"passive,omitempty"`
	Description           string                                                                    `json:"description,omitempty"`
	SoftReconfiguration   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborSoftReconfiguration `json:"soft-reconfiguration,omitempty"`
	LocalAs               *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs             `json:"local-as,omitempty"`
	AttributeUnchanged    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAttributeUnchanged  `json:"attribute-unchanged,omitempty"`
	RouteMap              *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborRouteMap            `json:"route-map,omitempty"`
	RemoteAs              int                                                                       `json:"remote-as,omitempty"`
	Activate              json.RawMessage                                                           `json:"activate,omitempty"`
	Port                  int                                                                       `json:"port,omitempty"`
	AdvertisementInterval int                                                                       `json:"advertisement-interval,omitempty"`
	RemovePrivateAs       json.RawMessage                                                           `json:"remove-private-as,omitempty"`
	PrefixList            *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborPrefixList          `json:"prefix-list,omitempty"`
	DistributeList        *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeList      `json:"distribute-list,omitempty"`
	PeerGroup             string                                                                    `json:"peer-group,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAllowasIn struct {
	Number int `json:"number,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborTimers struct {
	Holdtime  int `json:"holdtime,omitempty"`
	Keepalive int `json:"keepalive,omitempty"`
	Connect   int `json:"connect,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapability struct {
	Dynamic         json.RawMessage                                                     `json:"dynamic,omitempty"`
	Orf             *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart json.RawMessage                                                     `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborCapabilityOrfPrefixList struct {
	Both    json.RawMessage `json:"both,omitempty"`
	Receive json.RawMessage `json:"receive,omitempty"`
	Send    json.RawMessage `json:"send,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborSoftReconfiguration struct {
	Inbound json.RawMessage `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborLocalAs map[string]struct {
	NoPrepend json.RawMessage `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborAttributeUnchanged struct {
	AsPath  json.RawMessage `json:"as-path,omitempty"`
	NextHop json.RawMessage `json:"next-hop,omitempty"`
	Med     json.RawMessage `json:"med,omitempty"`
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
	Word *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord `json:"word,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNeighborDistributeListWord map[string]struct {
	Out json.RawMessage `json:"out,omitempty"`
	In  json.RawMessage `json:"in,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfNetwork map[string]struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParameters struct {
	Dampening     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersDampening     `json:"dampening,omitempty"`
	Confederation *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersConfederation `json:"confederation,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersDampening struct {
	MaxSuppressTime   int `json:"max-suppress-time,omitempty"`
	StartSuppressTime int `json:"start-suppress-time,omitempty"`
	ReUse             int `json:"re-use,omitempty"`
	HalfLife          int `json:"half-life,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfParametersConfederation struct {
	Identifier int `json:"identifier,omitempty"`
	Peers      int `json:"peers,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistribute struct {
	Rip       *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeStatic    `json:"static,omitempty"`
	Kernel    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeKernel    `json:"kernel,omitempty"`
	Ospf      *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeRip struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfRedistributeOspf struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroup map[string]struct {
	Weight                       int                                                                         `json:"weight,omitempty"`
	EbgpMultihop                 int                                                                         `json:"ebgp-multihop,omitempty"`
	MaximumPrefix                int                                                                         `json:"maximum-prefix,omitempty"`
	FilterList                   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupFilterList           `json:"filter-list,omitempty"`
	AllowasIn                    *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient         json.RawMessage                                                             `json:"route-reflector-client,omitempty"`
	OverrideCapability           json.RawMessage                                                             `json:"override-capability,omitempty"`
	Shutdown                     json.RawMessage                                                             `json:"shutdown,omitempty"`
	DisableSendCommunity         *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate             *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDefaultOriginate     `json:"default-originate,omitempty"`
	Capability                   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapability           `json:"capability,omitempty"`
	UpdateSource                 string                                                                      `json:"update-source,omitempty"`
	UnsuppressMap                string                                                                      `json:"unsuppress-map,omitempty"`
	Passive                      json.RawMessage                                                             `json:"passive,omitempty"`
	Timers                       *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupTimers               `json:".timers,omitempty"`
	Description                  string                                                                      `json:"description,omitempty"`
	SoftReconfiguration          *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	LocalAs                      *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs              `json:"local-as,omitempty"`
	AttributeUnchanged           *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap                     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupRouteMap             `json:"route-map,omitempty"`
	RemoteAs                     int                                                                         `json:"remote-as,omitempty"`
	DisableConnectedCheck        json.RawMessage                                                             `json:"disable-connected-check,omitempty"`
	DisableCapabilityNegotiation json.RawMessage                                                             `json:"disable-capability-negotiation,omitempty"`
	RemovePrivateAs              json.RawMessage                                                             `json:"remove-private-as,omitempty"`
	PrefixList                   *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupPrefixList           `json:"prefix-list,omitempty"`
	DistributeList               *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDistributeList       `json:"distribute-list,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAllowasIn struct {
	Number int `json:"number,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDisableSendCommunity struct {
	Standard json.RawMessage `json:"standard,omitempty"`
	Extended json.RawMessage `json:"extended,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapability struct {
	Dynamic json.RawMessage                                                      `json:"dynamic,omitempty"`
	Orf     *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrf `json:"orf,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupCapabilityOrfPrefixList struct {
	Receive json.RawMessage `json:"receive,omitempty"`
	Send    json.RawMessage `json:"send,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupTimers struct {
	Holdtime  int `json:"holdtime,omitempty"`
	Keepalive int `json:"keepalive,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupSoftReconfiguration struct {
	Inbound json.RawMessage `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupLocalAs map[string]struct {
	NoPrepend json.RawMessage `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv4UnicastVrfPeerGroupAttributeUnchanged struct {
	AsPath  json.RawMessage `json:"as-path,omitempty"`
	NextHop json.RawMessage `json:"next-hop,omitempty"`
	Med     json.RawMessage `json:"med,omitempty"`
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
	Export int `json:"export,omitempty"`
	Import int `json:"import,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6Unicast struct {
	Network          *ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork          `json:"network,omitempty"`
	AggregateAddress *ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress `json:"aggregate-address,omitempty"`
	Redistribute     *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistribute     `json:"redistribute,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastNetwork map[string]struct {
	RouteMap  string `json:"route-map,omitempty"`
	PathLimit int    `json:"path-limit,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastAggregateAddress map[string]struct {
	SummaryOnly json.RawMessage `json:"summary-only,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistribute struct {
	Connected *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeConnected `json:"connected,omitempty"`
	Ripng     *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeRipng     `json:"ripng,omitempty"`
	Static    *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeStatic    `json:"static,omitempty"`
	Ospfv3    *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeOspfv3    `json:"ospfv3,omitempty"`
	Kernel    *ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeRipng struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeOspfv3 struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpAddressFamilyIpv6UnicastRedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpDampening struct {
	RouteMap string                               `json:"route-map,omitempty"`
	HalfLife *ConfigProtocolsBgpDampeningHalfLife `json:"half-life,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLife map[string]struct {
	ReuseRoute *ConfigProtocolsBgpDampeningHalfLifeReuseRoute `json:"reuse-route,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLifeReuseRoute map[string]struct {
	SupRoute *ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute `json:"sup-route,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRoute map[string]struct {
	Time *ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime `json:"time,omitempty"`
}

type ConfigProtocolsBgpDampeningHalfLifeReuseRouteSupRouteTime map[string]struct {
	HalfTime int `json:"half-time,omitempty"`
}

type ConfigProtocolsBgpParameters struct {
	ClusterId                  IPv4                                         `json:"cluster-id,omitempty"`
	DisableNetworkImportCheck  json.RawMessage                              `json:"disable-network-import-check,omitempty"`
	NoClientToClientReflection json.RawMessage                              `json:"no-client-to-client-reflection,omitempty"`
	EnforceFirstAs             json.RawMessage                              `json:"enforce-first-as,omitempty"`
	RouterId                   IPv4                                         `json:"router-id,omitempty"`
	Distance                   *ConfigProtocolsBgpParametersDistance        `json:"distance,omitempty"`
	Default                    *ConfigProtocolsBgpParametersDefault         `json:"default,omitempty"`
	AlwaysCompareMed           json.RawMessage                              `json:"always-compare-med,omitempty"`
	GracefulRestart            *ConfigProtocolsBgpParametersGracefulRestart `json:"graceful-restart,omitempty"`
	Dampening                  *ConfigProtocolsBgpParametersDampening       `json:"dampening,omitempty"`
	DeterministicMed           json.RawMessage                              `json:"deterministic-med,omitempty"`
	Bestpath                   *ConfigProtocolsBgpParametersBestpath        `json:"bestpath,omitempty"`
	LogNeighborChanges         json.RawMessage                              `json:"log-neighbor-changes,omitempty"`
	ScanTime                   int                                          `json:"scan-time,omitempty"`
	Confederation              *ConfigProtocolsBgpParametersConfederation   `json:"confederation,omitempty"`
	NoFastExternalFailover     json.RawMessage                              `json:"no-fast-external-failover,omitempty"`
}

type ConfigProtocolsBgpParametersDistance struct {
	Prefix *ConfigProtocolsBgpParametersDistancePrefix `json:"prefix,omitempty"`
	Global *ConfigProtocolsBgpParametersDistanceGlobal `json:"global,omitempty"`
}

type ConfigProtocolsBgpParametersDistancePrefix map[string]struct {
	Distance int `json:"distance,omitempty"`
}

type ConfigProtocolsBgpParametersDistanceGlobal struct {
	Internal int `json:"internal,omitempty"`
	Local    int `json:"local,omitempty"`
	External int `json:"external,omitempty"`
}

type ConfigProtocolsBgpParametersDefault struct {
	NoIpv4Unicast json.RawMessage `json:"no-ipv4-unicast,omitempty"`
	LocalPref     int             `json:"local-pref,omitempty"`
}

type ConfigProtocolsBgpParametersGracefulRestart struct {
	StalepathTime int `json:"stalepath-time,omitempty"`
}

type ConfigProtocolsBgpParametersDampening struct {
	MaxSuppressTime   int `json:"max-suppress-time,omitempty"`
	StartSuppressTime int `json:"start-suppress-time,omitempty"`
	ReUse             int `json:"re-use,omitempty"`
	HalfLife          int `json:"half-life,omitempty"`
}

type ConfigProtocolsBgpParametersBestpath struct {
	AsPath          *ConfigProtocolsBgpParametersBestpathAsPath `json:"as-path,omitempty"`
	CompareRouterid json.RawMessage                             `json:"compare-routerid,omitempty"`
	Med             *ConfigProtocolsBgpParametersBestpathMed    `json:"med,omitempty"`
}

type ConfigProtocolsBgpParametersBestpathAsPath struct {
	Confed json.RawMessage `json:"confed,omitempty"`
	Ignore json.RawMessage `json:"ignore,omitempty"`
}

type ConfigProtocolsBgpParametersBestpathMed struct {
	Confed         json.RawMessage `json:"confed,omitempty"`
	MissingAsWorst json.RawMessage `json:"missing-as-worst,omitempty"`
}

type ConfigProtocolsBgpParametersConfederation struct {
	Identifier int `json:"identifier,omitempty"`
	Peers      int `json:"peers,omitempty"`
}

type ConfigProtocolsBgpRedistribute struct {
	Rip       *ConfigProtocolsBgpRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsBgpRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsBgpRedistributeStatic    `json:"static,omitempty"`
	Kernel    *ConfigProtocolsBgpRedistributeKernel    `json:"kernel,omitempty"`
	Ospf      *ConfigProtocolsBgpRedistributeOspf      `json:"ospf,omitempty"`
}

type ConfigProtocolsBgpRedistributeRip struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeConnected struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeStatic struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeKernel struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpRedistributeOspf struct {
	RouteMap string `json:"route-map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type ConfigProtocolsBgpPeerGroup map[string]struct {
	Weight                       int                                              `json:"weight,omitempty"`
	EbgpMultihop                 int                                              `json:"ebgp-multihop,omitempty"`
	Password                     string                                           `json:"password,omitempty"`
	MaximumPrefix                int                                              `json:"maximum-prefix,omitempty"`
	FilterList                   *ConfigProtocolsBgpPeerGroupFilterList           `json:"filter-list,omitempty"`
	AllowasIn                    *ConfigProtocolsBgpPeerGroupAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient         json.RawMessage                                  `json:"route-reflector-client,omitempty"`
	OverrideCapability           json.RawMessage                                  `json:"override-capability,omitempty"`
	Shutdown                     json.RawMessage                                  `json:"shutdown,omitempty"`
	DisableSendCommunity         *ConfigProtocolsBgpPeerGroupDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate             *ConfigProtocolsBgpPeerGroupDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient            json.RawMessage                                  `json:"route-server-client,omitempty"`
	Capability                   *ConfigProtocolsBgpPeerGroupCapability           `json:"capability,omitempty"`
	UpdateSource                 string                                           `json:"update-source,omitempty"`
	TtlSecurity                  *ConfigProtocolsBgpPeerGroupTtlSecurity          `json:"ttl-security,omitempty"`
	UnsuppressMap                string                                           `json:"unsuppress-map,omitempty"`
	Passive                      json.RawMessage                                  `json:"passive,omitempty"`
	Timers                       *ConfigProtocolsBgpPeerGroupTimers               `json:".timers,omitempty"`
	AddressFamily                *ConfigProtocolsBgpPeerGroupAddressFamily        `json:"address-family,omitempty"`
	Description                  string                                           `json:"description,omitempty"`
	SoftReconfiguration          *ConfigProtocolsBgpPeerGroupSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	LocalAs                      *ConfigProtocolsBgpPeerGroupLocalAs              `json:"local-as,omitempty"`
	AttributeUnchanged           *ConfigProtocolsBgpPeerGroupAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap                     *ConfigProtocolsBgpPeerGroupRouteMap             `json:"route-map,omitempty"`
	RemoteAs                     int                                              `json:"remote-as,omitempty"`
	NexthopSelf                  json.RawMessage                                  `json:"nexthop-self,omitempty"`
	DisableConnectedCheck        json.RawMessage                                  `json:"disable-connected-check,omitempty"`
	DisableCapabilityNegotiation json.RawMessage                                  `json:"disable-capability-negotiation,omitempty"`
	RemovePrivateAs              json.RawMessage                                  `json:"remove-private-as,omitempty"`
	PrefixList                   *ConfigProtocolsBgpPeerGroupPrefixList           `json:"prefix-list,omitempty"`
	DistributeList               *ConfigProtocolsBgpPeerGroupDistributeList       `json:"distribute-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAllowasIn struct {
	Number int `json:"number,omitempty"`
}

type ConfigProtocolsBgpPeerGroupDisableSendCommunity struct {
	Standard json.RawMessage `json:"standard,omitempty"`
	Extended json.RawMessage `json:"extended,omitempty"`
}

type ConfigProtocolsBgpPeerGroupDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpPeerGroupCapability struct {
	Dynamic         json.RawMessage                           `json:"dynamic,omitempty"`
	Orf             *ConfigProtocolsBgpPeerGroupCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart json.RawMessage                           `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpPeerGroupCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpPeerGroupCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupCapabilityOrfPrefixList struct {
	Receive json.RawMessage `json:"receive,omitempty"`
	Send    json.RawMessage `json:"send,omitempty"`
}

type ConfigProtocolsBgpPeerGroupTtlSecurity struct {
	Hops int `json:"hops,omitempty"`
}

type ConfigProtocolsBgpPeerGroupTimers struct {
	Holdtime  int `json:"holdtime,omitempty"`
	Keepalive int `json:"keepalive,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamily struct {
	Ipv6Unicast *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6Unicast `json:"ipv6-unicast,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6Unicast struct {
	MaximumPrefix        int                                                                      `json:"maximum-prefix,omitempty"`
	FilterList           *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastFilterList           `json:"filter-list,omitempty"`
	AllowasIn            *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAllowasIn            `json:"allowas-in,omitempty"`
	RouteReflectorClient json.RawMessage                                                          `json:"route-reflector-client,omitempty"`
	NexthopLocal         *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastNexthopLocal         `json:"nexthop-local,omitempty"`
	DisableSendCommunity *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDisableSendCommunity `json:"disable-send-community,omitempty"`
	DefaultOriginate     *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDefaultOriginate     `json:"default-originate,omitempty"`
	RouteServerClient    json.RawMessage                                                          `json:"route-server-client,omitempty"`
	Capability           *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapability           `json:"capability,omitempty"`
	UnsuppressMap        string                                                                   `json:"unsuppress-map,omitempty"`
	SoftReconfiguration  *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastSoftReconfiguration  `json:"soft-reconfiguration,omitempty"`
	AttributeUnchanged   *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAttributeUnchanged   `json:"attribute-unchanged,omitempty"`
	RouteMap             *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastRouteMap             `json:"route-map,omitempty"`
	NexthopSelf          json.RawMessage                                                          `json:"nexthop-self,omitempty"`
	RemovePrivateAs      json.RawMessage                                                          `json:"remove-private-as,omitempty"`
	PrefixList           *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastPrefixList           `json:"prefix-list,omitempty"`
	DistributeList       *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDistributeList       `json:"distribute-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastFilterList struct {
	Export string `json:"export,omitempty"`
	Import string `json:"import,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAllowasIn struct {
	Number int `json:"number,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastNexthopLocal struct {
	Unchanged json.RawMessage `json:"unchanged,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDisableSendCommunity struct {
	Standard json.RawMessage `json:"standard,omitempty"`
	Extended json.RawMessage `json:"extended,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastDefaultOriginate struct {
	RouteMap string `json:"route-map,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapability struct {
	Orf             *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrf `json:"orf,omitempty"`
	GracefulRestart json.RawMessage                                                   `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrf struct {
	PrefixList *ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrfPrefixList `json:"prefix-list,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastCapabilityOrfPrefixList struct {
	Receive json.RawMessage `json:"receive,omitempty"`
	Send    json.RawMessage `json:"send,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastSoftReconfiguration struct {
	Inbound json.RawMessage `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAddressFamilyIpv6UnicastAttributeUnchanged struct {
	AsPath  json.RawMessage `json:"as-path,omitempty"`
	NextHop json.RawMessage `json:"next-hop,omitempty"`
	Med     json.RawMessage `json:"med,omitempty"`
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
	Inbound json.RawMessage `json:"inbound,omitempty"`
}

type ConfigProtocolsBgpPeerGroupLocalAs map[string]struct {
	NoPrepend json.RawMessage `json:"no-prepend,omitempty"`
}

type ConfigProtocolsBgpPeerGroupAttributeUnchanged struct {
	AsPath  json.RawMessage `json:"as-path,omitempty"`
	NextHop json.RawMessage `json:"next-hop,omitempty"`
	Med     json.RawMessage `json:"med,omitempty"`
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
	Export int `json:"export,omitempty"`
	Import int `json:"import,omitempty"`
}

type ConfigProtocolsOspfv3 struct {
	Bfd                     *ConfigProtocolsOspfv3Bfd                 `json:"bfd,omitempty"`
	Area                    *ConfigProtocolsOspfv3Area                `json:"area,omitempty"`
	Timers                  *ConfigProtocolsOspfv3Timers              `json:"timers,omitempty"`
	Capability              *ConfigProtocolsOspfv3Capability          `json:"capability,omitempty"`
	DefaultMetric           int                                       `json:"default-metric,omitempty"`
	Distance                *ConfigProtocolsOspfv3Distance            `json:"distance,omitempty"`
	LogAdjacencyChanges     *ConfigProtocolsOspfv3LogAdjacencyChanges `json:"log-adjacency-changes,omitempty"`
	SummaryAddress          IPv6Net                                   `json:"summary-address,omitempty"`
	Cspf                    *ConfigProtocolsOspfv3Cspf                `json:"cspf,omitempty"`
	AutoCost                *ConfigProtocolsOspfv3AutoCost            `json:"auto-cost,omitempty"`
	PassiveInterfaceExclude string                                    `json:"passive-interface-exclude,omitempty"`
	Vrf                     *ConfigProtocolsOspfv3Vrf                 `json:".vrf,omitempty"`
	Parameters              *ConfigProtocolsOspfv3Parameters          `json:"parameters,omitempty"`
	PassiveInterface        string                                    `json:"passive-interface,omitempty"`
	MaxConcurrentDd         int                                       `json:"max-concurrent-dd,omitempty"`
	Redistribute            *ConfigProtocolsOspfv3Redistribute        `json:"redistribute,omitempty"`
	DistributeList          *ConfigProtocolsOspfv3DistributeList      `json:"distribute-list,omitempty"`
	DefaultInformation      *ConfigProtocolsOspfv3DefaultInformation  `json:"default-information,omitempty"`
}

type ConfigProtocolsOspfv3Bfd struct {
	Interface     string          `json:"interface,omitempty"`
	AllInterfaces json.RawMessage `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfv3Area map[string]struct {
	ExportList  string                                `json:"export-list,omitempty"`
	Interface   string                                `json:"interface,omitempty"`
	FilterList  *ConfigProtocolsOspfv3AreaFilterList  `json:".filter-list,omitempty"`
	ImportList  string                                `json:"import-list,omitempty"`
	AreaType    *ConfigProtocolsOspfv3AreaAreaType    `json:"area-type,omitempty"`
	VirtualLink *ConfigProtocolsOspfv3AreaVirtualLink `json:"virtual-link,omitempty"`
	Range       *ConfigProtocolsOspfv3AreaRange       `json:"range,omitempty"`
}

type ConfigProtocolsOspfv3AreaFilterList map[string]struct {
}

type ConfigProtocolsOspfv3AreaAreaType struct {
	Stub   *ConfigProtocolsOspfv3AreaAreaTypeStub `json:"stub,omitempty"`
	Normal json.RawMessage                        `json:"normal,omitempty"`
	Nssa   *ConfigProtocolsOspfv3AreaAreaTypeNssa `json:"nssa,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeStub struct {
	DefaultCost int             `json:"default-cost,omitempty"`
	NoSummary   json.RawMessage `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeNssa struct {
	DefaultCost                 int                                                               `json:"default-cost,omitempty"`
	Translate                   string                                                            `json:"translate,omitempty"`
	NoSummary                   json.RawMessage                                                   `json:"no-summary,omitempty"`
	StabilityInterval           int                                                               `json:"stability-interval,omitempty"`
	DefaultInformationOriginate *ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginate `json:"default-information-originate,omitempty"`
	NoRedistribution            json.RawMessage                                                   `json:"no-redistribution,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginate struct {
	RouteMap string                                                                  `json:"route-map,omitempty"`
	Metric   *ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric `json:"metric,omitempty"`
}

type ConfigProtocolsOspfv3AreaAreaTypeNssaDefaultInformationOriginateMetric map[string]struct {
	Type string `json:"type,omitempty"`
}

type ConfigProtocolsOspfv3AreaVirtualLink map[string]struct {
	Bfd json.RawMessage `json:"bfd,omitempty"`
}

type ConfigProtocolsOspfv3AreaRange map[string]struct {
	NotAdvertise json.RawMessage `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfv3Timers struct {
	SfpExpDelay *ConfigProtocolsOspfv3TimersSfpExpDelay `json:"sfp-exp-delay,omitempty"`
}

type ConfigProtocolsOspfv3TimersSfpExpDelay struct {
	Min *ConfigProtocolsOspfv3TimersSfpExpDelayMin `json:"min,omitempty"`
}

type ConfigProtocolsOspfv3TimersSfpExpDelayMin map[string]struct {
	Max int `json:"max,omitempty"`
}

type ConfigProtocolsOspfv3Capability struct {
	DbSummaryOpt    json.RawMessage `json:"db-summary-opt,omitempty"`
	Te              json.RawMessage `json:"te,omitempty"`
	Cspf            json.RawMessage `json:"cspf,omitempty"`
	GracefulRestart json.RawMessage `json:"graceful-restart,omitempty"`
}

type ConfigProtocolsOspfv3Distance struct {
	Global int                                  `json:"global,omitempty"`
	Ospfv3 *ConfigProtocolsOspfv3DistanceOspfv3 `json:"ospfv3,omitempty"`
}

type ConfigProtocolsOspfv3DistanceOspfv3 struct {
	InterArea int `json:"inter-area,omitempty"`
	External  int `json:"external,omitempty"`
	IntraArea int `json:"intra-area,omitempty"`
}

type ConfigProtocolsOspfv3LogAdjacencyChanges struct {
	Detail json.RawMessage `json:"detail,omitempty"`
}

type ConfigProtocolsOspfv3Cspf struct {
	TieBreak             string `json:"tie-break,omitempty"`
	DefaultRetryInterval int    `json:"default-retry-interval,omitempty"`
}

type ConfigProtocolsOspfv3AutoCost struct {
	ReferenceBandwidth int `json:"reference-bandwidth,omitempty"`
}

type ConfigProtocolsOspfv3Vrf map[string]struct {
	Bfd          *ConfigProtocolsOspfv3VrfBfd          `json:"bfd,omitempty"`
	Area         *ConfigProtocolsOspfv3VrfArea         `json:"area,omitempty"`
	Parameters   *ConfigProtocolsOspfv3VrfParameters   `json:"parameters,omitempty"`
	Redistribute *ConfigProtocolsOspfv3VrfRedistribute `json:"redistribute,omitempty"`
}

type ConfigProtocolsOspfv3VrfBfd struct {
	AllInterfaces json.RawMessage `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfv3VrfArea map[string]struct {
	ExportList  string                                   `json:"export-list,omitempty"`
	Interface   string                                   `json:"interface,omitempty"`
	FilterList  *ConfigProtocolsOspfv3VrfAreaFilterList  `json:".filter-list,omitempty"`
	ImportList  string                                   `json:"import-list,omitempty"`
	VirtualLink *ConfigProtocolsOspfv3VrfAreaVirtualLink `json:"virtual-link,omitempty"`
	Range       *ConfigProtocolsOspfv3VrfAreaRange       `json:"range,omitempty"`
}

type ConfigProtocolsOspfv3VrfAreaFilterList map[string]struct {
}

type ConfigProtocolsOspfv3VrfAreaVirtualLink map[string]struct {
	Bfd json.RawMessage `json:"bfd,omitempty"`
}

type ConfigProtocolsOspfv3VrfAreaRange map[string]struct {
	Advertise    json.RawMessage `json:"advertise,omitempty"`
	NotAdvertise json.RawMessage `json:"not-advertise,omitempty"`
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

type ConfigProtocolsOspfv3DistributeList map[string]struct {
	Out *ConfigProtocolsOspfv3DistributeListOut `json:"out,omitempty"`
	In  json.RawMessage                         `json:"in,omitempty"`
}

type ConfigProtocolsOspfv3DistributeListOut struct {
	Rip       json.RawMessage `json:"rip,omitempty"`
	Connected json.RawMessage `json:"connected,omitempty"`
	Static    json.RawMessage `json:"static,omitempty"`
	Bgp       json.RawMessage `json:"bgp,omitempty"`
	Kernel    json.RawMessage `json:"kernel,omitempty"`
	Ospf      int             `json:"ospf,omitempty"`
	Isis      json.RawMessage `json:"isis,omitempty"`
}

type ConfigProtocolsOspfv3DefaultInformation struct {
	Originate *ConfigProtocolsOspfv3DefaultInformationOriginate `json:"originate,omitempty"`
}

type ConfigProtocolsOspfv3DefaultInformationOriginate struct {
	Always     json.RawMessage `json:"always,omitempty"`
	RouteMap   string          `json:"route-map,omitempty"`
	MetricType string          `json:"metric-type,omitempty"`
	Metric     int             `json:"metric,omitempty"`
}

type ConfigProtocolsOspf struct {
	Neighbor                *ConfigProtocolsOspfNeighbor            `json:"neighbor,omitempty"`
	Bfd                     *ConfigProtocolsOspfBfd                 `json:"bfd,omitempty"`
	Area                    *ConfigProtocolsOspfArea                `json:"area,omitempty"`
	Refresh                 *ConfigProtocolsOspfRefresh             `json:"refresh,omitempty"`
	Timers                  *ConfigProtocolsOspfTimers              `json:"timers,omitempty"`
	DefaultMetric           int                                     `json:"default-metric,omitempty"`
	Distance                *ConfigProtocolsOspfDistance            `json:"distance,omitempty"`
	LogAdjacencyChanges     *ConfigProtocolsOspfLogAdjacencyChanges `json:"log-adjacency-changes,omitempty"`
	MplsTe                  *ConfigProtocolsOspfMplsTe              `json:"mpls-te,omitempty"`
	AutoCost                *ConfigProtocolsOspfAutoCost            `json:"auto-cost,omitempty"`
	PassiveInterfaceExclude string                                  `json:"passive-interface-exclude,omitempty"`
	AccessList              *ConfigProtocolsOspfAccessList          `json:"access-list,omitempty"`
	InstanceId              *ConfigProtocolsOspfInstanceId          `json:".instance-id,omitempty"`
	Parameters              *ConfigProtocolsOspfParameters          `json:"parameters,omitempty"`
	PassiveInterface        string                                  `json:"passive-interface,omitempty"`
	Redistribute            *ConfigProtocolsOspfRedistribute        `json:"redistribute,omitempty"`
	MaxMetric               *ConfigProtocolsOspfMaxMetric           `json:"max-metric,omitempty"`
	DefaultInformation      *ConfigProtocolsOspfDefaultInformation  `json:"default-information,omitempty"`
}

type ConfigProtocolsOspfNeighbor map[string]struct {
	PollInterval int `json:"poll-interval,omitempty"`
	Priority     int `json:"priority,omitempty"`
}

type ConfigProtocolsOspfBfd struct {
	Interface     string          `json:"interface,omitempty"`
	AllInterfaces json.RawMessage `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfArea map[string]struct {
	Shortcut       string                              `json:"shortcut,omitempty"`
	Network        IPv4Net                             `json:"network,omitempty"`
	AreaType       *ConfigProtocolsOspfAreaAreaType    `json:"area-type,omitempty"`
	VirtualLink    *ConfigProtocolsOspfAreaVirtualLink `json:"virtual-link,omitempty"`
	Range          *ConfigProtocolsOspfAreaRange       `json:"range,omitempty"`
	Authentication string                              `json:"authentication,omitempty"`
}

type ConfigProtocolsOspfAreaAreaType struct {
	Stub   *ConfigProtocolsOspfAreaAreaTypeStub `json:"stub,omitempty"`
	Normal json.RawMessage                      `json:"normal,omitempty"`
	Nssa   *ConfigProtocolsOspfAreaAreaTypeNssa `json:"nssa,omitempty"`
}

type ConfigProtocolsOspfAreaAreaTypeStub struct {
	DefaultCost int             `json:"default-cost,omitempty"`
	NoSummary   json.RawMessage `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfAreaAreaTypeNssa struct {
	DefaultCost int             `json:"default-cost,omitempty"`
	Translate   string          `json:"translate,omitempty"`
	NoSummary   json.RawMessage `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLink map[string]struct {
	RetransmitInterval int                                               `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                               `json:"transmit-delay,omitempty"`
	Bfd                json.RawMessage                                   `json:"bfd,omitempty"`
	DeadInterval       int                                               `json:"dead-interval,omitempty"`
	Authentication     *ConfigProtocolsOspfAreaVirtualLinkAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                               `json:"hello-interval,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLinkAuthentication struct {
	Md5               *ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                               `json:"plaintext-password,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5 struct {
	KeyId *ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigProtocolsOspfAreaVirtualLinkAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigProtocolsOspfAreaRange map[string]struct {
	Cost         int             `json:"cost,omitempty"`
	Substitute   IPv4Net         `json:"substitute,omitempty"`
	NotAdvertise json.RawMessage `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfRefresh struct {
	Timers int `json:"timers,omitempty"`
}

type ConfigProtocolsOspfTimers struct {
	Throttle *ConfigProtocolsOspfTimersThrottle `json:"throttle,omitempty"`
}

type ConfigProtocolsOspfTimersThrottle struct {
	Spf *ConfigProtocolsOspfTimersThrottleSpf `json:"spf,omitempty"`
}

type ConfigProtocolsOspfTimersThrottleSpf struct {
	MaxHoldtime     int `json:"max-holdtime,omitempty"`
	Delay           int `json:"delay,omitempty"`
	InitialHoldtime int `json:"initial-holdtime,omitempty"`
}

type ConfigProtocolsOspfDistance struct {
	Global int                              `json:"global,omitempty"`
	Ospf   *ConfigProtocolsOspfDistanceOspf `json:"ospf,omitempty"`
}

type ConfigProtocolsOspfDistanceOspf struct {
	InterArea int `json:"inter-area,omitempty"`
	External  int `json:"external,omitempty"`
	IntraArea int `json:"intra-area,omitempty"`
}

type ConfigProtocolsOspfLogAdjacencyChanges struct {
	Detail json.RawMessage `json:"detail,omitempty"`
}

type ConfigProtocolsOspfMplsTe struct {
	Enable        json.RawMessage `json:"enable,omitempty"`
	RouterAddress IPv4            `json:"router-address,omitempty"`
}

type ConfigProtocolsOspfAutoCost struct {
	ReferenceBandwidth int `json:"reference-bandwidth,omitempty"`
}

type ConfigProtocolsOspfAccessList map[string]struct {
	Export string          `json:"export,omitempty"`
	Import json.RawMessage `json:"import,omitempty"`
}

type ConfigProtocolsOspfInstanceId map[string]struct {
	Vrf *ConfigProtocolsOspfInstanceIdVrf `json:"vrf,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrf map[string]struct {
	Neighbor                *ConfigProtocolsOspfInstanceIdVrfNeighbor            `json:"neighbor,omitempty"`
	Bfd                     *ConfigProtocolsOspfInstanceIdVrfBfd                 `json:"bfd,omitempty"`
	Area                    *ConfigProtocolsOspfInstanceIdVrfArea                `json:"area,omitempty"`
	Refresh                 *ConfigProtocolsOspfInstanceIdVrfRefresh             `json:"refresh,omitempty"`
	Timers                  *ConfigProtocolsOspfInstanceIdVrfTimers              `json:"timers,omitempty"`
	Capability              *ConfigProtocolsOspfInstanceIdVrfCapability          `json:"capability,omitempty"`
	DefaultMetric           int                                                  `json:"default-metric,omitempty"`
	Distance                *ConfigProtocolsOspfInstanceIdVrfDistance            `json:"distance,omitempty"`
	LogAdjacencyChanges     *ConfigProtocolsOspfInstanceIdVrfLogAdjacencyChanges `json:"log-adjacency-changes,omitempty"`
	MplsTe                  *ConfigProtocolsOspfInstanceIdVrfMplsTe              `json:"mpls-te,omitempty"`
	AutoCost                *ConfigProtocolsOspfInstanceIdVrfAutoCost            `json:"auto-cost,omitempty"`
	PassiveInterfaceExclude string                                               `json:"passive-interface-exclude,omitempty"`
	AccessList              *ConfigProtocolsOspfInstanceIdVrfAccessList          `json:"access-list,omitempty"`
	Parameters              *ConfigProtocolsOspfInstanceIdVrfParameters          `json:"parameters,omitempty"`
	PassiveInterface        string                                               `json:"passive-interface,omitempty"`
	Redistribute            *ConfigProtocolsOspfInstanceIdVrfRedistribute        `json:"redistribute,omitempty"`
	MaxMetric               *ConfigProtocolsOspfInstanceIdVrfMaxMetric           `json:"max-metric,omitempty"`
	DefaultInformation      *ConfigProtocolsOspfInstanceIdVrfDefaultInformation  `json:"default-information,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfNeighbor map[string]struct {
	PollInterval int `json:"poll-interval,omitempty"`
	Priority     int `json:"priority,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfBfd struct {
	AllInterfaces json.RawMessage `json:"all-interfaces,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfArea map[string]struct {
	Shortcut       string                                           `json:"shortcut,omitempty"`
	Network        IPv4Net                                          `json:"network,omitempty"`
	AreaType       *ConfigProtocolsOspfInstanceIdVrfAreaAreaType    `json:"area-type,omitempty"`
	VirtualLink    *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink `json:"virtual-link,omitempty"`
	Range          *ConfigProtocolsOspfInstanceIdVrfAreaRange       `json:"range,omitempty"`
	Authentication string                                           `json:"authentication,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaAreaType struct {
	Stub   *ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeStub `json:"stub,omitempty"`
	Normal json.RawMessage                                   `json:"normal,omitempty"`
	Nssa   *ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeNssa `json:"nssa,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeStub struct {
	DefaultCost int             `json:"default-cost,omitempty"`
	NoSummary   json.RawMessage `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaAreaTypeNssa struct {
	DefaultCost int             `json:"default-cost,omitempty"`
	Translate   string          `json:"translate,omitempty"`
	NoSummary   json.RawMessage `json:"no-summary,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLink map[string]struct {
	RetransmitInterval int                                                            `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                            `json:"transmit-delay,omitempty"`
	Bfd                json.RawMessage                                                `json:"bfd,omitempty"`
	DeadInterval       int                                                            `json:"dead-interval,omitempty"`
	Authentication     *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                            `json:"hello-interval,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthentication struct {
	Md5               *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                            `json:"plaintext-password,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5 struct {
	KeyId *ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaVirtualLinkAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAreaRange map[string]struct {
	Cost         int             `json:"cost,omitempty"`
	Substitute   IPv4Net         `json:"substitute,omitempty"`
	NotAdvertise json.RawMessage `json:"not-advertise,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRefresh struct {
	Timers int `json:"timers,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfTimers struct {
	Throttle *ConfigProtocolsOspfInstanceIdVrfTimersThrottle `json:"throttle,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfTimersThrottle struct {
	Spf *ConfigProtocolsOspfInstanceIdVrfTimersThrottleSpf `json:"spf,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfTimersThrottleSpf struct {
	MaxHoldtime     int `json:"max-holdtime,omitempty"`
	Delay           int `json:"delay,omitempty"`
	InitialHoldtime int `json:"initial-holdtime,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfCapability struct {
	Cspf               *ConfigProtocolsOspfInstanceIdVrfCapabilityCspf `json:"cspf,omitempty"`
	TrafficEngineering json.RawMessage                                 `json:"traffic-engineering,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfCapabilityCspf struct {
	EnableBetterProtection  json.RawMessage                                         `json:"enable-better-protection,omitempty"`
	TieBreak                *ConfigProtocolsOspfInstanceIdVrfCapabilityCspfTieBreak `json:"tie-break,omitempty"`
	DisableBetterProtection json.RawMessage                                         `json:"disable-better-protection,omitempty"`
	DefaultRetryInterval    int                                                     `json:"default-retry-interval,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfCapabilityCspfTieBreak struct {
	MostFill  json.RawMessage `json:"most-fill,omitempty"`
	LeastFill json.RawMessage `json:"least-fill,omitempty"`
	Random    json.RawMessage `json:"random,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDistance struct {
	Global int                                           `json:"global,omitempty"`
	Ospf   *ConfigProtocolsOspfInstanceIdVrfDistanceOspf `json:"ospf,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDistanceOspf struct {
	InterArea int `json:"inter-area,omitempty"`
	External  int `json:"external,omitempty"`
	IntraArea int `json:"intra-area,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfLogAdjacencyChanges struct {
	Detail json.RawMessage `json:"detail,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfMplsTe struct {
	Enable        json.RawMessage `json:"enable,omitempty"`
	RouterAddress IPv4            `json:"router-address,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAutoCost struct {
	ReferenceBandwidth int `json:"reference-bandwidth,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfAccessList map[string]struct {
	Export string `json:"export,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfParameters struct {
	Rfc1583Compatibility json.RawMessage `json:"rfc1583-compatibility,omitempty"`
	RouterId             IPv4            `json:"router-id,omitempty"`
	AbrType              string          `json:"abr-type,omitempty"`
	OpaqueLsa            json.RawMessage `json:"opaque-lsa,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistribute struct {
	Rip       *ConfigProtocolsOspfInstanceIdVrfRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsOspfInstanceIdVrfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsOspfInstanceIdVrfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsOspfInstanceIdVrfRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsOspfInstanceIdVrfRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeRip struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeConnected struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeStatic struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeBgp struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfRedistributeKernel struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfMaxMetric struct {
	RouterLsa *ConfigProtocolsOspfInstanceIdVrfMaxMetricRouterLsa `json:"router-lsa,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfMaxMetricRouterLsa struct {
	OnStartup      int             `json:"on-startup,omitempty"`
	Administrative json.RawMessage `json:"administrative,omitempty"`
	OnShutdown     int             `json:"on-shutdown,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDefaultInformation struct {
	Originate *ConfigProtocolsOspfInstanceIdVrfDefaultInformationOriginate `json:"originate,omitempty"`
}

type ConfigProtocolsOspfInstanceIdVrfDefaultInformationOriginate struct {
	Always     json.RawMessage `json:"always,omitempty"`
	RouteMap   string          `json:"route-map,omitempty"`
	MetricType int             `json:"metric-type,omitempty"`
	Metric     int             `json:"metric,omitempty"`
}

type ConfigProtocolsOspfParameters struct {
	Rfc1583Compatibility json.RawMessage `json:"rfc1583-compatibility,omitempty"`
	RouterId             IPv4            `json:"router-id,omitempty"`
	AbrType              string          `json:"abr-type,omitempty"`
	OpaqueLsa            json.RawMessage `json:"opaque-lsa,omitempty"`
}

type ConfigProtocolsOspfRedistribute struct {
	Rip       *ConfigProtocolsOspfRedistributeRip       `json:"rip,omitempty"`
	Connected *ConfigProtocolsOspfRedistributeConnected `json:"connected,omitempty"`
	Static    *ConfigProtocolsOspfRedistributeStatic    `json:"static,omitempty"`
	Bgp       *ConfigProtocolsOspfRedistributeBgp       `json:"bgp,omitempty"`
	Kernel    *ConfigProtocolsOspfRedistributeKernel    `json:"kernel,omitempty"`
}

type ConfigProtocolsOspfRedistributeRip struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeConnected struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeStatic struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeBgp struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfRedistributeKernel struct {
	RouteMap   string `json:"route-map,omitempty"`
	MetricType int    `json:"metric-type,omitempty"`
	Metric     int    `json:"metric,omitempty"`
}

type ConfigProtocolsOspfMaxMetric struct {
	RouterLsa *ConfigProtocolsOspfMaxMetricRouterLsa `json:"router-lsa,omitempty"`
}

type ConfigProtocolsOspfMaxMetricRouterLsa struct {
	OnStartup      int             `json:"on-startup,omitempty"`
	Administrative json.RawMessage `json:"administrative,omitempty"`
	OnShutdown     int             `json:"on-shutdown,omitempty"`
}

type ConfigProtocolsOspfDefaultInformation struct {
	Originate *ConfigProtocolsOspfDefaultInformationOriginate `json:"originate,omitempty"`
}

type ConfigProtocolsOspfDefaultInformationOriginate struct {
	Always     json.RawMessage `json:"always,omitempty"`
	RouteMap   string          `json:"route-map,omitempty"`
	MetricType int             `json:"metric-type,omitempty"`
	Metric     int             `json:"metric,omitempty"`
}

type ConfigPolicy *struct {
	AsPathList       *ConfigPolicyAsPathList       `json:"as-path-list,omitempty"`
	AccessList       *ConfigPolicyAccessList       `json:"access-list,omitempty"`
	RouteMap         *ConfigPolicyRouteMap         `json:"route-map,omitempty"`
	AccessList6      *ConfigPolicyAccessList6      `json:"access-list6,omitempty"`
	PrefixList6      *ConfigPolicyPrefixList6      `json:"prefix-list6,omitempty"`
	CommunityList    *ConfigPolicyCommunityList    `json:"community-list,omitempty"`
	ExtcommunityList *ConfigPolicyExtcommunityList `json:"extcommunity-list,omitempty"`
	PrefixList       *ConfigPolicyPrefixList       `json:"prefix-list,omitempty"`
}

type ConfigPolicyAsPathList map[string]struct {
	Rule        *ConfigPolicyAsPathListRule `json:"rule,omitempty"`
	Description string                      `json:"description,omitempty"`
}

type ConfigPolicyAsPathListRule map[string]struct {
	Regex       string `json:"regex,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigPolicyAccessList map[string]struct {
	Rule        *ConfigPolicyAccessListRule `json:"rule,omitempty"`
	Description string                      `json:"description,omitempty"`
}

type ConfigPolicyAccessListRule map[string]struct {
	Source      *ConfigPolicyAccessListRuleSource      `json:"source,omitempty"`
	Destination *ConfigPolicyAccessListRuleDestination `json:"destination,omitempty"`
	Action      string                                 `json:"action,omitempty"`
	Description string                                 `json:"description,omitempty"`
}

type ConfigPolicyAccessListRuleSource struct {
	Host        IPv4            `json:"host,omitempty"`
	Network     IPv4            `json:"network,omitempty"`
	Any         json.RawMessage `json:"any,omitempty"`
	InverseMask IPv4            `json:"inverse-mask,omitempty"`
}

type ConfigPolicyAccessListRuleDestination struct {
	Host        IPv4            `json:"host,omitempty"`
	Network     IPv4            `json:"network,omitempty"`
	Any         json.RawMessage `json:"any,omitempty"`
	InverseMask IPv4            `json:"inverse-mask,omitempty"`
}

type ConfigPolicyRouteMap map[string]struct {
	Rule        *ConfigPolicyRouteMapRule `json:"rule,omitempty"`
	Description string                    `json:"description,omitempty"`
}

type ConfigPolicyRouteMapRule map[string]struct {
	Match       *ConfigPolicyRouteMapRuleMatch   `json:"match,omitempty"`
	OnMatch     *ConfigPolicyRouteMapRuleOnMatch `json:"on-match,omitempty"`
	Action      string                           `json:"action,omitempty"`
	Call        string                           `json:"call,omitempty"`
	Description string                           `json:"description,omitempty"`
	Set         *ConfigPolicyRouteMapRuleSet     `json:"set,omitempty"`
	Continue    int                              `json:"continue,omitempty"`
}

type ConfigPolicyRouteMapRuleMatch struct {
	AsPath       string                                     `json:"as-path,omitempty"`
	Interface    string                                     `json:"interface,omitempty"`
	Extcommunity *ConfigPolicyRouteMapRuleMatchExtcommunity `json:"extcommunity,omitempty"`
	Peer         string                                     `json:"peer,omitempty"`
	Origin       string                                     `json:"origin,omitempty"`
	Community    *ConfigPolicyRouteMapRuleMatchCommunity    `json:"community,omitempty"`
	Ip           *ConfigPolicyRouteMapRuleMatchIp           `json:"ip,omitempty"`
	Metric       int                                        `json:"metric,omitempty"`
	Ipv6         *ConfigPolicyRouteMapRuleMatchIpv6         `json:"ipv6,omitempty"`
	Tag          int                                        `json:"tag,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchExtcommunity struct {
	ExactMatch       json.RawMessage `json:"exact-match,omitempty"`
	ExtcommunityList int             `json:"extcommunity-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchCommunity struct {
	ExactMatch    json.RawMessage `json:"exact-match,omitempty"`
	CommunityList int             `json:"community-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIp struct {
	RouteSource *ConfigPolicyRouteMapRuleMatchIpRouteSource `json:"route-source,omitempty"`
	Nexthop     *ConfigPolicyRouteMapRuleMatchIpNexthop     `json:"nexthop,omitempty"`
	Address     *ConfigPolicyRouteMapRuleMatchIpAddress     `json:"address,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpRouteSource struct {
	AccessList int    `json:"access-list,omitempty"`
	PrefixList string `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpNexthop struct {
	AccessList int    `json:"access-list,omitempty"`
	PrefixList string `json:"prefix-list,omitempty"`
}

type ConfigPolicyRouteMapRuleMatchIpAddress struct {
	AccessList int    `json:"access-list,omitempty"`
	PrefixList string `json:"prefix-list,omitempty"`
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
	Next json.RawMessage `json:"next,omitempty"`
	Goto int             `json:"goto,omitempty"`
}

type ConfigPolicyRouteMapRuleSet struct {
	Weight          int                                      `json:"weight,omitempty"`
	AsPathPrepend   string                                   `json:"as-path-prepend,omitempty"`
	Ipv6NextHop     *ConfigPolicyRouteMapRuleSetIpv6NextHop  `json:"ipv6-next-hop,omitempty"`
	CommList        *ConfigPolicyRouteMapRuleSetCommList     `json:"comm-list,omitempty"`
	OriginatorId    IPv4                                     `json:"originator-id,omitempty"`
	Extcommunity    *ConfigPolicyRouteMapRuleSetExtcommunity `json:"extcommunity,omitempty"`
	Aggregator      *ConfigPolicyRouteMapRuleSetAggregator   `json:"aggregator,omitempty"`
	AtomicAggregate json.RawMessage                          `json:"atomic-aggregate,omitempty"`
	LocalPreference int                                      `json:"local-preference,omitempty"`
	MetricType      string                                   `json:"metric-type,omitempty"`
	Origin          string                                   `json:"origin,omitempty"`
	Community       string                                   `json:"community,omitempty"`
	Metric          string                                   `json:"metric,omitempty"`
	IpNextHop       IPv4                                     `json:"ip-next-hop,omitempty"`
	Tag             int                                      `json:"tag,omitempty"`
}

type ConfigPolicyRouteMapRuleSetIpv6NextHop struct {
	Local  IPv6 `json:"local,omitempty"`
	Global IPv6 `json:"global,omitempty"`
}

type ConfigPolicyRouteMapRuleSetCommList struct {
	CommList int             `json:"comm-list,omitempty"`
	Delete   json.RawMessage `json:"delete,omitempty"`
}

type ConfigPolicyRouteMapRuleSetExtcommunity struct {
	Rt string `json:"rt,omitempty"`
	Ro string `json:"ro,omitempty"`
}

type ConfigPolicyRouteMapRuleSetAggregator struct {
	As int  `json:"as,omitempty"`
	Ip IPv4 `json:"ip,omitempty"`
}

type ConfigPolicyAccessList6 map[string]struct {
	Rule        *ConfigPolicyAccessList6Rule `json:"rule,omitempty"`
	Description string                       `json:"description,omitempty"`
}

type ConfigPolicyAccessList6Rule map[string]struct {
	Source      *ConfigPolicyAccessList6RuleSource `json:"source,omitempty"`
	Action      string                             `json:"action,omitempty"`
	Description string                             `json:"description,omitempty"`
}

type ConfigPolicyAccessList6RuleSource struct {
	Network    IPv6Net         `json:"network,omitempty"`
	Any        json.RawMessage `json:"any,omitempty"`
	ExactMatch json.RawMessage `json:"exact-match,omitempty"`
}

type ConfigPolicyPrefixList6 map[string]struct {
	Rule        *ConfigPolicyPrefixList6Rule `json:"rule,omitempty"`
	Description string                       `json:"description,omitempty"`
}

type ConfigPolicyPrefixList6Rule map[string]struct {
	Prefix      IPv6Net `json:"prefix,omitempty"`
	Le          int     `json:"le,omitempty"`
	Action      string  `json:"action,omitempty"`
	Description string  `json:"description,omitempty"`
	Ge          int     `json:"ge,omitempty"`
}

type ConfigPolicyCommunityList map[string]struct {
	Rule        *ConfigPolicyCommunityListRule `json:"rule,omitempty"`
	Description string                         `json:"description,omitempty"`
}

type ConfigPolicyCommunityListRule map[string]struct {
	Regex       string `json:"regex,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigPolicyExtcommunityList map[string]struct {
	Rule        *ConfigPolicyExtcommunityListRule `json:"rule,omitempty"`
	Description string                            `json:"description,omitempty"`
}

type ConfigPolicyExtcommunityListRule map[string]struct {
	Rt          string `json:"rt,omitempty"`
	Regex       string `json:"regex,omitempty"`
	Ro          string `json:"ro,omitempty"`
	Action      string `json:"action,omitempty"`
	Description string `json:"description,omitempty"`
}

type ConfigPolicyPrefixList map[string]struct {
	Rule        *ConfigPolicyPrefixListRule `json:"rule,omitempty"`
	Description string                      `json:"description,omitempty"`
}

type ConfigPolicyPrefixListRule map[string]struct {
	Prefix      IPv4Net `json:"prefix,omitempty"`
	Le          int     `json:"le,omitempty"`
	Action      string  `json:"action,omitempty"`
	Description string  `json:"description,omitempty"`
	Ge          int     `json:"ge,omitempty"`
}

type ConfigInterfaces *struct {
	Wirelessmodem  *ConfigInterfacesWirelessmodem  `json:"wirelessmodem,omitempty"`
	Ipv6Tunnel     *ConfigInterfacesIpv6Tunnel     `json:"ipv6-tunnel,omitempty"`
	Bonding        *ConfigInterfacesBonding        `json:"bonding,omitempty"`
	L2tpv3         *ConfigInterfacesL2tpv3         `json:"l2tpv3,omitempty"`
	Vti            *ConfigInterfacesVti            `json:"vti,omitempty"`
	Input          *ConfigInterfacesInput          `json:"input,omitempty"`
	Bridge         *ConfigInterfacesBridge         `json:"bridge,omitempty"`
	L2tpClient     *ConfigInterfacesL2tpClient     `json:"l2tp-client,omitempty"`
	PptpClient     *ConfigInterfacesPptpClient     `json:"pptp-client,omitempty"`
	Ethernet       *ConfigInterfacesEthernet       `json:"ethernet,omitempty"`
	Tunnel         *ConfigInterfacesTunnel         `json:"tunnel,omitempty"`
	Openvpn        *ConfigInterfacesOpenvpn        `json:"openvpn,omitempty"`
	Loopback       *ConfigInterfacesLoopback       `json:"loopback,omitempty"`
	Switch         *ConfigInterfacesSwitch         `json:"switch,omitempty"`
	PseudoEthernet *ConfigInterfacesPseudoEthernet `json:"pseudo-ethernet,omitempty"`
}

type ConfigInterfacesWirelessmodem map[string]struct {
	Bandwidth         *ConfigInterfacesWirelessmodemBandwidth     `json:"bandwidth,omitempty"`
	Ondemand          json.RawMessage                             `json:"ondemand,omitempty"`
	Mtu               int                                         `json:"mtu,omitempty"`
	Network           string                                      `json:"network,omitempty"`
	TrafficPolicy     *ConfigInterfacesWirelessmodemTrafficPolicy `json:"traffic-policy,omitempty"`
	NoDns             json.RawMessage                             `json:"no-dns,omitempty"`
	DisableLinkDetect json.RawMessage                             `json:"disable-link-detect,omitempty"`
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
	ClassType *ConfigInterfacesWirelessmodemBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesWirelessmodemBandwidthConstraintClassType map[string]struct {
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
	Distance int `json:"distance,omitempty"`
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesWirelessmodemIpRipAuthentication struct {
	Md5               *ConfigInterfacesWirelessmodemIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                               `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesWirelessmodemIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspf struct {
	RetransmitInterval int                                                `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                `json:"transmit-delay,omitempty"`
	Network            string                                             `json:"network,omitempty"`
	Cost               int                                                `json:"cost,omitempty"`
	DeadInterval       int                                                `json:"dead-interval,omitempty"`
	Priority           int                                                `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                    `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesWirelessmodemIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                `json:"hello-interval,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspfAuthentication struct {
	Md5               *ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesWirelessmodemIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6 struct {
	DupAddrDetectTransmits int                                            `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesWirelessmodemIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesWirelessmodemIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesWirelessmodemIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesWirelessmodemIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesWirelessmodemIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6RouterAdvert struct {
	DefaultPreference string                                               `json:"default-preference,omitempty"`
	MinInterval       int                                                  `json:"min-interval,omitempty"`
	MaxInterval       int                                                  `json:"max-interval,omitempty"`
	ReachableTime     int                                                  `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                 `json:"name-server,omitempty"`
	RetransTimer      int                                                  `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                 `json:"send-advert,omitempty"`
	RadvdOptions      string                                               `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                 `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                 `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                  `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                  `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                  `json:"link-mtu,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesWirelessmodemIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesIpv6Tunnel map[string]struct {
	Disable           json.RawMessage                          `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesIpv6TunnelBandwidth     `json:"bandwidth,omitempty"`
	Encapsulation     string                                   `json:"encapsulation,omitempty"`
	Multicast         string                                   `json:"multicast,omitempty"`
	Ttl               int                                      `json:"ttl,omitempty"`
	Mtu               int                                      `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesIpv6TunnelTrafficPolicy `json:"traffic-policy,omitempty"`
	Key               int                                      `json:"key,omitempty"`
	DisableLinkDetect json.RawMessage                          `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesIpv6TunnelFirewall      `json:"firewall,omitempty"`
	Tos               int                                      `json:"tos,omitempty"`
	Description       string                                   `json:"description,omitempty"`
	Address           IPNet                                    `json:"address,omitempty"`
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
	ClassType *ConfigInterfacesIpv6TunnelBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesIpv6TunnelBandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpRipAuthentication struct {
	Md5               *ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspf struct {
	RetransmitInterval int                                             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                             `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               int                                             `json:"cost,omitempty"`
	DeadInterval       int                                             `json:"dead-interval,omitempty"`
	Priority           int                                             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                 `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesIpv6TunnelIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspfAuthentication struct {
	Md5               *ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpOspfAuthenticationMd5KeyId map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesIpv6TunnelIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBonding map[string]struct {
	BridgeGroup       *ConfigInterfacesBondingBridgeGroup   `json:"bridge-group,omitempty"`
	HashPolicy        string                                `json:"hash-policy,omitempty"`
	Disable           json.RawMessage                       `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBondingBandwidth     `json:"bandwidth,omitempty"`
	Mode              string                                `json:"mode,omitempty"`
	Mtu               int                                   `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesBondingTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBondingVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBondingDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect json.RawMessage                       `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBondingFirewall      `json:"firewall,omitempty"`
	Mac               MacAddr                               `json:"mac,omitempty"`
	DhcpOptions       *ConfigInterfacesBondingDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                `json:"description,omitempty"`
	Vif               *ConfigInterfacesBondingVif           `json:"vif,omitempty"`
	Address           string                                `json:"address,omitempty"`
	Redirect          string                                `json:"redirect,omitempty"`
	ArpMonitor        *ConfigInterfacesBondingArpMonitor    `json:"arp-monitor,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBondingDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesBondingIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBondingIpv6          `json:"ipv6,omitempty"`
	Primary           string                                `json:"primary,omitempty"`
}

type ConfigInterfacesBondingBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesBondingBandwidth struct {
	Maximum    string                                      `json:"maximum,omitempty"`
	Reservable string                                      `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBondingBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBondingBandwidthConstraint struct {
	ClassType *ConfigInterfacesBondingBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBondingBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBondingTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBondingVrrp struct {
	VrrpGroup *ConfigInterfacesBondingVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBondingVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                           `json:"disable,omitempty"`
	VirtualAddress       string                                                    `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                       `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                    `json:"sync-group,omitempty"`
	PreemptDelay         int                                                       `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBondingVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                      `json:"preempt,omitempty"`
	Description          string                                                    `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                      `json:"hello-source-address,omitempty"`
	Priority             int                                                       `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesBondingDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                             `json:"duid,omitempty"`
	NoDns       json.RawMessage                    `json:"no-dns,omitempty"`
	RapidCommit string                             `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                    `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBondingDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesBondingDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                      `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBondingDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                          `json:"no-dns,omitempty"`
	PrefixId      string                                                   `json:"prefix-id,omitempty"`
	HostAddress   string                                                   `json:"host-address,omitempty"`
	Service       string                                                   `json:"service,omitempty"`
}

type ConfigInterfacesBondingDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesBondingVif map[string]struct {
	BridgeGroup       *ConfigInterfacesBondingVifBridgeGroup   `json:"bridge-group,omitempty"`
	Disable           json.RawMessage                          `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBondingVifBandwidth     `json:"bandwidth,omitempty"`
	Mtu               int                                      `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesBondingVifTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBondingVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBondingVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect json.RawMessage                          `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBondingVifFirewall      `json:"firewall,omitempty"`
	DhcpOptions       *ConfigInterfacesBondingVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                   `json:"description,omitempty"`
	Address           string                                   `json:"address,omitempty"`
	Redirect          string                                   `json:"redirect,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBondingVifDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesBondingVifIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBondingVifIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesBondingVifBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesBondingVifBandwidth struct {
	Maximum    string                                         `json:"maximum,omitempty"`
	Reservable string                                         `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBondingVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBondingVifBandwidthConstraint struct {
	ClassType *ConfigInterfacesBondingVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBondingVifBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBondingVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBondingVifVrrp struct {
	VrrpGroup *ConfigInterfacesBondingVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBondingVifVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                              `json:"disable,omitempty"`
	VirtualAddress       string                                                       `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                          `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                       `json:"sync-group,omitempty"`
	PreemptDelay         int                                                          `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBondingVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                         `json:"preempt,omitempty"`
	Description          string                                                       `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                         `json:"hello-source-address,omitempty"`
	Priority             int                                                          `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesBondingVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                `json:"duid,omitempty"`
	NoDns       json.RawMessage                       `json:"no-dns,omitempty"`
	RapidCommit string                                `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                       `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesBondingVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                         `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                             `json:"no-dns,omitempty"`
	PrefixId      string                                                      `json:"prefix-id,omitempty"`
	HostAddress   string                                                      `json:"host-address,omitempty"`
	Service       string                                                      `json:"service,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesBondingVifDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesBondingVifIp struct {
	Rip              *ConfigInterfacesBondingVifIpRip  `json:"rip,omitempty"`
	SourceValidation string                            `json:"source-validation,omitempty"`
	ProxyArpPvlan    json.RawMessage                   `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesBondingVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBondingVifIpRip struct {
	SplitHorizon   *ConfigInterfacesBondingVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBondingVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBondingVifIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingVifIpRipAuthentication struct {
	Md5               *ConfigInterfacesBondingVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingVifIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBondingVifIpOspf struct {
	RetransmitInterval int                                             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                             `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               int                                             `json:"cost,omitempty"`
	DeadInterval       int                                             `json:"dead-interval,omitempty"`
	Priority           int                                             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                 `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBondingVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBondingVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBondingVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingVifIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBondingVifIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBondingVifIpv6 struct {
	DupAddrDetectTransmits int                                         `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                             `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBondingVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBondingVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBondingVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBondingVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBondingVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBondingVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBondingVifIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingVifIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesBondingVifIpv6RouterAdvert struct {
	DefaultPreference string                                            `json:"default-preference,omitempty"`
	MinInterval       int                                               `json:"min-interval,omitempty"`
	MaxInterval       int                                               `json:"max-interval,omitempty"`
	ReachableTime     int                                               `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesBondingVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                              `json:"name-server,omitempty"`
	RetransTimer      int                                               `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                              `json:"send-advert,omitempty"`
	RadvdOptions      string                                            `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                              `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                              `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                               `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                               `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                               `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBondingVifIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBondingVifIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBondingArpMonitor struct {
	Target   IPv4 `json:"target,omitempty"`
	Interval int  `json:"interval,omitempty"`
}

type ConfigInterfacesBondingDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesBondingIp struct {
	Rip              *ConfigInterfacesBondingIpRip  `json:"rip,omitempty"`
	EnableProxyArp   json.RawMessage                `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                         `json:"source-validation,omitempty"`
	ProxyArpPvlan    json.RawMessage                `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesBondingIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesBondingIpRip struct {
	SplitHorizon   *ConfigInterfacesBondingIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesBondingIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesBondingIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingIpRipAuthentication struct {
	Md5               *ConfigInterfacesBondingIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBondingIpOspf struct {
	RetransmitInterval int                                          `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                          `json:"transmit-delay,omitempty"`
	Network            string                                       `json:"network,omitempty"`
	Cost               int                                          `json:"cost,omitempty"`
	DeadInterval       int                                          `json:"dead-interval,omitempty"`
	Priority           int                                          `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                              `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBondingIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                          `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBondingIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBondingIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBondingIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBondingIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBondingIpv6 struct {
	DupAddrDetectTransmits int                                      `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                          `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBondingIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBondingIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBondingIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBondingIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBondingIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBondingIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBondingIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBondingIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesBondingIpv6RouterAdvert struct {
	DefaultPreference string                                         `json:"default-preference,omitempty"`
	MinInterval       int                                            `json:"min-interval,omitempty"`
	MaxInterval       int                                            `json:"max-interval,omitempty"`
	ReachableTime     int                                            `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesBondingIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                           `json:"name-server,omitempty"`
	RetransTimer      int                                            `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                           `json:"send-advert,omitempty"`
	RadvdOptions      string                                         `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                           `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                           `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                            `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                            `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                            `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBondingIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBondingIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpv3 map[string]struct {
	BridgeGroup     *ConfigInterfacesL2tpv3BridgeGroup   `json:"bridge-group,omitempty"`
	Disable         json.RawMessage                      `json:"disable,omitempty"`
	PeerSessionId   int                                  `json:"peer-session-id,omitempty"`
	Bandwidth       *ConfigInterfacesL2tpv3Bandwidth     `json:"bandwidth,omitempty"`
	Encapsulation   string                               `json:"encapsulation,omitempty"`
	Mtu             int                                  `json:"mtu,omitempty"`
	TrafficPolicy   *ConfigInterfacesL2tpv3TrafficPolicy `json:"traffic-policy,omitempty"`
	SourcePort      int                                  `json:"source-port,omitempty"`
	Firewall        *ConfigInterfacesL2tpv3Firewall      `json:"firewall,omitempty"`
	PeerTunnelId    int                                  `json:"peer-tunnel-id,omitempty"`
	Description     string                               `json:"description,omitempty"`
	Address         IPNet                                `json:"address,omitempty"`
	Redirect        string                               `json:"redirect,omitempty"`
	LocalIp         IP                                   `json:"local-ip,omitempty"`
	RemoteIp        IP                                   `json:"remote-ip,omitempty"`
	Ip              *ConfigInterfacesL2tpv3Ip            `json:"ip,omitempty"`
	DestinationPort int                                  `json:"destination-port,omitempty"`
	Ipv6            *ConfigInterfacesL2tpv3Ipv6          `json:"ipv6,omitempty"`
	TunnelId        int                                  `json:"tunnel-id,omitempty"`
	SessionId       int                                  `json:"session-id,omitempty"`
}

type ConfigInterfacesL2tpv3BridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesL2tpv3Bandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesL2tpv3BandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesL2tpv3BandwidthConstraint struct {
	ClassType *ConfigInterfacesL2tpv3BandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesL2tpv3BandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpv3IpRipAuthentication struct {
	Md5               *ConfigInterfacesL2tpv3IpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpv3IpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspf struct {
	RetransmitInterval int                                         `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                         `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               int                                         `json:"cost,omitempty"`
	DeadInterval       int                                         `json:"dead-interval,omitempty"`
	Priority           int                                         `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                             `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesL2tpv3IpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                         `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspfAuthentication struct {
	Md5               *ConfigInterfacesL2tpv3IpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesL2tpv3IpOspfAuthenticationMd5KeyId map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpv3Ipv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesVti map[string]struct {
	Disable       json.RawMessage                   `json:"disable,omitempty"`
	Bandwidth     *ConfigInterfacesVtiBandwidth     `json:"bandwidth,omitempty"`
	Mtu           int                               `json:"mtu,omitempty"`
	TrafficPolicy *ConfigInterfacesVtiTrafficPolicy `json:"traffic-policy,omitempty"`
	Firewall      *ConfigInterfacesVtiFirewall      `json:"firewall,omitempty"`
	Description   string                            `json:"description,omitempty"`
	Address       IPv4Net                           `json:"address,omitempty"`
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
	ClassType *ConfigInterfacesVtiBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesVtiBandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesVtiIpRipAuthentication struct {
	Md5               *ConfigInterfacesVtiIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                     `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesVtiIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesVtiIpOspf struct {
	RetransmitInterval int                                      `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                      `json:"transmit-delay,omitempty"`
	Network            string                                   `json:"network,omitempty"`
	Cost               int                                      `json:"cost,omitempty"`
	DeadInterval       int                                      `json:"dead-interval,omitempty"`
	Priority           int                                      `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                          `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesVtiIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                      `json:"hello-interval,omitempty"`
}

type ConfigInterfacesVtiIpOspfAuthentication struct {
	Md5               *ConfigInterfacesVtiIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                      `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesVtiIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesVtiIpOspfAuthenticationMd5KeyId map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesVtiIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesInput map[string]struct {
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

type ConfigInterfacesBridge map[string]struct {
	Disable           json.RawMessage                      `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBridgeBandwidth     `json:"bandwidth,omitempty"`
	Multicast         string                               `json:"multicast,omitempty"`
	Pppoe             *ConfigInterfacesBridgePppoe         `json:"pppoe,omitempty"`
	TrafficPolicy     *ConfigInterfacesBridgeTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBridgeVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBridgeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	Stp               bool                                 `json:"stp,omitempty"`
	DisableLinkDetect json.RawMessage                      `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBridgeFirewall      `json:"firewall,omitempty"`
	MaxAge            int                                  `json:"max-age,omitempty"`
	BridgedConntrack  string                               `json:"bridged-conntrack,omitempty"`
	DhcpOptions       *ConfigInterfacesBridgeDhcpOptions   `json:"dhcp-options,omitempty"`
	HelloTime         int                                  `json:"hello-time,omitempty"`
	Description       string                               `json:"description,omitempty"`
	Vif               *ConfigInterfacesBridgeVif           `json:"vif,omitempty"`
	Address           string                               `json:"address,omitempty"`
	Redirect          string                               `json:"redirect,omitempty"`
	ForwardingDelay   int                                  `json:"forwarding-delay,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBridgeDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Priority          int                                  `json:"priority,omitempty"`
	Promiscuous       string                               `json:"promiscuous,omitempty"`
	Ip                *ConfigInterfacesBridgeIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBridgeIpv6          `json:"ipv6,omitempty"`
	Aging             int                                  `json:"aging,omitempty"`
}

type ConfigInterfacesBridgeBandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgeBandwidthConstraint struct {
	ClassType *ConfigInterfacesBridgeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgePppoe map[string]struct {
	ServiceName        string                                    `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesBridgePppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                    `json:"password,omitempty"`
	RemoteAddress      IPv4                                      `json:"remote-address,omitempty"`
	HostUniq           string                                    `json:"host-uniq,omitempty"`
	Mtu                int                                       `json:"mtu,omitempty"`
	NameServer         string                                    `json:"name-server,omitempty"`
	DefaultRoute       string                                    `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesBridgePppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        int                                       `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesBridgePppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                           `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesBridgePppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                    `json:"user-id,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	LocalAddress       IPv4                                      `json:"local-address,omitempty"`
	Redirect           string                                    `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesBridgePppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesBridgePppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                           `json:"multilink,omitempty"`
	AccessConcentrator string                                    `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesBridgePppoeBandwidth struct {
	Maximum    string                                          `json:"maximum,omitempty"`
	Reservable string                                          `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgePppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgePppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesBridgePppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgePppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgePppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesBridgePppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                 `json:"duid,omitempty"`
	NoDns       json.RawMessage                        `json:"no-dns,omitempty"`
	RapidCommit string                                 `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                        `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesBridgePppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                          `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                              `json:"no-dns,omitempty"`
	PrefixId      string                                                       `json:"prefix-id,omitempty"`
	HostAddress   string                                                       `json:"host-address,omitempty"`
	Service       string                                                       `json:"service,omitempty"`
}

type ConfigInterfacesBridgePppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgePppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesBridgePppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgePppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspf struct {
	RetransmitInterval int                                              `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                              `json:"transmit-delay,omitempty"`
	Network            string                                           `json:"network,omitempty"`
	Cost               int                                              `json:"cost,omitempty"`
	DeadInterval       int                                              `json:"dead-interval,omitempty"`
	Priority           int                                              `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                  `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgePppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                              `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgePppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6 struct {
	Enable                 *ConfigInterfacesBridgePppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                          `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                              `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgePppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgePppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgePppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgePppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgePppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6RouterAdvert struct {
	DefaultPreference string                                             `json:"default-preference,omitempty"`
	MinInterval       int                                                `json:"min-interval,omitempty"`
	MaxInterval       int                                                `json:"max-interval,omitempty"`
	ReachableTime     int                                                `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                               `json:"name-server,omitempty"`
	RetransTimer      int                                                `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                               `json:"send-advert,omitempty"`
	RadvdOptions      string                                             `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                               `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                               `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgePppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgeVrrp struct {
	VrrpGroup *ConfigInterfacesBridgeVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBridgeVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                          `json:"disable,omitempty"`
	VirtualAddress       string                                                   `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                      `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                   `json:"sync-group,omitempty"`
	PreemptDelay         int                                                      `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBridgeVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                     `json:"preempt,omitempty"`
	Description          string                                                   `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                     `json:"hello-source-address,omitempty"`
	Priority             int                                                      `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesBridgeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                            `json:"duid,omitempty"`
	NoDns       json.RawMessage                   `json:"no-dns,omitempty"`
	RapidCommit string                            `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                   `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesBridgeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                     `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                         `json:"no-dns,omitempty"`
	PrefixId      string                                                  `json:"prefix-id,omitempty"`
	HostAddress   string                                                  `json:"host-address,omitempty"`
	Service       string                                                  `json:"service,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesBridgeVif map[string]struct {
	Disable           json.RawMessage                         `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesBridgeVifBandwidth     `json:"bandwidth,omitempty"`
	Pppoe             *ConfigInterfacesBridgeVifPppoe         `json:"pppoe,omitempty"`
	TrafficPolicy     *ConfigInterfacesBridgeVifTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesBridgeVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesBridgeVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect json.RawMessage                         `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesBridgeVifFirewall      `json:"firewall,omitempty"`
	DhcpOptions       *ConfigInterfacesBridgeVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                  `json:"description,omitempty"`
	Address           string                                  `json:"address,omitempty"`
	Redirect          string                                  `json:"redirect,omitempty"`
	Dhcpv6Options     *ConfigInterfacesBridgeVifDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesBridgeVifIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesBridgeVifIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesBridgeVifBandwidth struct {
	Maximum    string                                        `json:"maximum,omitempty"`
	Reservable string                                        `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgeVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgeVifBandwidthConstraint struct {
	ClassType *ConfigInterfacesBridgeVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgeVifBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgeVifPppoe map[string]struct {
	ServiceName        string                                       `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesBridgeVifPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                       `json:"password,omitempty"`
	RemoteAddress      IPv4                                         `json:"remote-address,omitempty"`
	HostUniq           string                                       `json:"host-uniq,omitempty"`
	Mtu                int                                          `json:"mtu,omitempty"`
	NameServer         string                                       `json:"name-server,omitempty"`
	DefaultRoute       string                                       `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesBridgeVifPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        int                                          `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesBridgeVifPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                              `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesBridgeVifPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                       `json:"user-id,omitempty"`
	Description        string                                       `json:"description,omitempty"`
	LocalAddress       IPv4                                         `json:"local-address,omitempty"`
	Redirect           string                                       `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesBridgeVifPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesBridgeVifPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                              `json:"multilink,omitempty"`
	AccessConcentrator string                                       `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeBandwidth struct {
	Maximum    string                                             `json:"maximum,omitempty"`
	Reservable string                                             `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesBridgeVifPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesBridgeVifPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                    `json:"duid,omitempty"`
	NoDns       json.RawMessage                           `json:"no-dns,omitempty"`
	RapidCommit string                                    `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                           `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                             `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                 `json:"no-dns,omitempty"`
	PrefixId      string                                                          `json:"prefix-id,omitempty"`
	HostAddress   string                                                          `json:"host-address,omitempty"`
	Service       string                                                          `json:"service,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspf struct {
	RetransmitInterval int                                                 `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                 `json:"transmit-delay,omitempty"`
	Network            string                                              `json:"network,omitempty"`
	Cost               int                                                 `json:"cost,omitempty"`
	DeadInterval       int                                                 `json:"dead-interval,omitempty"`
	Priority           int                                                 `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                     `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgeVifPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                 `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                 `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6 struct {
	Enable                 *ConfigInterfacesBridgeVifPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                             `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                 `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgeVifPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgeVifPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgeVifPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgeVifPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgeVifPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                `json:"default-preference,omitempty"`
	MinInterval       int                                                   `json:"min-interval,omitempty"`
	MaxInterval       int                                                   `json:"max-interval,omitempty"`
	ReachableTime     int                                                   `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                  `json:"name-server,omitempty"`
	RetransTimer      int                                                   `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                  `json:"send-advert,omitempty"`
	RadvdOptions      string                                                `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                  `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                  `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                   `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                   `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                   `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgeVifPppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesBridgeVifVrrp struct {
	VrrpGroup *ConfigInterfacesBridgeVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesBridgeVifVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                             `json:"disable,omitempty"`
	VirtualAddress       string                                                      `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                         `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                      `json:"sync-group,omitempty"`
	PreemptDelay         int                                                         `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesBridgeVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                        `json:"preempt,omitempty"`
	Description          string                                                      `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                        `json:"hello-source-address,omitempty"`
	Priority             int                                                         `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesBridgeVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                               `json:"duid,omitempty"`
	NoDns       json.RawMessage                      `json:"no-dns,omitempty"`
	RapidCommit string                               `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                      `json:"prefix-only,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesBridgeVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                        `json:"prefix-length,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                            `json:"no-dns,omitempty"`
	PrefixId      string                                                     `json:"prefix-id,omitempty"`
	HostAddress   string                                                     `json:"host-address,omitempty"`
	Service       string                                                     `json:"service,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesBridgeVifDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifIpRipAuthentication struct {
	Md5               *ConfigInterfacesBridgeVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspf struct {
	RetransmitInterval int                                            `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                            `json:"transmit-delay,omitempty"`
	Network            string                                         `json:"network,omitempty"`
	Cost               int                                            `json:"cost,omitempty"`
	DeadInterval       int                                            `json:"dead-interval,omitempty"`
	Priority           int                                            `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgeVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                            `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgeVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgeVifIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6 struct {
	DupAddrDetectTransmits int                                        `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                            `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgeVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgeVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgeVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgeVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgeVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6RouterAdvert struct {
	DefaultPreference string                                           `json:"default-preference,omitempty"`
	MinInterval       int                                              `json:"min-interval,omitempty"`
	MaxInterval       int                                              `json:"max-interval,omitempty"`
	ReachableTime     int                                              `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                             `json:"name-server,omitempty"`
	RetransTimer      int                                              `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                             `json:"send-advert,omitempty"`
	RadvdOptions      string                                           `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                             `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                             `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                              `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                              `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                              `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgeVifIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeIpRipAuthentication struct {
	Md5               *ConfigInterfacesBridgeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesBridgeIpOspf struct {
	RetransmitInterval int                                         `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                         `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               int                                         `json:"cost,omitempty"`
	DeadInterval       int                                         `json:"dead-interval,omitempty"`
	Priority           int                                         `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                             `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesBridgeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                         `json:"hello-interval,omitempty"`
}

type ConfigInterfacesBridgeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesBridgeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesBridgeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesBridgeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesBridgeIpv6 struct {
	DupAddrDetectTransmits int                                     `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                         `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesBridgeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesBridgeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesBridgeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesBridgeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesBridgeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesBridgeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesBridgeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesBridgeIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesBridgeIpv6RouterAdvert struct {
	DefaultPreference string                                        `json:"default-preference,omitempty"`
	MinInterval       int                                           `json:"min-interval,omitempty"`
	MaxInterval       int                                           `json:"max-interval,omitempty"`
	ReachableTime     int                                           `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesBridgeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                          `json:"name-server,omitempty"`
	RetransTimer      int                                           `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                          `json:"send-advert,omitempty"`
	RadvdOptions      string                                        `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                          `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                          `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                           `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                           `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                           `json:"link-mtu,omitempty"`
}

type ConfigInterfacesBridgeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesBridgeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpClient map[string]struct {
	Disable        json.RawMessage                           `json:"disable,omitempty"`
	Bandwidth      *ConfigInterfacesL2tpClientBandwidth      `json:"bandwidth,omitempty"`
	Mtu            int                                       `json:"mtu,omitempty"`
	NameServer     string                                    `json:"name-server,omitempty"`
	DefaultRoute   string                                    `json:"default-route,omitempty"`
	TrafficPolicy  *ConfigInterfacesL2tpClientTrafficPolicy  `json:"traffic-policy,omitempty"`
	Firewall       *ConfigInterfacesL2tpClientFirewall       `json:"firewall,omitempty"`
	ServerIp       string                                    `json:"server-ip,omitempty"`
	Description    string                                    `json:"description,omitempty"`
	Compression    *ConfigInterfacesL2tpClientCompression    `json:"compression,omitempty"`
	Redirect       string                                    `json:"redirect,omitempty"`
	RequireIpsec   json.RawMessage                           `json:"require-ipsec,omitempty"`
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
	ClassType *ConfigInterfacesL2tpClientBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesL2tpClientBandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpClientIpRipAuthentication struct {
	Md5               *ConfigInterfacesL2tpClientIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpClientIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspf struct {
	RetransmitInterval int                                             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                             `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               int                                             `json:"cost,omitempty"`
	DeadInterval       int                                             `json:"dead-interval,omitempty"`
	Priority           int                                             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                 `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesL2tpClientIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspfAuthentication struct {
	Md5               *ConfigInterfacesL2tpClientIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesL2tpClientIpOspfAuthenticationMd5KeyId map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesL2tpClientIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesL2tpClientAuthentication struct {
	Password    string          `json:"password,omitempty"`
	Refuse      string          `json:"refuse,omitempty"`
	UserId      string          `json:"user-id,omitempty"`
	RequireMppe json.RawMessage `json:"require-mppe,omitempty"`
}

type ConfigInterfacesPptpClient map[string]struct {
	Bandwidth       *ConfigInterfacesPptpClientBandwidth     `json:"bandwidth,omitempty"`
	Password        string                                   `json:"password,omitempty"`
	RemoteAddress   IPv4                                     `json:"remote-address,omitempty"`
	Mtu             int                                      `json:"mtu,omitempty"`
	NameServer      string                                   `json:"name-server,omitempty"`
	DefaultRoute    string                                   `json:"default-route,omitempty"`
	TrafficPolicy   *ConfigInterfacesPptpClientTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout     int                                      `json:"idle-timeout,omitempty"`
	ConnectOnDemand json.RawMessage                          `json:".connect-on-demand,omitempty"`
	Firewall        *ConfigInterfacesPptpClientFirewall      `json:"firewall,omitempty"`
	UserId          string                                   `json:"user-id,omitempty"`
	ServerIp        string                                   `json:"server-ip,omitempty"`
	Description     string                                   `json:"description,omitempty"`
	LocalAddress    IPv4                                     `json:"local-address,omitempty"`
	RequireMppe     json.RawMessage                          `json:"require-mppe,omitempty"`
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
	ClassType *ConfigInterfacesPptpClientBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPptpClientBandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPptpClientIpRipAuthentication struct {
	Md5               *ConfigInterfacesPptpClientIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPptpClientIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPptpClientIpOspf struct {
	RetransmitInterval int                                             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                             `json:"transmit-delay,omitempty"`
	Network            string                                          `json:"network,omitempty"`
	Cost               int                                             `json:"cost,omitempty"`
	DeadInterval       int                                             `json:"dead-interval,omitempty"`
	Priority           int                                             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                 `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPptpClientIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPptpClientIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPptpClientIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPptpClientIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPptpClientIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPptpClientIpv6 struct {
	Enable                 *ConfigInterfacesPptpClientIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                         `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                             `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesPptpClientIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesPptpClientIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesPptpClientIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesPptpClientIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPptpClientIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPptpClientIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesPptpClientIpv6RouterAdvert struct {
	DefaultPreference string                                            `json:"default-preference,omitempty"`
	MinInterval       int                                               `json:"min-interval,omitempty"`
	MaxInterval       int                                               `json:"max-interval,omitempty"`
	ReachableTime     int                                               `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesPptpClientIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                              `json:"name-server,omitempty"`
	RetransTimer      int                                               `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                              `json:"send-advert,omitempty"`
	RadvdOptions      string                                            `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                              `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                              `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                               `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                               `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                               `json:"link-mtu,omitempty"`
}

type ConfigInterfacesPptpClientIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesPptpClientIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernet map[string]struct {
	BridgeGroup        *ConfigInterfacesEthernetBridgeGroup   `json:"bridge-group,omitempty"`
	Poe                *ConfigInterfacesEthernetPoe           `json:"poe,omitempty"`
	Disable            json.RawMessage                        `json:"disable,omitempty"`
	Bandwidth          *ConfigInterfacesEthernetBandwidth     `json:"bandwidth,omitempty"`
	Pppoe              *ConfigInterfacesEthernetPppoe         `json:"pppoe,omitempty"`
	Speed              string                                 `json:"speed,omitempty"`
	Mtu                int                                    `json:"mtu,omitempty"`
	TrafficPolicy      *ConfigInterfacesEthernetTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp               *ConfigInterfacesEthernetVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesEthernetDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect  json.RawMessage                        `json:"disable-link-detect,omitempty"`
	Duplex             string                                 `json:"duplex,omitempty"`
	Firewall           *ConfigInterfacesEthernetFirewall      `json:"firewall,omitempty"`
	DisableFlowControl json.RawMessage                        `json:".disable-flow-control,omitempty"`
	Mac                MacAddr                                `json:"mac,omitempty"`
	DhcpOptions        *ConfigInterfacesEthernetDhcpOptions   `json:"dhcp-options,omitempty"`
	Description        string                                 `json:"description,omitempty"`
	BondGroup          string                                 `json:"bond-group,omitempty"`
	Vif                *ConfigInterfacesEthernetVif           `json:"vif,omitempty"`
	Address            string                                 `json:"address,omitempty"`
	Redirect           string                                 `json:"redirect,omitempty"`
	SmpAffinity        string                                 `json:".smp_affinity,omitempty"`
	Dhcpv6Options      *ConfigInterfacesEthernetDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                 *ConfigInterfacesEthernetIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesEthernetIpv6          `json:"ipv6,omitempty"`
	Mirror             string                                 `json:"mirror,omitempty"`
}

type ConfigInterfacesEthernetBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesEthernetPoe struct {
	Output   string                               `json:"output,omitempty"`
	Watchdog *ConfigInterfacesEthernetPoeWatchdog `json:"watchdog,omitempty"`
}

type ConfigInterfacesEthernetPoeWatchdog struct {
	Disable      json.RawMessage `json:"disable,omitempty"`
	FailureCount int             `json:"failure-count,omitempty"`
	OffDelay     int             `json:"off-delay,omitempty"`
	Interval     int             `json:"interval,omitempty"`
	StartDelay   int             `json:"start-delay,omitempty"`
	Address      IP              `json:"address,omitempty"`
}

type ConfigInterfacesEthernetBandwidth struct {
	Maximum    string                                       `json:"maximum,omitempty"`
	Reservable string                                       `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetBandwidthConstraint struct {
	ClassType *ConfigInterfacesEthernetBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetPppoe map[string]struct {
	ServiceName        string                                      `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesEthernetPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                      `json:"password,omitempty"`
	RemoteAddress      IPv4                                        `json:"remote-address,omitempty"`
	HostUniq           string                                      `json:"host-uniq,omitempty"`
	Mtu                int                                         `json:"mtu,omitempty"`
	NameServer         string                                      `json:"name-server,omitempty"`
	DefaultRoute       string                                      `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesEthernetPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        int                                         `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesEthernetPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                             `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesEthernetPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                      `json:"user-id,omitempty"`
	Description        string                                      `json:"description,omitempty"`
	LocalAddress       IPv4                                        `json:"local-address,omitempty"`
	Redirect           string                                      `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesEthernetPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesEthernetPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                             `json:"multilink,omitempty"`
	AccessConcentrator string                                      `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesEthernetPppoeBandwidth struct {
	Maximum    string                                            `json:"maximum,omitempty"`
	Reservable string                                            `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetPppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesEthernetPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetPppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesEthernetPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                   `json:"duid,omitempty"`
	NoDns       json.RawMessage                          `json:"no-dns,omitempty"`
	RapidCommit string                                   `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                          `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                            `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                `json:"no-dns,omitempty"`
	PrefixId      string                                                         `json:"prefix-id,omitempty"`
	HostAddress   string                                                         `json:"host-address,omitempty"`
	Service       string                                                         `json:"service,omitempty"`
}

type ConfigInterfacesEthernetPppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                               `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspf struct {
	RetransmitInterval int                                                `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                `json:"transmit-delay,omitempty"`
	Network            string                                             `json:"network,omitempty"`
	Cost               int                                                `json:"cost,omitempty"`
	DeadInterval       int                                                `json:"dead-interval,omitempty"`
	Priority           int                                                `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                    `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6 struct {
	Enable                 *ConfigInterfacesEthernetPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                            `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                               `json:"default-preference,omitempty"`
	MinInterval       int                                                  `json:"min-interval,omitempty"`
	MaxInterval       int                                                  `json:"max-interval,omitempty"`
	ReachableTime     int                                                  `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                 `json:"name-server,omitempty"`
	RetransTimer      int                                                  `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                 `json:"send-advert,omitempty"`
	RadvdOptions      string                                               `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                 `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                 `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                  `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                  `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                  `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetPppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetVrrp struct {
	VrrpGroup *ConfigInterfacesEthernetVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesEthernetVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                            `json:"disable,omitempty"`
	VirtualAddress       string                                                     `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                        `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                     `json:"sync-group,omitempty"`
	PreemptDelay         int                                                        `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesEthernetVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                       `json:"preempt,omitempty"`
	Description          string                                                     `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                       `json:"hello-source-address,omitempty"`
	Priority             int                                                        `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesEthernetDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                              `json:"duid,omitempty"`
	NoDns       json.RawMessage                     `json:"no-dns,omitempty"`
	RapidCommit string                              `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                     `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesEthernetDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                       `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                           `json:"no-dns,omitempty"`
	PrefixId      string                                                    `json:"prefix-id,omitempty"`
	HostAddress   string                                                    `json:"host-address,omitempty"`
	Service       string                                                    `json:"service,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesEthernetVif map[string]struct {
	BridgeGroup       *ConfigInterfacesEthernetVifBridgeGroup   `json:"bridge-group,omitempty"`
	Disable           json.RawMessage                           `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesEthernetVifBandwidth     `json:"bandwidth,omitempty"`
	EgressQos         string                                    `json:"egress-qos,omitempty"`
	Pppoe             *ConfigInterfacesEthernetVifPppoe         `json:"pppoe,omitempty"`
	Mtu               int                                       `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesEthernetVifTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp              *ConfigInterfacesEthernetVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesEthernetVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect json.RawMessage                           `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesEthernetVifFirewall      `json:"firewall,omitempty"`
	Mac               MacAddr                                   `json:"mac,omitempty"`
	DhcpOptions       *ConfigInterfacesEthernetVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                    `json:"description,omitempty"`
	Address           string                                    `json:"address,omitempty"`
	Redirect          string                                    `json:"redirect,omitempty"`
	Dhcpv6Options     *ConfigInterfacesEthernetVifDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesEthernetVifIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesEthernetVifIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesEthernetVifBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesEthernetVifBandwidth struct {
	Maximum    string                                          `json:"maximum,omitempty"`
	Reservable string                                          `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetVifBandwidthConstraint struct {
	ClassType *ConfigInterfacesEthernetVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetVifBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetVifPppoe map[string]struct {
	ServiceName        string                                         `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesEthernetVifPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                         `json:"password,omitempty"`
	RemoteAddress      IPv4                                           `json:"remote-address,omitempty"`
	HostUniq           string                                         `json:"host-uniq,omitempty"`
	Mtu                int                                            `json:"mtu,omitempty"`
	NameServer         string                                         `json:"name-server,omitempty"`
	DefaultRoute       string                                         `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesEthernetVifPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        int                                            `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesEthernetVifPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                                `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesEthernetVifPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                         `json:"user-id,omitempty"`
	Description        string                                         `json:"description,omitempty"`
	LocalAddress       IPv4                                           `json:"local-address,omitempty"`
	Redirect           string                                         `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesEthernetVifPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesEthernetVifPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                                `json:"multilink,omitempty"`
	AccessConcentrator string                                         `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeBandwidth struct {
	Maximum    string                                               `json:"maximum,omitempty"`
	Reservable string                                               `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesEthernetVifPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesEthernetVifPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                      `json:"duid,omitempty"`
	NoDns       json.RawMessage                             `json:"no-dns,omitempty"`
	RapidCommit string                                      `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                             `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                               `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                   `json:"no-dns,omitempty"`
	PrefixId      string                                                            `json:"prefix-id,omitempty"`
	HostAddress   string                                                            `json:"host-address,omitempty"`
	Service       string                                                            `json:"service,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                  `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspf struct {
	RetransmitInterval int                                                   `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                   `json:"transmit-delay,omitempty"`
	Network            string                                                `json:"network,omitempty"`
	Cost               int                                                   `json:"cost,omitempty"`
	DeadInterval       int                                                   `json:"dead-interval,omitempty"`
	Priority           int                                                   `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                       `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetVifPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                   `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6 struct {
	Enable                 *ConfigInterfacesEthernetVifPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                               `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                   `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetVifPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetVifPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetVifPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetVifPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetVifPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                  `json:"default-preference,omitempty"`
	MinInterval       int                                                     `json:"min-interval,omitempty"`
	MaxInterval       int                                                     `json:"max-interval,omitempty"`
	ReachableTime     int                                                     `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                    `json:"name-server,omitempty"`
	RetransTimer      int                                                     `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                    `json:"send-advert,omitempty"`
	RadvdOptions      string                                                  `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                    `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                    `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                     `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                     `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                     `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetVifPppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesEthernetVifVrrp struct {
	VrrpGroup *ConfigInterfacesEthernetVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesEthernetVifVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                               `json:"disable,omitempty"`
	VirtualAddress       string                                                        `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                           `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                        `json:"sync-group,omitempty"`
	PreemptDelay         int                                                           `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesEthernetVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                          `json:"preempt,omitempty"`
	Description          string                                                        `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                          `json:"hello-source-address,omitempty"`
	Priority             int                                                           `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesEthernetVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                 `json:"duid,omitempty"`
	NoDns       json.RawMessage                        `json:"no-dns,omitempty"`
	RapidCommit string                                 `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                        `json:"prefix-only,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesEthernetVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                          `json:"prefix-length,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                              `json:"no-dns,omitempty"`
	PrefixId      string                                                       `json:"prefix-id,omitempty"`
	HostAddress   string                                                       `json:"host-address,omitempty"`
	Service       string                                                       `json:"service,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesEthernetVifDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesEthernetVifIp struct {
	Rip              *ConfigInterfacesEthernetVifIpRip  `json:"rip,omitempty"`
	EnableProxyArp   json.RawMessage                    `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                             `json:"source-validation,omitempty"`
	ProxyArpPvlan    json.RawMessage                    `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesEthernetVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesEthernetVifIpRip struct {
	SplitHorizon   *ConfigInterfacesEthernetVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesEthernetVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetVifIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifIpRipAuthentication struct {
	Md5               *ConfigInterfacesEthernetVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspf struct {
	RetransmitInterval int                                              `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                              `json:"transmit-delay,omitempty"`
	Network            string                                           `json:"network,omitempty"`
	Cost               int                                              `json:"cost,omitempty"`
	DeadInterval       int                                              `json:"dead-interval,omitempty"`
	Priority           int                                              `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                  `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                              `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetVifIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6 struct {
	DupAddrDetectTransmits int                                          `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                              `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6RouterAdvert struct {
	DefaultPreference string                                             `json:"default-preference,omitempty"`
	MinInterval       int                                                `json:"min-interval,omitempty"`
	MaxInterval       int                                                `json:"max-interval,omitempty"`
	ReachableTime     int                                                `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                               `json:"name-server,omitempty"`
	RetransTimer      int                                                `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                               `json:"send-advert,omitempty"`
	RadvdOptions      string                                             `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                               `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                               `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetVifIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesEthernetIp struct {
	Rip              *ConfigInterfacesEthernetIpRip  `json:"rip,omitempty"`
	EnableProxyArp   json.RawMessage                 `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                          `json:"source-validation,omitempty"`
	ProxyArpPvlan    json.RawMessage                 `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesEthernetIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesEthernetIpRip struct {
	SplitHorizon   *ConfigInterfacesEthernetIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesEthernetIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesEthernetIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetIpRipAuthentication struct {
	Md5               *ConfigInterfacesEthernetIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesEthernetIpOspf struct {
	RetransmitInterval int                                           `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                           `json:"transmit-delay,omitempty"`
	Network            string                                        `json:"network,omitempty"`
	Cost               int                                           `json:"cost,omitempty"`
	DeadInterval       int                                           `json:"dead-interval,omitempty"`
	Priority           int                                           `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                               `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesEthernetIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                           `json:"hello-interval,omitempty"`
}

type ConfigInterfacesEthernetIpOspfAuthentication struct {
	Md5               *ConfigInterfacesEthernetIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesEthernetIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesEthernetIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesEthernetIpv6 struct {
	DupAddrDetectTransmits int                                       `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                           `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesEthernetIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesEthernetIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesEthernetIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesEthernetIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesEthernetIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesEthernetIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesEthernetIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesEthernetIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesEthernetIpv6RouterAdvert struct {
	DefaultPreference string                                          `json:"default-preference,omitempty"`
	MinInterval       int                                             `json:"min-interval,omitempty"`
	MaxInterval       int                                             `json:"max-interval,omitempty"`
	ReachableTime     int                                             `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesEthernetIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                            `json:"name-server,omitempty"`
	RetransTimer      int                                             `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                            `json:"send-advert,omitempty"`
	RadvdOptions      string                                          `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                            `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                            `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                             `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                             `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                             `json:"link-mtu,omitempty"`
}

type ConfigInterfacesEthernetIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesEthernetIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesTunnel map[string]struct {
	BridgeGroup       *ConfigInterfacesTunnelBridgeGroup   `json:"bridge-group,omitempty"`
	Disable           json.RawMessage                      `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesTunnelBandwidth     `json:"bandwidth,omitempty"`
	Encapsulation     string                               `json:"encapsulation,omitempty"`
	Multicast         string                               `json:"multicast,omitempty"`
	Ttl               int                                  `json:"ttl,omitempty"`
	Mtu               int                                  `json:"mtu,omitempty"`
	TrafficPolicy     *ConfigInterfacesTunnelTrafficPolicy `json:"traffic-policy,omitempty"`
	Key               int                                  `json:"key,omitempty"`
	DisableLinkDetect json.RawMessage                      `json:"disable-link-detect,omitempty"`
	SixrdPrefix       IPv6Net                              `json:"6rd-prefix,omitempty"`
	Firewall          *ConfigInterfacesTunnelFirewall      `json:"firewall,omitempty"`
	Tos               int                                  `json:"tos,omitempty"`
	SixrdRelayPrefix  IPv4Net                              `json:"6rd-relay_prefix,omitempty"`
	Description       string                               `json:"description,omitempty"`
	Address           IPNet                                `json:"address,omitempty"`
	Redirect          string                               `json:"redirect,omitempty"`
	LocalIp           IPv4                                 `json:"local-ip,omitempty"`
	RemoteIp          IPv4                                 `json:"remote-ip,omitempty"`
	SixrdDefaultGw    IPv6                                 `json:"6rd-default-gw,omitempty"`
	Ip                *ConfigInterfacesTunnelIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesTunnelIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesTunnelBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesTunnelBandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesTunnelBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesTunnelBandwidthConstraint struct {
	ClassType *ConfigInterfacesTunnelBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesTunnelBandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesTunnelIpRipAuthentication struct {
	Md5               *ConfigInterfacesTunnelIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesTunnelIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesTunnelIpOspf struct {
	RetransmitInterval int                                         `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                         `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               int                                         `json:"cost,omitempty"`
	DeadInterval       int                                         `json:"dead-interval,omitempty"`
	Priority           int                                         `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                             `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesTunnelIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                         `json:"hello-interval,omitempty"`
}

type ConfigInterfacesTunnelIpOspfAuthentication struct {
	Md5               *ConfigInterfacesTunnelIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesTunnelIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesTunnelIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesTunnelIpv6 struct {
	DupAddrDetectTransmits int                                     `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                         `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesTunnelIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesTunnelIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesTunnelIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesTunnelIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesTunnelIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesTunnelIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesTunnelIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesTunnelIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesTunnelIpv6RouterAdvert struct {
	DefaultPreference string                                        `json:"default-preference,omitempty"`
	MinInterval       int                                           `json:"min-interval,omitempty"`
	MaxInterval       int                                           `json:"max-interval,omitempty"`
	ReachableTime     int                                           `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesTunnelIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                          `json:"name-server,omitempty"`
	RetransTimer      int                                           `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                          `json:"send-advert,omitempty"`
	RadvdOptions      string                                        `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                          `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                          `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                           `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                           `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                           `json:"link-mtu,omitempty"`
}

type ConfigInterfacesTunnelIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesTunnelIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesOpenvpn map[string]struct {
	BridgeGroup         *ConfigInterfacesOpenvpnBridgeGroup         `json:"bridge-group,omitempty"`
	Encryption          string                                      `json:"encryption,omitempty"`
	Disable             json.RawMessage                             `json:"disable,omitempty"`
	RemoteHost          string                                      `json:"remote-host,omitempty"`
	Bandwidth           *ConfigInterfacesOpenvpnBandwidth           `json:"bandwidth,omitempty"`
	ReplaceDefaultRoute *ConfigInterfacesOpenvpnReplaceDefaultRoute `json:"replace-default-route,omitempty"`
	OpenvpnOption       string                                      `json:"openvpn-option,omitempty"`
	RemoteAddress       IPv4                                        `json:"remote-address,omitempty"`
	Mode                string                                      `json:"mode,omitempty"`
	Hash                string                                      `json:"hash,omitempty"`
	DeviceType          string                                      `json:"device-type,omitempty"`
	SharedSecretKeyFile string                                      `json:"shared-secret-key-file,omitempty"`
	LocalHost           IPv4                                        `json:"local-host,omitempty"`
	TrafficPolicy       *ConfigInterfacesOpenvpnTrafficPolicy       `json:"traffic-policy,omitempty"`
	Server              *ConfigInterfacesOpenvpnServer              `json:"server,omitempty"`
	Protocol            string                                      `json:"protocol,omitempty"`
	Firewall            *ConfigInterfacesOpenvpnFirewall            `json:"firewall,omitempty"`
	Tls                 *ConfigInterfacesOpenvpnTls                 `json:"tls,omitempty"`
	Description         string                                      `json:"description,omitempty"`
	LocalAddress        *ConfigInterfacesOpenvpnLocalAddress        `json:"local-address,omitempty"`
	LocalPort           int                                         `json:"local-port,omitempty"`
	Redirect            string                                      `json:"redirect,omitempty"`
	Ip                  *ConfigInterfacesOpenvpnIp                  `json:"ip,omitempty"`
	Ipv6                *ConfigInterfacesOpenvpnIpv6                `json:"ipv6,omitempty"`
	RemotePort          int                                         `json:"remote-port,omitempty"`
	ConfigFile          string                                      `json:"config-file,omitempty"`
}

type ConfigInterfacesOpenvpnBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesOpenvpnBandwidth struct {
	Maximum    string                                      `json:"maximum,omitempty"`
	Reservable string                                      `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesOpenvpnBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesOpenvpnBandwidthConstraint struct {
	ClassType *ConfigInterfacesOpenvpnBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesOpenvpnBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesOpenvpnReplaceDefaultRoute struct {
	Local json.RawMessage `json:"local,omitempty"`
}

type ConfigInterfacesOpenvpnTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesOpenvpnServer struct {
	PushRoute      IPv4Net                              `json:"push-route,omitempty"`
	Topology       string                               `json:"topology,omitempty"`
	NameServer     IPv4                                 `json:"name-server,omitempty"`
	DomainName     string                               `json:"domain-name,omitempty"`
	MaxConnections int                                  `json:"max-connections,omitempty"`
	Subnet         IPv4Net                              `json:"subnet,omitempty"`
	Client         *ConfigInterfacesOpenvpnServerClient `json:"client,omitempty"`
}

type ConfigInterfacesOpenvpnServerClient map[string]struct {
	PushRoute IPv4Net         `json:"push-route,omitempty"`
	Disable   json.RawMessage `json:"disable,omitempty"`
	Ip        IPv4            `json:"ip,omitempty"`
	Subnet    IPv4Net         `json:"subnet,omitempty"`
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

type ConfigInterfacesOpenvpnLocalAddress map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesOpenvpnIpRipAuthentication struct {
	Md5               *ConfigInterfacesOpenvpnIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesOpenvpnIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspf struct {
	RetransmitInterval int                                          `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                          `json:"transmit-delay,omitempty"`
	Network            string                                       `json:"network,omitempty"`
	Cost               int                                          `json:"cost,omitempty"`
	DeadInterval       int                                          `json:"dead-interval,omitempty"`
	Priority           int                                          `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                              `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesOpenvpnIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                          `json:"hello-interval,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspfAuthentication struct {
	Md5               *ConfigInterfacesOpenvpnIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesOpenvpnIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6 struct {
	DupAddrDetectTransmits int                                      `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                          `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesOpenvpnIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesOpenvpnIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesOpenvpnIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesOpenvpnIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesOpenvpnIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6RouterAdvert struct {
	DefaultPreference string                                         `json:"default-preference,omitempty"`
	MinInterval       int                                            `json:"min-interval,omitempty"`
	MaxInterval       int                                            `json:"max-interval,omitempty"`
	ReachableTime     int                                            `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                           `json:"name-server,omitempty"`
	RetransTimer      int                                            `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                           `json:"send-advert,omitempty"`
	RadvdOptions      string                                         `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                           `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                           `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                            `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                            `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                            `json:"link-mtu,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesOpenvpnIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesLoopback map[string]struct {
	Bandwidth     *ConfigInterfacesLoopbackBandwidth     `json:"bandwidth,omitempty"`
	TrafficPolicy *ConfigInterfacesLoopbackTrafficPolicy `json:"traffic-policy,omitempty"`
	Description   string                                 `json:"description,omitempty"`
	Address       IPNet                                  `json:"address,omitempty"`
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
	ClassType *ConfigInterfacesLoopbackBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesLoopbackBandwidthConstraintClassType map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesLoopbackIpRipAuthentication struct {
	Md5               *ConfigInterfacesLoopbackIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                          `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesLoopbackIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesLoopbackIpOspf struct {
	RetransmitInterval int                                           `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                           `json:"transmit-delay,omitempty"`
	Network            string                                        `json:"network,omitempty"`
	Cost               int                                           `json:"cost,omitempty"`
	DeadInterval       int                                           `json:"dead-interval,omitempty"`
	Priority           int                                           `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                               `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesLoopbackIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                           `json:"hello-interval,omitempty"`
}

type ConfigInterfacesLoopbackIpOspfAuthentication struct {
	Md5               *ConfigInterfacesLoopbackIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesLoopbackIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesLoopbackIpOspfAuthenticationMd5KeyId map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesLoopbackIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitch map[string]struct {
	BridgeGroup   *ConfigInterfacesSwitchBridgeGroup   `json:"bridge-group,omitempty"`
	Bandwidth     *ConfigInterfacesSwitchBandwidth     `json:"bandwidth,omitempty"`
	Pppoe         *ConfigInterfacesSwitchPppoe         `json:"pppoe,omitempty"`
	Mtu           int                                  `json:"mtu,omitempty"`
	SwitchPort    *ConfigInterfacesSwitchSwitchPort    `json:"switch-port,omitempty"`
	TrafficPolicy *ConfigInterfacesSwitchTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp          *ConfigInterfacesSwitchVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd      *ConfigInterfacesSwitchDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	Firewall      *ConfigInterfacesSwitchFirewall      `json:"firewall,omitempty"`
	DhcpOptions   *ConfigInterfacesSwitchDhcpOptions   `json:"dhcp-options,omitempty"`
	Description   string                               `json:"description,omitempty"`
	Vif           *ConfigInterfacesSwitchVif           `json:"vif,omitempty"`
	Address       string                               `json:"address,omitempty"`
	Redirect      string                               `json:"redirect,omitempty"`
	Dhcpv6Options *ConfigInterfacesSwitchDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip            *ConfigInterfacesSwitchIp            `json:"ip,omitempty"`
	Ipv6          *ConfigInterfacesSwitchIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesSwitchBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesSwitchBandwidth struct {
	Maximum    string                                     `json:"maximum,omitempty"`
	Reservable string                                     `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchBandwidthConstraint struct {
	ClassType *ConfigInterfacesSwitchBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchPppoe map[string]struct {
	ServiceName        string                                    `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesSwitchPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                    `json:"password,omitempty"`
	RemoteAddress      IPv4                                      `json:"remote-address,omitempty"`
	HostUniq           string                                    `json:"host-uniq,omitempty"`
	Mtu                int                                       `json:"mtu,omitempty"`
	NameServer         string                                    `json:"name-server,omitempty"`
	DefaultRoute       string                                    `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesSwitchPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        int                                       `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesSwitchPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                           `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesSwitchPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                    `json:"user-id,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	LocalAddress       IPv4                                      `json:"local-address,omitempty"`
	Redirect           string                                    `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesSwitchPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesSwitchPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                           `json:"multilink,omitempty"`
	AccessConcentrator string                                    `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesSwitchPppoeBandwidth struct {
	Maximum    string                                          `json:"maximum,omitempty"`
	Reservable string                                          `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchPppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesSwitchPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchPppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesSwitchPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                 `json:"duid,omitempty"`
	NoDns       json.RawMessage                        `json:"no-dns,omitempty"`
	RapidCommit string                                 `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                        `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                          `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                              `json:"no-dns,omitempty"`
	PrefixId      string                                                       `json:"prefix-id,omitempty"`
	HostAddress   string                                                       `json:"host-address,omitempty"`
	Service       string                                                       `json:"service,omitempty"`
}

type ConfigInterfacesSwitchPppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                             `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspf struct {
	RetransmitInterval int                                              `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                              `json:"transmit-delay,omitempty"`
	Network            string                                           `json:"network,omitempty"`
	Cost               int                                              `json:"cost,omitempty"`
	DeadInterval       int                                              `json:"dead-interval,omitempty"`
	Priority           int                                              `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                  `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                              `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                              `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6 struct {
	Enable                 *ConfigInterfacesSwitchPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                          `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                              `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                             `json:"default-preference,omitempty"`
	MinInterval       int                                                `json:"min-interval,omitempty"`
	MaxInterval       int                                                `json:"max-interval,omitempty"`
	ReachableTime     int                                                `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                               `json:"name-server,omitempty"`
	RetransTimer      int                                                `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                               `json:"send-advert,omitempty"`
	RadvdOptions      string                                             `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                               `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                               `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchPppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchSwitchPort struct {
	Interface *ConfigInterfacesSwitchSwitchPortInterface `json:"interface,omitempty"`
	VlanAware string                                     `json:"vlan-aware,omitempty"`
}

type ConfigInterfacesSwitchSwitchPortInterface map[string]struct {
	Vlan *ConfigInterfacesSwitchSwitchPortInterfaceVlan `json:"vlan,omitempty"`
}

type ConfigInterfacesSwitchSwitchPortInterfaceVlan struct {
	Vid  int `json:"vid,omitempty"`
	Pvid int `json:"pvid,omitempty"`
}

type ConfigInterfacesSwitchTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchVrrp struct {
	VrrpGroup *ConfigInterfacesSwitchVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesSwitchVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                          `json:"disable,omitempty"`
	VirtualAddress       string                                                   `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                      `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                   `json:"sync-group,omitempty"`
	PreemptDelay         int                                                      `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesSwitchVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                     `json:"preempt,omitempty"`
	Description          string                                                   `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                     `json:"hello-source-address,omitempty"`
	Priority             int                                                      `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesSwitchDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                            `json:"duid,omitempty"`
	NoDns       json.RawMessage                   `json:"no-dns,omitempty"`
	RapidCommit string                            `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                   `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesSwitchDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                     `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                         `json:"no-dns,omitempty"`
	PrefixId      string                                                  `json:"prefix-id,omitempty"`
	HostAddress   string                                                  `json:"host-address,omitempty"`
	Service       string                                                  `json:"service,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesSwitchVif map[string]struct {
	BridgeGroup   *ConfigInterfacesSwitchVifBridgeGroup   `json:"bridge-group,omitempty"`
	Disable       json.RawMessage                         `json:"disable,omitempty"`
	Bandwidth     *ConfigInterfacesSwitchVifBandwidth     `json:"bandwidth,omitempty"`
	Pppoe         *ConfigInterfacesSwitchVifPppoe         `json:"pppoe,omitempty"`
	Mtu           int                                     `json:"mtu,omitempty"`
	TrafficPolicy *ConfigInterfacesSwitchVifTrafficPolicy `json:"traffic-policy,omitempty"`
	Vrrp          *ConfigInterfacesSwitchVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd      *ConfigInterfacesSwitchVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	Firewall      *ConfigInterfacesSwitchVifFirewall      `json:"firewall,omitempty"`
	Mac           MacAddr                                 `json:"mac,omitempty"`
	DhcpOptions   *ConfigInterfacesSwitchVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description   string                                  `json:"description,omitempty"`
	Address       string                                  `json:"address,omitempty"`
	Redirect      string                                  `json:"redirect,omitempty"`
	Dhcpv6Options *ConfigInterfacesSwitchVifDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip            *ConfigInterfacesSwitchVifIp            `json:"ip,omitempty"`
	Ipv6          *ConfigInterfacesSwitchVifIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesSwitchVifBridgeGroup struct {
	Bridge   string `json:"bridge,omitempty"`
	Cost     int    `json:"cost,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

type ConfigInterfacesSwitchVifBandwidth struct {
	Maximum    string                                        `json:"maximum,omitempty"`
	Reservable string                                        `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchVifBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchVifBandwidthConstraint struct {
	ClassType *ConfigInterfacesSwitchVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchVifBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchVifPppoe map[string]struct {
	ServiceName        string                                       `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesSwitchVifPppoeBandwidth     `json:"bandwidth,omitempty"`
	Password           string                                       `json:"password,omitempty"`
	RemoteAddress      IPv4                                         `json:"remote-address,omitempty"`
	HostUniq           string                                       `json:"host-uniq,omitempty"`
	Mtu                int                                          `json:"mtu,omitempty"`
	NameServer         string                                       `json:"name-server,omitempty"`
	DefaultRoute       string                                       `json:"default-route,omitempty"`
	TrafficPolicy      *ConfigInterfacesSwitchVifPppoeTrafficPolicy `json:"traffic-policy,omitempty"`
	IdleTimeout        int                                          `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesSwitchVifPppoeDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                              `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesSwitchVifPppoeFirewall      `json:"firewall,omitempty"`
	UserId             string                                       `json:"user-id,omitempty"`
	Description        string                                       `json:"description,omitempty"`
	LocalAddress       IPv4                                         `json:"local-address,omitempty"`
	Redirect           string                                       `json:"redirect,omitempty"`
	Ip                 *ConfigInterfacesSwitchVifPppoeIp            `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesSwitchVifPppoeIpv6          `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                              `json:"multilink,omitempty"`
	AccessConcentrator string                                       `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeBandwidth struct {
	Maximum    string                                             `json:"maximum,omitempty"`
	Reservable string                                             `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesSwitchVifPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesSwitchVifPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                    `json:"duid,omitempty"`
	NoDns       json.RawMessage                           `json:"no-dns,omitempty"`
	RapidCommit string                                    `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                           `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                             `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                 `json:"no-dns,omitempty"`
	PrefixId      string                                                          `json:"prefix-id,omitempty"`
	HostAddress   string                                                          `json:"host-address,omitempty"`
	Service       string                                                          `json:"service,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspf struct {
	RetransmitInterval int                                                 `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                 `json:"transmit-delay,omitempty"`
	Network            string                                              `json:"network,omitempty"`
	Cost               int                                                 `json:"cost,omitempty"`
	DeadInterval       int                                                 `json:"dead-interval,omitempty"`
	Priority           int                                                 `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                     `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchVifPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                 `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                 `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6 struct {
	Enable                 *ConfigInterfacesSwitchVifPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                             `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                 `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchVifPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchVifPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchVifPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchVifPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchVifPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                `json:"default-preference,omitempty"`
	MinInterval       int                                                   `json:"min-interval,omitempty"`
	MaxInterval       int                                                   `json:"max-interval,omitempty"`
	ReachableTime     int                                                   `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                  `json:"name-server,omitempty"`
	RetransTimer      int                                                   `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                  `json:"send-advert,omitempty"`
	RadvdOptions      string                                                `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                  `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                  `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                   `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                   `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                   `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchVifPppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchVifTrafficPolicy struct {
	Out string `json:"out,omitempty"`
	In  string `json:"in,omitempty"`
}

type ConfigInterfacesSwitchVifVrrp struct {
	VrrpGroup *ConfigInterfacesSwitchVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesSwitchVifVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                             `json:"disable,omitempty"`
	VirtualAddress       string                                                      `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                         `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                      `json:"sync-group,omitempty"`
	PreemptDelay         int                                                         `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesSwitchVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                        `json:"preempt,omitempty"`
	Description          string                                                      `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                        `json:"hello-source-address,omitempty"`
	Priority             int                                                         `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesSwitchVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                               `json:"duid,omitempty"`
	NoDns       json.RawMessage                      `json:"no-dns,omitempty"`
	RapidCommit string                               `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                      `json:"prefix-only,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesSwitchVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                        `json:"prefix-length,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                            `json:"no-dns,omitempty"`
	PrefixId      string                                                     `json:"prefix-id,omitempty"`
	HostAddress   string                                                     `json:"host-address,omitempty"`
	Service       string                                                     `json:"service,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesSwitchVifDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesSwitchVifIp struct {
	Rip              *ConfigInterfacesSwitchVifIpRip  `json:"rip,omitempty"`
	EnableProxyArp   json.RawMessage                  `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                           `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesSwitchVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesSwitchVifIpRip struct {
	SplitHorizon   *ConfigInterfacesSwitchVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesSwitchVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchVifIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifIpRipAuthentication struct {
	Md5               *ConfigInterfacesSwitchVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                           `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspf struct {
	RetransmitInterval int                                            `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                            `json:"transmit-delay,omitempty"`
	Network            string                                         `json:"network,omitempty"`
	Cost               int                                            `json:"cost,omitempty"`
	DeadInterval       int                                            `json:"dead-interval,omitempty"`
	Priority           int                                            `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                            `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                            `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchVifIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6 struct {
	DupAddrDetectTransmits int                                        `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                            `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchVifIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchVifIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchVifIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchVifIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchVifIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6RouterAdvert struct {
	DefaultPreference string                                           `json:"default-preference,omitempty"`
	MinInterval       int                                              `json:"min-interval,omitempty"`
	MaxInterval       int                                              `json:"max-interval,omitempty"`
	ReachableTime     int                                              `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                             `json:"name-server,omitempty"`
	RetransTimer      int                                              `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                             `json:"send-advert,omitempty"`
	RadvdOptions      string                                           `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                             `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                             `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                              `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                              `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                              `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchVifIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesSwitchIp struct {
	Rip              *ConfigInterfacesSwitchIpRip  `json:"rip,omitempty"`
	EnableProxyArp   json.RawMessage               `json:"enable-proxy-arp,omitempty"`
	SourceValidation string                        `json:"source-validation,omitempty"`
	Ospf             *ConfigInterfacesSwitchIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesSwitchIpRip struct {
	SplitHorizon   *ConfigInterfacesSwitchIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesSwitchIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesSwitchIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchIpRipAuthentication struct {
	Md5               *ConfigInterfacesSwitchIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                        `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesSwitchIpOspf struct {
	RetransmitInterval int                                         `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                         `json:"transmit-delay,omitempty"`
	Network            string                                      `json:"network,omitempty"`
	Cost               int                                         `json:"cost,omitempty"`
	DeadInterval       int                                         `json:"dead-interval,omitempty"`
	Priority           int                                         `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                             `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesSwitchIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                         `json:"hello-interval,omitempty"`
}

type ConfigInterfacesSwitchIpOspfAuthentication struct {
	Md5               *ConfigInterfacesSwitchIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                         `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesSwitchIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesSwitchIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesSwitchIpv6 struct {
	DupAddrDetectTransmits int                                     `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                         `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesSwitchIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesSwitchIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesSwitchIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesSwitchIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesSwitchIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesSwitchIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesSwitchIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesSwitchIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesSwitchIpv6RouterAdvert struct {
	DefaultPreference string                                        `json:"default-preference,omitempty"`
	MinInterval       int                                           `json:"min-interval,omitempty"`
	MaxInterval       int                                           `json:"max-interval,omitempty"`
	ReachableTime     int                                           `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesSwitchIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                          `json:"name-server,omitempty"`
	RetransTimer      int                                           `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                          `json:"send-advert,omitempty"`
	RadvdOptions      string                                        `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                          `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                          `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                           `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                           `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                           `json:"link-mtu,omitempty"`
}

type ConfigInterfacesSwitchIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesSwitchIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernet map[string]struct {
	Disable           json.RawMessage                              `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesPseudoEthernetBandwidth     `json:"bandwidth,omitempty"`
	Pppoe             *ConfigInterfacesPseudoEthernetPppoe         `json:"pppoe,omitempty"`
	Vrrp              *ConfigInterfacesPseudoEthernetVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesPseudoEthernetDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect json.RawMessage                              `json:"disable-link-detect,omitempty"`
	Firewall          *ConfigInterfacesPseudoEthernetFirewall      `json:"firewall,omitempty"`
	Mac               MacAddr                                      `json:"mac,omitempty"`
	DhcpOptions       *ConfigInterfacesPseudoEthernetDhcpOptions   `json:"dhcp-options,omitempty"`
	Link              string                                       `json:"link,omitempty"`
	Description       string                                       `json:"description,omitempty"`
	Vif               *ConfigInterfacesPseudoEthernetVif           `json:"vif,omitempty"`
	Address           string                                       `json:"address,omitempty"`
	Dhcpv6Options     *ConfigInterfacesPseudoEthernetDhcpv6Options `json:"dhcpv6-options,omitempty"`
	Ip                *ConfigInterfacesPseudoEthernetIp            `json:"ip,omitempty"`
	Ipv6              *ConfigInterfacesPseudoEthernetIpv6          `json:"ipv6,omitempty"`
}

type ConfigInterfacesPseudoEthernetBandwidth struct {
	Maximum    string                                             `json:"maximum,omitempty"`
	Reservable string                                             `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesPseudoEthernetBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesPseudoEthernetBandwidthConstraint struct {
	ClassType *ConfigInterfacesPseudoEthernetBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPseudoEthernetBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoe map[string]struct {
	ServiceName        string                                        `json:"service-name,omitempty"`
	Bandwidth          *ConfigInterfacesPseudoEthernetPppoeBandwidth `json:"bandwidth,omitempty"`
	Password           string                                        `json:"password,omitempty"`
	RemoteAddress      IPv4                                          `json:"remote-address,omitempty"`
	HostUniq           string                                        `json:"host-uniq,omitempty"`
	Mtu                int                                           `json:"mtu,omitempty"`
	NameServer         string                                        `json:"name-server,omitempty"`
	DefaultRoute       string                                        `json:"default-route,omitempty"`
	IdleTimeout        int                                           `json:"idle-timeout,omitempty"`
	Dhcpv6Pd           *ConfigInterfacesPseudoEthernetPppoeDhcpv6Pd  `json:"dhcpv6-pd,omitempty"`
	ConnectOnDemand    json.RawMessage                               `json:"connect-on-demand,omitempty"`
	Firewall           *ConfigInterfacesPseudoEthernetPppoeFirewall  `json:"firewall,omitempty"`
	UserId             string                                        `json:"user-id,omitempty"`
	Description        string                                        `json:"description,omitempty"`
	LocalAddress       IPv4                                          `json:"local-address,omitempty"`
	Ip                 *ConfigInterfacesPseudoEthernetPppoeIp        `json:"ip,omitempty"`
	Ipv6               *ConfigInterfacesPseudoEthernetPppoeIpv6      `json:"ipv6,omitempty"`
	Multilink          json.RawMessage                               `json:"multilink,omitempty"`
	AccessConcentrator string                                        `json:"access-concentrator,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeBandwidth struct {
	Maximum    string                                                  `json:"maximum,omitempty"`
	Reservable string                                                  `json:"reservable,omitempty"`
	Constraint *ConfigInterfacesPseudoEthernetPppoeBandwidthConstraint `json:"constraint,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeBandwidthConstraint struct {
	ClassType *ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6Pd struct {
	Pd          *ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                         `json:"duid,omitempty"`
	NoDns       json.RawMessage                                `json:"no-dns,omitempty"`
	RapidCommit string                                         `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                                `json:"prefix-only,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                  `json:"prefix-length,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                      `json:"no-dns,omitempty"`
	PrefixId      string                                                               `json:"prefix-id,omitempty"`
	HostAddress   string                                                               `json:"host-address,omitempty"`
	Service       string                                                               `json:"service,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpRipAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                     `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspf struct {
	RetransmitInterval int                                                      `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                      `json:"transmit-delay,omitempty"`
	Network            string                                                   `json:"network,omitempty"`
	Cost               int                                                      `json:"cost,omitempty"`
	DeadInterval       int                                                      `json:"dead-interval,omitempty"`
	Priority           int                                                      `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                          `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPseudoEthernetPppoeIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                      `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                      `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6 struct {
	Enable                 *ConfigInterfacesPseudoEthernetPppoeIpv6Enable       `json:"enable,omitempty"`
	DupAddrDetectTransmits int                                                  `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                      `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesPseudoEthernetPppoeIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesPseudoEthernetPppoeIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesPseudoEthernetPppoeIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Enable struct {
	RemoteIdentifier IPv6 `json:"remote-identifier,omitempty"`
	LocalIdentifier  IPv6 `json:"local-identifier,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPseudoEthernetPppoeIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Address struct {
	Eui64     IPv6Net         `json:"eui64,omitempty"`
	Autoconf  json.RawMessage `json:"autoconf,omitempty"`
	Secondary IPv6Net         `json:"secondary,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvert struct {
	DefaultPreference string                                                     `json:"default-preference,omitempty"`
	MinInterval       int                                                        `json:"min-interval,omitempty"`
	MaxInterval       int                                                        `json:"max-interval,omitempty"`
	ReachableTime     int                                                        `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                       `json:"name-server,omitempty"`
	RetransTimer      int                                                        `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                       `json:"send-advert,omitempty"`
	RadvdOptions      string                                                     `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                       `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                       `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                        `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                        `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                        `json:"link-mtu,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesPseudoEthernetPppoeIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetVrrp struct {
	VrrpGroup *ConfigInterfacesPseudoEthernetVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesPseudoEthernetVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                                  `json:"disable,omitempty"`
	VirtualAddress       string                                                           `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                              `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                           `json:"sync-group,omitempty"`
	PreemptDelay         int                                                              `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesPseudoEthernetVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                             `json:"preempt,omitempty"`
	Description          string                                                           `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                             `json:"hello-source-address,omitempty"`
	Priority             int                                                              `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesPseudoEthernetDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                    `json:"duid,omitempty"`
	NoDns       json.RawMessage                           `json:"no-dns,omitempty"`
	RapidCommit string                                    `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                           `json:"prefix-only,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                             `json:"prefix-length,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                 `json:"no-dns,omitempty"`
	PrefixId      string                                                          `json:"prefix-id,omitempty"`
	HostAddress   string                                                          `json:"host-address,omitempty"`
	Service       string                                                          `json:"service,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6PdPdInterfaceStaticMapping map[string]struct {
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
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesPseudoEthernetVif map[string]struct {
	Disable           json.RawMessage                                 `json:"disable,omitempty"`
	Bandwidth         *ConfigInterfacesPseudoEthernetVifBandwidth     `json:"bandwidth,omitempty"`
	Vrrp              *ConfigInterfacesPseudoEthernetVifVrrp          `json:"vrrp,omitempty"`
	Dhcpv6Pd          *ConfigInterfacesPseudoEthernetVifDhcpv6Pd      `json:"dhcpv6-pd,omitempty"`
	DisableLinkDetect json.RawMessage                                 `json:"disable-link-detect,omitempty"`
	DhcpOptions       *ConfigInterfacesPseudoEthernetVifDhcpOptions   `json:"dhcp-options,omitempty"`
	Description       string                                          `json:"description,omitempty"`
	Address           string                                          `json:"address,omitempty"`
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
	ClassType *ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType `json:"class-type,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifBandwidthConstraintClassType map[string]struct {
	Bandwidth string `json:"bandwidth,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifVrrp struct {
	VrrpGroup *ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup `json:"vrrp-group,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifVrrpVrrpGroup map[string]struct {
	Disable              json.RawMessage                                                     `json:"disable,omitempty"`
	VirtualAddress       string                                                              `json:"virtual-address,omitempty"`
	AdvertiseInterval    int                                                                 `json:"advertise-interval,omitempty"`
	SyncGroup            string                                                              `json:"sync-group,omitempty"`
	PreemptDelay         int                                                                 `json:"preempt-delay,omitempty"`
	RunTransitionScripts *ConfigInterfacesPseudoEthernetVifVrrpVrrpGroupRunTransitionScripts `json:"run-transition-scripts,omitempty"`
	Preempt              bool                                                                `json:"preempt,omitempty"`
	Description          string                                                              `json:"description,omitempty"`
	HelloSourceAddress   IPv4                                                                `json:"hello-source-address,omitempty"`
	Priority             int                                                                 `json:"priority,omitempty"`
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
	Pd          *ConfigInterfacesPseudoEthernetVifDhcpv6PdPd `json:"pd,omitempty"`
	Duid        string                                       `json:"duid,omitempty"`
	NoDns       json.RawMessage                              `json:"no-dns,omitempty"`
	RapidCommit string                                       `json:"rapid-commit,omitempty"`
	PrefixOnly  json.RawMessage                              `json:"prefix-only,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6PdPd map[string]struct {
	Interface    *ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface `json:"interface,omitempty"`
	PrefixLength string                                                `json:"prefix-length,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterface map[string]struct {
	StaticMapping *ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping `json:"static-mapping,omitempty"`
	NoDns         json.RawMessage                                                    `json:"no-dns,omitempty"`
	PrefixId      string                                                             `json:"prefix-id,omitempty"`
	HostAddress   string                                                             `json:"host-address,omitempty"`
	Service       string                                                             `json:"service,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6PdPdInterfaceStaticMapping map[string]struct {
	Identifier  string `json:"identifier,omitempty"`
	HostAddress string `json:"host-address,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpOptions struct {
	NameServer           string `json:"name-server,omitempty"`
	DefaultRoute         string `json:"default-route,omitempty"`
	ClientOption         string `json:"client-option,omitempty"`
	DefaultRouteDistance int    `json:"default-route-distance,omitempty"`
	GlobalOption         string `json:"global-option,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIp struct {
	Rip              *ConfigInterfacesPseudoEthernetVifIpRip  `json:"rip,omitempty"`
	SourceValidation string                                   `json:"source-validation,omitempty"`
	ProxyArpPvlan    json.RawMessage                          `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesPseudoEthernetVifIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRip struct {
	SplitHorizon   *ConfigInterfacesPseudoEthernetVifIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesPseudoEthernetVifIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRipAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                   `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspf struct {
	RetransmitInterval int                                                    `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                    `json:"transmit-delay,omitempty"`
	Network            string                                                 `json:"network,omitempty"`
	Cost               int                                                    `json:"cost,omitempty"`
	DeadInterval       int                                                    `json:"dead-interval,omitempty"`
	Priority           int                                                    `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                        `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPseudoEthernetVifIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                    `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                    `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpOspfAuthenticationMd5KeyId map[string]struct {
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
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetVifIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetDhcpv6Options struct {
	ParametersOnly json.RawMessage `json:"parameters-only,omitempty"`
	Temporary      json.RawMessage `json:"temporary,omitempty"`
}

type ConfigInterfacesPseudoEthernetIp struct {
	Rip              *ConfigInterfacesPseudoEthernetIpRip  `json:"rip,omitempty"`
	SourceValidation string                                `json:"source-validation,omitempty"`
	ProxyArpPvlan    json.RawMessage                       `json:"proxy-arp-pvlan,omitempty"`
	Ospf             *ConfigInterfacesPseudoEthernetIpOspf `json:"ospf,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRip struct {
	SplitHorizon   *ConfigInterfacesPseudoEthernetIpRipSplitHorizon   `json:"split-horizon,omitempty"`
	Authentication *ConfigInterfacesPseudoEthernetIpRipAuthentication `json:"authentication,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRipSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRipAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpRipAuthenticationMd5 map[string]struct {
	Password string `json:"password,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspf struct {
	RetransmitInterval int                                                 `json:"retransmit-interval,omitempty"`
	TransmitDelay      int                                                 `json:"transmit-delay,omitempty"`
	Network            string                                              `json:"network,omitempty"`
	Cost               int                                                 `json:"cost,omitempty"`
	DeadInterval       int                                                 `json:"dead-interval,omitempty"`
	Priority           int                                                 `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage                                     `json:"mtu-ignore,omitempty"`
	Authentication     *ConfigInterfacesPseudoEthernetIpOspfAuthentication `json:"authentication,omitempty"`
	HelloInterval      int                                                 `json:"hello-interval,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspfAuthentication struct {
	Md5               *ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5 `json:"md5,omitempty"`
	PlaintextPassword string                                                 `json:"plaintext-password,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5 struct {
	KeyId *ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId `json:"key-id,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpOspfAuthenticationMd5KeyId map[string]struct {
	Md5Key string `json:"md5-key,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6 struct {
	DupAddrDetectTransmits int                                             `json:"dup-addr-detect-transmits,omitempty"`
	DisableForwarding      json.RawMessage                                 `json:"disable-forwarding,omitempty"`
	Ripng                  *ConfigInterfacesPseudoEthernetIpv6Ripng        `json:"ripng,omitempty"`
	Address                *ConfigInterfacesPseudoEthernetIpv6Address      `json:"address,omitempty"`
	RouterAdvert           *ConfigInterfacesPseudoEthernetIpv6RouterAdvert `json:"router-advert,omitempty"`
	Ospfv3                 *ConfigInterfacesPseudoEthernetIpv6Ospfv3       `json:"ospfv3,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6Ripng struct {
	SplitHorizon *ConfigInterfacesPseudoEthernetIpv6RipngSplitHorizon `json:"split-horizon,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6RipngSplitHorizon struct {
	Disable       json.RawMessage `json:"disable,omitempty"`
	PoisonReverse json.RawMessage `json:"poison-reverse,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6Address struct {
	Eui64    IPv6Net         `json:"eui64,omitempty"`
	Autoconf json.RawMessage `json:"autoconf,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6RouterAdvert struct {
	DefaultPreference string                                                `json:"default-preference,omitempty"`
	MinInterval       int                                                   `json:"min-interval,omitempty"`
	MaxInterval       int                                                   `json:"max-interval,omitempty"`
	ReachableTime     int                                                   `json:"reachable-time,omitempty"`
	Prefix            *ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix `json:"prefix,omitempty"`
	NameServer        IPv6                                                  `json:"name-server,omitempty"`
	RetransTimer      int                                                   `json:"retrans-timer,omitempty"`
	SendAdvert        bool                                                  `json:"send-advert,omitempty"`
	RadvdOptions      string                                                `json:"radvd-options,omitempty"`
	ManagedFlag       bool                                                  `json:"managed-flag,omitempty"`
	OtherConfigFlag   bool                                                  `json:"other-config-flag,omitempty"`
	DefaultLifetime   int                                                   `json:"default-lifetime,omitempty"`
	CurHopLimit       int                                                   `json:"cur-hop-limit,omitempty"`
	LinkMtu           int                                                   `json:"link-mtu,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6RouterAdvertPrefix map[string]struct {
	AutonomousFlag    bool   `json:"autonomous-flag,omitempty"`
	OnLinkFlag        bool   `json:"on-link-flag,omitempty"`
	ValidLifetime     string `json:"valid-lifetime,omitempty"`
	PreferredLifetime string `json:"preferred-lifetime,omitempty"`
}

type ConfigInterfacesPseudoEthernetIpv6Ospfv3 struct {
	RetransmitInterval int             `json:"retransmit-interval,omitempty"`
	TransmitDelay      int             `json:"transmit-delay,omitempty"`
	Cost               int             `json:"cost,omitempty"`
	Passive            json.RawMessage `json:"passive,omitempty"`
	DeadInterval       int             `json:"dead-interval,omitempty"`
	InstanceId         int             `json:"instance-id,omitempty"`
	Ifmtu              int             `json:"ifmtu,omitempty"`
	Priority           int             `json:"priority,omitempty"`
	MtuIgnore          json.RawMessage `json:"mtu-ignore,omitempty"`
	HelloInterval      int             `json:"hello-interval,omitempty"`
}

type ConfigCustomAttribute *struct {
	Nodetag *ConfigCustomAttributeNodetag `json:"node.tag,omitempty"`
}

type ConfigCustomAttributeNodetag struct {
	Value string `json:"value,omitempty"`
}

type Config struct {
	ZonePolicy      ConfigZonePolicy      `json:"zone-policy,omitempty"`
	LoadBalance     ConfigLoadBalance     `json:"load-balance,omitempty"`
	PortForward     ConfigPortForward     `json:"port-forward,omitempty"`
	Vpn             ConfigVpn             `json:"vpn,omitempty"`
	TrafficPolicy   ConfigTrafficPolicy   `json:"traffic-policy,omitempty"`
	Firewall        ConfigFirewall        `json:"firewall,omitempty"`
	System          ConfigSystem          `json:"system,omitempty"`
	TrafficControl  ConfigTrafficControl  `json:"traffic-control,omitempty"`
	Service         ConfigService         `json:"service,omitempty"`
	Protocols       ConfigProtocols       `json:"protocols,omitempty"`
	Policy          ConfigPolicy          `json:"policy,omitempty"`
	Interfaces      ConfigInterfaces      `json:"interfaces,omitempty"`
	CustomAttribute ConfigCustomAttribute `json:"custom-attribute,omitempty"`
}
