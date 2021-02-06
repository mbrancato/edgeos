package sdk

type Config struct {
	ZonePolicy struct {
		Zone map[string]struct {
			DefaultAction string `json:"default-action"`
			Interface     string `json:"interface"`
			LocalZone     string `json:"local-zone"`
			From          map[string]struct {
				ContentInspection struct {
					Enable     string `json:"enable"`
					Ipv6Enable string `json:".ipv6-enable"`
				} `json:".content-inspection"`
				Firewall struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"firewall"`
			} `json:"from"`
			Description string `json:"description"`
		} `json:"zone"`
	} `json:"zone-policy"`
	LoadBalance struct {
		Group map[string]struct {
			Interface map[string]struct {
				Weight    string `json:"weight"`
				RouteTest struct {
					Interval string `json:"interval"`
					Count    struct {
						Success string `json:"success"`
						Failure string `json:"failure"`
					} `json:"count"`
					InitialDelay string `json:"initial-delay"`
					Type         struct {
						Ping struct {
							Target string `json:"target"`
						} `json:"ping"`
						Default string `json:"default"`
						Script  string `json:"script"`
					} `json:"type"`
				} `json:"route-test"`
				Route struct {
					Default string `json:"default"`
					Table   string `json:"table"`
				} `json:"route"`
				FailoverOnly     string `json:"failover-only"`
				FailoverPriority string `json:"failover-priority"`
			} `json:"interface"`
			LbLocal               string `json:"lb-local"`
			GatewayUpdateInterval string `json:"gateway-update-interval"`
			LbLocalMetricChange   string `json:"lb-local-metric-change"`
			Sticky                struct {
				Proto      string `json:"proto"`
				SourceAddr string `json:"source-addr"`
				SourcePort string `json:"source-port"`
				DestPort   string `json:"dest-port"`
				DestAddr   string `json:"dest-addr"`
			} `json:"sticky"`
			FlushOnActive      string `json:"flush-on-active"`
			TransitionScript   string `json:"transition-script"`
			ExcludeLocalDns    string `json:"exclude-local-dns"`
			ReachabilityScript string `json:"reachability-script"`
		} `json:"group"`
	} `json:"load-balance"`
	PortForward struct {
		LanInterface string `json:"lan-interface"`
		AutoFirewall string `json:"auto-firewall"`
		Rule         map[string]struct {
			ForwardTo struct {
				Address string `json:"address"`
				Port    string `json:"port"`
			} `json:"forward-to"`
			OriginalPort string `json:"original-port"`
			Protocol     string `json:"protocol"`
			Description  string `json:"description"`
		} `json:"rule"`
		WanInterface string `json:"wan-interface"`
		HairpinNat   string `json:"hairpin-nat"`
	} `json:"port-forward"`
	Vpn struct {
		RsaKeys struct {
			LocalKey struct {
				File string `json:"file"`
			} `json:"local-key"`
			RsaKeyName map[string]struct {
				RsaKey string `json:"rsa-key"`
			} `json:"rsa-key-name"`
		} `json:"rsa-keys"`
		Ipsec struct {
			AutoUpdate  string `json:"auto-update"`
			NatNetworks struct {
				AllowedNetwork map[string]struct {
					Exclude string `json:"exclude"`
				} `json:"allowed-network"`
			} `json:"nat-networks"`
			AllowAccessToLocalInterface string `json:"allow-access-to-local-interface"`
			AutoFirewallNatExclude      string `json:"auto-firewall-nat-exclude"`
			DisableUniqreqids           string `json:"disable-uniqreqids"`
			SiteToSite                  struct {
				Peer map[string]struct {
					DefaultEspGroup    string `json:"default-esp-group"`
					ForceEncapsulation string `json:"force-encapsulation"`
					Vti                struct {
						EspGroup string `json:"esp-group"`
						Bind     string `json:"bind"`
					} `json:"vti"`
					ConnectionType string `json:"connection-type"`
					Ikev2Reauth    string `json:"ikev2-reauth"`
					Tunnel         map[string]struct {
						Disable             string `json:"disable"`
						AllowPublicNetworks string `json:"allow-public-networks"`
						Protocol            string `json:"protocol"`
						Local               struct {
							Prefix string `json:"prefix"`
							Port   string `json:"port"`
						} `json:"local"`
						EspGroup         string `json:"esp-group"`
						AllowNatNetworks string `json:"allow-nat-networks"`
						Remote           struct {
							Prefix string `json:"prefix"`
							Port   string `json:"port"`
						} `json:"remote"`
					} `json:"tunnel"`
					Description    string `json:"description"`
					LocalAddress   string `json:"local-address"`
					IkeGroup       string `json:"ike-group"`
					Authentication struct {
						Mode string `json:"mode"`
						X509 struct {
							CrlFile string `json:"crl-file"`
							Key     struct {
								Password string `json:"password"`
								File     string `json:"file"`
							} `json:"key"`
							CaCertFile string `json:"ca-cert-file"`
							CertFile   string `json:"cert-file"`
						} `json:"x509"`
						PreSharedSecret string `json:"pre-shared-secret"`
						Id              string `json:"id"`
						RemoteId        string `json:"remote-id"`
						RsaKeyName      string `json:"rsa-key-name"`
					} `json:"authentication"`
					DhcpInterface string `json:"dhcp-interface"`
				} `json:"peer"`
			} `json:"site-to-site"`
			RemoteAccess struct {
				OutsideAddress string `json:"outside-address"`
				WinsServers    struct {
					Server2 string `json:"server-2"`
					Server1 string `json:"server-1"`
				} `json:"wins-servers"`
				UpdownScript string `json:"updown-script"`
				Inactivity   string `json:"inactivity"`
				DnsServers   struct {
					Server2 string `json:"server-2"`
					Server1 string `json:"server-1"`
				} `json:"dns-servers"`
				IkeSettings struct {
					Proposal map[string]struct {
						Encryption string `json:"encryption"`
						Hash       string `json:"hash"`
						DhGroup    string `json:"dh-group"`
					} `json:"proposal"`
					EspGroup       string `json:"esp-group"`
					IkeLifetime    string `json:"ike-lifetime"`
					Authentication struct {
						Mode string `json:"mode"`
						X509 struct {
							ServerKeyFile     string `json:"server-key-file"`
							CrlFile           string `json:"crl-file"`
							ServerKeyPassword string `json:"server-key-password"`
							RemoteCaCertFile  string `json:"remote-ca-cert-file"`
							ServerCertFile    string `json:"server-cert-file"`
							ServerKeyType     string `json:"server-key-type"`
							RemoteId          string `json:"remote-id"`
							LocalId           string `json:"local-id"`
							CaCertFile        string `json:"ca-cert-file"`
						} `json:"x509"`
						PreSharedSecret string `json:"pre-shared-secret"`
					} `json:"authentication"`
					OperatingMode string `json:"operating-mode"`
					Fragmentation string `json:"fragmentation"`
				} `json:"ike-settings"`
				ClientIpPool struct {
					Subnet  string `json:"subnet"`
					Subnet6 string `json:"subnet6"`
				} `json:"client-ip-pool"`
				Description       string `json:"description"`
				LocalIp           string `json:"local-ip"`
				CompatibilityMode string `json:"compatibility-mode"`
				EspSettings       struct {
					Proposal map[string]struct {
						Encryption string `json:"encryption"`
						Hash       string `json:"hash"`
						DhGroup    string `json:"dh-group"`
					} `json:"proposal"`
				} `json:"esp-settings"`
				Authentication struct {
					Mode       string `json:"mode"`
					LocalUsers struct {
						Username map[string]struct {
							Disable  string `json:"disable"`
							Password string `json:"password"`
						} `json:"username"`
					} `json:"local-users"`
					RadiusServer map[string]struct {
						Key string `json:"key"`
					} `json:"radius-server"`
				} `json:"authentication"`
				DhcpInterface string `json:"dhcp-interface"`
			} `json:"remote-access"`
			IpsecInterfaces struct {
				Interface string `json:"interface"`
			} `json:"ipsec-interfaces"`
			GlobalConfig string `json:"global-config"`
			IkeGroup     map[string]struct {
				Mode              string `json:"mode"`
				DeadPeerDetection struct {
					Interval string `json:"interval"`
					Timeout  string `json:"timeout"`
					Action   string `json:"action"`
				} `json:"dead-peer-detection"`
				KeyExchange string `json:"key-exchange"`
				Ikev2Reauth string `json:"ikev2-reauth"`
				Lifetime    string `json:"lifetime"`
				Proposal    map[string]struct {
					Encryption string `json:"encryption"`
					Hash       string `json:"hash"`
					DhGroup    string `json:"dh-group"`
				} `json:"proposal"`
			} `json:"ike-group"`
			EspGroup map[string]struct {
				Mode     string `json:"mode"`
				Pfs      string `json:"pfs"`
				Lifetime string `json:"lifetime"`
				Proposal map[string]struct {
					Encryption string `json:"encryption"`
					Hash       string `json:"hash"`
				} `json:"proposal"`
				Compression string `json:"compression"`
			} `json:"esp-group"`
			IncludeIpsecSecrets string `json:"include-ipsec-secrets"`
			IncludeIpsecConf    string `json:"include-ipsec-conf"`
			Logging             struct {
				LogModes string `json:"log-modes"`
				LogLevel string `json:"log-level"`
			} `json:"logging"`
			NatTraversal string `json:"nat-traversal"`
		} `json:"ipsec"`
		Pptp struct {
			RemoteAccess struct {
				Accounting struct {
					RadiusServer map[string]struct {
						Key  string `json:"key"`
						Port string `json:"port"`
					} `json:"radius-server"`
				} `json:"accounting"`
				OutsideAddress string `json:"outside-address"`
				WinsServers    struct {
					Server2 string `json:"server-2"`
					Server1 string `json:"server-1"`
				} `json:"wins-servers"`
				DnsServers struct {
					Server2 string `json:"server-2"`
					Server1 string `json:"server-1"`
				} `json:"dns-servers"`
				Mtu          string `json:"mtu"`
				ClientIpPool struct {
					Start string `json:"start"`
					Stop  string `json:"stop"`
				} `json:"client-ip-pool"`
				LocalIp        string `json:"local-ip"`
				Authentication struct {
					Mode       string `json:"mode"`
					LocalUsers struct {
						Username map[string]struct {
							Disable  string `json:"disable"`
							Password string `json:"password"`
							StaticIp string `json:"static-ip"`
						} `json:"username"`
					} `json:"local-users"`
					RadiusServer map[string]struct {
						Key  string `json:"key"`
						Port string `json:"port"`
					} `json:"radius-server"`
				} `json:"authentication"`
				DhcpInterface string `json:"dhcp-interface"`
			} `json:"remote-access"`
		} `json:"pptp"`
		L2tp struct {
			RemoteAccess struct {
				OutsideNexthop string `json:"outside-nexthop"`
				Accounting     struct {
					RadiusServer map[string]struct {
						Key  string `json:"key"`
						Port string `json:"port"`
					} `json:"radius-server"`
				} `json:"accounting"`
				OutsideAddress string `json:"outside-address"`
				Idle           string `json:"idle"`
				WinsServers    struct {
					Server2 string `json:"server-2"`
					Server1 string `json:"server-1"`
				} `json:"wins-servers"`
				DnsServers struct {
					Server2 string `json:"server-2"`
					Server1 string `json:"server-1"`
				} `json:"dns-servers"`
				Mtu          string `json:"mtu"`
				ClientIpPool struct {
					Start string `json:"start"`
					Stop  string `json:"stop"`
				} `json:"client-ip-pool"`
				IpsecSettings struct {
					Lifetime       string `json:"lifetime"`
					IkeLifetime    string `json:"ike-lifetime"`
					Authentication struct {
						Mode string `json:"mode"`
						X509 struct {
							ServerKeyFile     string `json:"server-key-file"`
							CrlFile           string `json:"crl-file"`
							ServerKeyPassword string `json:"server-key-password"`
							ServerCertFile    string `json:"server-cert-file"`
							CaCertFile        string `json:"ca-cert-file"`
						} `json:"x509"`
						PreSharedSecret string `json:"pre-shared-secret"`
					} `json:"authentication"`
					Fragmentation string `json:"fragmentation"`
				} `json:"ipsec-settings"`
				Description                     string `json:"description"`
				AllowMultipleClientsFromSameNat string `json:"allow-multiple-clients-from-same-nat"`
				LocalIp                         string `json:"local-ip"`
				Authentication                  struct {
					Mode       string `json:"mode"`
					Require    string `json:"require"`
					LocalUsers struct {
						Username map[string]struct {
							Disable  string `json:"disable"`
							Password string `json:"password"`
							StaticIp string `json:"static-ip"`
						} `json:"username"`
					} `json:"local-users"`
					RadiusServer map[string]struct {
						Key  string `json:"key"`
						Port string `json:"port"`
					} `json:"radius-server"`
				} `json:"authentication"`
				DhcpInterface string `json:"dhcp-interface"`
			} `json:"remote-access"`
		} `json:"l2tp"`
	} `json:"vpn"`
	TrafficPolicy struct {
		NetworkEmulator map[string]struct {
			PacketCorruption string `json:"packet-corruption"`
			Bandwidth        string `json:"bandwidth"`
			Burst            string `json:"burst"`
			Description      string `json:"description"`
			QueueLimit       string `json:"queue-limit"`
			NetworkDelay     string `json:"network-delay"`
			PacketReordering string `json:"packet-reordering"`
			PacketLoss       string `json:"packet-loss"`
		} `json:"network-emulator"`
		DropTail map[string]struct {
			Description string `json:"description"`
			QueueLimit  string `json:"queue-limit"`
		} `json:"drop-tail"`
		RoundRobin map[string]struct {
			Default struct {
				QueueType  string `json:"queue-type"`
				QueueLimit string `json:"queue-limit"`
				Quantum    string `json:"quantum"`
			} `json:"default"`
			Description string `json:"description"`
			Class       map[string]struct {
				Match map[string]struct {
					Interface string `json:"interface"`
					Mark      string `json:"mark"`
					Ether     struct {
						Source      string `json:"source"`
						Destination string `json:"destination"`
						Protocol    string `json:"protocol"`
					} `json:"ether"`
					Description string `json:"description"`
					Vif         string `json:"vif"`
					Ip          struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ip"`
					Ipv6 struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ipv6"`
				} `json:"match"`
				QueueType   string `json:"queue-type"`
				Description string `json:"description"`
				QueueLimit  string `json:"queue-limit"`
				Quantum     string `json:"quantum"`
			} `json:"class"`
		} `json:"round-robin"`
		Limiter map[string]struct {
			Default struct {
				Bandwidth string `json:"bandwidth"`
				Burst     string `json:"burst"`
			} `json:"default"`
			Description string `json:"description"`
			Class       map[string]struct {
				Bandwidth string `json:"bandwidth"`
				Match     map[string]struct {
					Ether struct {
						Source      string `json:"source"`
						Destination string `json:"destination"`
						Protocol    string `json:"protocol"`
					} `json:"ether"`
					Description string `json:"description"`
					Vif         string `json:"vif"`
					Ip          struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ip"`
					Ipv6 struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ipv6"`
				} `json:"match"`
				Burst       string `json:"burst"`
				Description string `json:"description"`
				Priority    string `json:"priority"`
			} `json:"class"`
		} `json:"limiter"`
		FairQueue map[string]struct {
			HashInterval string `json:"hash-interval"`
			Description  string `json:"description"`
			QueueLimit   string `json:"queue-limit"`
		} `json:"fair-queue"`
		RateControl map[string]struct {
			Bandwidth   string `json:"bandwidth"`
			Burst       string `json:"burst"`
			Latency     string `json:"latency"`
			Description string `json:"description"`
		} `json:"rate-control"`
		Shaper map[string]struct {
			Bandwidth string `json:"bandwidth"`
			Default   struct {
				Bandwidth  string `json:"bandwidth"`
				Burst      string `json:"burst"`
				Ceiling    string `json:"ceiling"`
				QueueType  string `json:"queue-type"`
				Priority   string `json:"priority"`
				QueueLimit string `json:"queue-limit"`
				SetDscp    string `json:".set-dscp"`
			} `json:"default"`
			Description string `json:"description"`
			Class       map[string]struct {
				Bandwidth string `json:"bandwidth"`
				Match     map[string]struct {
					Interface string `json:"interface"`
					Mark      string `json:"mark"`
					Ether     struct {
						Source      string `json:"source"`
						Destination string `json:"destination"`
						Protocol    string `json:"protocol"`
					} `json:"ether"`
					Description string `json:"description"`
					Vif         string `json:"vif"`
					Ip          struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ip"`
					Ipv6 struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ipv6"`
				} `json:"match"`
				Burst       string `json:"burst"`
				Ceiling     string `json:"ceiling"`
				QueueType   string `json:"queue-type"`
				Description string `json:"description"`
				Priority    string `json:"priority"`
				QueueLimit  string `json:"queue-limit"`
				SetDscp     string `json:".set-dscp"`
			} `json:"class"`
		} `json:"shaper"`
		PriorityQueue map[string]struct {
			Default struct {
				QueueType  string `json:"queue-type"`
				QueueLimit string `json:"queue-limit"`
			} `json:"default"`
			Description string `json:"description"`
			Class       map[string]struct {
				Match map[string]struct {
					Interface string `json:"interface"`
					Mark      string `json:"mark"`
					Ether     struct {
						Source      string `json:"source"`
						Destination string `json:"destination"`
						Protocol    string `json:"protocol"`
					} `json:"ether"`
					Description string `json:"description"`
					Vif         string `json:"vif"`
					Ip          struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ip"`
					Ipv6 struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ipv6"`
				} `json:"match"`
				QueueType   string `json:"queue-type"`
				Description string `json:"description"`
				QueueLimit  string `json:"queue-limit"`
			} `json:"class"`
		} `json:"priority-queue"`
		RandomDetect map[string]struct {
			Bandwidth   string `json:"bandwidth"`
			Description string `json:"description"`
			Precedence  map[string]struct {
				MarkProbability  string `json:"mark-probability"`
				MinimumThreshold string `json:"minimum-threshold"`
				AveragePacket    string `json:"average-packet"`
				QueueLimit       string `json:"queue-limit"`
				MaximumThreshold string `json:"maximum-threshold"`
			} `json:"precedence"`
		} `json:"random-detect"`
	} `json:"traffic-policy"`
	Firewall struct {
		Options struct {
			MssClamp struct {
				Mss           string `json:"mss"`
				InterfaceType string `json:"interface-type"`
			} `json:"mss-clamp"`
			MssClamp6 struct {
				Mss           string `json:"mss"`
				InterfaceType string `json:"interface-type"`
			} `json:"mss-clamp6"`
		} `json:"options"`
		IpSrcRoute    string `json:"ip-src-route"`
		SendRedirects string `json:"send-redirects"`
		Group         struct {
			AddressGroup map[string]struct {
				Description string `json:"description"`
				Address     string `json:"address"`
			} `json:"address-group"`
			PortGroup map[string]struct {
				Description string `json:"description"`
				Port        string `json:"port"`
			} `json:"port-group"`
			NetworkGroup map[string]struct {
				Network     string `json:"network"`
				Description string `json:"description"`
			} `json:"network-group"`
			Ipv6AddressGroup map[string]struct {
				Ipv6Address string `json:"ipv6-address"`
				Description string `json:"description"`
			} `json:"ipv6-address-group"`
			Ipv6NetworkGroup map[string]struct {
				Description string `json:"description"`
				Ipv6Network string `json:"ipv6-network"`
			} `json:"ipv6-network-group"`
		} `json:"group"`
		Ipv6ReceiveRedirects string `json:"ipv6-receive-redirects"`
		AllPing              string `json:"all-ping"`
		SynCookies           string `json:"syn-cookies"`
		Modify               map[string]struct {
			Rule map[string]struct {
				Disable string `json:"disable"`
				Limit   struct {
					Rate  string `json:"rate"`
					Burst string `json:"burst"`
				} `json:"limit"`
				Source struct {
					Group struct {
						AddressGroup string `json:"address-group"`
						PortGroup    string `json:"port-group"`
						NetworkGroup string `json:"network-group"`
					} `json:"group"`
					MacAddress string `json:"mac-address"`
					Address    string `json:"address"`
					Port       string `json:"port"`
				} `json:"source"`
				Mark   string `json:"mark"`
				Modify struct {
					TcpMss   string `json:"tcp-mss"`
					Mark     string `json:"mark"`
					Table    string `json:"table"`
					Connmark struct {
						SaveMark    string `json:"save-mark"`
						RestoreMark string `json:"restore-mark"`
						SetMark     string `json:"set-mark"`
					} `json:"connmark"`
					Dscp    string `json:"dscp"`
					LbGroup string `json:"lb-group"`
				} `json:"modify"`
				Destination struct {
					Group struct {
						AddressGroup string `json:"address-group"`
						PortGroup    string `json:"port-group"`
						NetworkGroup string `json:"network-group"`
					} `json:"group"`
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"destination"`
				Protocol string `json:"protocol"`
				State    struct {
					Related     string `json:"related"`
					Invalid     string `json:"invalid"`
					Established string `json:"established"`
					New         string `json:"new"`
				} `json:"state"`
				Time struct {
					Stopdate   string `json:"stopdate"`
					Contiguous string `json:"contiguous"`
					Starttime  string `json:"starttime"`
					Stoptime   string `json:"stoptime"`
					Weekdays   string `json:"weekdays"`
					Utc        string `json:"utc"`
					Startdate  string `json:"startdate"`
					Monthdays  string `json:"monthdays"`
				} `json:"time"`
				Ipsec struct {
					MatchNone  string `json:"match-none"`
					MatchIpsec string `json:"match-ipsec"`
				} `json:"ipsec"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Tcp         struct {
					Flags string `json:"flags"`
				} `json:"tcp"`
				Fragment struct {
					MatchNonFrag string `json:"match-non-frag"`
					MatchFrag    string `json:"match-frag"`
				} `json:"fragment"`
				Icmp struct {
					Code     string `json:"code"`
					TypeName string `json:"type-name"`
					Type     string `json:"type"`
				} `json:"icmp"`
				P2p struct {
					Bittorrent    string `json:"bittorrent"`
					Gnutella      string `json:"gnutella"`
					All           string `json:"all"`
					Applejuice    string `json:"applejuice"`
					Edonkey       string `json:"edonkey"`
					Kazaa         string `json:"kazaa"`
					Directconnect string `json:"directconnect"`
				} `json:"p2p"`
				Connmark    string `json:"connmark"`
				Log         string `json:"log"`
				Application struct {
					Category       string `json:"category"`
					CustomCategory string `json:"custom-category"`
				} `json:"application"`
				Dscp      string `json:"dscp"`
				Statistic struct {
					Probability string `json:"probability"`
				} `json:"statistic"`
				Recent struct {
					Count string `json:"count"`
					Time  string `json:"time"`
				} `json:"recent"`
			} `json:"rule"`
			Description      string `json:"description"`
			EnableDefaultLog string `json:"enable-default-log"`
		} `json:"modify"`
		BroadcastPing string `json:"broadcast-ping"`
		LogMartians   string `json:"log-martians"`
		Ipv6Modify    map[string]struct {
			Rule map[string]struct {
				Disable string `json:"disable"`
				Icmpv6  struct {
					Type string `json:"type"`
				} `json:"icmpv6"`
				Limit struct {
					Rate  string `json:"rate"`
					Burst string `json:"burst"`
				} `json:"limit"`
				Source struct {
					Group struct {
						PortGroup        string `json:"port-group"`
						Ipv6AddressGroup string `json:"ipv6-address-group"`
						Ipv6NetworkGroup string `json:"ipv6-network-group"`
					} `json:"group"`
					MacAddress string `json:"mac-address"`
					Address    string `json:"address"`
					Port       string `json:"port"`
				} `json:"source"`
				Mark   string `json:"mark"`
				Modify struct {
					TcpMss   string `json:"tcp-mss"`
					Mark     string `json:"mark"`
					Table    string `json:"table"`
					Connmark struct {
						SaveMark    string `json:"save-mark"`
						RestoreMark string `json:"restore-mark"`
						SetMark     string `json:"set-mark"`
					} `json:"connmark"`
					Dscp string `json:"dscp"`
				} `json:"modify"`
				Destination struct {
					Group struct {
						PortGroup        string `json:"port-group"`
						Ipv6AddressGroup string `json:"ipv6-address-group"`
						Ipv6NetworkGroup string `json:"ipv6-network-group"`
					} `json:"group"`
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"destination"`
				Protocol string `json:"protocol"`
				State    struct {
					Related     string `json:"related"`
					Invalid     string `json:"invalid"`
					Established string `json:"established"`
					New         string `json:"new"`
				} `json:"state"`
				Time struct {
					Stopdate   string `json:"stopdate"`
					Contiguous string `json:"contiguous"`
					Starttime  string `json:"starttime"`
					Stoptime   string `json:"stoptime"`
					Weekdays   string `json:"weekdays"`
					Utc        string `json:"utc"`
					Startdate  string `json:"startdate"`
					Monthdays  string `json:"monthdays"`
				} `json:"time"`
				Ipsec struct {
					MatchNone  string `json:"match-none"`
					MatchIpsec string `json:"match-ipsec"`
				} `json:"ipsec"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Tcp         struct {
					Flags string `json:"flags"`
				} `json:"tcp"`
				P2p struct {
					Bittorrent    string `json:"bittorrent"`
					Gnutella      string `json:"gnutella"`
					All           string `json:"all"`
					Applejuice    string `json:"applejuice"`
					Edonkey       string `json:"edonkey"`
					Kazaa         string `json:"kazaa"`
					Directconnect string `json:"directconnect"`
				} `json:"p2p"`
				Connmark string `json:"connmark"`
				Log      string `json:"log"`
				Dscp     string `json:"dscp"`
				Recent   struct {
					Count string `json:"count"`
					Time  string `json:"time"`
				} `json:"recent"`
			} `json:"rule"`
			Description      string `json:"description"`
			EnableDefaultLog string `json:"enable-default-log"`
		} `json:"ipv6-modify"`
		SourceValidation string `json:"source-validation"`
		Name             map[string]struct {
			DefaultAction string `json:"default-action"`
			Rule          map[string]struct {
				Disable string `json:"disable"`
				Limit   struct {
					Rate  string `json:"rate"`
					Burst string `json:"burst"`
				} `json:"limit"`
				Source struct {
					Group struct {
						AddressGroup string `json:"address-group"`
						PortGroup    string `json:"port-group"`
						NetworkGroup string `json:"network-group"`
					} `json:"group"`
					MacAddress string `json:"mac-address"`
					Address    string `json:"address"`
					Port       string `json:"port"`
				} `json:"source"`
				Mark        string `json:"mark"`
				Destination struct {
					Group struct {
						AddressGroup string `json:"address-group"`
						PortGroup    string `json:"port-group"`
						NetworkGroup string `json:"network-group"`
					} `json:"group"`
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"destination"`
				Protocol string `json:"protocol"`
				State    struct {
					Related     string `json:"related"`
					Invalid     string `json:"invalid"`
					Established string `json:"established"`
					New         string `json:"new"`
				} `json:"state"`
				Time struct {
					Stopdate   string `json:"stopdate"`
					Contiguous string `json:"contiguous"`
					Starttime  string `json:"starttime"`
					Stoptime   string `json:"stoptime"`
					Weekdays   string `json:"weekdays"`
					Utc        string `json:"utc"`
					Startdate  string `json:"startdate"`
					Monthdays  string `json:"monthdays"`
				} `json:"time"`
				Ipsec struct {
					MatchNone  string `json:"match-none"`
					MatchIpsec string `json:"match-ipsec"`
				} `json:"ipsec"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Tcp         struct {
					Flags string `json:"flags"`
				} `json:"tcp"`
				Fragment struct {
					MatchNonFrag string `json:"match-non-frag"`
					MatchFrag    string `json:"match-frag"`
				} `json:"fragment"`
				Icmp struct {
					Code     string `json:"code"`
					TypeName string `json:"type-name"`
					Type     string `json:"type"`
				} `json:"icmp"`
				P2p struct {
					Bittorrent    string `json:"bittorrent"`
					Gnutella      string `json:"gnutella"`
					All           string `json:"all"`
					Applejuice    string `json:"applejuice"`
					Edonkey       string `json:"edonkey"`
					Kazaa         string `json:"kazaa"`
					Directconnect string `json:"directconnect"`
				} `json:"p2p"`
				Log         string `json:"log"`
				Application struct {
					Category       string `json:"category"`
					CustomCategory string `json:"custom-category"`
				} `json:"application"`
				Dscp   string `json:"dscp"`
				Recent struct {
					Count string `json:"count"`
					Time  string `json:"time"`
				} `json:"recent"`
			} `json:"rule"`
			Description      string `json:"description"`
			EnableDefaultLog string `json:"enable-default-log"`
		} `json:"name"`
		Ipv6SrcRoute     string `json:"ipv6-src-route"`
		ReceiveRedirects string `json:"receive-redirects"`
		Ipv6Name         map[string]struct {
			DefaultAction string `json:"default-action"`
			Rule          map[string]struct {
				Disable string `json:"disable"`
				Icmpv6  struct {
					Type string `json:"type"`
				} `json:"icmpv6"`
				Limit struct {
					Rate  string `json:"rate"`
					Burst string `json:"burst"`
				} `json:"limit"`
				Source struct {
					Group struct {
						PortGroup        string `json:"port-group"`
						Ipv6AddressGroup string `json:"ipv6-address-group"`
						Ipv6NetworkGroup string `json:"ipv6-network-group"`
					} `json:"group"`
					MacAddress string `json:"mac-address"`
					Address    string `json:"address"`
					Port       string `json:"port"`
				} `json:"source"`
				Mark        string `json:"mark"`
				Destination struct {
					Group struct {
						PortGroup        string `json:"port-group"`
						Ipv6AddressGroup string `json:"ipv6-address-group"`
						Ipv6NetworkGroup string `json:"ipv6-network-group"`
					} `json:"group"`
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"destination"`
				Protocol string `json:"protocol"`
				State    struct {
					Related     string `json:"related"`
					Invalid     string `json:"invalid"`
					Established string `json:"established"`
					New         string `json:"new"`
				} `json:"state"`
				Time struct {
					Stopdate   string `json:"stopdate"`
					Contiguous string `json:"contiguous"`
					Starttime  string `json:"starttime"`
					Stoptime   string `json:"stoptime"`
					Weekdays   string `json:"weekdays"`
					Utc        string `json:"utc"`
					Startdate  string `json:"startdate"`
					Monthdays  string `json:"monthdays"`
				} `json:"time"`
				Ipsec struct {
					MatchNone  string `json:"match-none"`
					MatchIpsec string `json:"match-ipsec"`
				} `json:"ipsec"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Tcp         struct {
					Flags string `json:"flags"`
				} `json:"tcp"`
				P2p struct {
					Bittorrent    string `json:"bittorrent"`
					Gnutella      string `json:"gnutella"`
					All           string `json:"all"`
					Applejuice    string `json:"applejuice"`
					Edonkey       string `json:"edonkey"`
					Kazaa         string `json:"kazaa"`
					Directconnect string `json:"directconnect"`
				} `json:"p2p"`
				Log    string `json:"log"`
				Dscp   string `json:"dscp"`
				Recent struct {
					Count string `json:"count"`
					Time  string `json:"time"`
				} `json:"recent"`
			} `json:"rule"`
			Description      string `json:"description"`
			EnableDefaultLog string `json:"enable-default-log"`
		} `json:"ipv6-name"`
	} `json:"firewall"`
	System struct {
		Options struct {
			RebootOnPanic string `json:"reboot-on-panic"`
		} `json:"options"`
		Syslog struct {
			Host map[string]struct {
				Facility map[string]struct {
					Level string `json:"level"`
				} `json:"facility"`
			} `json:"host"`
			File map[string]struct {
				Archive struct {
					Files string `json:"files"`
					Size  string `json:"size"`
				} `json:"archive"`
				Facility map[string]struct {
					Level string `json:"level"`
				} `json:"facility"`
			} `json:"file"`
			User map[string]struct {
				Facility map[string]struct {
					Level string `json:"level"`
				} `json:"facility"`
			} `json:"user"`
			Global struct {
				Archive struct {
					Files string `json:"files"`
					Size  string `json:"size"`
				} `json:"archive"`
				Facility map[string]struct {
					Level string `json:"level"`
				} `json:"facility"`
			} `json:"global"`
			Console struct {
				Facility map[string]struct {
					Level string `json:"level"`
				} `json:"facility"`
			} `json:"console"`
		} `json:"syslog"`
		FlowAccounting struct {
			Netflow struct {
				EngineId     string `json:"engine-id"`
				SamplingRate string `json:"sampling-rate"`
				Mode         string `json:"mode"`
				Timeout      struct {
					TcpFin         string `json:"tcp-fin"`
					Udp            string `json:"udp"`
					FlowGeneric    string `json:"flow-generic"`
					MaxActiveLife  string `json:"max-active-life"`
					TcpRst         string `json:"tcp-rst"`
					Icmp           string `json:"icmp"`
					TcpGeneric     string `json:"tcp-generic"`
					ExpiryInterval string `json:"expiry-interval"`
				} `json:"timeout"`
				Server map[string]struct {
					Port string `json:"port"`
				} `json:"server"`
				Version      string `json:"version"`
				EnableEgress struct {
					EngineId string `json:"engine-id"`
				} `json:"enable-egress"`
			} `json:"netflow"`
			Interface string `json:"interface"`
			Sflow     struct {
				SamplingRate string `json:"sampling-rate"`
				AgentAddress string `json:"agent-address"`
				Agentid      string `json:".agentid"`
				Server       map[string]struct {
					Port string `json:"port"`
				} `json:"server"`
			} `json:"sflow"`
			Aggregate struct {
				Egress  string `json:"egress"`
				Ingress string `json:"ingress"`
			} `json:"aggregate"`
			Unms struct {
				Exclude string `json:"exclude"`
				Subnets string `json:"subnets"`
			} `json:"unms"`
			IngressCapture     string `json:"ingress-capture"`
			SyslogFacility     string `json:"syslog-facility"`
			DisableMemoryTable string `json:"disable-memory-table"`
		} `json:"flow-accounting"`
		GatewayAddress string `json:"gateway-address"`
		TaskScheduler  struct {
			Task map[string]struct {
				Executable struct {
					Path      string `json:"path"`
					Arguments string `json:"arguments"`
				} `json:"executable"`
				CrontabSpec string `json:"crontab-spec"`
				Interval    string `json:"interval"`
			} `json:"task"`
		} `json:"task-scheduler"`
		AnalyticsHandler struct {
			SendAnalyticsReport string `json:"send-analytics-report"`
		} `json:"analytics-handler"`
		TimeZone string `json:"time-zone"`
		Systemd  struct {
			Journal struct {
				RateLimitBurst    string `json:"rate-limit-burst"`
				MaxRetention      string `json:"max-retention"`
				RuntimeMaxUse     string `json:"runtime-max-use"`
				Storage           string `json:"storage"`
				RateLimitInterval string `json:"rate-limit-interval"`
			} `json:"journal"`
		} `json:"systemd"`
		Conntrack struct {
			Ignore struct {
				Rule map[string]struct {
					InboundInterface string `json:"inbound-interface"`
					Source           struct {
						Address string `json:"address"`
						Port    string `json:"port"`
					} `json:"source"`
					Destination struct {
						Address string `json:"address"`
						Port    string `json:"port"`
					} `json:"destination"`
					Protocol    string `json:"protocol"`
					Description string `json:"description"`
				} `json:"rule"`
			} `json:"ignore"`
			Timeout struct {
				Udp struct {
					Stream string `json:"stream"`
					Other  string `json:"other"`
				} `json:"udp"`
				Other string `json:"other"`
				Tcp   struct {
					FinWait     string `json:"fin-wait"`
					TimeWait    string `json:"time-wait"`
					Close       string `json:"close"`
					SynSent     string `json:"syn-sent"`
					Established string `json:"established"`
					SynRecv     string `json:"syn-recv"`
					LastAck     string `json:"last-ack"`
					CloseWait   string `json:"close-wait"`
				} `json:"tcp"`
				Icmp   string `json:"icmp"`
				Custom struct {
					Rule map[string]struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol struct {
							Udp struct {
								Stream string `json:"stream"`
								Other  string `json:"other"`
							} `json:"udp"`
							Other string `json:"other"`
							Tcp   struct {
								FinWait     string `json:"fin-wait"`
								TimeWait    string `json:"time-wait"`
								Close       string `json:"close"`
								SynSent     string `json:"syn-sent"`
								Established string `json:"established"`
								SynRecv     string `json:"syn-recv"`
								LastAck     string `json:"last-ack"`
								CloseWait   string `json:"close-wait"`
							} `json:"tcp"`
							Icmp string `json:"icmp"`
						} `json:"protocol"`
						Description string `json:"description"`
					} `json:"rule"`
				} `json:".custom"`
			} `json:"timeout"`
			Tcp struct {
				Loose               string `json:"loose"`
				HalfOpenConnections string `json:"half-open-connections"`
				MaxRetrans          string `json:"max-retrans"`
			} `json:"tcp"`
			Log struct {
				Udp struct {
					Destroy string `json:"destroy"`
					Update  string `json:"update"`
					New     string `json:"new"`
				} `json:"udp"`
				Other struct {
					Destroy string `json:"destroy"`
					Update  string `json:"update"`
					New     string `json:"new"`
				} `json:"other"`
				Tcp struct {
					Destroy string `json:"destroy"`
					Update  struct {
						FinWait     string `json:"fin-wait"`
						TimeWait    string `json:"time-wait"`
						Established string `json:"established"`
						SynReceived string `json:"syn-received"`
						LastAck     string `json:"last-ack"`
						CloseWait   string `json:"close-wait"`
					} `json:"update"`
					New string `json:"new"`
				} `json:"tcp"`
				Icmp struct {
					Destroy string `json:"destroy"`
					Update  string `json:"update"`
					New     string `json:"new"`
				} `json:"icmp"`
			} `json:"log"`
			Modules struct {
				Ftp struct {
					Disable string `json:"disable"`
				} `json:"ftp"`
				Nfs struct {
					Disable string `json:"disable"`
				} `json:".nfs"`
				Rtsp struct {
					Enable string `json:"enable"`
				} `json:"rtsp"`
				Gre struct {
					Disable string `json:"disable"`
				} `json:"gre"`
				Tftp struct {
					Disable string `json:"disable"`
				} `json:"tftp"`
				Pptp struct {
					Disable string `json:"disable"`
				} `json:"pptp"`
				Sqlnet struct {
					Disable string `json:"disable"`
				} `json:".sqlnet"`
				Sip struct {
					Disable                  string `json:"disable"`
					EnableIndirectSignalling string `json:"enable-indirect-signalling"`
					EnableIndirectMedia      string `json:"enable-indirect-media"`
					Port                     string `json:"port"`
				} `json:"sip"`
				H323 struct {
					Disable string `json:"disable"`
				} `json:"h323"`
			} `json:"modules"`
			HashSize        string `json:"hash-size"`
			TableSize       string `json:"table-size"`
			ExpectTableSize string `json:"expect-table-size"`
		} `json:"conntrack"`
		NameServer        string `json:"name-server"`
		DomainName        string `json:"domain-name"`
		StaticHostMapping struct {
			HostName map[string]struct {
				Alias string `json:"alias"`
				Inet  string `json:"inet"`
			} `json:"host-name"`
		} `json:"static-host-mapping"`
		HostName string `json:"host-name"`
		Ntp      struct {
			Server map[string]struct {
				Prefer   string `json:"prefer"`
				Preempt  string `json:"preempt"`
				Noselect string `json:"noselect"`
			} `json:"server"`
		} `json:"ntp"`
		Coredump struct {
			Enabled string `json:"enabled"`
		} `json:"coredump"`
		DomainSearch struct {
			Domain string `json:"domain"`
		} `json:"domain-search"`
		ConfigManagement struct {
			CommitRevisions string `json:"commit-revisions"`
			CommitArchive   struct {
				Location string `json:"location"`
			} `json:"commit-archive"`
		} `json:"config-management"`
		TrafficAnalysis struct {
			SignatureUpdate struct {
				Disable    string `json:"disable"`
				UpdateHour string `json:"update-hour"`
			} `json:"signature-update"`
			Dpi            string `json:"dpi"`
			CustomCategory map[string]struct {
				Name string `json:"name"`
			} `json:"custom-category"`
			Export string `json:"export"`
		} `json:"traffic-analysis"`
		CrashHandler struct {
			SaveCoreFile    string `json:"save-core-file"`
			SendCrashReport string `json:"send-crash-report"`
		} `json:"crash-handler"`
		Ip struct {
			DisableForwarding  string `json:"disable-forwarding"`
			OverrideHostnameIp string `json:"override-hostname-ip"`
			Arp                struct {
				StaleTime         string `json:"stale-time"`
				BaseReachableTime string `json:"base-reachable-time"`
				TableSize         string `json:"table-size"`
			} `json:"arp"`
		} `json:"ip"`
		Ipv6 struct {
			Disable  string `json:"disable"`
			Neighbor struct {
				StaleTime         string `json:"stale-time"`
				BaseReachableTime string `json:"base-reachable-time"`
				TableSize         string `json:"table-size"`
			} `json:"neighbor"`
			DisableForwarding string `json:"disable-forwarding"`
			Blacklist         string `json:"blacklist"`
			StrictDad         string `json:"strict-dad"`
		} `json:"ipv6"`
		Login struct {
			RadiusServer map[string]struct {
				Timeout string `json:"timeout"`
				Secret  string `json:"secret"`
				Port    string `json:"port"`
			} `json:"radius-server"`
			User map[string]struct {
				Group          string `json:"group"`
				HomeDirectory  string `json:"home-directory"`
				Level          string `json:"level"`
				FullName       string `json:"full-name"`
				Authentication struct {
					EncryptedPassword string `json:"encrypted-password"`
					PublicKeys        map[string]struct {
						Options string `json:"options"`
						Key     string `json:"key"`
						Type    string `json:"type"`
					} `json:"public-keys"`
					PlaintextPassword string `json:"plaintext-password"`
				} `json:"authentication"`
			} `json:"user"`
			Banner struct {
				PostLogin string `json:"post-login"`
				PreLogin  string `json:"pre-login"`
			} `json:"banner"`
		} `json:"login"`
		PacketRxCoreNum string `json:"packet-rx-core-num"`
		Package         struct {
			Repository map[string]struct {
				Password     string `json:"password"`
				Distribution string `json:"distribution"`
				Url          string `json:"url"`
				Components   string `json:"components"`
				Description  string `json:"description"`
				Username     string `json:"username"`
			} `json:"repository"`
			AutoSync string `json:".auto-sync"`
		} `json:"package"`
		Offload struct {
			Hwnat string `json:"hwnat"`
			Ipv4  struct {
				DisableFlowFlushingUponFibChanges string `json:"disable-flow-flushing-upon-fib-changes"`
				Bonding                           string `json:"bonding"`
				Pppoe                             string `json:"pppoe"`
				Forwarding                        string `json:"forwarding"`
				Gre                               string `json:"gre"`
				Vlan                              string `json:"vlan"`
				TableSize                         string `json:"table-size"`
			} `json:"ipv4"`
			Ipsec        string `json:"ipsec"`
			FlowLifetime string `json:"flow-lifetime"`
			Ipv6         struct {
				DisableFlowFlushingUponFibChanges string `json:"disable-flow-flushing-upon-fib-changes"`
				Bonding                           string `json:"bonding"`
				Pppoe                             string `json:"pppoe"`
				Forwarding                        string `json:"forwarding"`
				Vlan                              string `json:"vlan"`
				TableSize                         string `json:"table-size"`
			} `json:"ipv6"`
		} `json:"offload"`
	} `json:"system"`
	TrafficControl struct {
		OptimizedQueue struct {
			Policy string `json:"policy"`
		} `json:"optimized-queue"`
		SmartQueue map[string]struct {
			WanInterface string `json:"wan-interface"`
			Download     struct {
				Rate       string `json:"rate"`
				HtbQuantum string `json:"htb-quantum"`
				Limit      string `json:"limit"`
				Target     string `json:"target"`
				Interval   string `json:"interval"`
				Burst      string `json:"burst"`
				Ecn        string `json:"ecn"`
				FqQuantum  string `json:"fq-quantum"`
				Flows      string `json:"flows"`
			} `json:"download"`
			Upload struct {
				Rate       string `json:"rate"`
				HtbQuantum string `json:"htb-quantum"`
				Limit      string `json:"limit"`
				Target     string `json:"target"`
				Interval   string `json:"interval"`
				Burst      string `json:"burst"`
				Ecn        string `json:"ecn"`
				FqQuantum  string `json:"fq-quantum"`
				Flows      string `json:"flows"`
			} `json:"upload"`
		} `json:"smart-queue"`
		AdvancedQueue struct {
			Filters struct {
				Match map[string]struct {
					Interface string `json:"interface"`
					Target    string `json:"target"`
					Mark      string `json:"mark"`
					Ether     struct {
						Source      string `json:"source"`
						Destination string `json:"destination"`
						Protocol    string `json:"protocol"`
					} `json:"ether"`
					Description string `json:"description"`
					Application struct {
						Category       string `json:"category"`
						CustomCategory string `json:"custom-category"`
					} `json:"application"`
					AttachTo string `json:"attach-to"`
					Ip       struct {
						Source struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"source"`
						Destination struct {
							Address string `json:"address"`
							Port    string `json:"port"`
						} `json:"destination"`
						Protocol string `json:"protocol"`
						Dscp     string `json:"dscp"`
					} `json:"ip"`
				} `json:"match"`
			} `json:"filters"`
			Leaf struct {
				Queue map[string]struct {
					Bandwidth string `json:"bandwidth"`
					Burst     struct {
						BurstRate string `json:"burst-rate"`
						BurstSize string `json:"burst-size"`
					} `json:"burst"`
					Ceiling     string `json:"ceiling"`
					QueueType   string `json:"queue-type"`
					Description string `json:"description"`
					Parent      string `json:"parent"`
					Priority    string `json:"priority"`
				} `json:"queue"`
			} `json:"leaf"`
			Branch struct {
				Queue map[string]struct {
					Bandwidth   string `json:"bandwidth"`
					Description string `json:"description"`
					Parent      string `json:"parent"`
					Priority    string `json:"priority"`
				} `json:"queue"`
			} `json:"branch"`
			QueueType struct {
				Pfifo map[string]struct {
					Limit string `json:"limit"`
				} `json:"pfifo"`
				Hfq map[string]struct {
					Burst struct {
						BurstRate string `json:"burst-rate"`
						BurstSize string `json:"burst-size"`
					} `json:"burst"`
					Description    string `json:"description"`
					HostIdentifier string `json:"host-identifier"`
					Subnet         string `json:"subnet"`
					MaxRate        string `json:"max-rate"`
				} `json:"hfq"`
				FqCodel map[string]struct {
					Limit    string `json:"limit"`
					Target   string `json:"target"`
					Interval string `json:"interval"`
					Ecn      string `json:"ecn"`
					Flows    string `json:"flows"`
					Quantum  string `json:"quantum"`
				} `json:"fq-codel"`
				Sfq map[string]struct {
					HashInterval string `json:"hash-interval"`
					Description  string `json:"description"`
					QueueLimit   string `json:"queue-limit"`
				} `json:"sfq"`
			} `json:"queue-type"`
			Root struct {
				Queue map[string]struct {
					Bandwidth   string `json:"bandwidth"`
					Default     string `json:"default"`
					Description string `json:"description"`
					AttachTo    string `json:"attach-to"`
				} `json:"queue"`
			} `json:"root"`
		} `json:"advanced-queue"`
	} `json:"traffic-control"`
	Service struct {
		UbntDiscover struct {
			Disable   string `json:"disable"`
			Interface map[string]struct {
				Disable string `json:"disable"`
			} `json:"interface"`
		} `json:"ubnt-discover"`
		UdapiServer string `json:"udapi-server"`
		Snmp        struct {
			Contact       string `json:"contact"`
			Location      string `json:"location"`
			ListenAddress map[string]struct {
				Interface string `json:"interface"`
				Port      string `json:"port"`
			} `json:"listen-address"`
			Description string `json:"description"`
			V3          struct {
				Group map[string]struct {
					Mode     string `json:"mode"`
					View     string `json:"view"`
					Seclevel string `json:"seclevel"`
				} `json:"group"`
				Tsm struct {
					LocalKey string `json:"local-key"`
					Port     string `json:"port"`
				} `json:"tsm"`
				User map[string]struct {
					TsmKey  string `json:"tsm-key"`
					Privacy struct {
						PlaintextKey string `json:"plaintext-key"`
						EncryptedKey string `json:"encrypted-key"`
						Type         string `json:"type"`
					} `json:"privacy"`
					Mode string `json:"mode"`
					Auth struct {
						PlaintextKey string `json:"plaintext-key"`
						EncryptedKey string `json:"encrypted-key"`
						Type         string `json:"type"`
					} `json:"auth"`
					Group    string `json:"group"`
					Engineid string `json:"engineid"`
				} `json:"user"`
				View map[string]struct {
					Oid map[string]struct {
						Exclude string `json:"exclude"`
						Mask    string `json:"mask"`
					} `json:"oid"`
				} `json:"view"`
				TrapTarget map[string]struct {
					Privacy struct {
						PlaintextKey string `json:"plaintext-key"`
						EncryptedKey string `json:"encrypted-key"`
						Type         string `json:"type"`
					} `json:"privacy"`
					Auth struct {
						PlaintextKey string `json:"plaintext-key"`
						EncryptedKey string `json:"encrypted-key"`
						Type         string `json:"type"`
					} `json:"auth"`
					User     string `json:"user"`
					Protocol string `json:"protocol"`
					Type     string `json:"type"`
					Port     string `json:"port"`
					Engineid string `json:"engineid"`
				} `json:"trap-target"`
				Engineid string `json:"engineid"`
			} `json:"v3"`
			TrapSource string `json:"trap-source"`
			TrapTarget map[string]struct {
				Port      string `json:"port"`
				Community string `json:"community"`
			} `json:"trap-target"`
			Community map[string]struct {
				Network       string `json:"network"`
				Authorization string `json:"authorization"`
				Client        string `json:"client"`
			} `json:"community"`
			IgnoreInterface string `json:"ignore-interface"`
		} `json:"snmp"`
		Dhcpv6Server struct {
			Preference        string `json:"preference"`
			SharedNetworkName map[string]struct {
				NameServer string `json:"name-server"`
				Subnet     map[string]struct {
					NisServer     string `json:"nis-server"`
					StaticMapping map[string]struct {
						Ipv6Address string `json:"ipv6-address"`
						Identifier  string `json:"identifier"`
					} `json:"static-mapping"`
					SntpServer       string `json:"sntp-server"`
					PrefixDelegation struct {
						Start map[string]struct {
							Stop map[string]struct {
								PrefixLength string `json:"prefix-length"`
							} `json:"stop"`
						} `json:"start"`
					} `json:"prefix-delegation"`
					NisplusDomain    string `json:"nisplus-domain"`
					SipServerAddress string `json:"sip-server-address"`
					SipServerName    string `json:"sip-server-name"`
					NameServer       string `json:"name-server"`
					NisDomain        string `json:"nis-domain"`
					DomainSearch     string `json:"domain-search"`
					LeaseTime        struct {
						Maximum string `json:"maximum"`
						Default string `json:"default"`
						Minimum string `json:"minimum"`
					} `json:"lease-time"`
					NisplusServer string `json:"nisplus-server"`
					AddressRange  struct {
						Prefix map[string]struct {
							Temporary string `json:"temporary"`
						} `json:"prefix"`
						Start map[string]struct {
							Stop string `json:"stop"`
						} `json:"start"`
					} `json:"address-range"`
				} `json:"subnet"`
			} `json:"shared-network-name"`
		} `json:"dhcpv6-server"`
		Upnp struct {
			ListenOn map[string]struct {
				OutboundInterface string `json:"outbound-interface"`
			} `json:"listen-on"`
		} `json:"upnp"`
		Lldp struct {
			LegacyProtocols struct {
				Cdp   string `json:"cdp"`
				Sonmp string `json:"sonmp"`
				Edp   string `json:"edp"`
				Fdp   string `json:"fdp"`
			} `json:"legacy-protocols"`
			Interface map[string]struct {
				Disable  string `json:"disable"`
				Location struct {
					CivicBased struct {
						CountryCode string `json:"country-code"`
						CaType      map[string]struct {
							CaValue string `json:"ca-value"`
						} `json:"ca-type"`
					} `json:"civic-based"`
					Elin            string `json:"elin"`
					CoordinateBased struct {
						Datum     string `json:"datum"`
						Longitude string `json:"longitude"`
						Altitude  string `json:"altitude"`
						Latitude  string `json:"latitude"`
					} `json:"coordinate-based"`
				} `json:"location"`
			} `json:"interface"`
			ManagementAddress string `json:"management-address"`
			ListenVlan        string `json:".listen-vlan"`
		} `json:"lldp"`
		Nat struct {
			Rule map[string]struct {
				OutsideAddress struct {
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"outside-address"`
				Disable          string `json:"disable"`
				InboundInterface string `json:"inbound-interface"`
				Exclude          string `json:"exclude"`
				Source           struct {
					Group struct {
						AddressGroup string `json:"address-group"`
						PortGroup    string `json:"port-group"`
						NetworkGroup string `json:"network-group"`
					} `json:"group"`
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"source"`
				OutboundInterface string `json:"outbound-interface"`
				Destination       struct {
					Group struct {
						AddressGroup string `json:"address-group"`
						PortGroup    string `json:"port-group"`
						NetworkGroup string `json:"network-group"`
					} `json:"group"`
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"destination"`
				Protocol      string `json:"protocol"`
				Type          string `json:"type"`
				Description   string `json:"description"`
				Log           string `json:"log"`
				InsideAddress struct {
					Address string `json:"address"`
					Port    string `json:"port"`
				} `json:"inside-address"`
			} `json:"rule"`
		} `json:"nat"`
		Webproxy struct {
			DomainBlock       string `json:"domain-block"`
			MinimumObjectSize string `json:"minimum-object-size"`
			ProxyBypass       string `json:"proxy-bypass"`
			ProxyBypassSource string `json:"proxy-bypass-source"`
			ListenAddress     map[string]struct {
				DisableTransparent string `json:"disable-transparent"`
				Port               string `json:"port"`
			} `json:"listen-address"`
			DomainNoncache    string `json:"domain-noncache"`
			MemCacheSize      string `json:"mem-cache-size"`
			MaximumObjectSize string `json:"maximum-object-size"`
			DefaultPort       string `json:"default-port"`
			AppendDomain      string `json:"append-domain"`
			UrlFiltering      struct {
				Disable    string `json:"disable"`
				Squidguard struct {
					AutoUpdate struct {
						UpdateHour string `json:"update-hour"`
					} `json:"auto-update"`
					DefaultAction    string `json:"default-action"`
					EnableSafeSearch string `json:"enable-safe-search"`
					SourceGroup      map[string]struct {
						Description string `json:"description"`
						Address     string `json:"address"`
						Domain      string `json:"domain"`
					} `json:"source-group"`
					RedirectUrl   string `json:"redirect-url"`
					LocalBlock    string `json:"local-block"`
					BlockCategory string `json:"block-category"`
					LocalOk       string `json:"local-ok"`
					TimePeriod    map[string]struct {
						Description string `json:"description"`
						Days        map[string]struct {
							Time string `json:"time"`
						} `json:"days"`
					} `json:"time-period"`
					LocalOkUrl     string `json:"local-ok-url"`
					AllowIpaddrUrl string `json:"allow-ipaddr-url"`
					Rule           map[string]struct {
						DefaultAction     string `json:"default-action"`
						EnableSafeSearch  string `json:"enable-safe-search"`
						SourceGroup       string `json:"source-group"`
						RedirectUrl       string `json:"redirect-url"`
						LocalBlock        string `json:"local-block"`
						BlockCategory     string `json:"block-category"`
						LocalOk           string `json:"local-ok"`
						TimePeriod        string `json:"time-period"`
						LocalOkUrl        string `json:"local-ok-url"`
						AllowIpaddrUrl    string `json:"allow-ipaddr-url"`
						Description       string `json:"description"`
						LocalBlockKeyword string `json:"local-block-keyword"`
						AllowCategory     string `json:"allow-category"`
						Log               string `json:"log"`
						LocalBlockUrl     string `json:"local-block-url"`
					} `json:"rule"`
					LocalBlockKeyword string `json:"local-block-keyword"`
					AllowCategory     string `json:"allow-category"`
					Log               string `json:"log"`
					LocalBlockUrl     string `json:"local-block-url"`
				} `json:"squidguard"`
			} `json:"url-filtering"`
			EnableAccessLog  string `json:"enable-access-log"`
			Administrator    string `json:"administrator"`
			CacheSize        string `json:"cache-size"`
			ReplyBlockMime   string `json:"reply-block-mime"`
			ReplyBodyMaxSize string `json:"reply-body-max-size"`
		} `json:"webproxy"`
		Suspend struct {
			ForwardTo struct {
				HttpPort  string `json:"http-port"`
				Address   string `json:"address"`
				HttpsPort string `json:"https-port"`
			} `json:"forward-to"`
			AllowDomain string `json:"allow-domain"`
			UserIp      string `json:"user-ip"`
			Redirect    struct {
				HttpPort  string `json:"http-port"`
				Url       string `json:"url"`
				HttpsPort string `json:"https-port"`
			} `json:"redirect"`
			AllowIp string `json:"allow-ip"`
		} `json:"suspend"`
		Unms struct {
			Disable    string `json:"disable"`
			Connection string `json:"connection"`
			Lldp       struct {
				Disable string `json:"disable"`
			} `json:"lldp"`
			RestApi struct {
				Interface string `json:"interface"`
				Port      string `json:"port"`
			} `json:"rest-api"`
		} `json:"unms"`
		Mdns struct {
			Reflector string `json:"reflector"`
			Repeater  struct {
				Interface string `json:"interface"`
			} `json:"repeater"`
		} `json:"mdns"`
		UbntDiscoverServer struct {
			Disable  string `json:"disable"`
			Protocol string `json:"protocol"`
		} `json:"ubnt-discover-server"`
		DhcpServer struct {
			UseDnsmasq        string `json:"use-dnsmasq"`
			StaticArp         string `json:"static-arp"`
			HostfileUpdate    string `json:"hostfile-update"`
			SharedNetworkName map[string]struct {
				Disable                 string `json:"disable"`
				SharedNetworkParameters string `json:"shared-network-parameters"`
				Authoritative           string `json:"authoritative"`
				Description             string `json:"description"`
				Subnet                  map[string]struct {
					StaticMapping map[string]struct {
						Disable                 string `json:"disable"`
						IpAddress               string `json:"ip-address"`
						StaticMappingParameters string `json:"static-mapping-parameters"`
						MacAddress              string `json:"mac-address"`
					} `json:"static-mapping"`
					BootfileName   string `json:"bootfile-name"`
					BootfileServer string `json:"bootfile-server"`
					PopServer      string `json:"pop-server"`
					Exclude        string `json:"exclude"`
					DomainName     string `json:"domain-name"`
					StaticRoute    struct {
						DestinationSubnet string `json:"destination-subnet"`
						Router            string `json:"router"`
					} `json:"static-route"`
					SubnetParameters string `json:"subnet-parameters"`
					Start            map[string]struct {
						Stop string `json:"stop"`
					} `json:"start"`
					TimeServer      string `json:"time-server"`
					WpadUrl         string `json:"wpad-url"`
					UnifiController string `json:"unifi-controller"`
					Lease           string `json:"lease"`
					DefaultRouter   string `json:"default-router"`
					TftpServerName  string `json:"tftp-server-name"`
					IpForwarding    struct {
						Enable string `json:"enable"`
					} `json:"ip-forwarding"`
					DnsServer          string `json:"dns-server"`
					NtpServer          string `json:"ntp-server"`
					TimeOffset         string `json:"time-offset"`
					SmtpServer         string `json:"smtp-server"`
					WinsServer         string `json:"wins-server"`
					ClientPrefixLength string `json:"client-prefix-length"`
					Failover           struct {
						PeerAddress  string `json:"peer-address"`
						Status       string `json:"status"`
						LocalAddress string `json:"local-address"`
						Name         string `json:"name"`
					} `json:"failover"`
					ServerIdentifier string `json:"server-identifier"`
				} `json:"subnet"`
			} `json:"shared-network-name"`
			Disabled         string `json:"disabled"`
			DynamicDnsUpdate struct {
				Enable string `json:"enable"`
			} `json:"dynamic-dns-update"`
			GlobalParameters string `json:"global-parameters"`
		} `json:"dhcp-server"`
		Ssh struct {
			DisablePasswordAuthentication string `json:"disable-password-authentication"`
			ListenAddress                 string `json:"listen-address"`
			AllowRoot                     string `json:"allow-root"`
			ProtocolVersion               string `json:"protocol-version"`
			DisableHostValidation         string `json:"disable-host-validation"`
			Port                          string `json:"port"`
		} `json:"ssh"`
		Gui struct {
			CaFile        string `json:"ca-file"`
			HttpPort      string `json:"http-port"`
			ListenAddress string `json:"listen-address"`
			HttpsPort     string `json:"https-port"`
			DhFile        string `json:"dh-file"`
			CertFile      string `json:"cert-file"`
			OlderCiphers  string `json:"older-ciphers"`
			Debug         string `json:"debug"`
		} `json:"gui"`
		PppoeServer struct {
			Encryption  string `json:"encryption"`
			ServiceName string `json:"service-name"`
			WinsServers struct {
				Server2 string `json:"server-2"`
				Server1 string `json:"server-1"`
			} `json:"wins-servers"`
			Interface  string `json:"interface"`
			DnsServers struct {
				Server2 string `json:"server-2"`
				Server1 string `json:"server-1"`
			} `json:"dns-servers"`
			Mtu          string `json:"mtu"`
			ClientIpPool struct {
				Start string `json:"start"`
				Stop  string `json:"stop"`
			} `json:"client-ip-pool"`
			Radius struct {
				DefaultInterimInterval string `json:"default-interim-interval"`
			} `json:"radius"`
			LocalIp        string `json:"local-ip"`
			Authentication struct {
				Mode       string `json:"mode"`
				LocalUsers struct {
					Username map[string]struct {
						Disable  string `json:"disable"`
						Password string `json:"password"`
						StaticIp string `json:"static-ip"`
					} `json:"username"`
				} `json:"local-users"`
				RadiusServer map[string]struct {
					Key string `json:"key"`
				} `json:"radius-server"`
			} `json:"authentication"`
			AccessConcentrator string `json:"access-concentrator"`
		} `json:"pppoe-server"`
		SshRecovery struct {
			ListenOn string `json:"listen-on"`
			Lifetime string `json:"lifetime"`
			Disabled string `json:"disabled"`
			Port     string `json:"port"`
		} `json:"ssh-recovery"`
		Dns struct {
			Dynamic struct {
				Interface map[string]struct {
					Web     string `json:"web"`
					WebSkip string `json:"web-skip"`
					Service map[string]struct {
						Options  string `json:"options"`
						Password string `json:"password"`
						Server   string `json:"server"`
						HostName string `json:"host-name"`
						Protocol string `json:"protocol"`
						Login    string `json:"login"`
					} `json:"service"`
				} `json:"interface"`
			} `json:"dynamic"`
			Forwarding struct {
				Options             string `json:"options"`
				ExceptInterface     string `json:"except-interface"`
				ForcePublicDnsBoost string `json:"force-public-dns-boost"`
				ListenOn            string `json:"listen-on"`
				NameServer          string `json:"name-server"`
				System              string `json:"system"`
				Dhcp                string `json:"dhcp"`
				CacheSize           string `json:"cache-size"`
			} `json:"forwarding"`
		} `json:"dns"`
		DhcpRelay struct {
			Interface    string `json:"interface"`
			RelayOptions struct {
				HopCount           string `json:"hop-count"`
				MaxSize            string `json:"max-size"`
				Port               string `json:"port"`
				RelayAgentsPackets string `json:"relay-agents-packets"`
			} `json:"relay-options"`
			Server string `json:"server"`
		} `json:"dhcp-relay"`
		Upnp2 struct {
			ListenOn string `json:"listen-on"`
			NatPmp   string `json:"nat-pmp"`
			BitRate  struct {
				Up   string `json:"up"`
				Down string `json:"down"`
			} `json:"bit-rate"`
			Wan        string `json:"wan"`
			Port       string `json:"port"`
			SecureMode string `json:"secure-mode"`
			Acl        struct {
				Rule map[string]struct {
					Action       string `json:"action"`
					Description  string `json:"description"`
					ExternalPort string `json:"external-port"`
					LocalPort    string `json:"local-port"`
					Subnet       string `json:"subnet"`
				} `json:"rule"`
			} `json:"acl"`
		} `json:"upnp2"`
		Telnet struct {
			ListenAddress string `json:"listen-address"`
			AllowRoot     string `json:"allow-root"`
			Port          string `json:"port"`
		} `json:"telnet"`
		Dhcpv6Relay struct {
			ListenInterface map[string]struct {
				Address string `json:"address"`
			} `json:"listen-interface"`
			MaxHopCount          string `json:"max-hop-count"`
			UseInterfaceIdOption string `json:"use-interface-id-option"`
			UpstreamInterface    map[string]struct {
				Address string `json:"address"`
			} `json:"upstream-interface"`
			ListenPort string `json:"listen-port"`
		} `json:"dhcpv6-relay"`
	} `json:"service"`
	Protocols struct {
		Rip struct {
			Interface string `json:"interface"`
			Neighbor  string `json:"neighbor"`
			Route     string `json:"route"`
			Bfd       struct {
				Neighbor map[string]struct {
					FallOver string `json:"fall-over"`
				} `json:"neighbor"`
				AllInterfaces string `json:"all-interfaces"`
			} `json:"bfd"`
			DefaultDistance string `json:"default-distance"`
			Timers          struct {
				Update            string `json:"update"`
				Timeout           string `json:"timeout"`
				GarbageCollection string `json:"garbage-collection"`
			} `json:"timers"`
			Network       string `json:"network"`
			DefaultMetric string `json:"default-metric"`
			Vrf           map[string]struct {
				Interface string `json:"interface"`
				Bfd       struct {
					Neighbor map[string]struct {
						FallOver string `json:"fall-over"`
					} `json:"neighbor"`
					AllInterfaces string `json:"all-interfaces"`
				} `json:"bfd"`
				DefaultDistance string `json:"default-distance"`
				Network         string `json:"network"`
				DefaultMetric   string `json:"default-metric"`
				NetworkDistance map[string]struct {
					Distance   string `json:"distance"`
					AccessList string `json:"access-list"`
				} `json:"network-distance"`
				Redistribute struct {
					Connected struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"connected"`
					Static struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"static"`
					Bgp struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"bgp"`
					Ospf struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"ospf"`
				} `json:"redistribute"`
				DistributeList struct {
					Interface map[string]struct {
						AccessList struct {
							Out string `json:"out"`
							In  string `json:"in"`
						} `json:"access-list"`
						PrefixList struct {
							Out string `json:"out"`
							In  string `json:"in"`
						} `json:"prefix-list"`
					} `json:"interface"`
					AccessList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"access-list"`
					PrefixList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"prefix-list"`
				} `json:"distribute-list"`
				DefaultInformation struct {
					Originate string `json:"originate"`
				} `json:"default-information"`
			} `json:".vrf"`
			NetworkDistance map[string]struct {
				Distance   string `json:"distance"`
				AccessList string `json:"access-list"`
			} `json:"network-distance"`
			PassiveInterface string `json:"passive-interface"`
			Redistribute     struct {
				Connected struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"connected"`
				Static struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"static"`
				Bgp struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"bgp"`
				Kernel struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"kernel"`
				Ospf struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"ospf"`
			} `json:"redistribute"`
			DistributeList struct {
				Interface map[string]struct {
					AccessList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"access-list"`
					PrefixList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"prefix-list"`
				} `json:"interface"`
				AccessList struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"access-list"`
				PrefixList struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"prefix-list"`
			} `json:"distribute-list"`
			DefaultInformation struct {
				Originate string `json:"originate"`
			} `json:"default-information"`
		} `json:"rip"`
		Mpls struct {
			LspTunneling struct {
				Interface map[string]struct {
					InLabel map[string]struct {
						OutLabel map[string]struct {
							NetworkFec string `json:"network-fec"`
						} `json:"out-label"`
					} `json:"in-label"`
				} `json:"interface"`
			} `json:"lsp-tunneling"`
			AcGroup map[string]struct {
				GroupId string `json:"group-id"`
			} `json:"ac-group"`
			LocalPacketHandling string `json:"local-packet-handling"`
			Interface           map[string]struct {
				MulticastHellos  string `json:"multicast-hellos"`
				KeepaliveTimeout string `json:"keepalive-timeout"`
				VcMode           struct {
					Standby   string `json:"standby"`
					Revertive string `json:"revertive"`
				} `json:"vc-mode"`
				LdpIgp struct {
					Sync struct {
						Ospf struct {
							HolddownTimer string `json:"holddown-timer"`
						} `json:"ospf"`
					} `json:"sync"`
					SyncDelay string `json:"sync-delay"`
				} `json:"ldp-igp"`
				MaxPduLength       string `json:"max-pdu-length"`
				LabelRetentionMode struct {
					Liberal      string `json:"liberal"`
					Conservative string `json:"conservative"`
				} `json:"label-retention-mode"`
				AdminGroup string `json:"admin-group"`
				L2Circuit  map[string]struct {
					Hdlc struct {
						Primary   string `json:"primary"`
						Secondary string `json:"secondary"`
					} `json:".hdlc"`
					Ppp struct {
						Primary   string `json:"primary"`
						Secondary string `json:"secondary"`
					} `json:".ppp"`
					Ethernet struct {
						Primary   string `json:"primary"`
						Secondary string `json:"secondary"`
					} `json:".ethernet"`
				} `json:"l2-circuit"`
				LabelSwitching    string `json:"label-switching"`
				HoldTime          string `json:"hold-time"`
				KeepaliveInterval string `json:"keepalive-interval"`
				AdvertisementMode struct {
					DownstreamOnDemand    string `json:"downstream-on-demand"`
					DownstreamUnsolicited string `json:"downstream-unsolicited"`
				} `json:"advertisement-mode"`
				HelloInterval string `json:"hello-interval"`
			} `json:"interface"`
			L2CircuitFibEntry map[string]struct {
				InLabel map[string]struct {
					OutLabel map[string]struct {
						Ipv4 map[string]struct {
							Int map[string]struct {
								Int string `json:"int"`
							} `json:"int"`
						} `json:"ipv4"`
						Ipv6 map[string]struct {
							Int map[string]struct {
								Int string `json:"int"`
							} `json:"int"`
						} `json:"ipv6"`
					} `json:"out-label"`
				} `json:"in-label"`
			} `json:".l2-circuit-fib-entry"`
			EnableAllInterfaces string `json:"enable-all-interfaces"`
			MsPw                map[string]struct {
				Description string `json:"description"`
			} `json:"ms-pw"`
			IngressTtl string `json:"ingress-ttl"`
			TeClass    map[string]struct {
				Name map[string]struct {
					Priority string `json:"priority"`
				} `json:"name"`
			} `json:"te-class"`
			LspModel struct {
				Pipe string `json:"pipe"`
			} `json:"lsp-model"`
			FtnEntry struct {
				TunnelId map[string]struct {
					Ip map[string]struct {
						Mask map[string]struct {
							OutLabel map[string]struct {
								Nexthop map[string]struct {
									Interface map[string]struct {
										Primary   string `json:"primary"`
										Secondary string `json:"secondary"`
									} `json:"interface"`
								} `json:"nexthop"`
							} `json:"out-label"`
						} `json:"mask"`
					} `json:"ip"`
					Ipv6mask map[string]struct {
						OutLabel map[string]struct {
							Nexthop map[string]struct {
								Interface map[string]struct {
									Primary   string `json:"primary"`
									Secondary string `json:"secondary"`
								} `json:"interface"`
							} `json:"nexthop"`
						} `json:"out-label"`
					} `json:"ipv6mask"`
					Ipv4mask map[string]struct {
						OutLabel map[string]struct {
							Nexthop map[string]struct {
								Interface map[string]struct {
									Primary   string `json:"primary"`
									Secondary string `json:"secondary"`
								} `json:"interface"`
							} `json:"nexthop"`
						} `json:"out-label"`
					} `json:"ipv4mask"`
				} `json:"tunnel-id"`
			} `json:"ftn-entry"`
			ClassToExp map[string]struct {
				Bit string `json:"bit"`
			} `json:"class-to-exp"`
			L2Circuit map[string]struct {
				Ipv4 map[string]struct {
					Agi map[string]struct {
						Saii map[string]struct {
							Taii map[string]struct {
								Manual    string `json:"manual"`
								Groupname map[string]struct {
									GroupId string `json:"group-id"`
								} `json:"groupname"`
								ControlWord struct {
									Manual   string `json:"manual"`
									TunnelId map[string]struct {
										Passive string `json:"passive"`
										Reverse struct {
											Passive string `json:"passive"`
											Manual  string `json:"manual"`
										} `json:"reverse"`
										Manual  string `json:"manual"`
										Forward struct {
											Passive string `json:"passive"`
											Manual  string `json:"manual"`
										} `json:"forward"`
									} `json:"tunnel-id"`
								} `json:"control-word"`
								TunnelId map[string]struct {
									Passive string `json:"passive"`
									Reverse struct {
										Passive string `json:"passive"`
										Manual  string `json:"manual"`
									} `json:"reverse"`
									Manual  string `json:"manual"`
									Forward struct {
										Passive string `json:"passive"`
										Manual  string `json:"manual"`
									} `json:"forward"`
								} `json:"tunnel-id"`
							} `json:"taii"`
						} `json:"saii"`
					} `json:"agi"`
				} `json:"ipv4"`
				Id map[string]struct {
					Ipv4 map[string]struct {
						Passive   string `json:"passive"`
						Manual    string `json:"manual"`
						Groupname map[string]struct {
							ControlWord struct {
								Manual string `json:"manual"`
							} `json:"control-word"`
						} `json:"groupname"`
						ControlWord struct {
							Passive  string `json:"passive"`
							Manual   string `json:"manual"`
							TunnelId map[string]struct {
								Passive string `json:"passive"`
								Reverse struct {
									Passive string `json:"passive"`
									Manual  string `json:"manual"`
								} `json:"reverse"`
								Manual  string `json:"manual"`
								Forward struct {
									Passive string `json:"passive"`
									Manual  string `json:"manual"`
								} `json:"forward"`
							} `json:"tunnel-id"`
						} `json:"control-word"`
						TunnelId map[string]struct {
							Passive string `json:"passive"`
							Reverse struct {
								Passive string `json:"passive"`
								Manual  string `json:"manual"`
							} `json:"reverse"`
							Manual  string `json:"manual"`
							Forward struct {
								Passive string `json:"passive"`
								Manual  string `json:"manual"`
							} `json:"forward"`
						} `json:"tunnel-id"`
					} `json:"ipv4"`
					Ipv6 map[string]struct {
						Manual string `json:"manual"`
					} `json:"ipv6"`
				} `json:"id"`
			} `json:".l2-circuit"`
			EgressTtl     string `json:"egress-ttl"`
			MinLabelValue map[string]struct {
				LabelSpace string `json:"label-space"`
			} `json:"min-label-value"`
			AdminGroup map[string]struct {
				Value string `json:"value"`
			} `json:"admin-group"`
			MsPwStitch map[string]struct {
				Vc1 map[string]struct {
					Vc2 map[string]struct {
						Mtu map[string]struct {
							Ethernet string `json:"ethernet"`
							Vlan     string `json:"vlan"`
						} `json:"mtu"`
					} `json:"vc2"`
				} `json:"vc1"`
			} `json:"ms-pw-stitch"`
			ClassType map[string]struct {
				Name string `json:"name"`
			} `json:"class-type"`
			IlmEntry map[string]struct {
				Interface map[string]struct {
					Pop  string `json:"pop"`
					Swap map[string]struct {
						Interface map[string]struct {
							Ip map[string]struct {
								Fec map[string]struct {
									Mask string `json:"mask"`
								} `json:"fec"`
							} `json:"ip"`
						} `json:"interface"`
					} `json:"swap"`
				} `json:"interface"`
			} `json:"ilm-entry"`
			SupportDiffservClass string `json:"support-diffserv-class"`
			MapRoute             map[string]struct {
				Fec string `json:"fec"`
			} `json:"map-route"`
			Rsvp struct {
				MinLabelValue map[string]struct {
					LabelSpace string `json:"label-space"`
				} `json:"min-label-value"`
				MaxLabelValue map[string]struct {
					LabelSpace string `json:"label-space"`
				} `json:"max-label-value"`
			} `json:"rsvp"`
			Ldp struct {
				MinLabelValue map[string]struct {
					LabelSpace string `json:"label-space"`
				} `json:"min-label-value"`
				MaxLabelValue map[string]struct {
					LabelSpace string `json:"label-space"`
				} `json:"max-label-value"`
			} `json:"ldp"`
			Bgp struct {
				MinLabelValue map[string]struct {
					LabelSpace string `json:"label-space"`
				} `json:"min-label-value"`
				MaxLabelValue map[string]struct {
					LabelSpace string `json:"label-space"`
				} `json:"max-label-value"`
			} `json:"bgp"`
			MaxLabelValue map[string]struct {
				LabelSpace string `json:"label-space"`
			} `json:"max-label-value"`
			PropagateTtl         string `json:"propagate-ttl"`
			DisableAllInterfaces string `json:"disable-all-interfaces"`
		} `json:"mpls"`
		Bfd struct {
			Interface map[string]struct {
				Enable string `json:"enable"`
				Echo   struct {
					Interval string `json:"interval"`
				} `json:"echo"`
				Auth struct {
					Key  string `json:"key"`
					Type string `json:"type"`
				} `json:"auth"`
				Interval map[string]struct {
					Minrx map[string]struct {
						Multiplier string `json:"multiplier"`
					} `json:"minrx"`
				} `json:"interval"`
				Session struct {
					Source map[string]struct {
						Dest map[string]struct {
							Multihop struct {
								AdminDown  string `json:"admin-down"`
								DemandMode struct {
									AdminDown     string `json:"admin-down"`
									NonPersistent struct {
										AdminDown string `json:"admin-down"`
									} `json:"non-persistent"`
								} `json:"demand-mode"`
							} `json:"multihop"`
							AdminDown  string `json:"admin-down"`
							DemandMode struct {
								AdminDown     string `json:"admin-down"`
								NonPersistent struct {
									AdminDown string `json:"admin-down"`
								} `json:"non-persistent"`
							} `json:"demand-mode"`
							NonPersistent struct {
								AdminDown string `json:"admin-down"`
							} `json:"non-persistent"`
						} `json:"dest"`
					} `json:"source"`
				} `json:"session"`
			} `json:"interface"`
			Echo         string `json:"echo"`
			Notification struct {
				Enable string `json:"enable"`
			} `json:"notification"`
			SlowTimer string `json:"slow-timer"`
			Gtsm      struct {
				Enable string `json:"enable"`
				Ttl    string `json:"ttl"`
			} `json:"gtsm"`
			MultihopPeer map[string]struct {
				Auth struct {
					Key  string `json:"key"`
					Type string `json:"type"`
				} `json:"auth"`
				Interval map[string]struct {
					Minrx map[string]struct {
						Multiplier string `json:"multiplier"`
					} `json:"minrx"`
				} `json:"interval"`
			} `json:"multihop-peer"`
		} `json:"bfd"`
		Ripng struct {
			Interface string `json:"interface"`
			Route     string `json:"route"`
			Timers    struct {
				Update            string `json:"update"`
				Timeout           string `json:"timeout"`
				GarbageCollection string `json:"garbage-collection"`
			} `json:"timers"`
			Network          string `json:"network"`
			DefaultMetric    string `json:"default-metric"`
			AggregateAddress string `json:"aggregate-address"`
			Vrf              map[string]struct {
				Interface string `json:"interface"`
				Route     string `json:"route"`
				Timers    struct {
					Update            string `json:"update"`
					Timeout           string `json:"timeout"`
					GarbageCollection string `json:"garbage-collection"`
				} `json:"timers"`
				Network          string `json:"network"`
				DefaultMetric    string `json:"default-metric"`
				AggregateAddress string `json:"aggregate-address"`
				PassiveInterface string `json:"passive-interface"`
				Redistribute     struct {
					Connected struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"connected"`
					Static struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"static"`
					Bgp struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"bgp"`
					Ospfv3 struct {
						RouteMap string `json:"route-map"`
						Metric   string `json:"metric"`
					} `json:"ospfv3"`
				} `json:"redistribute"`
				DistributeList struct {
					Interface map[string]struct {
						AccessList struct {
							Out string `json:"out"`
							In  string `json:"in"`
						} `json:"access-list"`
						PrefixList struct {
							Out string `json:"out"`
							In  string `json:"in"`
						} `json:"prefix-list"`
					} `json:"interface"`
					AccessList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"access-list"`
					PrefixList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"prefix-list"`
				} `json:"distribute-list"`
				DefaultInformation struct {
					Originate string `json:"originate"`
				} `json:"default-information"`
			} `json:".vrf"`
			PassiveInterface string `json:"passive-interface"`
			Redistribute     struct {
				Connected struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"connected"`
				Static struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"static"`
				Bgp struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"bgp"`
				Ospfv3 struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"ospfv3"`
				Kernel struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"kernel"`
			} `json:"redistribute"`
			DistributeList struct {
				Interface map[string]struct {
					AccessList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"access-list"`
					PrefixList struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"prefix-list"`
				} `json:"interface"`
				AccessList struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"access-list"`
				PrefixList struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"prefix-list"`
			} `json:"distribute-list"`
			DefaultInformation struct {
				Originate string `json:"originate"`
			} `json:"default-information"`
		} `json:"ripng"`
		Vrf map[string]struct {
			Interface   string `json:"interface"`
			RouterId    string `json:"router-id"`
			RouteTarget struct {
				Both   string `json:"both"`
				Export string `json:"export"`
				Import string `json:"import"`
			} `json:"route-target"`
			Description string `json:"description"`
			Import      struct {
				Map string `json:"map"`
			} `json:"import"`
			Rd struct {
				Int string `json:"int"`
				Ip  string `json:"ip"`
			} `json:"rd"`
		} `json:".vrf"`
		Static struct {
			InterfaceRoute6 map[string]struct {
				NextHopInterface map[string]struct {
					Disable     string `json:"disable"`
					Distance    string `json:"distance"`
					Description string `json:"description"`
				} `json:"next-hop-interface"`
			} `json:"interface-route6"`
			Route map[string]struct {
				NextHop map[string]struct {
					Disable     string `json:"disable"`
					Bfd         string `json:"bfd"`
					Distance    string `json:"distance"`
					Description string `json:"description"`
				} `json:"next-hop"`
				Blackhole struct {
					Disable     string `json:"disable"`
					Distance    string `json:"distance"`
					Description string `json:"description"`
				} `json:"blackhole"`
			} `json:"route"`
			Bfd struct {
				Interface map[string]struct {
					Ipv4 string `json:"ipv4"`
					Ipv6 string `json:"ipv6"`
				} `json:"interface"`
				AllInterfaces struct {
					Ipv4 string `json:"ipv4"`
					Ipv6 string `json:"ipv6"`
				} `json:"all-interfaces"`
			} `json:"bfd"`
			Vrf map[string]struct {
				InterfaceRoute6 map[string]struct {
					NextHopInterface map[string]struct {
						Gw map[string]struct {
							Disable string `json:"disable"`
						} `json:"gw"`
					} `json:"next-hop-interface"`
				} `json:"interface-route6"`
				Route map[string]struct {
					NextHop map[string]struct {
						Disable   string `json:"disable"`
						Interface string `json:"interface"`
					} `json:"next-hop"`
					Blackhole struct {
						Disable   string `json:"disable"`
						Interface string `json:"interface"`
					} `json:"blackhole"`
				} `json:"route"`
				InterfaceRoute map[string]struct {
					NextHopInterface map[string]struct {
						Disable string `json:"disable"`
					} `json:"next-hop-interface"`
				} `json:"interface-route"`
				Ip struct {
					Forwarding string `json:"forwarding"`
				} `json:"ip"`
				Route6 map[string]struct {
					NextHop map[string]struct {
						Disable   string `json:"disable"`
						Interface string `json:"interface"`
					} `json:"next-hop"`
				} `json:"route6"`
			} `json:".vrf"`
			Table map[string]struct {
				InterfaceRoute6 map[string]struct {
					NextHopInterface map[string]struct {
						Disable     string `json:"disable"`
						Distance    string `json:"distance"`
						Description string `json:"description"`
					} `json:"next-hop-interface"`
				} `json:"interface-route6"`
				Route map[string]struct {
					NextHop map[string]struct {
						Disable     string `json:"disable"`
						Distance    string `json:"distance"`
						Description string `json:"description"`
					} `json:"next-hop"`
					Blackhole struct {
						Distance    string `json:"distance"`
						Description string `json:"description"`
					} `json:"blackhole"`
				} `json:"route"`
				Mark           string `json:"mark"`
				Description    string `json:"description"`
				InterfaceRoute map[string]struct {
					NextHopInterface map[string]struct {
						Disable     string `json:"disable"`
						Distance    string `json:"distance"`
						Description string `json:"description"`
					} `json:"next-hop-interface"`
				} `json:"interface-route"`
				Route6 map[string]struct {
					NextHop map[string]struct {
						Disable     string `json:"disable"`
						Distance    string `json:"distance"`
						Description string `json:"description"`
					} `json:"next-hop"`
					Blackhole struct {
						Distance    string `json:"distance"`
						Description string `json:"description"`
					} `json:"blackhole"`
				} `json:"route6"`
			} `json:"table"`
			InterfaceRoute map[string]struct {
				NextHopInterface map[string]struct {
					Disable     string `json:"disable"`
					Distance    string `json:"distance"`
					Description string `json:"description"`
				} `json:"next-hop-interface"`
			} `json:"interface-route"`
			Arp map[string]struct {
				Hwaddr string `json:"hwaddr"`
			} `json:"arp"`
			Route6 map[string]struct {
				NextHop map[string]struct {
					Disable     string `json:"disable"`
					Interface   string `json:"interface"`
					Bfd         string `json:"bfd"`
					Distance    string `json:"distance"`
					Description string `json:"description"`
				} `json:"next-hop"`
				Blackhole struct {
					Disable     string `json:"disable"`
					Distance    string `json:"distance"`
					Description string `json:"description"`
				} `json:"blackhole"`
			} `json:"route6"`
		} `json:"static"`
		Rsvp struct {
			HelloTimeout string `json:"hello-timeout"`
			Interface    map[string]struct {
				HelloTimeout     string `json:"hello-timeout"`
				Disable          string `json:"disable"`
				AckWaitTimeout   string `json:"ack-wait-timeout"`
				MessageAck       string `json:"message-ack"`
				RefreshReduction string `json:"refresh-reduction"`
				RefreshTime      string `json:"refresh-time"`
				HelloReceipt     string `json:"hello-receipt"`
				KeepMultiplier   string `json:"keep-multiplier"`
				NonIANAHello     string `json:"non-IANA-hello"`
				HelloInterval    string `json:"hello-interval"`
			} `json:"interface"`
			Neighbor                 string `json:"neighbor"`
			BundleSend               string `json:"bundle-send"`
			ExplicitNull             string `json:"explicit-null"`
			OverrideDiffserv         string `json:"override-diffserv"`
			PreprogramSuggestedLabel string `json:"preprogram-suggested-label"`
			Notification             string `json:"notification"`
			Path                     map[string]struct {
				Mpls struct {
					Loose      string `json:"loose"`
					Unnumbered map[string]struct {
						LinkId string `json:"link-id"`
					} `json:".unnumbered"`
					Strict    string `json:"strict"`
					StrictHop string `json:".strict-hop"`
				} `json:"mpls"`
				Gmpls struct {
					StrictHop  string `json:"strict-hop"`
					Unnumbered map[string]struct {
						LinkId string `json:"link-id"`
					} `json:"unnumbered"`
					Strict string `json:".strict"`
					Loose  string `json:".loose"`
				} `json:".gmpls"`
			} `json:"path"`
			From               string `json:"from"`
			AckWaitTimeout     string `json:"ack-wait-timeout"`
			RefreshPathParsing string `json:"refresh-path-parsing"`
			Cspf               string `json:"cspf"`
			GracefulRestart    struct {
				Enable       string `json:"enable"`
				RestartTime  string `json:"restart-time"`
				RecoveryTime string `json:"recovery-time"`
			} `json:"graceful-restart"`
			RefreshResvParsing string `json:"refresh-resv-parsing"`
			MessageAck         string `json:"message-ack"`
			RefreshReduction   string `json:"refresh-reduction"`
			LocalProtection    string `json:"local-protection"`
			RefreshTime        string `json:"refresh-time"`
			NoPhp              string `json:"no-php"`
			HelloReceipt       string `json:"hello-receipt"`
			KeepMultiplier     string `json:"keep-multiplier"`
			LoopDetection      string `json:"loop-detection"`
			HelloInterval      string `json:"hello-interval"`
			Trunk              map[string]struct {
				Gmpls struct {
					ExtTunnelId string `json:"ext-tunnel-id"`
					LspMetric   struct {
						Relative string `json:"relative"`
						Absolute string `json:"absolute"`
					} `json:"lsp-metric"`
					EnableIgpShortcut string `json:".enable-igp-shortcut"`
					Capability        struct {
						Psc1  string `json:"psc-1"`
						PbbTe string `json:"pbb-te"`
						Psc4  string `json:"psc-4"`
						Psc3  string `json:"psc-3"`
						Psc2  string `json:"psc-2"`
					} `json:"capability"`
					From string `json:"from"`
					Gpid struct {
						Ethernet string `json:"ethernet"`
						Ipv4     string `json:"ipv4"`
					} `json:"gpid"`
					RsvpTrunkRestart string `json:"rsvp-trunk-restart"`
					GmplsLabelSet    struct {
						Range struct {
							StartRange map[string]struct {
								EndRange string `json:"end_range"`
							} `json:"start_range"`
						} `json:"range"`
						Packet struct {
							Range struct {
								StartRange map[string]struct {
									EndRange string `json:"end_range"`
								} `json:"start_range"`
							} `json:"range"`
						} `json:"packet"`
					} `json:"gmpls-label-set"`
					Direction struct {
						Bidirectional  string `json:"bidirectional"`
						Unidirectional string `json:"unidirectional"`
					} `json:"direction"`
					UpdateType struct {
						MakeBeforeBreak string `json:"make-before-break"`
						BreakBeforeMake string `json:"break-before-make"`
					} `json:"update-type"`
					DisableIgpShortcut string `json:".disable-igp-shortcut"`
					Primary            struct {
						Traffic struct {
							ControlledLoad string `json:"controlled-load"`
							Guaranteed     string `json:"guaranteed"`
						} `json:"traffic"`
						Bandwidth         string `json:"bandwidth"`
						SetupPriority     string `json:"setup-priority"`
						Record            string `json:"record"`
						IncludeAny        string `json:"include-any"`
						Affinity          string `json:"affinity"`
						ReuseRouteRecord  string `json:"reuse-route-record"`
						ElspPreconfigured string `json:"elsp-preconfigured"`
						Path              string `json:"path"`
						HoldPriority      string `json:"hold-priority"`
						HopLimit          string `json:"hop-limit"`
						Cspf              string `json:"cspf"`
						LabelRecord       string `json:"label-record"`
						NoAffinity        string `json:"no-affinity"`
						Protection        struct {
							Unprotected         string `json:"unprotected"`
							DedicatedOneToOne   string `json:"dedicated-one-to-one"`
							Shared              string `json:"shared"`
							ExtraTraffic        string `json:"extra-traffic"`
							DedicatedOnePlusOne string `json:"dedicated-one-plus-one"`
							Ehanced             string `json:"ehanced"`
						} `json:"protection"`
						RetryLimit      string `json:"retry-limit"`
						CspfRetryTimer  string `json:"cspf-retry-timer"`
						ClassType       string `json:"class-type"`
						ElspSignaled    string `json:"elsp-signaled"`
						LocalProtection string `json:"local-protection"`
						ClassToExpBit   map[string]struct {
							Bit string `json:"bit"`
						} `json:"class-to-exp-bit"`
						Filter struct {
							SharedExplicit string `json:"shared-explicit"`
							Fixed          string `json:"fixed"`
						} `json:"filter"`
						ExplicitLabel map[string]struct {
							Reverse string `json:"reverse"`
							Packet  struct {
								Reverse string `json:"reverse"`
								Forward string `json:"forward"`
							} `json:"packet"`
							Forward string `json:"forward"`
						} `json:"explicit-label"`
						CspfRetryLimit string `json:"cspf-retry-limit"`
						ExcludeAny     string `json:"exclude-any"`
						RetryTimer     string `json:"retry-timer"`
						NoRecord       string `json:"no-record"`
						Llsp           string `json:"llsp"`
					} `json:"primary"`
					To        string `json:"to"`
					Secondary struct {
						Traffic struct {
							ControlledLoad string `json:"controlled-load"`
							Guaranteed     string `json:"guaranteed"`
						} `json:"traffic"`
						Bandwidth         string `json:"bandwidth"`
						SetupPriority     string `json:"setup-priority"`
						Record            string `json:"record"`
						IncludeAny        string `json:"include-any"`
						Affinity          string `json:"affinity"`
						ReuseRouteRecord  string `json:"reuse-route-record"`
						ElspPreconfigured string `json:"elsp-preconfigured"`
						Path              string `json:"path"`
						HoldPriority      string `json:"hold-priority"`
						HopLimit          string `json:"hop-limit"`
						Cspf              string `json:"cspf"`
						LabelRecord       string `json:"label-record"`
						NoAffinity        string `json:"no-affinity"`
						Protection        struct {
							Unprotected         string `json:"unprotected"`
							DedicatedOneToOne   string `json:"dedicated-one-to-one"`
							Shared              string `json:"shared"`
							ExtraTraffic        string `json:"extra-traffic"`
							DedicatedOnePlusOne string `json:"dedicated-one-plus-one"`
							Ehanced             string `json:"ehanced"`
						} `json:"protection"`
						RetryLimit      string `json:"retry-limit"`
						CspfRetryTimer  string `json:"cspf-retry-timer"`
						ClassType       string `json:"class-type"`
						ElspSignaled    string `json:"elsp-signaled"`
						LocalProtection string `json:"local-protection"`
						ClassToExpBit   map[string]struct {
							Bit string `json:"bit"`
						} `json:"class-to-exp-bit"`
						Filter struct {
							SharedExplicit string `json:"shared-explicit"`
							Fixed          string `json:"fixed"`
						} `json:"filter"`
						ExplicitLabel map[string]struct {
							Reverse string `json:"reverse"`
							Packet  struct {
								Reverse string `json:"reverse"`
								Forward string `json:"forward"`
							} `json:"packet"`
							Forward string `json:"forward"`
						} `json:"explicit-label"`
						CspfRetryLimit string `json:"cspf-retry-limit"`
						ExcludeAny     string `json:"exclude-any"`
						RetryTimer     string `json:"retry-timer"`
						NoRecord       string `json:"no-record"`
						Llsp           string `json:"llsp"`
					} `json:"secondary"`
				} `json:".gmpls"`
				Ipv4 struct {
					ExtTunnelId string `json:"ext-tunnel-id"`
					LspMetric   struct {
						Relative string `json:"relative"`
						Absolute string `json:"absolute"`
					} `json:"lsp-metric"`
					From             string `json:"from"`
					RsvpTrunkRestart string `json:".rsvp-trunk-restart"`
					Capability       struct {
						Psc1 string `json:"psc-1"`
						Psc4 string `json:"psc-4"`
						Psc3 string `json:"psc-3"`
						Psc2 string `json:"psc-2"`
					} `json:".capability"`
					Direction struct {
						Bidirectional  string `json:"bidirectional"`
						Unidirectional string `json:"unidirectional"`
					} `json:".direction"`
					MapRoute map[string]struct {
						Class string `json:"class"`
					} `json:"map-route"`
					UpdateType string `json:"update-type"`
					Primary    struct {
						Traffic       string `json:"traffic"`
						Bandwidth     string `json:"bandwidth"`
						SetupPriority string `json:"setup-priority"`
						Record        string `json:"record"`
						IncludeAny    string `json:"include-any"`
						Protection    struct {
							Unprotected         string `json:"unprotected"`
							DedicatedOneToOne   string `json:"dedicated-one-to-one"`
							Shared              string `json:"shared"`
							ExtraTraffic        string `json:"extra-traffic"`
							DedicatedOnePlusOne string `json:"dedicated-one-plus-one"`
							Ehanced             string `json:"ehanced"`
						} `json:".protection"`
						ReuseRouteRecord  string `json:"reuse-route-record"`
						ElspPreconfigured string `json:"elsp-preconfigured"`
						Path              string `json:"path"`
						ExplicitLabel     map[string]struct {
							Reverse string `json:"reverse"`
							Packet  struct {
								Reverse string `json:"reverse"`
								Forward string `json:"forward"`
							} `json:"packet"`
							Forward string `json:"forward"`
						} `json:".explicit-label"`
						ClassToExp map[string]struct {
							Bit string `json:"bit"`
						} `json:"class-to-exp"`
						HoldPriority    string `json:"hold-priority"`
						HopLimit        string `json:"hop-limit"`
						Cspf            string `json:"cspf"`
						LabelRecord     string `json:"label-record"`
						NoAffinity      string `json:"no-affinity"`
						RetryLimit      string `json:"retry-limit"`
						CspfRetryTimer  string `json:"cspf-retry-timer"`
						ClassType       string `json:"class-type"`
						NoRecord        string `json:".no-record"`
						ElspSignaled    string `json:"elsp-signaled"`
						LocalProtection string `json:"local-protection"`
						Filter          string `json:"filter"`
						CspfRetryLimit  string `json:"cspf-retry-limit"`
						ExcludeAny      string `json:"exclude-any"`
						RetryTimer      string `json:"retry-timer"`
						Llsp            string `json:"llsp"`
					} `json:"primary"`
					To                string `json:"to"`
					EnableIgpShortcut string `json:"enable-igp-shortcut"`
					Secondary         struct {
						Traffic       string `json:"traffic"`
						Bandwidth     string `json:"bandwidth"`
						SetupPriority string `json:"setup-priority"`
						Record        string `json:"record"`
						IncludeAny    string `json:"include-any"`
						Protection    struct {
							Unprotected         string `json:"unprotected"`
							DedicatedOneToOne   string `json:"dedicated-one-to-one"`
							Shared              string `json:"shared"`
							ExtraTraffic        string `json:"extra-traffic"`
							DedicatedOnePlusOne string `json:"dedicated-one-plus-one"`
							Ehanced             string `json:"ehanced"`
						} `json:".protection"`
						ReuseRouteRecord  string `json:"reuse-route-record"`
						ElspPreconfigured string `json:"elsp-preconfigured"`
						Path              string `json:"path"`
						ExplicitLabel     map[string]struct {
							Reverse string `json:"reverse"`
							Packet  struct {
								Reverse string `json:"reverse"`
								Forward string `json:"forward"`
							} `json:"packet"`
							Forward string `json:"forward"`
						} `json:".explicit-label"`
						ClassToExp map[string]struct {
							Bit string `json:"bit"`
						} `json:"class-to-exp"`
						HoldPriority    string `json:"hold-priority"`
						HopLimit        string `json:"hop-limit"`
						Cspf            string `json:"cspf"`
						LabelRecord     string `json:"label-record"`
						NoAffinity      string `json:"no-affinity"`
						RetryLimit      string `json:"retry-limit"`
						CspfRetryTimer  string `json:"cspf-retry-timer"`
						ClassType       string `json:"class-type"`
						NoRecord        string `json:".no-record"`
						ElspSignaled    string `json:"elsp-signaled"`
						LocalProtection string `json:"local-protection"`
						Filter          string `json:"filter"`
						CspfRetryLimit  string `json:"cspf-retry-limit"`
						ExcludeAny      string `json:"exclude-any"`
						RetryTimer      string `json:"retry-timer"`
						Llsp            string `json:"llsp"`
					} `json:"secondary"`
					GmplsLabelSet struct {
						Range struct {
							StartRange map[string]struct {
								EndRange string `json:"end_range"`
							} `json:"start_range"`
						} `json:"range"`
						Packet struct {
							Range struct {
								StartRange map[string]struct {
									EndRange string `json:"end_range"`
								} `json:"start_range"`
							} `json:"range"`
						} `json:"packet"`
					} `json:".gmpls-label-set"`
				} `json:"ipv4"`
				Ipv6 struct {
					ExtTunnelId string `json:"ext-tunnel-id"`
					LspMetric   struct {
						Relative string `json:"relative"`
						Absolute string `json:"absolute"`
					} `json:"lsp-metric"`
					From             string `json:"from"`
					Ethernet         string `json:"ethernet"`
					RsvpTrunkRestart string `json:"rsvp-trunk-restart"`
					Capability       struct {
						Psc1 string `json:"psc-1"`
						Psc4 string `json:"psc-4"`
						Psc3 string `json:"psc-3"`
						Psc2 string `json:"psc-2"`
					} `json:".capability"`
					Direction struct {
						Bidirectional  string `json:"bidirectional"`
						Unidirectional string `json:"unidirectional"`
					} `json:".direction"`
					MapRoute struct {
						Prefix map[string]struct {
							Mask map[string]struct {
								Class string `json:"class"`
							} `json:"mask"`
						} `json:"prefix"`
						Mask map[string]struct {
							Class string `json:"class"`
						} `json:"mask"`
					} `json:"map-route"`
					DisableIgpShortcut string `json:"disable-igp-shortcut"`
					UpdateType         struct {
						MakeBeforeBreak string `json:"make-before-break"`
						BreakBeforeMake string `json:"break-before-make"`
					} `json:"update-type"`
					Primary struct {
						Traffic struct {
							ControlledLoad string `json:"controlled-load"`
							Guaranteed     string `json:"guaranteed"`
						} `json:"traffic"`
						Bandwidth     string `json:"bandwidth"`
						SetupPriority string `json:"setup-priority"`
						Record        string `json:"record"`
						IncludeAny    string `json:"include-any"`
						Protection    struct {
							Unprotected         string `json:"unprotected"`
							DedicatedOneToOne   string `json:"dedicated-one-to-one"`
							Shared              string `json:"shared"`
							ExtraTraffic        string `json:"extra-traffic"`
							DedicatedOnePlusOne string `json:"dedicated-one-plus-one"`
							Ehanced             string `json:"ehanced"`
						} `json:".protection"`
						Affinity          string `json:"affinity"`
						ReuseRouteRecord  string `json:"reuse-route-record"`
						ElspPreconfigured string `json:"elsp-preconfigured"`
						Path              string `json:"path"`
						ExplicitLabel     map[string]struct {
							Reverse string `json:"reverse"`
							Packet  struct {
								Reverse string `json:"reverse"`
								Forward string `json:"forward"`
							} `json:"packet"`
							Forward string `json:"forward"`
						} `json:".explicit-label"`
						HoldPriority    string `json:"hold-priority"`
						HopLimit        string `json:"hop-limit"`
						Cspf            string `json:"cspf"`
						LabelRecord     string `json:"label-record"`
						RetryLimit      string `json:"retry-limit"`
						CspfRetryTimer  string `json:"cspf-retry-timer"`
						ClassType       string `json:"class-type"`
						NoRecord        string `json:".no-record"`
						ElspSignaled    string `json:"elsp-signaled"`
						NoAffinity      string `json:".no-affinity"`
						LocalProtection string `json:"local-protection"`
						ClassToExpBit   map[string]struct {
							Bit string `json:"bit"`
						} `json:"class-to-exp-bit"`
						Filter struct {
							SharedExplicit string `json:"shared-explicit"`
							Fixed          string `json:"fixed"`
						} `json:"filter"`
						CspfRetryLimit string `json:"cspf-retry-limit"`
						ExcludeAny     string `json:"exclude-any"`
						RetryTimer     string `json:"retry-timer"`
						Llsp           string `json:"llsp"`
					} `json:"primary"`
					To                string `json:"to"`
					EnableIgpShortcut string `json:"enable-igp-shortcut"`
					Secondary         struct {
						Traffic struct {
							ControlledLoad string `json:"controlled-load"`
							Guaranteed     string `json:"guaranteed"`
						} `json:"traffic"`
						Bandwidth     string `json:"bandwidth"`
						SetupPriority string `json:"setup-priority"`
						Record        string `json:"record"`
						IncludeAny    string `json:"include-any"`
						Protection    struct {
							Unprotected         string `json:"unprotected"`
							DedicatedOneToOne   string `json:"dedicated-one-to-one"`
							Shared              string `json:"shared"`
							ExtraTraffic        string `json:"extra-traffic"`
							DedicatedOnePlusOne string `json:"dedicated-one-plus-one"`
							Ehanced             string `json:"ehanced"`
						} `json:".protection"`
						Affinity          string `json:"affinity"`
						ReuseRouteRecord  string `json:"reuse-route-record"`
						ElspPreconfigured string `json:"elsp-preconfigured"`
						Path              string `json:"path"`
						ExplicitLabel     map[string]struct {
							Reverse string `json:"reverse"`
							Packet  struct {
								Reverse string `json:"reverse"`
								Forward string `json:"forward"`
							} `json:"packet"`
							Forward string `json:"forward"`
						} `json:".explicit-label"`
						HoldPriority    string `json:"hold-priority"`
						HopLimit        string `json:"hop-limit"`
						Cspf            string `json:"cspf"`
						LabelRecord     string `json:"label-record"`
						RetryLimit      string `json:"retry-limit"`
						CspfRetryTimer  string `json:"cspf-retry-timer"`
						ClassType       string `json:"class-type"`
						NoRecord        string `json:".no-record"`
						ElspSignaled    string `json:"elsp-signaled"`
						NoAffinity      string `json:".no-affinity"`
						LocalProtection string `json:"local-protection"`
						ClassToExpBit   map[string]struct {
							Bit string `json:"bit"`
						} `json:"class-to-exp-bit"`
						Filter struct {
							SharedExplicit string `json:"shared-explicit"`
							Fixed          string `json:"fixed"`
						} `json:"filter"`
						CspfRetryLimit string `json:"cspf-retry-limit"`
						ExcludeAny     string `json:"exclude-any"`
						RetryTimer     string `json:"retry-timer"`
						Llsp           string `json:"llsp"`
					} `json:"secondary"`
					GmplsLabelSet struct {
						Range struct {
							StartRange map[string]struct {
								EndRange string `json:"end_range"`
							} `json:"start_range"`
						} `json:"range"`
						Packet struct {
							Range struct {
								StartRange map[string]struct {
									EndRange string `json:"end_range"`
								} `json:"start_range"`
							} `json:"range"`
						} `json:"packet"`
					} `json:".gmpls-label-set"`
				} `json:".ipv6"`
			} `json:"trunk"`
		} `json:"rsvp"`
		Vpls struct {
			Interface map[string]struct {
				VlanInstance map[string]struct {
					Vlan map[string]struct {
					} `json:"vlan"`
				} `json:"vlan-instance"`
				Instance string `json:"instance"`
			} `json:"interface"`
			FibEntry map[string]struct {
				Peer map[string]struct {
					InLabel map[string]struct {
						OutInterface map[string]struct {
							OutLabel string `json:"out-label"`
						} `json:"out-interface"`
					} `json:"in-label"`
				} `json:"peer"`
				SpokeVc map[string]struct {
					InLabel map[string]struct {
						OutInterface map[string]struct {
							OutLabel string `json:"out-label"`
						} `json:"out-interface"`
					} `json:"in-label"`
				} `json:".spoke-vc"`
			} `json:"fib-entry"`
			Instance map[string]struct {
				Id map[string]struct {
					VplsAcGroup string `json:"vpls-ac-group"`
					VplsPeer    map[string]struct {
						Manual   string `json:"manual"`
						TunnelId map[string]struct {
							Reverse struct {
								Manual string `json:"manual"`
							} `json:"reverse"`
							Manual  string `json:"manual"`
							Forward struct {
								Manual string `json:"manual"`
							} `json:"forward"`
						} `json:"tunnel-id"`
					} `json:"vpls-peer"`
					Learning struct {
						Disable string `json:"disable"`
						Limit   string `json:"limit"`
					} `json:"learning"`
					VplsVc map[string]struct {
						Ethernet string `json:"ethernet"`
						Vlan     string `json:"vlan"`
						Normal   string `json:"normal"`
					} `json:"vpls-vc"`
					VplsDescription string `json:"vpls-description"`
					Signaling       struct {
						Ldp struct {
							VplsPeer map[string]struct {
								Agi map[string]struct {
									Saii map[string]struct {
										Taii map[string]struct {
											Normal   string `json:"normal"`
											TunnelId map[string]struct {
												Reverse string `json:"reverse"`
												Normal  string `json:"normal"`
												Forward string `json:"forward"`
											} `json:"tunnel-id"`
										} `json:"taii"`
									} `json:"saii"`
								} `json:"agi"`
								TunnelId map[string]struct {
									Reverse string `json:"reverse"`
									Forward string `json:"forward"`
								} `json:"tunnel-id"`
							} `json:"vpls-peer"`
						} `json:"ldp"`
						Bgp struct {
							VeRange     string `json:"ve-range"`
							VeId        string `json:"ve-id"`
							RouteTarget string `json:"route-target"`
							Rd          string `json:"rd"`
						} `json:"bgp"`
					} `json:"signaling"`
					VplsType string `json:"vpls-type"`
					VplsMtu  string `json:"vpls-mtu"`
				} `json:"id"`
			} `json:"instance"`
		} `json:"vpls"`
		Ldp struct {
			LdpOptimization           string `json:"ldp-optimization"`
			TargetedPeerHelloInterval string `json:"targeted-peer-hello-interval"`
			Interface                 map[string]struct {
				Enable struct {
					Both string `json:"both"`
					Ipv4 string `json:"ipv4"`
					Ipv6 string `json:"ipv6"`
				} `json:"enable"`
				KeepaliveTimeout   string `json:"keepalive-timeout"`
				LabelRetentionMode struct {
					Liberal      string `json:"liberal"`
					Conservative string `json:"conservative"`
				} `json:"label-retention-mode"`
				HoldTime          string `json:"hold-time"`
				KeepaliveInterval string `json:"keepalive-interval"`
				AdvertisementMode struct {
					DownstreamOnDemand    string `json:"downstream-on-demand"`
					DownstreamUnsolicited string `json:"downstream-unsolicited"`
				} `json:"advertisement-mode"`
				HelloInterval string `json:"hello-interval"`
			} `json:"interface"`
			Neighbor map[string]struct {
				Auth struct {
					Md5 struct {
						Password map[string]struct {
							Type string `json:"type"`
						} `json:"password"`
					} `json:"md5"`
				} `json:"auth"`
			} `json:"neighbor"`
			MulticastHellos string `json:"multicast-hellos"`
			ExplicitNull    string `json:"explicit-null"`
			ImportBgpRoutes string `json:"import-bgp-routes"`
			AdvertiseLabels struct {
				ForAcl map[string]struct {
					To struct {
						Any string `json:"any"`
					} `json:"to"`
				} `json:"for-acl"`
				For struct {
					PeerAcl map[string]struct {
						To struct {
							PeerAcl string `json:"peer-acl"`
							Any     string `json:"any"`
						} `json:"to"`
					} `json:"peer-acl"`
					Any struct {
						To struct {
							None string `json:"none"`
						} `json:"to"`
					} `json:"any"`
				} `json:"for"`
			} `json:"advertise-labels"`
			KeepaliveTimeout string `json:"keepalive-timeout"`
			PropagateRelease string `json:"propagate-release"`
			TransportAddress struct {
				Ipv4 map[string]struct {
					Labelspace string `json:"labelspace"`
				} `json:"ipv4"`
				Ipv6 map[string]struct {
					Labelspace string `json:"labelspace"`
				} `json:".ipv6"`
			} `json:"transport-address"`
			RouterId    string `json:"router-id"`
			ControlMode struct {
				Independent string `json:"independent"`
				Ordered     string `json:"ordered"`
			} `json:"control-mode"`
			LabelRetentionMode struct {
				Liberal      string `json:"liberal"`
				Conservative string `json:"conservative"`
			} `json:"label-retention-mode"`
			RequestRetryTimeout string `json:"request-retry-timeout"`
			GracefulRestart     struct {
				Enable  string `json:"enable"`
				Disable string `json:"disable"`
				Timers  struct {
					MaxRecovery      string `json:"max-recovery"`
					NeighborLiveness string `json:"neighbor-liveness"`
				} `json:"timers"`
			} `json:"graceful-restart"`
			TargetedPeerHoldTime      string `json:"targeted-peer-hold-time"`
			LoopDetectionPathVecCount string `json:"loop-detection-path-vec-count"`
			HoldTime                  string `json:"hold-time"`
			RequestRetry              string `json:"request-retry"`
			LoopDetection             string `json:"loop-detection"`
			TargetedPeer              struct {
				Ipv4 map[string]struct {
				} `json:"ipv4"`
				Ipv6 string `json:".ipv6"`
			} `json:"targeted-peer"`
			GlobalMergeCapability struct {
				NonMergeCapable string `json:"non-merge-capable"`
				MergeCapable    string `json:"merge-capable"`
			} `json:"global-merge-capability"`
			KeepaliveInterval string `json:"keepalive-interval"`
			AdvertisementMode struct {
				DownstreamOnDemand    string `json:"downstream-on-demand"`
				DownstreamUnsolicited string `json:"downstream-unsolicited"`
			} `json:"advertisement-mode"`
			LoopDetectionHopCount string `json:"loop-detection-hop-count"`
			HelloInterval         string `json:"hello-interval"`
			PwStatusTlv           string `json:"pw-status-tlv"`
		} `json:"ldp"`
		IgmpProxy struct {
			Disable   string `json:"disable"`
			Interface map[string]struct {
				Whitelist string `json:"whitelist"`
				Role      string `json:"role"`
				AltSubnet string `json:"alt-subnet"`
				Threshold string `json:"threshold"`
			} `json:"interface"`
			DisableQuickleave string `json:"disable-quickleave"`
		} `json:"igmp-proxy"`
		Bgp map[string]struct {
			Neighbor map[string]struct {
				Weight        string `json:"weight"`
				NoActivate    string `json:"no-activate"`
				EbgpMultihop  string `json:"ebgp-multihop"`
				Password      string `json:"password"`
				MaximumPrefix string `json:"maximum-prefix"`
				FilterList    struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"filter-list"`
				AllowasIn struct {
					Number string `json:"number"`
				} `json:"allowas-in"`
				RouteReflectorClient  string `json:"route-reflector-client"`
				OverrideCapability    string `json:"override-capability"`
				Shutdown              string `json:"shutdown"`
				StrictCapabilityMatch string `json:"strict-capability-match"`
				DisableSendCommunity  struct {
					Standard string `json:"standard"`
					Extended string `json:"extended"`
				} `json:"disable-send-community"`
				Timers struct {
					Holdtime  string `json:"holdtime"`
					Keepalive string `json:"keepalive"`
					Connect   string `json:"connect"`
				} `json:"timers"`
				DefaultOriginate struct {
					RouteMap string `json:"route-map"`
				} `json:"default-originate"`
				RouteServerClient string `json:"route-server-client"`
				Capability        struct {
					Dynamic string `json:"dynamic"`
					Orf     struct {
						PrefixList struct {
							Both    string `json:"both"`
							Receive string `json:"receive"`
							Send    string `json:"send"`
						} `json:"prefix-list"`
					} `json:"orf"`
					GracefulRestart string `json:"graceful-restart"`
				} `json:"capability"`
				UpdateSource string `json:"update-source"`
				TtlSecurity  struct {
					Hops string `json:"hops"`
				} `json:"ttl-security"`
				UnsuppressMap string `json:"unsuppress-map"`
				FallOver      struct {
					Bfd struct {
						Multihop string `json:"multihop"`
					} `json:"bfd"`
				} `json:"fall-over"`
				Passive       string `json:"passive"`
				AddressFamily struct {
					Ipv6Unicast struct {
						MaximumPrefix string `json:"maximum-prefix"`
						FilterList    struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"filter-list"`
						AllowasIn struct {
							Number string `json:"number"`
						} `json:"allowas-in"`
						RouteReflectorClient string `json:"route-reflector-client"`
						NexthopLocal         struct {
							Unchanged string `json:"unchanged"`
						} `json:"nexthop-local"`
						DisableSendCommunity struct {
							Standard string `json:"standard"`
							Extended string `json:"extended"`
						} `json:"disable-send-community"`
						DefaultOriginate struct {
							RouteMap string `json:"route-map"`
						} `json:"default-originate"`
						RouteServerClient string `json:"route-server-client"`
						Capability        struct {
							Orf struct {
								PrefixList struct {
									Receive string `json:"receive"`
									Send    string `json:"send"`
								} `json:"prefix-list"`
							} `json:"orf"`
							GracefulRestart string `json:"graceful-restart"`
						} `json:"capability"`
						UnsuppressMap       string `json:"unsuppress-map"`
						SoftReconfiguration struct {
							Inbound string `json:"inbound"`
						} `json:"soft-reconfiguration"`
						AttributeUnchanged struct {
							AsPath  string `json:"as-path"`
							NextHop string `json:"next-hop"`
							Med     string `json:"med"`
						} `json:"attribute-unchanged"`
						RouteMap struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"route-map"`
						NexthopSelf     string `json:"nexthop-self"`
						RemovePrivateAs string `json:"remove-private-as"`
						PrefixList      struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"prefix-list"`
						DistributeList struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"distribute-list"`
						PeerGroup string `json:"peer-group"`
					} `json:"ipv6-unicast"`
				} `json:"address-family"`
				Description         string `json:"description"`
				SoftReconfiguration struct {
					Inbound string `json:"inbound"`
				} `json:"soft-reconfiguration"`
				LocalAs map[string]struct {
					NoPrepend string `json:"no-prepend"`
				} `json:"local-as"`
				AttributeUnchanged struct {
					AsPath  string `json:"as-path"`
					NextHop string `json:"next-hop"`
					Med     string `json:"med"`
				} `json:"attribute-unchanged"`
				RouteMap struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"route-map"`
				RemoteAs                     string `json:"remote-as"`
				NexthopSelf                  string `json:"nexthop-self"`
				DisableConnectedCheck        string `json:"disable-connected-check"`
				DisableCapabilityNegotiation string `json:"disable-capability-negotiation"`
				Port                         string `json:"port"`
				AdvertisementInterval        string `json:"advertisement-interval"`
				RemovePrivateAs              string `json:"remove-private-as"`
				PrefixList                   struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"prefix-list"`
				DistributeList struct {
					Word map[string]struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"word"`
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"distribute-list"`
				PeerGroup string `json:"peer-group"`
			} `json:"neighbor"`
			Timers struct {
				Holdtime  string `json:"holdtime"`
				Keepalive string `json:"keepalive"`
			} `json:"timers"`
			MaximumPaths struct {
				Ibgp string `json:"ibgp"`
				Ebgp string `json:"ebgp"`
			} `json:"maximum-paths"`
			Network map[string]struct {
				Backdoor string `json:"backdoor"`
				RouteMap string `json:"route-map"`
			} `json:"network"`
			AggregateAddress map[string]struct {
				SummaryOnly string `json:"summary-only"`
				AsSet       string `json:"as-set"`
			} `json:"aggregate-address"`
			AddressFamily struct {
				L2vpn struct {
					Vpls struct {
						Neighbor struct {
							Ipv4 map[string]struct {
								Activate string `json:"activate"`
							} `json:"ipv4"`
							Ipv6 map[string]struct {
								Activate string `json:"activate"`
							} `json:"ipv6"`
							Tag map[string]struct {
								Activate string `json:"activate"`
							} `json:"tag"`
						} `json:"neighbor"`
					} `json:"vpls"`
				} `json:"l2vpn"`
				Ipv4Unicast struct {
					Vrf map[string]struct {
						Neighbor map[string]struct {
							Weight        string `json:"weight"`
							EbgpMultihop  string `json:"ebgp-multihop"`
							MaximumPrefix string `json:"maximum-prefix"`
							FilterList    struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"filter-list"`
							AllowasIn struct {
								Number string `json:"number"`
							} `json:"allowas-in"`
							RouteReflectorClient string `json:"route-reflector-client"`
							Shutdown             string `json:"shutdown"`
							Timers               struct {
								Holdtime  string `json:"holdtime"`
								Keepalive string `json:"keepalive"`
								Connect   string `json:"connect"`
							} `json:"timers"`
							DefaultOriginate struct {
								RouteMap string `json:"route-map"`
							} `json:"default-originate"`
							Capability struct {
								Dynamic string `json:"dynamic"`
								Orf     struct {
									PrefixList struct {
										Both    string `json:"both"`
										Receive string `json:"receive"`
										Send    string `json:"send"`
									} `json:"prefix-list"`
								} `json:"orf"`
								GracefulRestart string `json:"graceful-restart"`
							} `json:"capability"`
							UpdateSource        string `json:"update-source"`
							UnsuppressMap       string `json:"unsuppress-map"`
							Passive             string `json:"passive"`
							Description         string `json:"description"`
							SoftReconfiguration struct {
								Inbound string `json:"inbound"`
							} `json:"soft-reconfiguration"`
							LocalAs map[string]struct {
								NoPrepend string `json:"no-prepend"`
							} `json:"local-as"`
							AttributeUnchanged struct {
								AsPath  string `json:"as-path"`
								NextHop string `json:"next-hop"`
								Med     string `json:"med"`
							} `json:"attribute-unchanged"`
							RouteMap struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"route-map"`
							RemoteAs              string `json:"remote-as"`
							Activate              string `json:"activate"`
							Port                  string `json:"port"`
							AdvertisementInterval string `json:"advertisement-interval"`
							RemovePrivateAs       string `json:"remove-private-as"`
							PrefixList            struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"prefix-list"`
							DistributeList struct {
								Word map[string]struct {
									Out string `json:"out"`
									In  string `json:"in"`
								} `json:"word"`
							} `json:"distribute-list"`
							PeerGroup string `json:"peer-group"`
						} `json:"neighbor"`
						Network map[string]struct {
							RouteMap string `json:"route-map"`
						} `json:"network"`
						Parameters struct {
							Dampening struct {
								MaxSuppressTime   string `json:"max-suppress-time"`
								StartSuppressTime string `json:"start-suppress-time"`
								ReUse             string `json:"re-use"`
								HalfLife          string `json:"half-life"`
							} `json:"dampening"`
							Confederation struct {
								Identifier string `json:"identifier"`
								Peers      string `json:"peers"`
							} `json:"confederation"`
						} `json:"parameters"`
						Redistribute struct {
							Rip struct {
								RouteMap string `json:"route-map"`
								Metric   string `json:"metric"`
							} `json:"rip"`
							Connected struct {
								RouteMap string `json:"route-map"`
								Metric   string `json:"metric"`
							} `json:"connected"`
							Static struct {
								RouteMap string `json:"route-map"`
								Metric   string `json:"metric"`
							} `json:"static"`
							Kernel struct {
								RouteMap string `json:"route-map"`
								Metric   string `json:"metric"`
							} `json:"kernel"`
							Ospf struct {
								RouteMap string `json:"route-map"`
								Metric   string `json:"metric"`
							} `json:"ospf"`
						} `json:"redistribute"`
						PeerGroup map[string]struct {
							Weight        string `json:"weight"`
							EbgpMultihop  string `json:"ebgp-multihop"`
							MaximumPrefix string `json:"maximum-prefix"`
							FilterList    struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"filter-list"`
							AllowasIn struct {
								Number string `json:"number"`
							} `json:"allowas-in"`
							RouteReflectorClient string `json:"route-reflector-client"`
							OverrideCapability   string `json:"override-capability"`
							Shutdown             string `json:"shutdown"`
							DisableSendCommunity struct {
								Standard string `json:"standard"`
								Extended string `json:"extended"`
							} `json:"disable-send-community"`
							DefaultOriginate struct {
								RouteMap string `json:"route-map"`
							} `json:"default-originate"`
							Capability struct {
								Dynamic string `json:"dynamic"`
								Orf     struct {
									PrefixList struct {
										Receive string `json:"receive"`
										Send    string `json:"send"`
									} `json:"prefix-list"`
								} `json:"orf"`
							} `json:"capability"`
							UpdateSource  string `json:"update-source"`
							UnsuppressMap string `json:"unsuppress-map"`
							Passive       string `json:"passive"`
							Timers        struct {
								Holdtime  string `json:"holdtime"`
								Keepalive string `json:"keepalive"`
							} `json:".timers"`
							Description         string `json:"description"`
							SoftReconfiguration struct {
								Inbound string `json:"inbound"`
							} `json:"soft-reconfiguration"`
							LocalAs map[string]struct {
								NoPrepend string `json:"no-prepend"`
							} `json:"local-as"`
							AttributeUnchanged struct {
								AsPath  string `json:"as-path"`
								NextHop string `json:"next-hop"`
								Med     string `json:"med"`
							} `json:"attribute-unchanged"`
							RouteMap struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"route-map"`
							RemoteAs                     string `json:"remote-as"`
							DisableConnectedCheck        string `json:"disable-connected-check"`
							DisableCapabilityNegotiation string `json:"disable-capability-negotiation"`
							RemovePrivateAs              string `json:"remove-private-as"`
							PrefixList                   struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"prefix-list"`
							DistributeList struct {
								Export string `json:"export"`
								Import string `json:"import"`
							} `json:"distribute-list"`
						} `json:"peer-group"`
					} `json:"vrf"`
				} `json:".ipv4-unicast"`
				Ipv6Unicast struct {
					Network map[string]struct {
						RouteMap  string `json:"route-map"`
						PathLimit string `json:"path-limit"`
					} `json:"network"`
					AggregateAddress map[string]struct {
						SummaryOnly string `json:"summary-only"`
					} `json:"aggregate-address"`
					Redistribute struct {
						Connected struct {
							RouteMap string `json:"route-map"`
							Metric   string `json:"metric"`
						} `json:"connected"`
						Ripng struct {
							RouteMap string `json:"route-map"`
							Metric   string `json:"metric"`
						} `json:"ripng"`
						Static struct {
							RouteMap string `json:"route-map"`
							Metric   string `json:"metric"`
						} `json:"static"`
						Ospfv3 struct {
							RouteMap string `json:"route-map"`
							Metric   string `json:"metric"`
						} `json:"ospfv3"`
						Kernel struct {
							RouteMap string `json:"route-map"`
							Metric   string `json:"metric"`
						} `json:"kernel"`
					} `json:"redistribute"`
				} `json:"ipv6-unicast"`
			} `json:"address-family"`
			Dampening struct {
				RouteMap string `json:"route-map"`
				HalfLife map[string]struct {
					ReuseRoute map[string]struct {
						SupRoute map[string]struct {
							Time map[string]struct {
								HalfTime string `json:"half-time"`
							} `json:"time"`
						} `json:"sup-route"`
					} `json:"reuse-route"`
				} `json:"half-life"`
			} `json:"dampening"`
			Parameters struct {
				ClusterId                  string `json:"cluster-id"`
				DisableNetworkImportCheck  string `json:"disable-network-import-check"`
				NoClientToClientReflection string `json:"no-client-to-client-reflection"`
				EnforceFirstAs             string `json:"enforce-first-as"`
				RouterId                   string `json:"router-id"`
				Distance                   struct {
					Prefix map[string]struct {
						Distance string `json:"distance"`
					} `json:"prefix"`
					Global struct {
						Internal string `json:"internal"`
						Local    string `json:"local"`
						External string `json:"external"`
					} `json:"global"`
				} `json:"distance"`
				Default struct {
					NoIpv4Unicast string `json:"no-ipv4-unicast"`
					LocalPref     string `json:"local-pref"`
				} `json:"default"`
				AlwaysCompareMed string `json:"always-compare-med"`
				GracefulRestart  struct {
					StalepathTime string `json:"stalepath-time"`
				} `json:"graceful-restart"`
				Dampening struct {
					MaxSuppressTime   string `json:"max-suppress-time"`
					StartSuppressTime string `json:"start-suppress-time"`
					ReUse             string `json:"re-use"`
					HalfLife          string `json:"half-life"`
				} `json:"dampening"`
				DeterministicMed string `json:"deterministic-med"`
				Bestpath         struct {
					AsPath struct {
						Confed string `json:"confed"`
						Ignore string `json:"ignore"`
					} `json:"as-path"`
					CompareRouterid string `json:"compare-routerid"`
					Med             struct {
						Confed         string `json:"confed"`
						MissingAsWorst string `json:"missing-as-worst"`
					} `json:"med"`
				} `json:"bestpath"`
				LogNeighborChanges string `json:"log-neighbor-changes"`
				ScanTime           string `json:"scan-time"`
				Confederation      struct {
					Identifier string `json:"identifier"`
					Peers      string `json:"peers"`
				} `json:"confederation"`
				NoFastExternalFailover string `json:"no-fast-external-failover"`
			} `json:"parameters"`
			Redistribute struct {
				Rip struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"rip"`
				Connected struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"connected"`
				Static struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"static"`
				Kernel struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"kernel"`
				Ospf struct {
					RouteMap string `json:"route-map"`
					Metric   string `json:"metric"`
				} `json:"ospf"`
			} `json:"redistribute"`
			PeerGroup map[string]struct {
				Weight        string `json:"weight"`
				EbgpMultihop  string `json:"ebgp-multihop"`
				Password      string `json:"password"`
				MaximumPrefix string `json:"maximum-prefix"`
				FilterList    struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"filter-list"`
				AllowasIn struct {
					Number string `json:"number"`
				} `json:"allowas-in"`
				RouteReflectorClient string `json:"route-reflector-client"`
				OverrideCapability   string `json:"override-capability"`
				Shutdown             string `json:"shutdown"`
				DisableSendCommunity struct {
					Standard string `json:"standard"`
					Extended string `json:"extended"`
				} `json:"disable-send-community"`
				DefaultOriginate struct {
					RouteMap string `json:"route-map"`
				} `json:"default-originate"`
				RouteServerClient string `json:"route-server-client"`
				Capability        struct {
					Dynamic string `json:"dynamic"`
					Orf     struct {
						PrefixList struct {
							Receive string `json:"receive"`
							Send    string `json:"send"`
						} `json:"prefix-list"`
					} `json:"orf"`
					GracefulRestart string `json:"graceful-restart"`
				} `json:"capability"`
				UpdateSource string `json:"update-source"`
				TtlSecurity  struct {
					Hops string `json:"hops"`
				} `json:"ttl-security"`
				UnsuppressMap string `json:"unsuppress-map"`
				Passive       string `json:"passive"`
				Timers        struct {
					Holdtime  string `json:"holdtime"`
					Keepalive string `json:"keepalive"`
				} `json:".timers"`
				AddressFamily struct {
					Ipv6Unicast struct {
						MaximumPrefix string `json:"maximum-prefix"`
						FilterList    struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"filter-list"`
						AllowasIn struct {
							Number string `json:"number"`
						} `json:"allowas-in"`
						RouteReflectorClient string `json:"route-reflector-client"`
						NexthopLocal         struct {
							Unchanged string `json:"unchanged"`
						} `json:"nexthop-local"`
						DisableSendCommunity struct {
							Standard string `json:"standard"`
							Extended string `json:"extended"`
						} `json:"disable-send-community"`
						DefaultOriginate struct {
							RouteMap string `json:"route-map"`
						} `json:"default-originate"`
						RouteServerClient string `json:"route-server-client"`
						Capability        struct {
							Orf struct {
								PrefixList struct {
									Receive string `json:"receive"`
									Send    string `json:"send"`
								} `json:"prefix-list"`
							} `json:"orf"`
							GracefulRestart string `json:"graceful-restart"`
						} `json:"capability"`
						UnsuppressMap       string `json:"unsuppress-map"`
						SoftReconfiguration struct {
							Inbound string `json:"inbound"`
						} `json:"soft-reconfiguration"`
						AttributeUnchanged struct {
							AsPath  string `json:"as-path"`
							NextHop string `json:"next-hop"`
							Med     string `json:"med"`
						} `json:"attribute-unchanged"`
						RouteMap struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"route-map"`
						NexthopSelf     string `json:"nexthop-self"`
						RemovePrivateAs string `json:"remove-private-as"`
						PrefixList      struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"prefix-list"`
						DistributeList struct {
							Export string `json:"export"`
							Import string `json:"import"`
						} `json:"distribute-list"`
					} `json:"ipv6-unicast"`
				} `json:"address-family"`
				Description         string `json:"description"`
				SoftReconfiguration struct {
					Inbound string `json:"inbound"`
				} `json:"soft-reconfiguration"`
				LocalAs map[string]struct {
					NoPrepend string `json:"no-prepend"`
				} `json:"local-as"`
				AttributeUnchanged struct {
					AsPath  string `json:"as-path"`
					NextHop string `json:"next-hop"`
					Med     string `json:"med"`
				} `json:"attribute-unchanged"`
				RouteMap struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"route-map"`
				RemoteAs                     string `json:"remote-as"`
				NexthopSelf                  string `json:"nexthop-self"`
				DisableConnectedCheck        string `json:"disable-connected-check"`
				DisableCapabilityNegotiation string `json:"disable-capability-negotiation"`
				RemovePrivateAs              string `json:"remove-private-as"`
				PrefixList                   struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"prefix-list"`
				DistributeList struct {
					Export string `json:"export"`
					Import string `json:"import"`
				} `json:"distribute-list"`
			} `json:"peer-group"`
		} `json:"bgp"`
		Ospfv3 struct {
			Bfd struct {
				Interface     string `json:"interface"`
				AllInterfaces string `json:"all-interfaces"`
			} `json:"bfd"`
			Area map[string]struct {
				ExportList string `json:"export-list"`
				Interface  string `json:"interface"`
				FilterList map[string]struct {
				} `json:".filter-list"`
				ImportList string `json:"import-list"`
				AreaType   struct {
					Stub struct {
						DefaultCost string `json:"default-cost"`
						NoSummary   string `json:"no-summary"`
					} `json:"stub"`
					Normal string `json:"normal"`
					Nssa   struct {
						DefaultCost                 string `json:"default-cost"`
						Translate                   string `json:"translate"`
						NoSummary                   string `json:"no-summary"`
						StabilityInterval           string `json:"stability-interval"`
						DefaultInformationOriginate struct {
							RouteMap string `json:"route-map"`
							Metric   map[string]struct {
								Type string `json:"type"`
							} `json:"metric"`
						} `json:"default-information-originate"`
						NoRedistribution string `json:"no-redistribution"`
					} `json:"nssa"`
				} `json:"area-type"`
				VirtualLink map[string]struct {
					Bfd string `json:"bfd"`
				} `json:"virtual-link"`
				Range map[string]struct {
					NotAdvertise string `json:"not-advertise"`
				} `json:"range"`
			} `json:"area"`
			Timers struct {
				SfpExpDelay struct {
					Min map[string]struct {
						Max string `json:"max"`
					} `json:"min"`
				} `json:"sfp-exp-delay"`
			} `json:"timers"`
			Capability struct {
				DbSummaryOpt    string `json:"db-summary-opt"`
				Te              string `json:"te"`
				Cspf            string `json:"cspf"`
				GracefulRestart string `json:"graceful-restart"`
			} `json:"capability"`
			DefaultMetric string `json:"default-metric"`
			Distance      struct {
				Global string `json:"global"`
				Ospfv3 struct {
					InterArea string `json:"inter-area"`
					External  string `json:"external"`
					IntraArea string `json:"intra-area"`
				} `json:"ospfv3"`
			} `json:"distance"`
			LogAdjacencyChanges struct {
				Detail string `json:"detail"`
			} `json:"log-adjacency-changes"`
			SummaryAddress string `json:"summary-address"`
			Cspf           struct {
				TieBreak             string `json:"tie-break"`
				DefaultRetryInterval string `json:"default-retry-interval"`
			} `json:"cspf"`
			AutoCost struct {
				ReferenceBandwidth string `json:"reference-bandwidth"`
			} `json:"auto-cost"`
			PassiveInterfaceExclude string `json:"passive-interface-exclude"`
			Vrf                     map[string]struct {
				Bfd struct {
					AllInterfaces string `json:"all-interfaces"`
				} `json:"bfd"`
				Area map[string]struct {
					ExportList string `json:"export-list"`
					Interface  string `json:"interface"`
					FilterList map[string]struct {
					} `json:".filter-list"`
					ImportList  string `json:"import-list"`
					VirtualLink map[string]struct {
						Bfd string `json:"bfd"`
					} `json:"virtual-link"`
					Range map[string]struct {
						Advertise    string `json:"advertise"`
						NotAdvertise string `json:"not-advertise"`
					} `json:"range"`
				} `json:"area"`
				Parameters struct {
					RouterId string `json:"router-id"`
				} `json:"parameters"`
				Redistribute struct {
					Connected struct {
						RouteMap string `json:"route-map"`
					} `json:"connected"`
					Ripng struct {
						RouteMap string `json:"route-map"`
					} `json:"ripng"`
					Static struct {
						RouteMap string `json:"route-map"`
					} `json:"static"`
					Bgp struct {
						RouteMap string `json:"route-map"`
					} `json:"bgp"`
					Kernel struct {
						RouteMap string `json:"route-map"`
					} `json:"kernel"`
				} `json:"redistribute"`
			} `json:".vrf"`
			Parameters struct {
				RouterId string `json:"router-id"`
				AbrType  string `json:"abr-type"`
			} `json:"parameters"`
			PassiveInterface string `json:"passive-interface"`
			MaxConcurrentDd  string `json:"max-concurrent-dd"`
			Redistribute     struct {
				Connected struct {
					RouteMap string `json:"route-map"`
				} `json:"connected"`
				Ripng struct {
					RouteMap string `json:"route-map"`
				} `json:"ripng"`
				Static struct {
					RouteMap string `json:"route-map"`
				} `json:"static"`
				Bgp struct {
					RouteMap string `json:"route-map"`
				} `json:"bgp"`
				Kernel struct {
					RouteMap string `json:"route-map"`
				} `json:"kernel"`
			} `json:"redistribute"`
			DistributeList map[string]struct {
				Out struct {
					Rip       string `json:"rip"`
					Connected string `json:"connected"`
					Static    string `json:"static"`
					Bgp       string `json:"bgp"`
					Kernel    string `json:"kernel"`
					Ospf      string `json:"ospf"`
					Isis      string `json:"isis"`
				} `json:"out"`
				In string `json:"in"`
			} `json:"distribute-list"`
			DefaultInformation struct {
				Originate struct {
					Always     string `json:"always"`
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"originate"`
			} `json:"default-information"`
		} `json:"ospfv3"`
		Ospf struct {
			Neighbor map[string]struct {
				PollInterval string `json:"poll-interval"`
				Priority     string `json:"priority"`
			} `json:"neighbor"`
			Bfd struct {
				Interface     string `json:"interface"`
				AllInterfaces string `json:"all-interfaces"`
			} `json:"bfd"`
			Area map[string]struct {
				Shortcut string `json:"shortcut"`
				Network  string `json:"network"`
				AreaType struct {
					Stub struct {
						DefaultCost string `json:"default-cost"`
						NoSummary   string `json:"no-summary"`
					} `json:"stub"`
					Normal string `json:"normal"`
					Nssa   struct {
						DefaultCost string `json:"default-cost"`
						Translate   string `json:"translate"`
						NoSummary   string `json:"no-summary"`
					} `json:"nssa"`
				} `json:"area-type"`
				VirtualLink map[string]struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Bfd                string `json:"bfd"`
					DeadInterval       string `json:"dead-interval"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"virtual-link"`
				Range map[string]struct {
					Cost         string `json:"cost"`
					Substitute   string `json:"substitute"`
					NotAdvertise string `json:"not-advertise"`
				} `json:"range"`
				Authentication string `json:"authentication"`
			} `json:"area"`
			Refresh struct {
				Timers string `json:"timers"`
			} `json:"refresh"`
			Timers struct {
				Throttle struct {
					Spf struct {
						MaxHoldtime     string `json:"max-holdtime"`
						Delay           string `json:"delay"`
						InitialHoldtime string `json:"initial-holdtime"`
					} `json:"spf"`
				} `json:"throttle"`
			} `json:"timers"`
			DefaultMetric string `json:"default-metric"`
			Distance      struct {
				Global string `json:"global"`
				Ospf   struct {
					InterArea string `json:"inter-area"`
					External  string `json:"external"`
					IntraArea string `json:"intra-area"`
				} `json:"ospf"`
			} `json:"distance"`
			LogAdjacencyChanges struct {
				Detail string `json:"detail"`
			} `json:"log-adjacency-changes"`
			MplsTe struct {
				Enable        string `json:"enable"`
				RouterAddress string `json:"router-address"`
			} `json:"mpls-te"`
			AutoCost struct {
				ReferenceBandwidth string `json:"reference-bandwidth"`
			} `json:"auto-cost"`
			PassiveInterfaceExclude string `json:"passive-interface-exclude"`
			AccessList              map[string]struct {
				Export string `json:"export"`
				Import string `json:"import"`
			} `json:"access-list"`
			InstanceId map[string]struct {
				Vrf map[string]struct {
					Neighbor map[string]struct {
						PollInterval string `json:"poll-interval"`
						Priority     string `json:"priority"`
					} `json:"neighbor"`
					Bfd struct {
						AllInterfaces string `json:"all-interfaces"`
					} `json:"bfd"`
					Area map[string]struct {
						Shortcut string `json:"shortcut"`
						Network  string `json:"network"`
						AreaType struct {
							Stub struct {
								DefaultCost string `json:"default-cost"`
								NoSummary   string `json:"no-summary"`
							} `json:"stub"`
							Normal string `json:"normal"`
							Nssa   struct {
								DefaultCost string `json:"default-cost"`
								Translate   string `json:"translate"`
								NoSummary   string `json:"no-summary"`
							} `json:"nssa"`
						} `json:"area-type"`
						VirtualLink map[string]struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Bfd                string `json:"bfd"`
							DeadInterval       string `json:"dead-interval"`
							Authentication     struct {
								Md5 struct {
									KeyId map[string]struct {
										Md5Key string `json:"md5-key"`
									} `json:"key-id"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
							HelloInterval string `json:"hello-interval"`
						} `json:"virtual-link"`
						Range map[string]struct {
							Cost         string `json:"cost"`
							Substitute   string `json:"substitute"`
							NotAdvertise string `json:"not-advertise"`
						} `json:"range"`
						Authentication string `json:"authentication"`
					} `json:"area"`
					Refresh struct {
						Timers string `json:"timers"`
					} `json:"refresh"`
					Timers struct {
						Throttle struct {
							Spf struct {
								MaxHoldtime     string `json:"max-holdtime"`
								Delay           string `json:"delay"`
								InitialHoldtime string `json:"initial-holdtime"`
							} `json:"spf"`
						} `json:"throttle"`
					} `json:"timers"`
					Capability struct {
						Cspf struct {
							EnableBetterProtection string `json:"enable-better-protection"`
							TieBreak               struct {
								MostFill  string `json:"most-fill"`
								LeastFill string `json:"least-fill"`
								Random    string `json:"random"`
							} `json:"tie-break"`
							DisableBetterProtection string `json:"disable-better-protection"`
							DefaultRetryInterval    string `json:"default-retry-interval"`
						} `json:"cspf"`
						TrafficEngineering string `json:"traffic-engineering"`
					} `json:"capability"`
					DefaultMetric string `json:"default-metric"`
					Distance      struct {
						Global string `json:"global"`
						Ospf   struct {
							InterArea string `json:"inter-area"`
							External  string `json:"external"`
							IntraArea string `json:"intra-area"`
						} `json:"ospf"`
					} `json:"distance"`
					LogAdjacencyChanges struct {
						Detail string `json:"detail"`
					} `json:"log-adjacency-changes"`
					MplsTe struct {
						Enable        string `json:"enable"`
						RouterAddress string `json:"router-address"`
					} `json:"mpls-te"`
					AutoCost struct {
						ReferenceBandwidth string `json:"reference-bandwidth"`
					} `json:"auto-cost"`
					PassiveInterfaceExclude string `json:"passive-interface-exclude"`
					AccessList              map[string]struct {
						Export string `json:"export"`
					} `json:"access-list"`
					Parameters struct {
						Rfc1583Compatibility string `json:"rfc1583-compatibility"`
						RouterId             string `json:"router-id"`
						AbrType              string `json:"abr-type"`
						OpaqueLsa            string `json:"opaque-lsa"`
					} `json:"parameters"`
					PassiveInterface string `json:"passive-interface"`
					Redistribute     struct {
						Rip struct {
							RouteMap   string `json:"route-map"`
							MetricType string `json:"metric-type"`
							Metric     string `json:"metric"`
						} `json:"rip"`
						Connected struct {
							RouteMap   string `json:"route-map"`
							MetricType string `json:"metric-type"`
							Metric     string `json:"metric"`
						} `json:"connected"`
						Static struct {
							RouteMap   string `json:"route-map"`
							MetricType string `json:"metric-type"`
							Metric     string `json:"metric"`
						} `json:"static"`
						Bgp struct {
							RouteMap   string `json:"route-map"`
							MetricType string `json:"metric-type"`
							Metric     string `json:"metric"`
						} `json:"bgp"`
						Kernel struct {
							RouteMap   string `json:"route-map"`
							MetricType string `json:"metric-type"`
							Metric     string `json:"metric"`
						} `json:"kernel"`
					} `json:"redistribute"`
					MaxMetric struct {
						RouterLsa struct {
							OnStartup      string `json:"on-startup"`
							Administrative string `json:"administrative"`
							OnShutdown     string `json:"on-shutdown"`
						} `json:"router-lsa"`
					} `json:"max-metric"`
					DefaultInformation struct {
						Originate struct {
							Always     string `json:"always"`
							RouteMap   string `json:"route-map"`
							MetricType string `json:"metric-type"`
							Metric     string `json:"metric"`
						} `json:"originate"`
					} `json:"default-information"`
				} `json:"vrf"`
			} `json:".instance-id"`
			Parameters struct {
				Rfc1583Compatibility string `json:"rfc1583-compatibility"`
				RouterId             string `json:"router-id"`
				AbrType              string `json:"abr-type"`
				OpaqueLsa            string `json:"opaque-lsa"`
			} `json:"parameters"`
			PassiveInterface string `json:"passive-interface"`
			Redistribute     struct {
				Rip struct {
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"rip"`
				Connected struct {
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"connected"`
				Static struct {
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"static"`
				Bgp struct {
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"bgp"`
				Kernel struct {
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"kernel"`
			} `json:"redistribute"`
			MaxMetric struct {
				RouterLsa struct {
					OnStartup      string `json:"on-startup"`
					Administrative string `json:"administrative"`
					OnShutdown     string `json:"on-shutdown"`
				} `json:"router-lsa"`
			} `json:"max-metric"`
			DefaultInformation struct {
				Originate struct {
					Always     string `json:"always"`
					RouteMap   string `json:"route-map"`
					MetricType string `json:"metric-type"`
					Metric     string `json:"metric"`
				} `json:"originate"`
			} `json:"default-information"`
		} `json:"ospf"`
	} `json:"protocols"`
	Policy struct {
		AsPathList map[string]struct {
			Rule map[string]struct {
				Regex       string `json:"regex"`
				Action      string `json:"action"`
				Description string `json:"description"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"as-path-list"`
		AccessList map[string]struct {
			Rule map[string]struct {
				Source struct {
					Host        string `json:"host"`
					Network     string `json:"network"`
					Any         string `json:"any"`
					InverseMask string `json:"inverse-mask"`
				} `json:"source"`
				Destination struct {
					Host        string `json:"host"`
					Network     string `json:"network"`
					Any         string `json:"any"`
					InverseMask string `json:"inverse-mask"`
				} `json:"destination"`
				Action      string `json:"action"`
				Description string `json:"description"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"access-list"`
		RouteMap map[string]struct {
			Rule map[string]struct {
				Match struct {
					AsPath       string `json:"as-path"`
					Interface    string `json:"interface"`
					Extcommunity struct {
						ExactMatch       string `json:"exact-match"`
						ExtcommunityList string `json:"extcommunity-list"`
					} `json:"extcommunity"`
					Peer      string `json:"peer"`
					Origin    string `json:"origin"`
					Community struct {
						ExactMatch    string `json:"exact-match"`
						CommunityList string `json:"community-list"`
					} `json:"community"`
					Ip struct {
						RouteSource struct {
							AccessList string `json:"access-list"`
							PrefixList string `json:"prefix-list"`
						} `json:"route-source"`
						Nexthop struct {
							AccessList string `json:"access-list"`
							PrefixList string `json:"prefix-list"`
						} `json:"nexthop"`
						Address struct {
							AccessList string `json:"access-list"`
							PrefixList string `json:"prefix-list"`
						} `json:"address"`
					} `json:"ip"`
					Metric string `json:"metric"`
					Ipv6   struct {
						Nexthop struct {
							AccessList string `json:"access-list"`
							PrefixList string `json:"prefix-list"`
						} `json:"nexthop"`
						Address struct {
							AccessList string `json:"access-list"`
							PrefixList string `json:"prefix-list"`
						} `json:"address"`
					} `json:"ipv6"`
					Tag string `json:"tag"`
				} `json:"match"`
				OnMatch struct {
					Next string `json:"next"`
					Goto string `json:"goto"`
				} `json:"on-match"`
				Action      string `json:"action"`
				Call        string `json:"call"`
				Description string `json:"description"`
				Set         struct {
					Weight        string `json:"weight"`
					AsPathPrepend string `json:"as-path-prepend"`
					Ipv6NextHop   struct {
						Local  string `json:"local"`
						Global string `json:"global"`
					} `json:"ipv6-next-hop"`
					CommList struct {
						CommList string `json:"comm-list"`
						Delete   string `json:"delete"`
					} `json:"comm-list"`
					OriginatorId string `json:"originator-id"`
					Extcommunity struct {
						Rt string `json:"rt"`
						Ro string `json:"ro"`
					} `json:"extcommunity"`
					Aggregator struct {
						As string `json:"as"`
						Ip string `json:"ip"`
					} `json:"aggregator"`
					AtomicAggregate string `json:"atomic-aggregate"`
					LocalPreference string `json:"local-preference"`
					MetricType      string `json:"metric-type"`
					Origin          string `json:"origin"`
					Community       string `json:"community"`
					Metric          string `json:"metric"`
					IpNextHop       string `json:"ip-next-hop"`
					Tag             string `json:"tag"`
				} `json:"set"`
				Continue string `json:"continue"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"route-map"`
		AccessList6 map[string]struct {
			Rule map[string]struct {
				Source struct {
					Network    string `json:"network"`
					Any        string `json:"any"`
					ExactMatch string `json:"exact-match"`
				} `json:"source"`
				Action      string `json:"action"`
				Description string `json:"description"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"access-list6"`
		PrefixList6 map[string]struct {
			Rule map[string]struct {
				Prefix      string `json:"prefix"`
				Le          string `json:"le"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Ge          string `json:"ge"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"prefix-list6"`
		CommunityList map[string]struct {
			Rule map[string]struct {
				Regex       string `json:"regex"`
				Action      string `json:"action"`
				Description string `json:"description"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"community-list"`
		ExtcommunityList map[string]struct {
			Rule map[string]struct {
				Rt          string `json:"rt"`
				Regex       string `json:"regex"`
				Ro          string `json:"ro"`
				Action      string `json:"action"`
				Description string `json:"description"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"extcommunity-list"`
		PrefixList map[string]struct {
			Rule map[string]struct {
				Prefix      string `json:"prefix"`
				Le          string `json:"le"`
				Action      string `json:"action"`
				Description string `json:"description"`
				Ge          string `json:"ge"`
			} `json:"rule"`
			Description string `json:"description"`
		} `json:"prefix-list"`
	} `json:"policy"`
	Interfaces struct {
		Wirelessmodem map[string]struct {
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Ondemand      string `json:"ondemand"`
			Mtu           string `json:"mtu"`
			Network       string `json:"network"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			NoDns             string `json:"no-dns"`
			DisableLinkDetect string `json:"disable-link-detect"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Description string `json:"description"`
			Redirect    string `json:"redirect"`
			Device      string `json:"device"`
			Backup      struct {
				Distance string `json:"distance"`
			} `json:"backup"`
			Ip struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"wirelessmodem"`
		Ipv6Tunnel map[string]struct {
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Encapsulation string `json:"encapsulation"`
			Multicast     string `json:"multicast"`
			Ttl           string `json:"ttl"`
			Mtu           string `json:"mtu"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Key               string `json:"key"`
			DisableLinkDetect string `json:"disable-link-detect"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Tos         string `json:"tos"`
			Description string `json:"description"`
			Address     string `json:"address"`
			Redirect    string `json:"redirect"`
			LocalIp     string `json:"local-ip"`
			RemoteIp    string `json:"remote-ip"`
			Ip          struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				Ripng struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"ipv6-tunnel"`
		Bonding map[string]struct {
			BridgeGroup struct {
				Bridge   string `json:"bridge"`
				Cost     string `json:"cost"`
				Priority string `json:"priority"`
			} `json:"bridge-group"`
			HashPolicy string `json:"hash-policy"`
			Disable    string `json:"disable"`
			Bandwidth  struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Mode          string `json:"mode"`
			Mtu           string `json:"mtu"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Vrrp struct {
				VrrpGroup map[string]struct {
					Disable              string `json:"disable"`
					VirtualAddress       string `json:"virtual-address"`
					AdvertiseInterval    string `json:"advertise-interval"`
					SyncGroup            string `json:"sync-group"`
					PreemptDelay         string `json:"preempt-delay"`
					RunTransitionScripts struct {
						Master string `json:"master"`
						Fault  string `json:"fault"`
						Backup string `json:"backup"`
					} `json:"run-transition-scripts"`
					Preempt            string `json:"preempt"`
					Description        string `json:"description"`
					HelloSourceAddress string `json:"hello-source-address"`
					Priority           string `json:"priority"`
					Authentication     struct {
						Password string `json:"password"`
						Type     string `json:"type"`
					} `json:"authentication"`
				} `json:"vrrp-group"`
			} `json:"vrrp"`
			Dhcpv6Pd struct {
				Pd map[string]struct {
					Interface map[string]struct {
						StaticMapping map[string]struct {
							Identifier  string `json:"identifier"`
							HostAddress string `json:"host-address"`
						} `json:"static-mapping"`
						NoDns       string `json:"no-dns"`
						PrefixId    string `json:"prefix-id"`
						HostAddress string `json:"host-address"`
						Service     string `json:"service"`
					} `json:"interface"`
					PrefixLength string `json:"prefix-length"`
				} `json:"pd"`
				Duid        string `json:"duid"`
				NoDns       string `json:"no-dns"`
				RapidCommit string `json:"rapid-commit"`
				PrefixOnly  string `json:"prefix-only"`
			} `json:"dhcpv6-pd"`
			DisableLinkDetect string `json:"disable-link-detect"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Mac         string `json:"mac"`
			DhcpOptions struct {
				NameServer           string `json:"name-server"`
				DefaultRoute         string `json:"default-route"`
				ClientOption         string `json:"client-option"`
				DefaultRouteDistance string `json:"default-route-distance"`
				GlobalOption         string `json:"global-option"`
			} `json:"dhcp-options"`
			Description string `json:"description"`
			Vif         map[string]struct {
				BridgeGroup struct {
					Bridge   string `json:"bridge"`
					Cost     string `json:"cost"`
					Priority string `json:"priority"`
				} `json:"bridge-group"`
				Disable   string `json:"disable"`
				Bandwidth struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Mtu           string `json:"mtu"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				Vrrp struct {
					VrrpGroup map[string]struct {
						Disable              string `json:"disable"`
						VirtualAddress       string `json:"virtual-address"`
						AdvertiseInterval    string `json:"advertise-interval"`
						SyncGroup            string `json:"sync-group"`
						PreemptDelay         string `json:"preempt-delay"`
						RunTransitionScripts struct {
							Master string `json:"master"`
							Fault  string `json:"fault"`
							Backup string `json:"backup"`
						} `json:"run-transition-scripts"`
						Preempt            string `json:"preempt"`
						Description        string `json:"description"`
						HelloSourceAddress string `json:"hello-source-address"`
						Priority           string `json:"priority"`
						Authentication     struct {
							Password string `json:"password"`
							Type     string `json:"type"`
						} `json:"authentication"`
					} `json:"vrrp-group"`
				} `json:"vrrp"`
				Dhcpv6Pd struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				DisableLinkDetect string `json:"disable-link-detect"`
				Firewall          struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				DhcpOptions struct {
					NameServer           string `json:"name-server"`
					DefaultRoute         string `json:"default-route"`
					ClientOption         string `json:"client-option"`
					DefaultRouteDistance string `json:"default-route-distance"`
					GlobalOption         string `json:"global-option"`
				} `json:"dhcp-options"`
				Description   string `json:"description"`
				Address       string `json:"address"`
				Redirect      string `json:"redirect"`
				Dhcpv6Options struct {
					ParametersOnly string `json:"parameters-only"`
					Temporary      string `json:"temporary"`
				} `json:"dhcpv6-options"`
				Ip struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					ProxyArpPvlan    string `json:"proxy-arp-pvlan"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64    string `json:"eui64"`
						Autoconf string `json:"autoconf"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
			} `json:"vif"`
			Address    string `json:"address"`
			Redirect   string `json:"redirect"`
			ArpMonitor struct {
				Target   string `json:"target"`
				Interval string `json:"interval"`
			} `json:"arp-monitor"`
			Dhcpv6Options struct {
				ParametersOnly string `json:"parameters-only"`
				Temporary      string `json:"temporary"`
			} `json:"dhcpv6-options"`
			Ip struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				EnableProxyArp   string `json:"enable-proxy-arp"`
				SourceValidation string `json:"source-validation"`
				ProxyArpPvlan    string `json:"proxy-arp-pvlan"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
			Primary string `json:"primary"`
		} `json:"bonding"`
		L2tpv3 map[string]struct {
			BridgeGroup struct {
				Bridge   string `json:"bridge"`
				Cost     string `json:"cost"`
				Priority string `json:"priority"`
			} `json:"bridge-group"`
			Disable       string `json:"disable"`
			PeerSessionId string `json:"peer-session-id"`
			Bandwidth     struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Encapsulation string `json:"encapsulation"`
			Mtu           string `json:"mtu"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			SourcePort string `json:"source-port"`
			Firewall   struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			PeerTunnelId string `json:"peer-tunnel-id"`
			Description  string `json:"description"`
			Address      string `json:"address"`
			Redirect     string `json:"redirect"`
			LocalIp      string `json:"local-ip"`
			RemoteIp     string `json:"remote-ip"`
			Ip           struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			DestinationPort string `json:"destination-port"`
			Ipv6            struct {
				Ripng struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
			TunnelId  string `json:"tunnel-id"`
			SessionId string `json:"session-id"`
		} `json:"l2tpv3"`
		Vti map[string]struct {
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Mtu           string `json:"mtu"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Firewall struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Description string `json:"description"`
			Address     string `json:"address"`
			Redirect    string `json:"redirect"`
			Ip          struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				Ripng struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"vti"`
		Input map[string]struct {
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Firewall struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Description string `json:"description"`
			Redirect    string `json:"redirect"`
		} `json:"input"`
		Bridge map[string]struct {
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Multicast string `json:"multicast"`
			Pppoe     map[string]struct {
				ServiceName string `json:"service-name"`
				Bandwidth   struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Password      string `json:"password"`
				RemoteAddress string `json:"remote-address"`
				HostUniq      string `json:"host-uniq"`
				Mtu           string `json:"mtu"`
				NameServer    string `json:"name-server"`
				DefaultRoute  string `json:"default-route"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				IdleTimeout string `json:"idle-timeout"`
				Dhcpv6Pd    struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				ConnectOnDemand string `json:"connect-on-demand"`
				Firewall        struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				UserId       string `json:"user-id"`
				Description  string `json:"description"`
				LocalAddress string `json:"local-address"`
				Redirect     string `json:"redirect"`
				Ip           struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					Enable struct {
						RemoteIdentifier string `json:"remote-identifier"`
						LocalIdentifier  string `json:"local-identifier"`
					} `json:"enable"`
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64     string `json:"eui64"`
						Autoconf  string `json:"autoconf"`
						Secondary string `json:"secondary"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
				Multilink          string `json:"multilink"`
				AccessConcentrator string `json:"access-concentrator"`
			} `json:"pppoe"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Vrrp struct {
				VrrpGroup map[string]struct {
					Disable              string `json:"disable"`
					VirtualAddress       string `json:"virtual-address"`
					AdvertiseInterval    string `json:"advertise-interval"`
					SyncGroup            string `json:"sync-group"`
					PreemptDelay         string `json:"preempt-delay"`
					RunTransitionScripts struct {
						Master string `json:"master"`
						Fault  string `json:"fault"`
						Backup string `json:"backup"`
					} `json:"run-transition-scripts"`
					Preempt            string `json:"preempt"`
					Description        string `json:"description"`
					HelloSourceAddress string `json:"hello-source-address"`
					Priority           string `json:"priority"`
					Authentication     struct {
						Password string `json:"password"`
						Type     string `json:"type"`
					} `json:"authentication"`
				} `json:"vrrp-group"`
			} `json:"vrrp"`
			Dhcpv6Pd struct {
				Pd map[string]struct {
					Interface map[string]struct {
						StaticMapping map[string]struct {
							Identifier  string `json:"identifier"`
							HostAddress string `json:"host-address"`
						} `json:"static-mapping"`
						NoDns       string `json:"no-dns"`
						PrefixId    string `json:"prefix-id"`
						HostAddress string `json:"host-address"`
						Service     string `json:"service"`
					} `json:"interface"`
					PrefixLength string `json:"prefix-length"`
				} `json:"pd"`
				Duid        string `json:"duid"`
				NoDns       string `json:"no-dns"`
				RapidCommit string `json:"rapid-commit"`
				PrefixOnly  string `json:"prefix-only"`
			} `json:"dhcpv6-pd"`
			Stp               string `json:"stp"`
			DisableLinkDetect string `json:"disable-link-detect"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			MaxAge           string `json:"max-age"`
			BridgedConntrack string `json:"bridged-conntrack"`
			DhcpOptions      struct {
				NameServer           string `json:"name-server"`
				DefaultRoute         string `json:"default-route"`
				ClientOption         string `json:"client-option"`
				DefaultRouteDistance string `json:"default-route-distance"`
				GlobalOption         string `json:"global-option"`
			} `json:"dhcp-options"`
			HelloTime   string `json:"hello-time"`
			Description string `json:"description"`
			Vif         map[string]struct {
				Disable   string `json:"disable"`
				Bandwidth struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Pppoe map[string]struct {
					ServiceName string `json:"service-name"`
					Bandwidth   struct {
						Maximum    string `json:"maximum"`
						Reservable string `json:"reservable"`
						Constraint struct {
							ClassType map[string]struct {
								Bandwidth string `json:"bandwidth"`
							} `json:"class-type"`
						} `json:"constraint"`
					} `json:"bandwidth"`
					Password      string `json:"password"`
					RemoteAddress string `json:"remote-address"`
					HostUniq      string `json:"host-uniq"`
					Mtu           string `json:"mtu"`
					NameServer    string `json:"name-server"`
					DefaultRoute  string `json:"default-route"`
					TrafficPolicy struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"traffic-policy"`
					IdleTimeout string `json:"idle-timeout"`
					Dhcpv6Pd    struct {
						Pd map[string]struct {
							Interface map[string]struct {
								StaticMapping map[string]struct {
									Identifier  string `json:"identifier"`
									HostAddress string `json:"host-address"`
								} `json:"static-mapping"`
								NoDns       string `json:"no-dns"`
								PrefixId    string `json:"prefix-id"`
								HostAddress string `json:"host-address"`
								Service     string `json:"service"`
							} `json:"interface"`
							PrefixLength string `json:"prefix-length"`
						} `json:"pd"`
						Duid        string `json:"duid"`
						NoDns       string `json:"no-dns"`
						RapidCommit string `json:"rapid-commit"`
						PrefixOnly  string `json:"prefix-only"`
					} `json:"dhcpv6-pd"`
					ConnectOnDemand string `json:"connect-on-demand"`
					Firewall        struct {
						Out struct {
							Modify     string `json:"modify"`
							Ipv6Modify string `json:"ipv6-modify"`
							Name       string `json:"name"`
							Ipv6Name   string `json:"ipv6-name"`
						} `json:"out"`
						In struct {
							Modify     string `json:"modify"`
							Ipv6Modify string `json:"ipv6-modify"`
							Name       string `json:"name"`
							Ipv6Name   string `json:"ipv6-name"`
						} `json:"in"`
						Local struct {
							Name     string `json:"name"`
							Ipv6Name string `json:"ipv6-name"`
						} `json:"local"`
					} `json:"firewall"`
					UserId       string `json:"user-id"`
					Description  string `json:"description"`
					LocalAddress string `json:"local-address"`
					Redirect     string `json:"redirect"`
					Ip           struct {
						Rip struct {
							SplitHorizon struct {
								Disable       string `json:"disable"`
								PoisonReverse string `json:"poison-reverse"`
							} `json:"split-horizon"`
							Authentication struct {
								Md5 map[string]struct {
									Password string `json:"password"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
						} `json:"rip"`
						SourceValidation string `json:"source-validation"`
						Ospf             struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Network            string `json:"network"`
							Cost               string `json:"cost"`
							DeadInterval       string `json:"dead-interval"`
							Priority           string `json:"priority"`
							MtuIgnore          string `json:"mtu-ignore"`
							Authentication     struct {
								Md5 struct {
									KeyId map[string]struct {
										Md5Key string `json:"md5-key"`
									} `json:"key-id"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
							HelloInterval string `json:"hello-interval"`
						} `json:"ospf"`
					} `json:"ip"`
					Ipv6 struct {
						Enable struct {
							RemoteIdentifier string `json:"remote-identifier"`
							LocalIdentifier  string `json:"local-identifier"`
						} `json:"enable"`
						DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
						DisableForwarding      string `json:"disable-forwarding"`
						Ripng                  struct {
							SplitHorizon struct {
								Disable       string `json:"disable"`
								PoisonReverse string `json:"poison-reverse"`
							} `json:"split-horizon"`
						} `json:"ripng"`
						Address struct {
							Eui64     string `json:"eui64"`
							Autoconf  string `json:"autoconf"`
							Secondary string `json:"secondary"`
						} `json:"address"`
						RouterAdvert struct {
							DefaultPreference string `json:"default-preference"`
							MinInterval       string `json:"min-interval"`
							MaxInterval       string `json:"max-interval"`
							ReachableTime     string `json:"reachable-time"`
							Prefix            map[string]struct {
								AutonomousFlag    string `json:"autonomous-flag"`
								OnLinkFlag        string `json:"on-link-flag"`
								ValidLifetime     string `json:"valid-lifetime"`
								PreferredLifetime string `json:"preferred-lifetime"`
							} `json:"prefix"`
							NameServer      string `json:"name-server"`
							RetransTimer    string `json:"retrans-timer"`
							SendAdvert      string `json:"send-advert"`
							RadvdOptions    string `json:"radvd-options"`
							ManagedFlag     string `json:"managed-flag"`
							OtherConfigFlag string `json:"other-config-flag"`
							DefaultLifetime string `json:"default-lifetime"`
							CurHopLimit     string `json:"cur-hop-limit"`
							LinkMtu         string `json:"link-mtu"`
						} `json:"router-advert"`
						Ospfv3 struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Cost               string `json:"cost"`
							Passive            string `json:"passive"`
							DeadInterval       string `json:"dead-interval"`
							InstanceId         string `json:"instance-id"`
							Ifmtu              string `json:"ifmtu"`
							Priority           string `json:"priority"`
							MtuIgnore          string `json:"mtu-ignore"`
							HelloInterval      string `json:"hello-interval"`
						} `json:"ospfv3"`
					} `json:"ipv6"`
					Multilink          string `json:"multilink"`
					AccessConcentrator string `json:"access-concentrator"`
				} `json:"pppoe"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				Vrrp struct {
					VrrpGroup map[string]struct {
						Disable              string `json:"disable"`
						VirtualAddress       string `json:"virtual-address"`
						AdvertiseInterval    string `json:"advertise-interval"`
						SyncGroup            string `json:"sync-group"`
						PreemptDelay         string `json:"preempt-delay"`
						RunTransitionScripts struct {
							Master string `json:"master"`
							Fault  string `json:"fault"`
							Backup string `json:"backup"`
						} `json:"run-transition-scripts"`
						Preempt            string `json:"preempt"`
						Description        string `json:"description"`
						HelloSourceAddress string `json:"hello-source-address"`
						Priority           string `json:"priority"`
						Authentication     struct {
							Password string `json:"password"`
							Type     string `json:"type"`
						} `json:"authentication"`
					} `json:"vrrp-group"`
				} `json:"vrrp"`
				Dhcpv6Pd struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				DisableLinkDetect string `json:"disable-link-detect"`
				Firewall          struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				DhcpOptions struct {
					NameServer           string `json:"name-server"`
					DefaultRoute         string `json:"default-route"`
					ClientOption         string `json:"client-option"`
					DefaultRouteDistance string `json:"default-route-distance"`
					GlobalOption         string `json:"global-option"`
				} `json:"dhcp-options"`
				Description   string `json:"description"`
				Address       string `json:"address"`
				Redirect      string `json:"redirect"`
				Dhcpv6Options struct {
					ParametersOnly string `json:"parameters-only"`
					Temporary      string `json:"temporary"`
				} `json:"dhcpv6-options"`
				Ip struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64    string `json:"eui64"`
						Autoconf string `json:"autoconf"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
			} `json:"vif"`
			Address         string `json:"address"`
			Redirect        string `json:"redirect"`
			ForwardingDelay string `json:"forwarding-delay"`
			Dhcpv6Options   struct {
				ParametersOnly string `json:"parameters-only"`
				Temporary      string `json:"temporary"`
			} `json:"dhcpv6-options"`
			Priority    string `json:"priority"`
			Promiscuous string `json:"promiscuous"`
			Ip          struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
			Aging string `json:"aging"`
		} `json:"bridge"`
		L2tpClient map[string]struct {
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Mtu           string `json:"mtu"`
			NameServer    string `json:"name-server"`
			DefaultRoute  string `json:"default-route"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Firewall struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			ServerIp    string `json:"server-ip"`
			Description string `json:"description"`
			Compression struct {
				ProtocolField string `json:"protocol-field"`
				Bsd           string `json:"bsd"`
				TcpHeader     string `json:"tcp-header"`
				Deflate       string `json:"deflate"`
				Control       string `json:"control"`
			} `json:"compression"`
			Redirect     string `json:"redirect"`
			RequireIpsec string `json:"require-ipsec"`
			Ip           struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				Ripng struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
			Authentication struct {
				Password    string `json:"password"`
				Refuse      string `json:"refuse"`
				UserId      string `json:"user-id"`
				RequireMppe string `json:"require-mppe"`
			} `json:"authentication"`
		} `json:"l2tp-client"`
		PptpClient map[string]struct {
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Password      string `json:"password"`
			RemoteAddress string `json:"remote-address"`
			Mtu           string `json:"mtu"`
			NameServer    string `json:"name-server"`
			DefaultRoute  string `json:"default-route"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			IdleTimeout     string `json:"idle-timeout"`
			ConnectOnDemand string `json:".connect-on-demand"`
			Firewall        struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			UserId       string `json:"user-id"`
			ServerIp     string `json:"server-ip"`
			Description  string `json:"description"`
			LocalAddress string `json:"local-address"`
			RequireMppe  string `json:"require-mppe"`
			Redirect     string `json:"redirect"`
			Ip           struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				Enable struct {
					RemoteIdentifier string `json:"remote-identifier"`
					LocalIdentifier  string `json:"local-identifier"`
				} `json:"enable"`
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64     string `json:"eui64"`
					Autoconf  string `json:"autoconf"`
					Secondary string `json:"secondary"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"pptp-client"`
		Ethernet map[string]struct {
			BridgeGroup struct {
				Bridge   string `json:"bridge"`
				Cost     string `json:"cost"`
				Priority string `json:"priority"`
			} `json:"bridge-group"`
			Poe struct {
				Output   string `json:"output"`
				Watchdog struct {
					Disable      string `json:"disable"`
					FailureCount string `json:"failure-count"`
					OffDelay     string `json:"off-delay"`
					Interval     string `json:"interval"`
					StartDelay   string `json:"start-delay"`
					Address      string `json:"address"`
				} `json:"watchdog"`
			} `json:"poe"`
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Pppoe map[string]struct {
				ServiceName string `json:"service-name"`
				Bandwidth   struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Password      string `json:"password"`
				RemoteAddress string `json:"remote-address"`
				HostUniq      string `json:"host-uniq"`
				Mtu           string `json:"mtu"`
				NameServer    string `json:"name-server"`
				DefaultRoute  string `json:"default-route"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				IdleTimeout string `json:"idle-timeout"`
				Dhcpv6Pd    struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				ConnectOnDemand string `json:"connect-on-demand"`
				Firewall        struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				UserId       string `json:"user-id"`
				Description  string `json:"description"`
				LocalAddress string `json:"local-address"`
				Redirect     string `json:"redirect"`
				Ip           struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					Enable struct {
						RemoteIdentifier string `json:"remote-identifier"`
						LocalIdentifier  string `json:"local-identifier"`
					} `json:"enable"`
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64     string `json:"eui64"`
						Autoconf  string `json:"autoconf"`
						Secondary string `json:"secondary"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
				Multilink          string `json:"multilink"`
				AccessConcentrator string `json:"access-concentrator"`
			} `json:"pppoe"`
			Speed         string `json:"speed"`
			Mtu           string `json:"mtu"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Vrrp struct {
				VrrpGroup map[string]struct {
					Disable              string `json:"disable"`
					VirtualAddress       string `json:"virtual-address"`
					AdvertiseInterval    string `json:"advertise-interval"`
					SyncGroup            string `json:"sync-group"`
					PreemptDelay         string `json:"preempt-delay"`
					RunTransitionScripts struct {
						Master string `json:"master"`
						Fault  string `json:"fault"`
						Backup string `json:"backup"`
					} `json:"run-transition-scripts"`
					Preempt            string `json:"preempt"`
					Description        string `json:"description"`
					HelloSourceAddress string `json:"hello-source-address"`
					Priority           string `json:"priority"`
					Authentication     struct {
						Password string `json:"password"`
						Type     string `json:"type"`
					} `json:"authentication"`
				} `json:"vrrp-group"`
			} `json:"vrrp"`
			Dhcpv6Pd struct {
				Pd map[string]struct {
					Interface map[string]struct {
						StaticMapping map[string]struct {
							Identifier  string `json:"identifier"`
							HostAddress string `json:"host-address"`
						} `json:"static-mapping"`
						NoDns       string `json:"no-dns"`
						PrefixId    string `json:"prefix-id"`
						HostAddress string `json:"host-address"`
						Service     string `json:"service"`
					} `json:"interface"`
					PrefixLength string `json:"prefix-length"`
				} `json:"pd"`
				Duid        string `json:"duid"`
				NoDns       string `json:"no-dns"`
				RapidCommit string `json:"rapid-commit"`
				PrefixOnly  string `json:"prefix-only"`
			} `json:"dhcpv6-pd"`
			DisableLinkDetect string `json:"disable-link-detect"`
			Duplex            string `json:"duplex"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			DisableFlowControl string `json:".disable-flow-control"`
			Mac                string `json:"mac"`
			DhcpOptions        struct {
				NameServer           string `json:"name-server"`
				DefaultRoute         string `json:"default-route"`
				ClientOption         string `json:"client-option"`
				DefaultRouteDistance string `json:"default-route-distance"`
				GlobalOption         string `json:"global-option"`
			} `json:"dhcp-options"`
			Description string `json:"description"`
			BondGroup   string `json:"bond-group"`
			Vif         map[string]struct {
				BridgeGroup struct {
					Bridge   string `json:"bridge"`
					Cost     string `json:"cost"`
					Priority string `json:"priority"`
				} `json:"bridge-group"`
				Disable   string `json:"disable"`
				Bandwidth struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				EgressQos string `json:"egress-qos"`
				Pppoe     map[string]struct {
					ServiceName string `json:"service-name"`
					Bandwidth   struct {
						Maximum    string `json:"maximum"`
						Reservable string `json:"reservable"`
						Constraint struct {
							ClassType map[string]struct {
								Bandwidth string `json:"bandwidth"`
							} `json:"class-type"`
						} `json:"constraint"`
					} `json:"bandwidth"`
					Password      string `json:"password"`
					RemoteAddress string `json:"remote-address"`
					HostUniq      string `json:"host-uniq"`
					Mtu           string `json:"mtu"`
					NameServer    string `json:"name-server"`
					DefaultRoute  string `json:"default-route"`
					TrafficPolicy struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"traffic-policy"`
					IdleTimeout string `json:"idle-timeout"`
					Dhcpv6Pd    struct {
						Pd map[string]struct {
							Interface map[string]struct {
								StaticMapping map[string]struct {
									Identifier  string `json:"identifier"`
									HostAddress string `json:"host-address"`
								} `json:"static-mapping"`
								NoDns       string `json:"no-dns"`
								PrefixId    string `json:"prefix-id"`
								HostAddress string `json:"host-address"`
								Service     string `json:"service"`
							} `json:"interface"`
							PrefixLength string `json:"prefix-length"`
						} `json:"pd"`
						Duid        string `json:"duid"`
						NoDns       string `json:"no-dns"`
						RapidCommit string `json:"rapid-commit"`
						PrefixOnly  string `json:"prefix-only"`
					} `json:"dhcpv6-pd"`
					ConnectOnDemand string `json:"connect-on-demand"`
					Firewall        struct {
						Out struct {
							Modify     string `json:"modify"`
							Ipv6Modify string `json:"ipv6-modify"`
							Name       string `json:"name"`
							Ipv6Name   string `json:"ipv6-name"`
						} `json:"out"`
						In struct {
							Modify     string `json:"modify"`
							Ipv6Modify string `json:"ipv6-modify"`
							Name       string `json:"name"`
							Ipv6Name   string `json:"ipv6-name"`
						} `json:"in"`
						Local struct {
							Name     string `json:"name"`
							Ipv6Name string `json:"ipv6-name"`
						} `json:"local"`
					} `json:"firewall"`
					UserId       string `json:"user-id"`
					Description  string `json:"description"`
					LocalAddress string `json:"local-address"`
					Redirect     string `json:"redirect"`
					Ip           struct {
						Rip struct {
							SplitHorizon struct {
								Disable       string `json:"disable"`
								PoisonReverse string `json:"poison-reverse"`
							} `json:"split-horizon"`
							Authentication struct {
								Md5 map[string]struct {
									Password string `json:"password"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
						} `json:"rip"`
						SourceValidation string `json:"source-validation"`
						Ospf             struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Network            string `json:"network"`
							Cost               string `json:"cost"`
							DeadInterval       string `json:"dead-interval"`
							Priority           string `json:"priority"`
							MtuIgnore          string `json:"mtu-ignore"`
							Authentication     struct {
								Md5 struct {
									KeyId map[string]struct {
										Md5Key string `json:"md5-key"`
									} `json:"key-id"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
							HelloInterval string `json:"hello-interval"`
						} `json:"ospf"`
					} `json:"ip"`
					Ipv6 struct {
						Enable struct {
							RemoteIdentifier string `json:"remote-identifier"`
							LocalIdentifier  string `json:"local-identifier"`
						} `json:"enable"`
						DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
						DisableForwarding      string `json:"disable-forwarding"`
						Ripng                  struct {
							SplitHorizon struct {
								Disable       string `json:"disable"`
								PoisonReverse string `json:"poison-reverse"`
							} `json:"split-horizon"`
						} `json:"ripng"`
						Address struct {
							Eui64     string `json:"eui64"`
							Autoconf  string `json:"autoconf"`
							Secondary string `json:"secondary"`
						} `json:"address"`
						RouterAdvert struct {
							DefaultPreference string `json:"default-preference"`
							MinInterval       string `json:"min-interval"`
							MaxInterval       string `json:"max-interval"`
							ReachableTime     string `json:"reachable-time"`
							Prefix            map[string]struct {
								AutonomousFlag    string `json:"autonomous-flag"`
								OnLinkFlag        string `json:"on-link-flag"`
								ValidLifetime     string `json:"valid-lifetime"`
								PreferredLifetime string `json:"preferred-lifetime"`
							} `json:"prefix"`
							NameServer      string `json:"name-server"`
							RetransTimer    string `json:"retrans-timer"`
							SendAdvert      string `json:"send-advert"`
							RadvdOptions    string `json:"radvd-options"`
							ManagedFlag     string `json:"managed-flag"`
							OtherConfigFlag string `json:"other-config-flag"`
							DefaultLifetime string `json:"default-lifetime"`
							CurHopLimit     string `json:"cur-hop-limit"`
							LinkMtu         string `json:"link-mtu"`
						} `json:"router-advert"`
						Ospfv3 struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Cost               string `json:"cost"`
							Passive            string `json:"passive"`
							DeadInterval       string `json:"dead-interval"`
							InstanceId         string `json:"instance-id"`
							Ifmtu              string `json:"ifmtu"`
							Priority           string `json:"priority"`
							MtuIgnore          string `json:"mtu-ignore"`
							HelloInterval      string `json:"hello-interval"`
						} `json:"ospfv3"`
					} `json:"ipv6"`
					Multilink          string `json:"multilink"`
					AccessConcentrator string `json:"access-concentrator"`
				} `json:"pppoe"`
				Mtu           string `json:"mtu"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				Vrrp struct {
					VrrpGroup map[string]struct {
						Disable              string `json:"disable"`
						VirtualAddress       string `json:"virtual-address"`
						AdvertiseInterval    string `json:"advertise-interval"`
						SyncGroup            string `json:"sync-group"`
						PreemptDelay         string `json:"preempt-delay"`
						RunTransitionScripts struct {
							Master string `json:"master"`
							Fault  string `json:"fault"`
							Backup string `json:"backup"`
						} `json:"run-transition-scripts"`
						Preempt            string `json:"preempt"`
						Description        string `json:"description"`
						HelloSourceAddress string `json:"hello-source-address"`
						Priority           string `json:"priority"`
						Authentication     struct {
							Password string `json:"password"`
							Type     string `json:"type"`
						} `json:"authentication"`
					} `json:"vrrp-group"`
				} `json:"vrrp"`
				Dhcpv6Pd struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				DisableLinkDetect string `json:"disable-link-detect"`
				Firewall          struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				Mac         string `json:"mac"`
				DhcpOptions struct {
					NameServer           string `json:"name-server"`
					DefaultRoute         string `json:"default-route"`
					ClientOption         string `json:"client-option"`
					DefaultRouteDistance string `json:"default-route-distance"`
					GlobalOption         string `json:"global-option"`
				} `json:"dhcp-options"`
				Description   string `json:"description"`
				Address       string `json:"address"`
				Redirect      string `json:"redirect"`
				Dhcpv6Options struct {
					ParametersOnly string `json:"parameters-only"`
					Temporary      string `json:"temporary"`
				} `json:"dhcpv6-options"`
				Ip struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					EnableProxyArp   string `json:"enable-proxy-arp"`
					SourceValidation string `json:"source-validation"`
					ProxyArpPvlan    string `json:"proxy-arp-pvlan"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64    string `json:"eui64"`
						Autoconf string `json:"autoconf"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
			} `json:"vif"`
			Address       string `json:"address"`
			Redirect      string `json:"redirect"`
			SmpAffinity   string `json:".smp_affinity"`
			Dhcpv6Options struct {
				ParametersOnly string `json:"parameters-only"`
				Temporary      string `json:"temporary"`
			} `json:"dhcpv6-options"`
			Ip struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				EnableProxyArp   string `json:"enable-proxy-arp"`
				SourceValidation string `json:"source-validation"`
				ProxyArpPvlan    string `json:"proxy-arp-pvlan"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
			Mirror string `json:"mirror"`
		} `json:"ethernet"`
		Tunnel map[string]struct {
			BridgeGroup struct {
				Bridge   string `json:"bridge"`
				Cost     string `json:"cost"`
				Priority string `json:"priority"`
			} `json:"bridge-group"`
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Encapsulation string `json:"encapsulation"`
			Multicast     string `json:"multicast"`
			Ttl           string `json:"ttl"`
			Mtu           string `json:"mtu"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Key               string `json:"key"`
			DisableLinkDetect string `json:"disable-link-detect"`
			SixrdPrefix       string `json:"6rd-prefix"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Tos              string `json:"tos"`
			SixrdRelayPrefix string `json:"6rd-relay_prefix"`
			Description      string `json:"description"`
			Address          string `json:"address"`
			Redirect         string `json:"redirect"`
			LocalIp          string `json:"local-ip"`
			RemoteIp         string `json:"remote-ip"`
			SixrdDefaultGw   string `json:"6rd-default-gw"`
			Ip               struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"tunnel"`
		Openvpn map[string]struct {
			BridgeGroup struct {
				Bridge   string `json:"bridge"`
				Cost     string `json:"cost"`
				Priority string `json:"priority"`
			} `json:"bridge-group"`
			Encryption string `json:"encryption"`
			Disable    string `json:"disable"`
			RemoteHost string `json:"remote-host"`
			Bandwidth  struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			ReplaceDefaultRoute struct {
				Local string `json:"local"`
			} `json:"replace-default-route"`
			OpenvpnOption       string `json:"openvpn-option"`
			RemoteAddress       string `json:"remote-address"`
			Mode                string `json:"mode"`
			Hash                string `json:"hash"`
			DeviceType          string `json:"device-type"`
			SharedSecretKeyFile string `json:"shared-secret-key-file"`
			LocalHost           string `json:"local-host"`
			TrafficPolicy       struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Server struct {
				PushRoute      string `json:"push-route"`
				Topology       string `json:"topology"`
				NameServer     string `json:"name-server"`
				DomainName     string `json:"domain-name"`
				MaxConnections string `json:"max-connections"`
				Subnet         string `json:"subnet"`
				Client         map[string]struct {
					PushRoute string `json:"push-route"`
					Disable   string `json:"disable"`
					Ip        string `json:"ip"`
					Subnet    string `json:"subnet"`
				} `json:"client"`
			} `json:"server"`
			Protocol string `json:"protocol"`
			Firewall struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Tls struct {
				CrlFile    string `json:"crl-file"`
				Role       string `json:"role"`
				KeyFile    string `json:"key-file"`
				DhFile     string `json:"dh-file"`
				CaCertFile string `json:"ca-cert-file"`
				CertFile   string `json:"cert-file"`
			} `json:"tls"`
			Description  string `json:"description"`
			LocalAddress map[string]struct {
				SubnetMask string `json:"subnet-mask"`
			} `json:"local-address"`
			LocalPort string `json:"local-port"`
			Redirect  string `json:"redirect"`
			Ip        struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
			RemotePort string `json:"remote-port"`
			ConfigFile string `json:"config-file"`
		} `json:"openvpn"`
		Loopback map[string]struct {
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Description string `json:"description"`
			Address     string `json:"address"`
			Redirect    string `json:"redirect"`
			Ip          struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				Ripng struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"loopback"`
		Switch map[string]struct {
			BridgeGroup struct {
				Bridge   string `json:"bridge"`
				Cost     string `json:"cost"`
				Priority string `json:"priority"`
			} `json:"bridge-group"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Pppoe map[string]struct {
				ServiceName string `json:"service-name"`
				Bandwidth   struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Password      string `json:"password"`
				RemoteAddress string `json:"remote-address"`
				HostUniq      string `json:"host-uniq"`
				Mtu           string `json:"mtu"`
				NameServer    string `json:"name-server"`
				DefaultRoute  string `json:"default-route"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				IdleTimeout string `json:"idle-timeout"`
				Dhcpv6Pd    struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				ConnectOnDemand string `json:"connect-on-demand"`
				Firewall        struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				UserId       string `json:"user-id"`
				Description  string `json:"description"`
				LocalAddress string `json:"local-address"`
				Redirect     string `json:"redirect"`
				Ip           struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					Enable struct {
						RemoteIdentifier string `json:"remote-identifier"`
						LocalIdentifier  string `json:"local-identifier"`
					} `json:"enable"`
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64     string `json:"eui64"`
						Autoconf  string `json:"autoconf"`
						Secondary string `json:"secondary"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
				Multilink          string `json:"multilink"`
				AccessConcentrator string `json:"access-concentrator"`
			} `json:"pppoe"`
			Mtu        string `json:"mtu"`
			SwitchPort struct {
				Interface map[string]struct {
					Vlan struct {
						Vid  string `json:"vid"`
						Pvid string `json:"pvid"`
					} `json:"vlan"`
				} `json:"interface"`
				VlanAware string `json:"vlan-aware"`
			} `json:"switch-port"`
			TrafficPolicy struct {
				Out string `json:"out"`
				In  string `json:"in"`
			} `json:"traffic-policy"`
			Vrrp struct {
				VrrpGroup map[string]struct {
					Disable              string `json:"disable"`
					VirtualAddress       string `json:"virtual-address"`
					AdvertiseInterval    string `json:"advertise-interval"`
					SyncGroup            string `json:"sync-group"`
					PreemptDelay         string `json:"preempt-delay"`
					RunTransitionScripts struct {
						Master string `json:"master"`
						Fault  string `json:"fault"`
						Backup string `json:"backup"`
					} `json:"run-transition-scripts"`
					Preempt            string `json:"preempt"`
					Description        string `json:"description"`
					HelloSourceAddress string `json:"hello-source-address"`
					Priority           string `json:"priority"`
					Authentication     struct {
						Password string `json:"password"`
						Type     string `json:"type"`
					} `json:"authentication"`
				} `json:"vrrp-group"`
			} `json:"vrrp"`
			Dhcpv6Pd struct {
				Pd map[string]struct {
					Interface map[string]struct {
						StaticMapping map[string]struct {
							Identifier  string `json:"identifier"`
							HostAddress string `json:"host-address"`
						} `json:"static-mapping"`
						NoDns       string `json:"no-dns"`
						PrefixId    string `json:"prefix-id"`
						HostAddress string `json:"host-address"`
						Service     string `json:"service"`
					} `json:"interface"`
					PrefixLength string `json:"prefix-length"`
				} `json:"pd"`
				Duid        string `json:"duid"`
				NoDns       string `json:"no-dns"`
				RapidCommit string `json:"rapid-commit"`
				PrefixOnly  string `json:"prefix-only"`
			} `json:"dhcpv6-pd"`
			Firewall struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			DhcpOptions struct {
				NameServer           string `json:"name-server"`
				DefaultRoute         string `json:"default-route"`
				ClientOption         string `json:"client-option"`
				DefaultRouteDistance string `json:"default-route-distance"`
				GlobalOption         string `json:"global-option"`
			} `json:"dhcp-options"`
			Description string `json:"description"`
			Vif         map[string]struct {
				BridgeGroup struct {
					Bridge   string `json:"bridge"`
					Cost     string `json:"cost"`
					Priority string `json:"priority"`
				} `json:"bridge-group"`
				Disable   string `json:"disable"`
				Bandwidth struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Pppoe map[string]struct {
					ServiceName string `json:"service-name"`
					Bandwidth   struct {
						Maximum    string `json:"maximum"`
						Reservable string `json:"reservable"`
						Constraint struct {
							ClassType map[string]struct {
								Bandwidth string `json:"bandwidth"`
							} `json:"class-type"`
						} `json:"constraint"`
					} `json:"bandwidth"`
					Password      string `json:"password"`
					RemoteAddress string `json:"remote-address"`
					HostUniq      string `json:"host-uniq"`
					Mtu           string `json:"mtu"`
					NameServer    string `json:"name-server"`
					DefaultRoute  string `json:"default-route"`
					TrafficPolicy struct {
						Out string `json:"out"`
						In  string `json:"in"`
					} `json:"traffic-policy"`
					IdleTimeout string `json:"idle-timeout"`
					Dhcpv6Pd    struct {
						Pd map[string]struct {
							Interface map[string]struct {
								StaticMapping map[string]struct {
									Identifier  string `json:"identifier"`
									HostAddress string `json:"host-address"`
								} `json:"static-mapping"`
								NoDns       string `json:"no-dns"`
								PrefixId    string `json:"prefix-id"`
								HostAddress string `json:"host-address"`
								Service     string `json:"service"`
							} `json:"interface"`
							PrefixLength string `json:"prefix-length"`
						} `json:"pd"`
						Duid        string `json:"duid"`
						NoDns       string `json:"no-dns"`
						RapidCommit string `json:"rapid-commit"`
						PrefixOnly  string `json:"prefix-only"`
					} `json:"dhcpv6-pd"`
					ConnectOnDemand string `json:"connect-on-demand"`
					Firewall        struct {
						Out struct {
							Modify     string `json:"modify"`
							Ipv6Modify string `json:"ipv6-modify"`
							Name       string `json:"name"`
							Ipv6Name   string `json:"ipv6-name"`
						} `json:"out"`
						In struct {
							Modify     string `json:"modify"`
							Ipv6Modify string `json:"ipv6-modify"`
							Name       string `json:"name"`
							Ipv6Name   string `json:"ipv6-name"`
						} `json:"in"`
						Local struct {
							Name     string `json:"name"`
							Ipv6Name string `json:"ipv6-name"`
						} `json:"local"`
					} `json:"firewall"`
					UserId       string `json:"user-id"`
					Description  string `json:"description"`
					LocalAddress string `json:"local-address"`
					Redirect     string `json:"redirect"`
					Ip           struct {
						Rip struct {
							SplitHorizon struct {
								Disable       string `json:"disable"`
								PoisonReverse string `json:"poison-reverse"`
							} `json:"split-horizon"`
							Authentication struct {
								Md5 map[string]struct {
									Password string `json:"password"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
						} `json:"rip"`
						SourceValidation string `json:"source-validation"`
						Ospf             struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Network            string `json:"network"`
							Cost               string `json:"cost"`
							DeadInterval       string `json:"dead-interval"`
							Priority           string `json:"priority"`
							MtuIgnore          string `json:"mtu-ignore"`
							Authentication     struct {
								Md5 struct {
									KeyId map[string]struct {
										Md5Key string `json:"md5-key"`
									} `json:"key-id"`
								} `json:"md5"`
								PlaintextPassword string `json:"plaintext-password"`
							} `json:"authentication"`
							HelloInterval string `json:"hello-interval"`
						} `json:"ospf"`
					} `json:"ip"`
					Ipv6 struct {
						Enable struct {
							RemoteIdentifier string `json:"remote-identifier"`
							LocalIdentifier  string `json:"local-identifier"`
						} `json:"enable"`
						DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
						DisableForwarding      string `json:"disable-forwarding"`
						Ripng                  struct {
							SplitHorizon struct {
								Disable       string `json:"disable"`
								PoisonReverse string `json:"poison-reverse"`
							} `json:"split-horizon"`
						} `json:"ripng"`
						Address struct {
							Eui64     string `json:"eui64"`
							Autoconf  string `json:"autoconf"`
							Secondary string `json:"secondary"`
						} `json:"address"`
						RouterAdvert struct {
							DefaultPreference string `json:"default-preference"`
							MinInterval       string `json:"min-interval"`
							MaxInterval       string `json:"max-interval"`
							ReachableTime     string `json:"reachable-time"`
							Prefix            map[string]struct {
								AutonomousFlag    string `json:"autonomous-flag"`
								OnLinkFlag        string `json:"on-link-flag"`
								ValidLifetime     string `json:"valid-lifetime"`
								PreferredLifetime string `json:"preferred-lifetime"`
							} `json:"prefix"`
							NameServer      string `json:"name-server"`
							RetransTimer    string `json:"retrans-timer"`
							SendAdvert      string `json:"send-advert"`
							RadvdOptions    string `json:"radvd-options"`
							ManagedFlag     string `json:"managed-flag"`
							OtherConfigFlag string `json:"other-config-flag"`
							DefaultLifetime string `json:"default-lifetime"`
							CurHopLimit     string `json:"cur-hop-limit"`
							LinkMtu         string `json:"link-mtu"`
						} `json:"router-advert"`
						Ospfv3 struct {
							RetransmitInterval string `json:"retransmit-interval"`
							TransmitDelay      string `json:"transmit-delay"`
							Cost               string `json:"cost"`
							Passive            string `json:"passive"`
							DeadInterval       string `json:"dead-interval"`
							InstanceId         string `json:"instance-id"`
							Ifmtu              string `json:"ifmtu"`
							Priority           string `json:"priority"`
							MtuIgnore          string `json:"mtu-ignore"`
							HelloInterval      string `json:"hello-interval"`
						} `json:"ospfv3"`
					} `json:"ipv6"`
					Multilink          string `json:"multilink"`
					AccessConcentrator string `json:"access-concentrator"`
				} `json:"pppoe"`
				Mtu           string `json:"mtu"`
				TrafficPolicy struct {
					Out string `json:"out"`
					In  string `json:"in"`
				} `json:"traffic-policy"`
				Vrrp struct {
					VrrpGroup map[string]struct {
						Disable              string `json:"disable"`
						VirtualAddress       string `json:"virtual-address"`
						AdvertiseInterval    string `json:"advertise-interval"`
						SyncGroup            string `json:"sync-group"`
						PreemptDelay         string `json:"preempt-delay"`
						RunTransitionScripts struct {
							Master string `json:"master"`
							Fault  string `json:"fault"`
							Backup string `json:"backup"`
						} `json:"run-transition-scripts"`
						Preempt            string `json:"preempt"`
						Description        string `json:"description"`
						HelloSourceAddress string `json:"hello-source-address"`
						Priority           string `json:"priority"`
						Authentication     struct {
							Password string `json:"password"`
							Type     string `json:"type"`
						} `json:"authentication"`
					} `json:"vrrp-group"`
				} `json:"vrrp"`
				Dhcpv6Pd struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				Firewall struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				Mac         string `json:"mac"`
				DhcpOptions struct {
					NameServer           string `json:"name-server"`
					DefaultRoute         string `json:"default-route"`
					ClientOption         string `json:"client-option"`
					DefaultRouteDistance string `json:"default-route-distance"`
					GlobalOption         string `json:"global-option"`
				} `json:"dhcp-options"`
				Description   string `json:"description"`
				Address       string `json:"address"`
				Redirect      string `json:"redirect"`
				Dhcpv6Options struct {
					ParametersOnly string `json:"parameters-only"`
					Temporary      string `json:"temporary"`
				} `json:"dhcpv6-options"`
				Ip struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					EnableProxyArp   string `json:"enable-proxy-arp"`
					SourceValidation string `json:"source-validation"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64    string `json:"eui64"`
						Autoconf string `json:"autoconf"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
			} `json:"vif"`
			Address       string `json:"address"`
			Redirect      string `json:"redirect"`
			Dhcpv6Options struct {
				ParametersOnly string `json:"parameters-only"`
				Temporary      string `json:"temporary"`
			} `json:"dhcpv6-options"`
			Ip struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				EnableProxyArp   string `json:"enable-proxy-arp"`
				SourceValidation string `json:"source-validation"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"switch"`
		PseudoEthernet map[string]struct {
			Disable   string `json:"disable"`
			Bandwidth struct {
				Maximum    string `json:"maximum"`
				Reservable string `json:"reservable"`
				Constraint struct {
					ClassType map[string]struct {
						Bandwidth string `json:"bandwidth"`
					} `json:"class-type"`
				} `json:"constraint"`
			} `json:"bandwidth"`
			Pppoe map[string]struct {
				ServiceName string `json:"service-name"`
				Bandwidth   struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Password      string `json:"password"`
				RemoteAddress string `json:"remote-address"`
				HostUniq      string `json:"host-uniq"`
				Mtu           string `json:"mtu"`
				NameServer    string `json:"name-server"`
				DefaultRoute  string `json:"default-route"`
				IdleTimeout   string `json:"idle-timeout"`
				Dhcpv6Pd      struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				ConnectOnDemand string `json:"connect-on-demand"`
				Firewall        struct {
					Out struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"out"`
					In struct {
						Modify     string `json:"modify"`
						Ipv6Modify string `json:"ipv6-modify"`
						Name       string `json:"name"`
						Ipv6Name   string `json:"ipv6-name"`
					} `json:"in"`
					Local struct {
						Name     string `json:"name"`
						Ipv6Name string `json:"ipv6-name"`
					} `json:"local"`
				} `json:"firewall"`
				UserId       string `json:"user-id"`
				Description  string `json:"description"`
				LocalAddress string `json:"local-address"`
				Ip           struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					Enable struct {
						RemoteIdentifier string `json:"remote-identifier"`
						LocalIdentifier  string `json:"local-identifier"`
					} `json:"enable"`
					DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
					DisableForwarding      string `json:"disable-forwarding"`
					Ripng                  struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Address struct {
						Eui64     string `json:"eui64"`
						Autoconf  string `json:"autoconf"`
						Secondary string `json:"secondary"`
					} `json:"address"`
					RouterAdvert struct {
						DefaultPreference string `json:"default-preference"`
						MinInterval       string `json:"min-interval"`
						MaxInterval       string `json:"max-interval"`
						ReachableTime     string `json:"reachable-time"`
						Prefix            map[string]struct {
							AutonomousFlag    string `json:"autonomous-flag"`
							OnLinkFlag        string `json:"on-link-flag"`
							ValidLifetime     string `json:"valid-lifetime"`
							PreferredLifetime string `json:"preferred-lifetime"`
						} `json:"prefix"`
						NameServer      string `json:"name-server"`
						RetransTimer    string `json:"retrans-timer"`
						SendAdvert      string `json:"send-advert"`
						RadvdOptions    string `json:"radvd-options"`
						ManagedFlag     string `json:"managed-flag"`
						OtherConfigFlag string `json:"other-config-flag"`
						DefaultLifetime string `json:"default-lifetime"`
						CurHopLimit     string `json:"cur-hop-limit"`
						LinkMtu         string `json:"link-mtu"`
					} `json:"router-advert"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
				Multilink          string `json:"multilink"`
				AccessConcentrator string `json:"access-concentrator"`
			} `json:"pppoe"`
			Vrrp struct {
				VrrpGroup map[string]struct {
					Disable              string `json:"disable"`
					VirtualAddress       string `json:"virtual-address"`
					AdvertiseInterval    string `json:"advertise-interval"`
					SyncGroup            string `json:"sync-group"`
					PreemptDelay         string `json:"preempt-delay"`
					RunTransitionScripts struct {
						Master string `json:"master"`
						Fault  string `json:"fault"`
						Backup string `json:"backup"`
					} `json:"run-transition-scripts"`
					Preempt            string `json:"preempt"`
					Description        string `json:"description"`
					HelloSourceAddress string `json:"hello-source-address"`
					Priority           string `json:"priority"`
					Authentication     struct {
						Password string `json:"password"`
						Type     string `json:"type"`
					} `json:"authentication"`
				} `json:"vrrp-group"`
			} `json:"vrrp"`
			Dhcpv6Pd struct {
				Pd map[string]struct {
					Interface map[string]struct {
						StaticMapping map[string]struct {
							Identifier  string `json:"identifier"`
							HostAddress string `json:"host-address"`
						} `json:"static-mapping"`
						NoDns       string `json:"no-dns"`
						PrefixId    string `json:"prefix-id"`
						HostAddress string `json:"host-address"`
						Service     string `json:"service"`
					} `json:"interface"`
					PrefixLength string `json:"prefix-length"`
				} `json:"pd"`
				Duid        string `json:"duid"`
				NoDns       string `json:"no-dns"`
				RapidCommit string `json:"rapid-commit"`
				PrefixOnly  string `json:"prefix-only"`
			} `json:"dhcpv6-pd"`
			DisableLinkDetect string `json:"disable-link-detect"`
			Firewall          struct {
				Out struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"out"`
				In struct {
					Modify     string `json:"modify"`
					Ipv6Modify string `json:"ipv6-modify"`
					Name       string `json:"name"`
					Ipv6Name   string `json:"ipv6-name"`
				} `json:"in"`
				Local struct {
					Name     string `json:"name"`
					Ipv6Name string `json:"ipv6-name"`
				} `json:"local"`
			} `json:"firewall"`
			Mac         string `json:"mac"`
			DhcpOptions struct {
				NameServer           string `json:"name-server"`
				DefaultRoute         string `json:"default-route"`
				ClientOption         string `json:"client-option"`
				DefaultRouteDistance string `json:"default-route-distance"`
				GlobalOption         string `json:"global-option"`
			} `json:"dhcp-options"`
			Link        string `json:"link"`
			Description string `json:"description"`
			Vif         map[string]struct {
				Disable   string `json:"disable"`
				Bandwidth struct {
					Maximum    string `json:"maximum"`
					Reservable string `json:"reservable"`
					Constraint struct {
						ClassType map[string]struct {
							Bandwidth string `json:"bandwidth"`
						} `json:"class-type"`
					} `json:"constraint"`
				} `json:"bandwidth"`
				Vrrp struct {
					VrrpGroup map[string]struct {
						Disable              string `json:"disable"`
						VirtualAddress       string `json:"virtual-address"`
						AdvertiseInterval    string `json:"advertise-interval"`
						SyncGroup            string `json:"sync-group"`
						PreemptDelay         string `json:"preempt-delay"`
						RunTransitionScripts struct {
							Master string `json:"master"`
							Fault  string `json:"fault"`
							Backup string `json:"backup"`
						} `json:"run-transition-scripts"`
						Preempt            string `json:"preempt"`
						Description        string `json:"description"`
						HelloSourceAddress string `json:"hello-source-address"`
						Priority           string `json:"priority"`
						Authentication     struct {
							Password string `json:"password"`
							Type     string `json:"type"`
						} `json:"authentication"`
					} `json:"vrrp-group"`
				} `json:"vrrp"`
				Dhcpv6Pd struct {
					Pd map[string]struct {
						Interface map[string]struct {
							StaticMapping map[string]struct {
								Identifier  string `json:"identifier"`
								HostAddress string `json:"host-address"`
							} `json:"static-mapping"`
							NoDns       string `json:"no-dns"`
							PrefixId    string `json:"prefix-id"`
							HostAddress string `json:"host-address"`
							Service     string `json:"service"`
						} `json:"interface"`
						PrefixLength string `json:"prefix-length"`
					} `json:"pd"`
					Duid        string `json:"duid"`
					NoDns       string `json:"no-dns"`
					RapidCommit string `json:"rapid-commit"`
					PrefixOnly  string `json:"prefix-only"`
				} `json:"dhcpv6-pd"`
				DisableLinkDetect string `json:"disable-link-detect"`
				DhcpOptions       struct {
					NameServer           string `json:"name-server"`
					DefaultRoute         string `json:"default-route"`
					ClientOption         string `json:"client-option"`
					DefaultRouteDistance string `json:"default-route-distance"`
					GlobalOption         string `json:"global-option"`
				} `json:"dhcp-options"`
				Description   string `json:"description"`
				Address       string `json:"address"`
				Dhcpv6Options struct {
					ParametersOnly string `json:"parameters-only"`
					Temporary      string `json:"temporary"`
				} `json:"dhcpv6-options"`
				Ip struct {
					Rip struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
						Authentication struct {
							Md5 map[string]struct {
								Password string `json:"password"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
					} `json:"rip"`
					SourceValidation string `json:"source-validation"`
					ProxyArpPvlan    string `json:"proxy-arp-pvlan"`
					Ospf             struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Network            string `json:"network"`
						Cost               string `json:"cost"`
						DeadInterval       string `json:"dead-interval"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						Authentication     struct {
							Md5 struct {
								KeyId map[string]struct {
									Md5Key string `json:"md5-key"`
								} `json:"key-id"`
							} `json:"md5"`
							PlaintextPassword string `json:"plaintext-password"`
						} `json:"authentication"`
						HelloInterval string `json:"hello-interval"`
					} `json:"ospf"`
				} `json:"ip"`
				Ipv6 struct {
					Ripng struct {
						SplitHorizon struct {
							Disable       string `json:"disable"`
							PoisonReverse string `json:"poison-reverse"`
						} `json:"split-horizon"`
					} `json:"ripng"`
					Ospfv3 struct {
						RetransmitInterval string `json:"retransmit-interval"`
						TransmitDelay      string `json:"transmit-delay"`
						Cost               string `json:"cost"`
						Passive            string `json:"passive"`
						DeadInterval       string `json:"dead-interval"`
						InstanceId         string `json:"instance-id"`
						Ifmtu              string `json:"ifmtu"`
						Priority           string `json:"priority"`
						MtuIgnore          string `json:"mtu-ignore"`
						HelloInterval      string `json:"hello-interval"`
					} `json:"ospfv3"`
				} `json:"ipv6"`
			} `json:"vif"`
			Address       string `json:"address"`
			Dhcpv6Options struct {
				ParametersOnly string `json:"parameters-only"`
				Temporary      string `json:"temporary"`
			} `json:"dhcpv6-options"`
			Ip struct {
				Rip struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
					Authentication struct {
						Md5 map[string]struct {
							Password string `json:"password"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
				} `json:"rip"`
				SourceValidation string `json:"source-validation"`
				ProxyArpPvlan    string `json:"proxy-arp-pvlan"`
				Ospf             struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Network            string `json:"network"`
					Cost               string `json:"cost"`
					DeadInterval       string `json:"dead-interval"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					Authentication     struct {
						Md5 struct {
							KeyId map[string]struct {
								Md5Key string `json:"md5-key"`
							} `json:"key-id"`
						} `json:"md5"`
						PlaintextPassword string `json:"plaintext-password"`
					} `json:"authentication"`
					HelloInterval string `json:"hello-interval"`
				} `json:"ospf"`
			} `json:"ip"`
			Ipv6 struct {
				DupAddrDetectTransmits string `json:"dup-addr-detect-transmits"`
				DisableForwarding      string `json:"disable-forwarding"`
				Ripng                  struct {
					SplitHorizon struct {
						Disable       string `json:"disable"`
						PoisonReverse string `json:"poison-reverse"`
					} `json:"split-horizon"`
				} `json:"ripng"`
				Address struct {
					Eui64    string `json:"eui64"`
					Autoconf string `json:"autoconf"`
				} `json:"address"`
				RouterAdvert struct {
					DefaultPreference string `json:"default-preference"`
					MinInterval       string `json:"min-interval"`
					MaxInterval       string `json:"max-interval"`
					ReachableTime     string `json:"reachable-time"`
					Prefix            map[string]struct {
						AutonomousFlag    string `json:"autonomous-flag"`
						OnLinkFlag        string `json:"on-link-flag"`
						ValidLifetime     string `json:"valid-lifetime"`
						PreferredLifetime string `json:"preferred-lifetime"`
					} `json:"prefix"`
					NameServer      string `json:"name-server"`
					RetransTimer    string `json:"retrans-timer"`
					SendAdvert      string `json:"send-advert"`
					RadvdOptions    string `json:"radvd-options"`
					ManagedFlag     string `json:"managed-flag"`
					OtherConfigFlag string `json:"other-config-flag"`
					DefaultLifetime string `json:"default-lifetime"`
					CurHopLimit     string `json:"cur-hop-limit"`
					LinkMtu         string `json:"link-mtu"`
				} `json:"router-advert"`
				Ospfv3 struct {
					RetransmitInterval string `json:"retransmit-interval"`
					TransmitDelay      string `json:"transmit-delay"`
					Cost               string `json:"cost"`
					Passive            string `json:"passive"`
					DeadInterval       string `json:"dead-interval"`
					InstanceId         string `json:"instance-id"`
					Ifmtu              string `json:"ifmtu"`
					Priority           string `json:"priority"`
					MtuIgnore          string `json:"mtu-ignore"`
					HelloInterval      string `json:"hello-interval"`
				} `json:"ospfv3"`
			} `json:"ipv6"`
		} `json:"pseudo-ethernet"`
	} `json:"interfaces"`
	CustomAttribute map[string]struct {
		Value string `json:"value"`
	} `json:"custom-attribute"`
}
