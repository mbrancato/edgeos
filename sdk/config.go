package sdk

type Config struct {
	ZonePolicy *struct {
		Zone *map[string]struct {
			DefaultAction *string `json:"default-action,omitempty"`
			Interface     *string `json:"interface,omitempty"`
			LocalZone     *string `json:"local-zone,omitempty"`
			From          *map[string]struct {
				ContentInspection *struct {
					Enable     *string `json:"enable,omitempty"`
					Ipv6Enable *string `json:".ipv6-enable,omitempty"`
				} `json:".content-inspection,omitempty"`
				Firewall *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"firewall,omitempty"`
			} `json:"from,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"zone,omitempty"`
	} `json:"zone-policy,omitempty"`
	LoadBalance *struct {
		Group *map[string]struct {
			Interface *map[string]struct {
				Weight    *int `json:"weight,omitempty"`
				RouteTest *struct {
					Interval *int `json:"interval,omitempty"`
					Count    *struct {
						Success *int `json:"success,omitempty"`
						Failure *int `json:"failure,omitempty"`
					} `json:"count,omitempty"`
					InitialDelay *int `json:"initial-delay,omitempty"`
					Type         *struct {
						Ping *struct {
							Target *IP `json:"target,omitempty"`
						} `json:"ping,omitempty"`
						Default *string `json:"default,omitempty"`
						Script  *string `json:"script,omitempty"`
					} `json:"type,omitempty"`
				} `json:"route-test,omitempty"`
				Route *struct {
					Default *string `json:"default,omitempty"`
					Table   *int    `json:"table,omitempty"`
				} `json:"route,omitempty"`
				FailoverOnly     *string `json:"failover-only,omitempty"`
				FailoverPriority *int    `json:"failover-priority,omitempty"`
			} `json:"interface,omitempty"`
			LbLocal               *string `json:"lb-local,omitempty"`
			GatewayUpdateInterval *int    `json:"gateway-update-interval,omitempty"`
			LbLocalMetricChange   *string `json:"lb-local-metric-change,omitempty"`
			Sticky                *struct {
				Proto      *string `json:"proto,omitempty"`
				SourceAddr *string `json:"source-addr,omitempty"`
				SourcePort *string `json:"source-port,omitempty"`
				DestPort   *string `json:"dest-port,omitempty"`
				DestAddr   *string `json:"dest-addr,omitempty"`
			} `json:"sticky,omitempty"`
			FlushOnActive      *string `json:"flush-on-active,omitempty"`
			TransitionScript   *string `json:"transition-script,omitempty"`
			ExcludeLocalDns    *string `json:"exclude-local-dns,omitempty"`
			ReachabilityScript *string `json:"reachability-script,omitempty"`
		} `json:"group,omitempty"`
	} `json:"load-balance,omitempty"`
	PortForward *struct {
		LanInterface *string `json:"lan-interface,omitempty"`
		AutoFirewall *string `json:"auto-firewall,omitempty"`
		Rule         *map[string]struct {
			ForwardTo *struct {
				Address *IPv4   `json:"address,omitempty"`
				Port    *string `json:"port,omitempty"`
			} `json:"forward-to,omitempty"`
			OriginalPort *string `json:"original-port,omitempty"`
			Protocol     *string `json:"protocol,omitempty"`
			Description  *string `json:"description,omitempty"`
		} `json:"rule,omitempty"`
		WanInterface *string `json:"wan-interface,omitempty"`
		HairpinNat   *string `json:"hairpin-nat,omitempty"`
	} `json:"port-forward,omitempty"`
	Vpn *struct {
		RsaKeys *struct {
			LocalKey *struct {
				File *string `json:"file,omitempty"`
			} `json:"local-key,omitempty"`
			RsaKeyName *map[string]struct {
				RsaKey *string `json:"rsa-key,omitempty"`
			} `json:"rsa-key-name,omitempty"`
		} `json:"rsa-keys,omitempty"`
		Ipsec *struct {
			AutoUpdate  *int `json:"auto-update,omitempty"`
			NatNetworks *struct {
				AllowedNetwork *map[string]struct {
					Exclude *IPv4Net `json:"exclude,omitempty"`
				} `json:"allowed-network,omitempty"`
			} `json:"nat-networks,omitempty"`
			AllowAccessToLocalInterface *string `json:"allow-access-to-local-interface,omitempty"`
			AutoFirewallNatExclude      *string `json:"auto-firewall-nat-exclude,omitempty"`
			DisableUniqreqids           *string `json:"disable-uniqreqids,omitempty"`
			SiteToSite                  *struct {
				Peer *map[string]struct {
					DefaultEspGroup    *string `json:"default-esp-group,omitempty"`
					ForceEncapsulation *string `json:"force-encapsulation,omitempty"`
					Vti                *struct {
						EspGroup *string `json:"esp-group,omitempty"`
						Bind     *string `json:"bind,omitempty"`
					} `json:"vti,omitempty"`
					ConnectionType *string `json:"connection-type,omitempty"`
					Ikev2Reauth    *string `json:"ikev2-reauth,omitempty"`
					Tunnel         *map[string]struct {
						Disable             *string `json:"disable,omitempty"`
						AllowPublicNetworks *string `json:"allow-public-networks,omitempty"`
						Protocol            *string `json:"protocol,omitempty"`
						Local               *struct {
							Prefix *IPNet  `json:"prefix,omitempty"`
							Port   *string `json:"port,omitempty"`
						} `json:"local,omitempty"`
						EspGroup         *string `json:"esp-group,omitempty"`
						AllowNatNetworks *string `json:"allow-nat-networks,omitempty"`
						Remote           *struct {
							Prefix *IPNet  `json:"prefix,omitempty"`
							Port   *string `json:"port,omitempty"`
						} `json:"remote,omitempty"`
					} `json:"tunnel,omitempty"`
					Description    *string `json:"description,omitempty"`
					LocalAddress   *string `json:"local-address,omitempty"`
					IkeGroup       *string `json:"ike-group,omitempty"`
					Authentication *struct {
						Mode *string `json:"mode,omitempty"`
						X509 *struct {
							CrlFile *string `json:"crl-file,omitempty"`
							Key     *struct {
								Password *string `json:"password,omitempty"`
								File     *string `json:"file,omitempty"`
							} `json:"key,omitempty"`
							CaCertFile *string `json:"ca-cert-file,omitempty"`
							CertFile   *string `json:"cert-file,omitempty"`
						} `json:"x509,omitempty"`
						PreSharedSecret *string `json:"pre-shared-secret,omitempty"`
						Id              *string `json:"id,omitempty"`
						RemoteId        *string `json:"remote-id,omitempty"`
						RsaKeyName      *string `json:"rsa-key-name,omitempty"`
					} `json:"authentication,omitempty"`
					DhcpInterface *string `json:"dhcp-interface,omitempty"`
				} `json:"peer,omitempty"`
			} `json:"site-to-site,omitempty"`
			RemoteAccess *struct {
				OutsideAddress *IPv4 `json:"outside-address,omitempty"`
				WinsServers    *struct {
					Server2 *IPv4 `json:"server-2,omitempty"`
					Server1 *IPv4 `json:"server-1,omitempty"`
				} `json:"wins-servers,omitempty"`
				UpdownScript *string `json:"updown-script,omitempty"`
				Inactivity   *int    `json:"inactivity,omitempty"`
				DnsServers   *struct {
					Server2 *IPv4 `json:"server-2,omitempty"`
					Server1 *IPv4 `json:"server-1,omitempty"`
				} `json:"dns-servers,omitempty"`
				IkeSettings *struct {
					Proposal *map[string]struct {
						Encryption *string `json:"encryption,omitempty"`
						Hash       *string `json:"hash,omitempty"`
						DhGroup    *int    `json:"dh-group,omitempty"`
					} `json:"proposal,omitempty"`
					EspGroup       *string `json:"esp-group,omitempty"`
					IkeLifetime    *int    `json:"ike-lifetime,omitempty"`
					Authentication *struct {
						Mode *string `json:"mode,omitempty"`
						X509 *struct {
							ServerKeyFile     *string `json:"server-key-file,omitempty"`
							CrlFile           *string `json:"crl-file,omitempty"`
							ServerKeyPassword *string `json:"server-key-password,omitempty"`
							RemoteCaCertFile  *string `json:"remote-ca-cert-file,omitempty"`
							ServerCertFile    *string `json:"server-cert-file,omitempty"`
							ServerKeyType     *string `json:"server-key-type,omitempty"`
							RemoteId          *string `json:"remote-id,omitempty"`
							LocalId           *string `json:"local-id,omitempty"`
							CaCertFile        *string `json:"ca-cert-file,omitempty"`
						} `json:"x509,omitempty"`
						PreSharedSecret *string `json:"pre-shared-secret,omitempty"`
					} `json:"authentication,omitempty"`
					OperatingMode *string `json:"operating-mode,omitempty"`
					Fragmentation *string `json:"fragmentation,omitempty"`
				} `json:"ike-settings,omitempty"`
				ClientIpPool *struct {
					Subnet  *IPv4Net `json:"subnet,omitempty"`
					Subnet6 *IPv6Net `json:"subnet6,omitempty"`
				} `json:"client-ip-pool,omitempty"`
				Description       *string `json:"description,omitempty"`
				LocalIp           *IPv4   `json:"local-ip,omitempty"`
				CompatibilityMode *string `json:"compatibility-mode,omitempty"`
				EspSettings       *struct {
					Proposal *map[string]struct {
						Encryption *string `json:"encryption,omitempty"`
						Hash       *string `json:"hash,omitempty"`
						DhGroup    *int    `json:"dh-group,omitempty"`
					} `json:"proposal,omitempty"`
				} `json:"esp-settings,omitempty"`
				Authentication *struct {
					Mode       *string `json:"mode,omitempty"`
					LocalUsers *struct {
						Username *map[string]struct {
							Disable  *string `json:"disable,omitempty"`
							Password *string `json:"password,omitempty"`
						} `json:"username,omitempty"`
					} `json:"local-users,omitempty"`
					RadiusServer *map[string]struct {
						Key *string `json:"key,omitempty"`
					} `json:"radius-server,omitempty"`
				} `json:"authentication,omitempty"`
				DhcpInterface *string `json:"dhcp-interface,omitempty"`
			} `json:"remote-access,omitempty"`
			IpsecInterfaces *struct {
				Interface *string `json:"interface,omitempty"`
			} `json:"ipsec-interfaces,omitempty"`
			GlobalConfig *string `json:"global-config,omitempty"`
			IkeGroup     *map[string]struct {
				Mode              *string `json:"mode,omitempty"`
				DeadPeerDetection *struct {
					Interval *int    `json:"interval,omitempty"`
					Timeout  *int    `json:"timeout,omitempty"`
					Action   *string `json:"action,omitempty"`
				} `json:"dead-peer-detection,omitempty"`
				KeyExchange *string `json:"key-exchange,omitempty"`
				Ikev2Reauth *string `json:"ikev2-reauth,omitempty"`
				Lifetime    *int    `json:"lifetime,omitempty"`
				Proposal    *map[string]struct {
					Encryption *string `json:"encryption,omitempty"`
					Hash       *string `json:"hash,omitempty"`
					DhGroup    *int    `json:"dh-group,omitempty"`
				} `json:"proposal,omitempty"`
			} `json:"ike-group,omitempty"`
			EspGroup *map[string]struct {
				Mode     *string `json:"mode,omitempty"`
				Pfs      *string `json:"pfs,omitempty"`
				Lifetime *int    `json:"lifetime,omitempty"`
				Proposal *map[string]struct {
					Encryption *string `json:"encryption,omitempty"`
					Hash       *string `json:"hash,omitempty"`
				} `json:"proposal,omitempty"`
				Compression *string `json:"compression,omitempty"`
			} `json:"esp-group,omitempty"`
			IncludeIpsecSecrets *string `json:"include-ipsec-secrets,omitempty"`
			IncludeIpsecConf    *string `json:"include-ipsec-conf,omitempty"`
			Logging             *struct {
				LogModes *string `json:"log-modes,omitempty"`
				LogLevel *int    `json:"log-level,omitempty"`
			} `json:"logging,omitempty"`
			NatTraversal *string `json:"nat-traversal,omitempty"`
		} `json:"ipsec,omitempty"`
		Pptp *struct {
			RemoteAccess *struct {
				Accounting *struct {
					RadiusServer *map[string]struct {
						Key  *string `json:"key,omitempty"`
						Port *int    `json:"port,omitempty"`
					} `json:"radius-server,omitempty"`
				} `json:"accounting,omitempty"`
				OutsideAddress *IPv4 `json:"outside-address,omitempty"`
				WinsServers    *struct {
					Server2 *IPv4 `json:"server-2,omitempty"`
					Server1 *IPv4 `json:"server-1,omitempty"`
				} `json:"wins-servers,omitempty"`
				DnsServers *struct {
					Server2 *IPv4 `json:"server-2,omitempty"`
					Server1 *IPv4 `json:"server-1,omitempty"`
				} `json:"dns-servers,omitempty"`
				Mtu          *int `json:"mtu,omitempty"`
				ClientIpPool *struct {
					Start *IPv4 `json:"start,omitempty"`
					Stop  *IPv4 `json:"stop,omitempty"`
				} `json:"client-ip-pool,omitempty"`
				LocalIp        *IPv4 `json:"local-ip,omitempty"`
				Authentication *struct {
					Mode       *string `json:"mode,omitempty"`
					LocalUsers *struct {
						Username *map[string]struct {
							Disable  *string `json:"disable,omitempty"`
							Password *string `json:"password,omitempty"`
							StaticIp *IPv4   `json:"static-ip,omitempty"`
						} `json:"username,omitempty"`
					} `json:"local-users,omitempty"`
					RadiusServer *map[string]struct {
						Key  *string `json:"key,omitempty"`
						Port *int    `json:"port,omitempty"`
					} `json:"radius-server,omitempty"`
				} `json:"authentication,omitempty"`
				DhcpInterface *string `json:"dhcp-interface,omitempty"`
			} `json:"remote-access,omitempty"`
		} `json:"pptp,omitempty"`
		L2tp *struct {
			RemoteAccess *struct {
				OutsideNexthop *IPv4 `json:"outside-nexthop,omitempty"`
				Accounting     *struct {
					RadiusServer *map[string]struct {
						Key  *string `json:"key,omitempty"`
						Port *int    `json:"port,omitempty"`
					} `json:"radius-server,omitempty"`
				} `json:"accounting,omitempty"`
				OutsideAddress *IPv4 `json:"outside-address,omitempty"`
				Idle           *int  `json:"idle,omitempty"`
				WinsServers    *struct {
					Server2 *IPv4 `json:"server-2,omitempty"`
					Server1 *IPv4 `json:"server-1,omitempty"`
				} `json:"wins-servers,omitempty"`
				DnsServers *struct {
					Server2 *IPv4 `json:"server-2,omitempty"`
					Server1 *IPv4 `json:"server-1,omitempty"`
				} `json:"dns-servers,omitempty"`
				Mtu          *int `json:"mtu,omitempty"`
				ClientIpPool *struct {
					Start *IPv4 `json:"start,omitempty"`
					Stop  *IPv4 `json:"stop,omitempty"`
				} `json:"client-ip-pool,omitempty"`
				IpsecSettings *struct {
					Lifetime       *int `json:"lifetime,omitempty"`
					IkeLifetime    *int `json:"ike-lifetime,omitempty"`
					Authentication *struct {
						Mode *string `json:"mode,omitempty"`
						X509 *struct {
							ServerKeyFile     *string `json:"server-key-file,omitempty"`
							CrlFile           *string `json:"crl-file,omitempty"`
							ServerKeyPassword *string `json:"server-key-password,omitempty"`
							ServerCertFile    *string `json:"server-cert-file,omitempty"`
							CaCertFile        *string `json:"ca-cert-file,omitempty"`
						} `json:"x509,omitempty"`
						PreSharedSecret *string `json:"pre-shared-secret,omitempty"`
					} `json:"authentication,omitempty"`
					Fragmentation *string `json:"fragmentation,omitempty"`
				} `json:"ipsec-settings,omitempty"`
				Description                     *string `json:"description,omitempty"`
				AllowMultipleClientsFromSameNat *string `json:"allow-multiple-clients-from-same-nat,omitempty"`
				LocalIp                         *IPv4   `json:"local-ip,omitempty"`
				Authentication                  *struct {
					Mode       *string `json:"mode,omitempty"`
					Require    *string `json:"require,omitempty"`
					LocalUsers *struct {
						Username *map[string]struct {
							Disable  *string `json:"disable,omitempty"`
							Password *string `json:"password,omitempty"`
							StaticIp *IPv4   `json:"static-ip,omitempty"`
						} `json:"username,omitempty"`
					} `json:"local-users,omitempty"`
					RadiusServer *map[string]struct {
						Key  *string `json:"key,omitempty"`
						Port *int    `json:"port,omitempty"`
					} `json:"radius-server,omitempty"`
				} `json:"authentication,omitempty"`
				DhcpInterface *string `json:"dhcp-interface,omitempty"`
			} `json:"remote-access,omitempty"`
		} `json:"l2tp,omitempty"`
	} `json:"vpn,omitempty"`
	TrafficPolicy *struct {
		NetworkEmulator *map[string]struct {
			PacketCorruption *string `json:"packet-corruption,omitempty"`
			Bandwidth        *string `json:"bandwidth,omitempty"`
			Burst            *string `json:"burst,omitempty"`
			Description      *string `json:"description,omitempty"`
			QueueLimit       *int    `json:"queue-limit,omitempty"`
			NetworkDelay     *string `json:"network-delay,omitempty"`
			PacketReordering *string `json:"packet-reordering,omitempty"`
			PacketLoss       *string `json:"packet-loss,omitempty"`
		} `json:"network-emulator,omitempty"`
		DropTail *map[string]struct {
			Description *string `json:"description,omitempty"`
			QueueLimit  *int    `json:"queue-limit,omitempty"`
		} `json:"drop-tail,omitempty"`
		RoundRobin *map[string]struct {
			Default *struct {
				QueueType  *string `json:"queue-type,omitempty"`
				QueueLimit *int    `json:"queue-limit,omitempty"`
				Quantum    *int    `json:"quantum,omitempty"`
			} `json:"default,omitempty"`
			Description *string `json:"description,omitempty"`
			Class       *map[string]struct {
				Match *map[string]struct {
					Interface *string `json:"interface,omitempty"`
					Mark      *int    `json:"mark,omitempty"`
					Ether     *struct {
						Source      *MacAddr `json:"source,omitempty"`
						Destination *MacAddr `json:"destination,omitempty"`
						Protocol    *string  `json:"protocol,omitempty"`
					} `json:"ether,omitempty"`
					Description *string `json:"description,omitempty"`
					Vif         *int    `json:"vif,omitempty"`
					Ip          *struct {
						Source *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Source *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ipv6,omitempty"`
				} `json:"match,omitempty"`
				QueueType   *string `json:"queue-type,omitempty"`
				Description *string `json:"description,omitempty"`
				QueueLimit  *int    `json:"queue-limit,omitempty"`
				Quantum     *int    `json:"quantum,omitempty"`
			} `json:"class,omitempty"`
		} `json:"round-robin,omitempty"`
		Limiter *map[string]struct {
			Default *struct {
				Bandwidth *string `json:"bandwidth,omitempty"`
				Burst     *string `json:"burst,omitempty"`
			} `json:"default,omitempty"`
			Description *string `json:"description,omitempty"`
			Class       *map[string]struct {
				Bandwidth *string `json:"bandwidth,omitempty"`
				Match     *map[string]struct {
					Ether *struct {
						Source      *MacAddr `json:"source,omitempty"`
						Destination *MacAddr `json:"destination,omitempty"`
						Protocol    *string  `json:"protocol,omitempty"`
					} `json:"ether,omitempty"`
					Description *string `json:"description,omitempty"`
					Vif         *int    `json:"vif,omitempty"`
					Ip          *struct {
						Source *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Source *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ipv6,omitempty"`
				} `json:"match,omitempty"`
				Burst       *string `json:"burst,omitempty"`
				Description *string `json:"description,omitempty"`
				Priority    *int    `json:"priority,omitempty"`
			} `json:"class,omitempty"`
		} `json:"limiter,omitempty"`
		FairQueue *map[string]struct {
			HashInterval *int    `json:"hash-interval,omitempty"`
			Description  *string `json:"description,omitempty"`
			QueueLimit   *int    `json:"queue-limit,omitempty"`
		} `json:"fair-queue,omitempty"`
		RateControl *map[string]struct {
			Bandwidth   *string `json:"bandwidth,omitempty"`
			Burst       *string `json:"burst,omitempty"`
			Latency     *string `json:"latency,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"rate-control,omitempty"`
		Shaper *map[string]struct {
			Bandwidth *string `json:"bandwidth,omitempty"`
			Default   *struct {
				Bandwidth  *string `json:"bandwidth,omitempty"`
				Burst      *string `json:"burst,omitempty"`
				Ceiling    *string `json:"ceiling,omitempty"`
				QueueType  *string `json:"queue-type,omitempty"`
				Priority   *int    `json:"priority,omitempty"`
				QueueLimit *int    `json:"queue-limit,omitempty"`
				SetDscp    *string `json:".set-dscp,omitempty"`
			} `json:"default,omitempty"`
			Description *string `json:"description,omitempty"`
			Class       *map[string]struct {
				Bandwidth *string `json:"bandwidth,omitempty"`
				Match     *map[string]struct {
					Interface *string `json:"interface,omitempty"`
					Mark      *string `json:"mark,omitempty"`
					Ether     *struct {
						Source      *MacAddr `json:"source,omitempty"`
						Destination *MacAddr `json:"destination,omitempty"`
						Protocol    *string  `json:"protocol,omitempty"`
					} `json:"ether,omitempty"`
					Description *string `json:"description,omitempty"`
					Vif         *int    `json:"vif,omitempty"`
					Ip          *struct {
						Source *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Source *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ipv6,omitempty"`
				} `json:"match,omitempty"`
				Burst       *string `json:"burst,omitempty"`
				Ceiling     *string `json:"ceiling,omitempty"`
				QueueType   *string `json:"queue-type,omitempty"`
				Description *string `json:"description,omitempty"`
				Priority    *int    `json:"priority,omitempty"`
				QueueLimit  *int    `json:"queue-limit,omitempty"`
				SetDscp     *string `json:".set-dscp,omitempty"`
			} `json:"class,omitempty"`
		} `json:"shaper,omitempty"`
		PriorityQueue *map[string]struct {
			Default *struct {
				QueueType  *string `json:"queue-type,omitempty"`
				QueueLimit *int    `json:"queue-limit,omitempty"`
			} `json:"default,omitempty"`
			Description *string `json:"description,omitempty"`
			Class       *map[string]struct {
				Match *map[string]struct {
					Interface *string `json:"interface,omitempty"`
					Mark      *int    `json:"mark,omitempty"`
					Ether     *struct {
						Source      *MacAddr `json:"source,omitempty"`
						Destination *MacAddr `json:"destination,omitempty"`
						Protocol    *string  `json:"protocol,omitempty"`
					} `json:"ether,omitempty"`
					Description *string `json:"description,omitempty"`
					Vif         *int    `json:"vif,omitempty"`
					Ip          *struct {
						Source *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Source *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv6Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Dscp     *string `json:"dscp,omitempty"`
					} `json:"ipv6,omitempty"`
				} `json:"match,omitempty"`
				QueueType   *string `json:"queue-type,omitempty"`
				Description *string `json:"description,omitempty"`
				QueueLimit  *int    `json:"queue-limit,omitempty"`
			} `json:"class,omitempty"`
		} `json:"priority-queue,omitempty"`
		RandomDetect *map[string]struct {
			Bandwidth   *string `json:"bandwidth,omitempty"`
			Description *string `json:"description,omitempty"`
			Precedence  *map[string]struct {
				MarkProbability  *int `json:"mark-probability,omitempty"`
				MinimumThreshold *int `json:"minimum-threshold,omitempty"`
				AveragePacket    *int `json:"average-packet,omitempty"`
				QueueLimit       *int `json:"queue-limit,omitempty"`
				MaximumThreshold *int `json:"maximum-threshold,omitempty"`
			} `json:"precedence,omitempty"`
		} `json:"random-detect,omitempty"`
	} `json:"traffic-policy,omitempty"`
	Firewall *struct {
		Options *struct {
			MssClamp *struct {
				Mss           *int    `json:"mss,omitempty"`
				InterfaceType *string `json:"interface-type,omitempty"`
			} `json:"mss-clamp,omitempty"`
			MssClamp6 *struct {
				Mss           *int    `json:"mss,omitempty"`
				InterfaceType *string `json:"interface-type,omitempty"`
			} `json:"mss-clamp6,omitempty"`
		} `json:"options,omitempty"`
		IpSrcRoute    *string `json:"ip-src-route,omitempty"`
		SendRedirects *string `json:"send-redirects,omitempty"`
		Group         *struct {
			AddressGroup *map[string]struct {
				Description *string `json:"description,omitempty"`
				Address     *string `json:"address,omitempty"`
			} `json:"address-group,omitempty"`
			PortGroup *map[string]struct {
				Description *string `json:"description,omitempty"`
				Port        *string `json:"port,omitempty"`
			} `json:"port-group,omitempty"`
			NetworkGroup *map[string]struct {
				Network     *IPv4Net `json:"network,omitempty"`
				Description *string  `json:"description,omitempty"`
			} `json:"network-group,omitempty"`
			Ipv6AddressGroup *map[string]struct {
				Ipv6Address *IPv6Net `json:"ipv6-address,omitempty"`
				Description *string  `json:"description,omitempty"`
			} `json:"ipv6-address-group,omitempty"`
			Ipv6NetworkGroup *map[string]struct {
				Description *string  `json:"description,omitempty"`
				Ipv6Network *IPv6Net `json:"ipv6-network,omitempty"`
			} `json:"ipv6-network-group,omitempty"`
		} `json:"group,omitempty"`
		Ipv6ReceiveRedirects *string `json:"ipv6-receive-redirects,omitempty"`
		AllPing              *string `json:"all-ping,omitempty"`
		SynCookies           *string `json:"syn-cookies,omitempty"`
		Modify               *map[string]struct {
			Rule *map[string]struct {
				Disable *string `json:"disable,omitempty"`
				Limit   *struct {
					Rate  *string `json:"rate,omitempty"`
					Burst *int    `json:"burst,omitempty"`
				} `json:"limit,omitempty"`
				Source *struct {
					Group *struct {
						AddressGroup *string `json:"address-group,omitempty"`
						PortGroup    *string `json:"port-group,omitempty"`
						NetworkGroup *string `json:"network-group,omitempty"`
					} `json:"group,omitempty"`
					MacAddress *string `json:"mac-address,omitempty"`
					Address    *string `json:"address,omitempty"`
					Port       *string `json:"port,omitempty"`
				} `json:"source,omitempty"`
				Mark   *string `json:"mark,omitempty"`
				Modify *struct {
					TcpMss   *string `json:"tcp-mss,omitempty"`
					Mark     *string `json:"mark,omitempty"`
					Table    *string `json:"table,omitempty"`
					Connmark *struct {
						SaveMark    *string `json:"save-mark,omitempty"`
						RestoreMark *string `json:"restore-mark,omitempty"`
						SetMark     *int    `json:"set-mark,omitempty"`
					} `json:"connmark,omitempty"`
					Dscp    *int    `json:"dscp,omitempty"`
					LbGroup *string `json:"lb-group,omitempty"`
				} `json:"modify,omitempty"`
				Destination *struct {
					Group *struct {
						AddressGroup *string `json:"address-group,omitempty"`
						PortGroup    *string `json:"port-group,omitempty"`
						NetworkGroup *string `json:"network-group,omitempty"`
					} `json:"group,omitempty"`
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"destination,omitempty"`
				Protocol *string `json:"protocol,omitempty"`
				State    *struct {
					Related     *string `json:"related,omitempty"`
					Invalid     *string `json:"invalid,omitempty"`
					Established *string `json:"established,omitempty"`
					New         *string `json:"new,omitempty"`
				} `json:"state,omitempty"`
				Time *struct {
					Stopdate   *string `json:"stopdate,omitempty"`
					Contiguous *string `json:"contiguous,omitempty"`
					Starttime  *string `json:"starttime,omitempty"`
					Stoptime   *string `json:"stoptime,omitempty"`
					Weekdays   *string `json:"weekdays,omitempty"`
					Utc        *string `json:"utc,omitempty"`
					Startdate  *string `json:"startdate,omitempty"`
					Monthdays  *string `json:"monthdays,omitempty"`
				} `json:"time,omitempty"`
				Ipsec *struct {
					MatchNone  *string `json:"match-none,omitempty"`
					MatchIpsec *string `json:"match-ipsec,omitempty"`
				} `json:"ipsec,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
				Tcp         *struct {
					Flags *string `json:"flags,omitempty"`
				} `json:"tcp,omitempty"`
				Fragment *struct {
					MatchNonFrag *string `json:"match-non-frag,omitempty"`
					MatchFrag    *string `json:"match-frag,omitempty"`
				} `json:"fragment,omitempty"`
				Icmp *struct {
					Code     *int    `json:"code,omitempty"`
					TypeName *string `json:"type-name,omitempty"`
					Type     *int    `json:"type,omitempty"`
				} `json:"icmp,omitempty"`
				P2p *struct {
					Bittorrent    *string `json:"bittorrent,omitempty"`
					Gnutella      *string `json:"gnutella,omitempty"`
					All           *string `json:"all,omitempty"`
					Applejuice    *string `json:"applejuice,omitempty"`
					Edonkey       *string `json:"edonkey,omitempty"`
					Kazaa         *string `json:"kazaa,omitempty"`
					Directconnect *string `json:"directconnect,omitempty"`
				} `json:"p2p,omitempty"`
				Connmark    *string `json:"connmark,omitempty"`
				Log         *string `json:"log,omitempty"`
				Application *struct {
					Category       *string `json:"category,omitempty"`
					CustomCategory *string `json:"custom-category,omitempty"`
				} `json:"application,omitempty"`
				Dscp      *int `json:"dscp,omitempty"`
				Statistic *struct {
					Probability *string `json:"probability,omitempty"`
				} `json:"statistic,omitempty"`
				Recent *struct {
					Count *int `json:"count,omitempty"`
					Time  *int `json:"time,omitempty"`
				} `json:"recent,omitempty"`
			} `json:"rule,omitempty"`
			Description      *string `json:"description,omitempty"`
			EnableDefaultLog *string `json:"enable-default-log,omitempty"`
		} `json:"modify,omitempty"`
		BroadcastPing *string `json:"broadcast-ping,omitempty"`
		LogMartians   *string `json:"log-martians,omitempty"`
		Ipv6Modify    *map[string]struct {
			Rule *map[string]struct {
				Disable *string `json:"disable,omitempty"`
				Icmpv6  *struct {
					Type *string `json:"type,omitempty"`
				} `json:"icmpv6,omitempty"`
				Limit *struct {
					Rate  *string `json:"rate,omitempty"`
					Burst *int    `json:"burst,omitempty"`
				} `json:"limit,omitempty"`
				Source *struct {
					Group *struct {
						PortGroup        *string `json:"port-group,omitempty"`
						Ipv6AddressGroup *string `json:"ipv6-address-group,omitempty"`
						Ipv6NetworkGroup *string `json:"ipv6-network-group,omitempty"`
					} `json:"group,omitempty"`
					MacAddress *string `json:"mac-address,omitempty"`
					Address    *string `json:"address,omitempty"`
					Port       *string `json:"port,omitempty"`
				} `json:"source,omitempty"`
				Mark   *string `json:"mark,omitempty"`
				Modify *struct {
					TcpMss   *string `json:"tcp-mss,omitempty"`
					Mark     *string `json:"mark,omitempty"`
					Table    *string `json:"table,omitempty"`
					Connmark *struct {
						SaveMark    *string `json:"save-mark,omitempty"`
						RestoreMark *string `json:"restore-mark,omitempty"`
						SetMark     *int    `json:"set-mark,omitempty"`
					} `json:"connmark,omitempty"`
					Dscp *int `json:"dscp,omitempty"`
				} `json:"modify,omitempty"`
				Destination *struct {
					Group *struct {
						PortGroup        *string `json:"port-group,omitempty"`
						Ipv6AddressGroup *string `json:"ipv6-address-group,omitempty"`
						Ipv6NetworkGroup *string `json:"ipv6-network-group,omitempty"`
					} `json:"group,omitempty"`
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"destination,omitempty"`
				Protocol *string `json:"protocol,omitempty"`
				State    *struct {
					Related     *string `json:"related,omitempty"`
					Invalid     *string `json:"invalid,omitempty"`
					Established *string `json:"established,omitempty"`
					New         *string `json:"new,omitempty"`
				} `json:"state,omitempty"`
				Time *struct {
					Stopdate   *string `json:"stopdate,omitempty"`
					Contiguous *string `json:"contiguous,omitempty"`
					Starttime  *string `json:"starttime,omitempty"`
					Stoptime   *string `json:"stoptime,omitempty"`
					Weekdays   *string `json:"weekdays,omitempty"`
					Utc        *string `json:"utc,omitempty"`
					Startdate  *string `json:"startdate,omitempty"`
					Monthdays  *string `json:"monthdays,omitempty"`
				} `json:"time,omitempty"`
				Ipsec *struct {
					MatchNone  *string `json:"match-none,omitempty"`
					MatchIpsec *string `json:"match-ipsec,omitempty"`
				} `json:"ipsec,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
				Tcp         *struct {
					Flags *string `json:"flags,omitempty"`
				} `json:"tcp,omitempty"`
				P2p *struct {
					Bittorrent    *string `json:"bittorrent,omitempty"`
					Gnutella      *string `json:"gnutella,omitempty"`
					All           *string `json:"all,omitempty"`
					Applejuice    *string `json:"applejuice,omitempty"`
					Edonkey       *string `json:"edonkey,omitempty"`
					Kazaa         *string `json:"kazaa,omitempty"`
					Directconnect *string `json:"directconnect,omitempty"`
				} `json:"p2p,omitempty"`
				Connmark *string `json:"connmark,omitempty"`
				Log      *string `json:"log,omitempty"`
				Dscp     *int    `json:"dscp,omitempty"`
				Recent   *struct {
					Count *int `json:"count,omitempty"`
					Time  *int `json:"time,omitempty"`
				} `json:"recent,omitempty"`
			} `json:"rule,omitempty"`
			Description      *string `json:"description,omitempty"`
			EnableDefaultLog *string `json:"enable-default-log,omitempty"`
		} `json:"ipv6-modify,omitempty"`
		SourceValidation *string `json:"source-validation,omitempty"`
		Name             *map[string]struct {
			DefaultAction *string `json:"default-action,omitempty"`
			Rule          *map[string]struct {
				Disable *string `json:"disable,omitempty"`
				Limit   *struct {
					Rate  *string `json:"rate,omitempty"`
					Burst *int    `json:"burst,omitempty"`
				} `json:"limit,omitempty"`
				Source *struct {
					Group *struct {
						AddressGroup *string `json:"address-group,omitempty"`
						PortGroup    *string `json:"port-group,omitempty"`
						NetworkGroup *string `json:"network-group,omitempty"`
					} `json:"group,omitempty"`
					MacAddress *string `json:"mac-address,omitempty"`
					Address    *string `json:"address,omitempty"`
					Port       *string `json:"port,omitempty"`
				} `json:"source,omitempty"`
				Mark        *string `json:"mark,omitempty"`
				Destination *struct {
					Group *struct {
						AddressGroup *string `json:"address-group,omitempty"`
						PortGroup    *string `json:"port-group,omitempty"`
						NetworkGroup *string `json:"network-group,omitempty"`
					} `json:"group,omitempty"`
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"destination,omitempty"`
				Protocol *string `json:"protocol,omitempty"`
				State    *struct {
					Related     *string `json:"related,omitempty"`
					Invalid     *string `json:"invalid,omitempty"`
					Established *string `json:"established,omitempty"`
					New         *string `json:"new,omitempty"`
				} `json:"state,omitempty"`
				Time *struct {
					Stopdate   *string `json:"stopdate,omitempty"`
					Contiguous *string `json:"contiguous,omitempty"`
					Starttime  *string `json:"starttime,omitempty"`
					Stoptime   *string `json:"stoptime,omitempty"`
					Weekdays   *string `json:"weekdays,omitempty"`
					Utc        *string `json:"utc,omitempty"`
					Startdate  *string `json:"startdate,omitempty"`
					Monthdays  *string `json:"monthdays,omitempty"`
				} `json:"time,omitempty"`
				Ipsec *struct {
					MatchNone  *string `json:"match-none,omitempty"`
					MatchIpsec *string `json:"match-ipsec,omitempty"`
				} `json:"ipsec,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
				Tcp         *struct {
					Flags *string `json:"flags,omitempty"`
				} `json:"tcp,omitempty"`
				Fragment *struct {
					MatchNonFrag *string `json:"match-non-frag,omitempty"`
					MatchFrag    *string `json:"match-frag,omitempty"`
				} `json:"fragment,omitempty"`
				Icmp *struct {
					Code     *int    `json:"code,omitempty"`
					TypeName *string `json:"type-name,omitempty"`
					Type     *int    `json:"type,omitempty"`
				} `json:"icmp,omitempty"`
				P2p *struct {
					Bittorrent    *string `json:"bittorrent,omitempty"`
					Gnutella      *string `json:"gnutella,omitempty"`
					All           *string `json:"all,omitempty"`
					Applejuice    *string `json:"applejuice,omitempty"`
					Edonkey       *string `json:"edonkey,omitempty"`
					Kazaa         *string `json:"kazaa,omitempty"`
					Directconnect *string `json:"directconnect,omitempty"`
				} `json:"p2p,omitempty"`
				Log         *string `json:"log,omitempty"`
				Application *struct {
					Category       *string `json:"category,omitempty"`
					CustomCategory *string `json:"custom-category,omitempty"`
				} `json:"application,omitempty"`
				Dscp   *int `json:"dscp,omitempty"`
				Recent *struct {
					Count *int `json:"count,omitempty"`
					Time  *int `json:"time,omitempty"`
				} `json:"recent,omitempty"`
			} `json:"rule,omitempty"`
			Description      *string `json:"description,omitempty"`
			EnableDefaultLog *string `json:"enable-default-log,omitempty"`
		} `json:"name,omitempty"`
		Ipv6SrcRoute     *string `json:"ipv6-src-route,omitempty"`
		ReceiveRedirects *string `json:"receive-redirects,omitempty"`
		Ipv6Name         *map[string]struct {
			DefaultAction *string `json:"default-action,omitempty"`
			Rule          *map[string]struct {
				Disable *string `json:"disable,omitempty"`
				Icmpv6  *struct {
					Type *string `json:"type,omitempty"`
				} `json:"icmpv6,omitempty"`
				Limit *struct {
					Rate  *string `json:"rate,omitempty"`
					Burst *int    `json:"burst,omitempty"`
				} `json:"limit,omitempty"`
				Source *struct {
					Group *struct {
						PortGroup        *string `json:"port-group,omitempty"`
						Ipv6AddressGroup *string `json:"ipv6-address-group,omitempty"`
						Ipv6NetworkGroup *string `json:"ipv6-network-group,omitempty"`
					} `json:"group,omitempty"`
					MacAddress *string `json:"mac-address,omitempty"`
					Address    *string `json:"address,omitempty"`
					Port       *string `json:"port,omitempty"`
				} `json:"source,omitempty"`
				Mark        *string `json:"mark,omitempty"`
				Destination *struct {
					Group *struct {
						PortGroup        *string `json:"port-group,omitempty"`
						Ipv6AddressGroup *string `json:"ipv6-address-group,omitempty"`
						Ipv6NetworkGroup *string `json:"ipv6-network-group,omitempty"`
					} `json:"group,omitempty"`
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"destination,omitempty"`
				Protocol *string `json:"protocol,omitempty"`
				State    *struct {
					Related     *string `json:"related,omitempty"`
					Invalid     *string `json:"invalid,omitempty"`
					Established *string `json:"established,omitempty"`
					New         *string `json:"new,omitempty"`
				} `json:"state,omitempty"`
				Time *struct {
					Stopdate   *string `json:"stopdate,omitempty"`
					Contiguous *string `json:"contiguous,omitempty"`
					Starttime  *string `json:"starttime,omitempty"`
					Stoptime   *string `json:"stoptime,omitempty"`
					Weekdays   *string `json:"weekdays,omitempty"`
					Utc        *string `json:"utc,omitempty"`
					Startdate  *string `json:"startdate,omitempty"`
					Monthdays  *string `json:"monthdays,omitempty"`
				} `json:"time,omitempty"`
				Ipsec *struct {
					MatchNone  *string `json:"match-none,omitempty"`
					MatchIpsec *string `json:"match-ipsec,omitempty"`
				} `json:"ipsec,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
				Tcp         *struct {
					Flags *string `json:"flags,omitempty"`
				} `json:"tcp,omitempty"`
				P2p *struct {
					Bittorrent    *string `json:"bittorrent,omitempty"`
					Gnutella      *string `json:"gnutella,omitempty"`
					All           *string `json:"all,omitempty"`
					Applejuice    *string `json:"applejuice,omitempty"`
					Edonkey       *string `json:"edonkey,omitempty"`
					Kazaa         *string `json:"kazaa,omitempty"`
					Directconnect *string `json:"directconnect,omitempty"`
				} `json:"p2p,omitempty"`
				Log    *string `json:"log,omitempty"`
				Dscp   *int    `json:"dscp,omitempty"`
				Recent *struct {
					Count *int `json:"count,omitempty"`
					Time  *int `json:"time,omitempty"`
				} `json:"recent,omitempty"`
			} `json:"rule,omitempty"`
			Description      *string `json:"description,omitempty"`
			EnableDefaultLog *string `json:"enable-default-log,omitempty"`
		} `json:"ipv6-name,omitempty"`
	} `json:"firewall,omitempty"`
	System *struct {
		Options *struct {
			RebootOnPanic *bool `json:"reboot-on-panic,omitempty"`
		} `json:"options,omitempty"`
		Syslog *struct {
			Host *map[string]struct {
				Facility *map[string]struct {
					Level *string `json:"level,omitempty"`
				} `json:"facility,omitempty"`
			} `json:"host,omitempty"`
			File *map[string]struct {
				Archive *struct {
					Files *int `json:"files,omitempty"`
					Size  *int `json:"size,omitempty"`
				} `json:"archive,omitempty"`
				Facility *map[string]struct {
					Level *string `json:"level,omitempty"`
				} `json:"facility,omitempty"`
			} `json:"file,omitempty"`
			User *map[string]struct {
				Facility *map[string]struct {
					Level *string `json:"level,omitempty"`
				} `json:"facility,omitempty"`
			} `json:"user,omitempty"`
			Global *struct {
				Archive *struct {
					Files *int `json:"files,omitempty"`
					Size  *int `json:"size,omitempty"`
				} `json:"archive,omitempty"`
				Facility *map[string]struct {
					Level *string `json:"level,omitempty"`
				} `json:"facility,omitempty"`
			} `json:"global,omitempty"`
			Console *struct {
				Facility *map[string]struct {
					Level *string `json:"level,omitempty"`
				} `json:"facility,omitempty"`
			} `json:"console,omitempty"`
		} `json:"syslog,omitempty"`
		FlowAccounting *struct {
			Netflow *struct {
				EngineId     *int    `json:"engine-id,omitempty"`
				SamplingRate *int    `json:"sampling-rate,omitempty"`
				Mode         *string `json:"mode,omitempty"`
				Timeout      *struct {
					TcpFin         *int `json:"tcp-fin,omitempty"`
					Udp            *int `json:"udp,omitempty"`
					FlowGeneric    *int `json:"flow-generic,omitempty"`
					MaxActiveLife  *int `json:"max-active-life,omitempty"`
					TcpRst         *int `json:"tcp-rst,omitempty"`
					Icmp           *int `json:"icmp,omitempty"`
					TcpGeneric     *int `json:"tcp-generic,omitempty"`
					ExpiryInterval *int `json:"expiry-interval,omitempty"`
				} `json:"timeout,omitempty"`
				Server *map[string]struct {
					Port *int `json:"port,omitempty"`
				} `json:"server,omitempty"`
				Version      *string `json:"version,omitempty"`
				EnableEgress *struct {
					EngineId *int `json:"engine-id,omitempty"`
				} `json:"enable-egress,omitempty"`
			} `json:"netflow,omitempty"`
			Interface *string `json:"interface,omitempty"`
			Sflow     *struct {
				SamplingRate *int    `json:"sampling-rate,omitempty"`
				AgentAddress *string `json:"agent-address,omitempty"`
				Agentid      *int    `json:".agentid,omitempty"`
				Server       *map[string]struct {
					Port *int `json:"port,omitempty"`
				} `json:"server,omitempty"`
			} `json:"sflow,omitempty"`
			Aggregate *struct {
				Egress  *string `json:"egress,omitempty"`
				Ingress *string `json:"ingress,omitempty"`
			} `json:"aggregate,omitempty"`
			Unms *struct {
				Exclude *string `json:"exclude,omitempty"`
				Subnets *string `json:"subnets,omitempty"`
			} `json:"unms,omitempty"`
			IngressCapture     *string `json:"ingress-capture,omitempty"`
			SyslogFacility     *string `json:"syslog-facility,omitempty"`
			DisableMemoryTable *string `json:"disable-memory-table,omitempty"`
		} `json:"flow-accounting,omitempty"`
		GatewayAddress *IPv4 `json:"gateway-address,omitempty"`
		TaskScheduler  *struct {
			Task *map[string]struct {
				Executable *struct {
					Path      *string `json:"path,omitempty"`
					Arguments *string `json:"arguments,omitempty"`
				} `json:"executable,omitempty"`
				CrontabSpec *string `json:"crontab-spec,omitempty"`
				Interval    *string `json:"interval,omitempty"`
			} `json:"task,omitempty"`
		} `json:"task-scheduler,omitempty"`
		AnalyticsHandler *struct {
			SendAnalyticsReport *bool `json:"send-analytics-report,omitempty"`
		} `json:"analytics-handler,omitempty"`
		TimeZone *string `json:"time-zone,omitempty"`
		Systemd  *struct {
			Journal *struct {
				RateLimitBurst    *int    `json:"rate-limit-burst,omitempty"`
				MaxRetention      *int    `json:"max-retention,omitempty"`
				RuntimeMaxUse     *int    `json:"runtime-max-use,omitempty"`
				Storage           *string `json:"storage,omitempty"`
				RateLimitInterval *int    `json:"rate-limit-interval,omitempty"`
			} `json:"journal,omitempty"`
		} `json:"systemd,omitempty"`
		Conntrack *struct {
			Ignore *struct {
				Rule *map[string]struct {
					InboundInterface *string `json:"inbound-interface,omitempty"`
					Source           *struct {
						Address *string `json:"address,omitempty"`
						Port    *string `json:"port,omitempty"`
					} `json:"source,omitempty"`
					Destination *struct {
						Address *string `json:"address,omitempty"`
						Port    *string `json:"port,omitempty"`
					} `json:"destination,omitempty"`
					Protocol    *string `json:"protocol,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"rule,omitempty"`
			} `json:"ignore,omitempty"`
			Timeout *struct {
				Udp *struct {
					Stream *int `json:"stream,omitempty"`
					Other  *int `json:"other,omitempty"`
				} `json:"udp,omitempty"`
				Other *int `json:"other,omitempty"`
				Tcp   *struct {
					FinWait     *int `json:"fin-wait,omitempty"`
					TimeWait    *int `json:"time-wait,omitempty"`
					Close       *int `json:"close,omitempty"`
					SynSent     *int `json:"syn-sent,omitempty"`
					Established *int `json:"established,omitempty"`
					SynRecv     *int `json:"syn-recv,omitempty"`
					LastAck     *int `json:"last-ack,omitempty"`
					CloseWait   *int `json:"close-wait,omitempty"`
				} `json:"tcp,omitempty"`
				Icmp   *int `json:"icmp,omitempty"`
				Custom *struct {
					Rule *map[string]struct {
						Source *struct {
							Address *string `json:"address,omitempty"`
							Port    *string `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *string `json:"address,omitempty"`
							Port    *string `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *struct {
							Udp *struct {
								Stream *int `json:"stream,omitempty"`
								Other  *int `json:"other,omitempty"`
							} `json:"udp,omitempty"`
							Other *int `json:"other,omitempty"`
							Tcp   *struct {
								FinWait     *int `json:"fin-wait,omitempty"`
								TimeWait    *int `json:"time-wait,omitempty"`
								Close       *int `json:"close,omitempty"`
								SynSent     *int `json:"syn-sent,omitempty"`
								Established *int `json:"established,omitempty"`
								SynRecv     *int `json:"syn-recv,omitempty"`
								LastAck     *int `json:"last-ack,omitempty"`
								CloseWait   *int `json:"close-wait,omitempty"`
							} `json:"tcp,omitempty"`
							Icmp *int `json:"icmp,omitempty"`
						} `json:"protocol,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"rule,omitempty"`
				} `json:".custom,omitempty"`
			} `json:"timeout,omitempty"`
			Tcp *struct {
				Loose               *string `json:"loose,omitempty"`
				HalfOpenConnections *int    `json:"half-open-connections,omitempty"`
				MaxRetrans          *int    `json:"max-retrans,omitempty"`
			} `json:"tcp,omitempty"`
			Log *struct {
				Udp *struct {
					Destroy *string `json:"destroy,omitempty"`
					Update  *string `json:"update,omitempty"`
					New     *string `json:"new,omitempty"`
				} `json:"udp,omitempty"`
				Other *struct {
					Destroy *string `json:"destroy,omitempty"`
					Update  *string `json:"update,omitempty"`
					New     *string `json:"new,omitempty"`
				} `json:"other,omitempty"`
				Tcp *struct {
					Destroy *string `json:"destroy,omitempty"`
					Update  *struct {
						FinWait     *string `json:"fin-wait,omitempty"`
						TimeWait    *string `json:"time-wait,omitempty"`
						Established *string `json:"established,omitempty"`
						SynReceived *string `json:"syn-received,omitempty"`
						LastAck     *string `json:"last-ack,omitempty"`
						CloseWait   *string `json:"close-wait,omitempty"`
					} `json:"update,omitempty"`
					New *string `json:"new,omitempty"`
				} `json:"tcp,omitempty"`
				Icmp *struct {
					Destroy *string `json:"destroy,omitempty"`
					Update  *string `json:"update,omitempty"`
					New     *string `json:"new,omitempty"`
				} `json:"icmp,omitempty"`
			} `json:"log,omitempty"`
			Modules *struct {
				Ftp *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:"ftp,omitempty"`
				Nfs *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:".nfs,omitempty"`
				Rtsp *struct {
					Enable *string `json:"enable,omitempty"`
				} `json:"rtsp,omitempty"`
				Gre *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:"gre,omitempty"`
				Tftp *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:"tftp,omitempty"`
				Pptp *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:"pptp,omitempty"`
				Sqlnet *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:".sqlnet,omitempty"`
				Sip *struct {
					Disable                  *string `json:"disable,omitempty"`
					EnableIndirectSignalling *string `json:"enable-indirect-signalling,omitempty"`
					EnableIndirectMedia      *string `json:"enable-indirect-media,omitempty"`
					Port                     *int    `json:"port,omitempty"`
				} `json:"sip,omitempty"`
				H323 *struct {
					Disable *string `json:"disable,omitempty"`
				} `json:"h323,omitempty"`
			} `json:"modules,omitempty"`
			HashSize        *int `json:"hash-size,omitempty"`
			TableSize       *int `json:"table-size,omitempty"`
			ExpectTableSize *int `json:"expect-table-size,omitempty"`
		} `json:"conntrack,omitempty"`
		NameServer        *IP     `json:"name-server,omitempty"`
		DomainName        *string `json:"domain-name,omitempty"`
		StaticHostMapping *struct {
			HostName *map[string]struct {
				Alias *string `json:"alias,omitempty"`
				Inet  *IP     `json:"inet,omitempty"`
			} `json:"host-name,omitempty"`
		} `json:"static-host-mapping,omitempty"`
		HostName *string `json:"host-name,omitempty"`
		Ntp      *struct {
			Server *map[string]struct {
				Prefer   *string `json:"prefer,omitempty"`
				Preempt  *string `json:"preempt,omitempty"`
				Noselect *string `json:"noselect,omitempty"`
			} `json:"server,omitempty"`
		} `json:"ntp,omitempty"`
		Coredump *struct {
			Enabled *bool `json:"enabled,omitempty"`
		} `json:"coredump,omitempty"`
		DomainSearch *struct {
			Domain *string `json:"domain,omitempty"`
		} `json:"domain-search,omitempty"`
		ConfigManagement *struct {
			CommitRevisions *int `json:"commit-revisions,omitempty"`
			CommitArchive   *struct {
				Location *string `json:"location,omitempty"`
			} `json:"commit-archive,omitempty"`
		} `json:"config-management,omitempty"`
		TrafficAnalysis *struct {
			SignatureUpdate *struct {
				Disable    *string `json:"disable,omitempty"`
				UpdateHour *int    `json:"update-hour,omitempty"`
			} `json:"signature-update,omitempty"`
			Dpi            *string `json:"dpi,omitempty"`
			CustomCategory *map[string]struct {
				Name *string `json:"name,omitempty"`
			} `json:"custom-category,omitempty"`
			Export *string `json:"export,omitempty"`
		} `json:"traffic-analysis,omitempty"`
		CrashHandler *struct {
			SaveCoreFile    *bool `json:"save-core-file,omitempty"`
			SendCrashReport *bool `json:"send-crash-report,omitempty"`
		} `json:"crash-handler,omitempty"`
		Ip *struct {
			DisableForwarding  *string `json:"disable-forwarding,omitempty"`
			OverrideHostnameIp *IPv4   `json:"override-hostname-ip,omitempty"`
			Arp                *struct {
				StaleTime         *int `json:"stale-time,omitempty"`
				BaseReachableTime *int `json:"base-reachable-time,omitempty"`
				TableSize         *int `json:"table-size,omitempty"`
			} `json:"arp,omitempty"`
		} `json:"ip,omitempty"`
		Ipv6 *struct {
			Disable  *string `json:"disable,omitempty"`
			Neighbor *struct {
				StaleTime         *int `json:"stale-time,omitempty"`
				BaseReachableTime *int `json:"base-reachable-time,omitempty"`
				TableSize         *int `json:"table-size,omitempty"`
			} `json:"neighbor,omitempty"`
			DisableForwarding *string `json:"disable-forwarding,omitempty"`
			Blacklist         *string `json:"blacklist,omitempty"`
			StrictDad         *string `json:"strict-dad,omitempty"`
		} `json:"ipv6,omitempty"`
		Login *struct {
			RadiusServer *map[string]struct {
				Timeout *int    `json:"timeout,omitempty"`
				Secret  *string `json:"secret,omitempty"`
				Port    *int    `json:"port,omitempty"`
			} `json:"radius-server,omitempty"`
			User *map[string]struct {
				Group          *string `json:"group,omitempty"`
				HomeDirectory  *string `json:"home-directory,omitempty"`
				Level          *string `json:"level,omitempty"`
				FullName       *string `json:"full-name,omitempty"`
				Authentication *struct {
					EncryptedPassword *string `json:"encrypted-password,omitempty"`
					PublicKeys        *map[string]struct {
						Options *string `json:"options,omitempty"`
						Key     *string `json:"key,omitempty"`
						Type    *string `json:"type,omitempty"`
					} `json:"public-keys,omitempty"`
					PlaintextPassword *string `json:"plaintext-password,omitempty"`
				} `json:"authentication,omitempty"`
			} `json:"user,omitempty"`
			Banner *struct {
				PostLogin *string `json:"post-login,omitempty"`
				PreLogin  *string `json:"pre-login,omitempty"`
			} `json:"banner,omitempty"`
		} `json:"login,omitempty"`
		PacketRxCoreNum *string `json:"packet-rx-core-num,omitempty"`
		Package         *struct {
			Repository *map[string]struct {
				Password     *string `json:"password,omitempty"`
				Distribution *string `json:"distribution,omitempty"`
				Url          *string `json:"url,omitempty"`
				Components   *string `json:"components,omitempty"`
				Description  *string `json:"description,omitempty"`
				Username     *string `json:"username,omitempty"`
			} `json:"repository,omitempty"`
			AutoSync *int `json:".auto-sync,omitempty"`
		} `json:"package,omitempty"`
		Offload *struct {
			Hwnat *string `json:"hwnat,omitempty"`
			Ipv4  *struct {
				DisableFlowFlushingUponFibChanges *string `json:"disable-flow-flushing-upon-fib-changes,omitempty"`
				Bonding                           *string `json:"bonding,omitempty"`
				Pppoe                             *string `json:"pppoe,omitempty"`
				Forwarding                        *string `json:"forwarding,omitempty"`
				Gre                               *string `json:"gre,omitempty"`
				Vlan                              *string `json:"vlan,omitempty"`
				TableSize                         *int    `json:"table-size,omitempty"`
			} `json:"ipv4,omitempty"`
			Ipsec        *string `json:"ipsec,omitempty"`
			FlowLifetime *int    `json:"flow-lifetime,omitempty"`
			Ipv6         *struct {
				DisableFlowFlushingUponFibChanges *string `json:"disable-flow-flushing-upon-fib-changes,omitempty"`
				Bonding                           *string `json:"bonding,omitempty"`
				Pppoe                             *string `json:"pppoe,omitempty"`
				Forwarding                        *string `json:"forwarding,omitempty"`
				Vlan                              *string `json:"vlan,omitempty"`
				TableSize                         *int    `json:"table-size,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"offload,omitempty"`
	} `json:"system,omitempty"`
	TrafficControl *struct {
		OptimizedQueue *struct {
			Policy *string `json:"policy,omitempty"`
		} `json:"optimized-queue,omitempty"`
		SmartQueue *map[string]struct {
			WanInterface *string `json:"wan-interface,omitempty"`
			Download     *struct {
				Rate       *string `json:"rate,omitempty"`
				HtbQuantum *int    `json:"htb-quantum,omitempty"`
				Limit      *int    `json:"limit,omitempty"`
				Target     *string `json:"target,omitempty"`
				Interval   *string `json:"interval,omitempty"`
				Burst      *string `json:"burst,omitempty"`
				Ecn        *string `json:"ecn,omitempty"`
				FqQuantum  *int    `json:"fq-quantum,omitempty"`
				Flows      *int    `json:"flows,omitempty"`
			} `json:"download,omitempty"`
			Upload *struct {
				Rate       *string `json:"rate,omitempty"`
				HtbQuantum *int    `json:"htb-quantum,omitempty"`
				Limit      *int    `json:"limit,omitempty"`
				Target     *string `json:"target,omitempty"`
				Interval   *string `json:"interval,omitempty"`
				Burst      *string `json:"burst,omitempty"`
				Ecn        *string `json:"ecn,omitempty"`
				FqQuantum  *int    `json:"fq-quantum,omitempty"`
				Flows      *int    `json:"flows,omitempty"`
			} `json:"upload,omitempty"`
		} `json:"smart-queue,omitempty"`
		AdvancedQueue *struct {
			Filters *struct {
				Match *map[string]struct {
					Interface *string `json:"interface,omitempty"`
					Target    *string `json:"target,omitempty"`
					Mark      *string `json:"mark,omitempty"`
					Ether     *struct {
						Source      *MacAddr `json:"source,omitempty"`
						Destination *MacAddr `json:"destination,omitempty"`
						Protocol    *string  `json:"protocol,omitempty"`
					} `json:"ether,omitempty"`
					Description *string `json:"description,omitempty"`
					Application *struct {
						Category       *string `json:"category,omitempty"`
						CustomCategory *string `json:"custom-category,omitempty"`
					} `json:"application,omitempty"`
					AttachTo *string `json:"attach-to,omitempty"`
					Ip       *struct {
						Source *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"source,omitempty"`
						Destination *struct {
							Address *IPv4Net `json:"address,omitempty"`
							Port    *string  `json:"port,omitempty"`
						} `json:"destination,omitempty"`
						Protocol *int `json:"protocol,omitempty"`
						Dscp     *int `json:"dscp,omitempty"`
					} `json:"ip,omitempty"`
				} `json:"match,omitempty"`
			} `json:"filters,omitempty"`
			Leaf *struct {
				Queue *map[string]struct {
					Bandwidth *string `json:"bandwidth,omitempty"`
					Burst     *struct {
						BurstRate *string `json:"burst-rate,omitempty"`
						BurstSize *string `json:"burst-size,omitempty"`
					} `json:"burst,omitempty"`
					Ceiling     *string `json:"ceiling,omitempty"`
					QueueType   *string `json:"queue-type,omitempty"`
					Description *string `json:"description,omitempty"`
					Parent      *string `json:"parent,omitempty"`
					Priority    *int    `json:"priority,omitempty"`
				} `json:"queue,omitempty"`
			} `json:"leaf,omitempty"`
			Branch *struct {
				Queue *map[string]struct {
					Bandwidth   *string `json:"bandwidth,omitempty"`
					Description *string `json:"description,omitempty"`
					Parent      *string `json:"parent,omitempty"`
					Priority    *int    `json:"priority,omitempty"`
				} `json:"queue,omitempty"`
			} `json:"branch,omitempty"`
			QueueType *struct {
				Pfifo *map[string]struct {
					Limit *int `json:"limit,omitempty"`
				} `json:"pfifo,omitempty"`
				Hfq *map[string]struct {
					Burst *struct {
						BurstRate *string `json:"burst-rate,omitempty"`
						BurstSize *string `json:"burst-size,omitempty"`
					} `json:"burst,omitempty"`
					Description    *string  `json:"description,omitempty"`
					HostIdentifier *string  `json:"host-identifier,omitempty"`
					Subnet         *IPv4Net `json:"subnet,omitempty"`
					MaxRate        *string  `json:"max-rate,omitempty"`
				} `json:"hfq,omitempty"`
				FqCodel *map[string]struct {
					Limit    *int    `json:"limit,omitempty"`
					Target   *string `json:"target,omitempty"`
					Interval *string `json:"interval,omitempty"`
					Ecn      *string `json:"ecn,omitempty"`
					Flows    *int    `json:"flows,omitempty"`
					Quantum  *int    `json:"quantum,omitempty"`
				} `json:"fq-codel,omitempty"`
				Sfq *map[string]struct {
					HashInterval *int    `json:"hash-interval,omitempty"`
					Description  *string `json:"description,omitempty"`
					QueueLimit   *int    `json:"queue-limit,omitempty"`
				} `json:"sfq,omitempty"`
			} `json:"queue-type,omitempty"`
			Root *struct {
				Queue *map[string]struct {
					Bandwidth   *string `json:"bandwidth,omitempty"`
					Default     *int    `json:"default,omitempty"`
					Description *string `json:"description,omitempty"`
					AttachTo    *string `json:"attach-to,omitempty"`
				} `json:"queue,omitempty"`
			} `json:"root,omitempty"`
		} `json:"advanced-queue,omitempty"`
	} `json:"traffic-control,omitempty"`
	Service *struct {
		UbntDiscover *struct {
			Disable   *string `json:"disable,omitempty"`
			Interface *map[string]struct {
				Disable *string `json:"disable,omitempty"`
			} `json:"interface,omitempty"`
		} `json:"ubnt-discover,omitempty"`
		UdapiServer *string `json:"udapi-server,omitempty"`
		Snmp        *struct {
			Contact       *string `json:"contact,omitempty"`
			Location      *string `json:"location,omitempty"`
			ListenAddress *map[string]struct {
				Interface *string `json:"interface,omitempty"`
				Port      *int    `json:"port,omitempty"`
			} `json:"listen-address,omitempty"`
			Description *string `json:"description,omitempty"`
			V3          *struct {
				Group *map[string]struct {
					Mode     *string `json:"mode,omitempty"`
					View     *string `json:"view,omitempty"`
					Seclevel *string `json:"seclevel,omitempty"`
				} `json:"group,omitempty"`
				Tsm *struct {
					LocalKey *string `json:"local-key,omitempty"`
					Port     *int    `json:"port,omitempty"`
				} `json:"tsm,omitempty"`
				User *map[string]struct {
					TsmKey  *string `json:"tsm-key,omitempty"`
					Privacy *struct {
						PlaintextKey *string `json:"plaintext-key,omitempty"`
						EncryptedKey *string `json:"encrypted-key,omitempty"`
						Type         *string `json:"type,omitempty"`
					} `json:"privacy,omitempty"`
					Mode *string `json:"mode,omitempty"`
					Auth *struct {
						PlaintextKey *string `json:"plaintext-key,omitempty"`
						EncryptedKey *string `json:"encrypted-key,omitempty"`
						Type         *string `json:"type,omitempty"`
					} `json:"auth,omitempty"`
					Group    *string `json:"group,omitempty"`
					Engineid *string `json:"engineid,omitempty"`
				} `json:"user,omitempty"`
				View *map[string]struct {
					Oid *map[string]struct {
						Exclude *string `json:"exclude,omitempty"`
						Mask    *string `json:"mask,omitempty"`
					} `json:"oid,omitempty"`
				} `json:"view,omitempty"`
				TrapTarget *map[string]struct {
					Privacy *struct {
						PlaintextKey *string `json:"plaintext-key,omitempty"`
						EncryptedKey *string `json:"encrypted-key,omitempty"`
						Type         *string `json:"type,omitempty"`
					} `json:"privacy,omitempty"`
					Auth *struct {
						PlaintextKey *string `json:"plaintext-key,omitempty"`
						EncryptedKey *string `json:"encrypted-key,omitempty"`
						Type         *string `json:"type,omitempty"`
					} `json:"auth,omitempty"`
					User     *string `json:"user,omitempty"`
					Protocol *string `json:"protocol,omitempty"`
					Type     *string `json:"type,omitempty"`
					Port     *int    `json:"port,omitempty"`
					Engineid *string `json:"engineid,omitempty"`
				} `json:"trap-target,omitempty"`
				Engineid *string `json:"engineid,omitempty"`
			} `json:"v3,omitempty"`
			TrapSource *IP `json:"trap-source,omitempty"`
			TrapTarget *map[string]struct {
				Port      *int    `json:"port,omitempty"`
				Community *string `json:"community,omitempty"`
			} `json:"trap-target,omitempty"`
			Community *map[string]struct {
				Network       *IPNet  `json:"network,omitempty"`
				Authorization *string `json:"authorization,omitempty"`
				Client        *IP     `json:"client,omitempty"`
			} `json:"community,omitempty"`
			IgnoreInterface *string `json:"ignore-interface,omitempty"`
		} `json:"snmp,omitempty"`
		Dhcpv6Server *struct {
			Preference        *int `json:"preference,omitempty"`
			SharedNetworkName *map[string]struct {
				NameServer *IPv6 `json:"name-server,omitempty"`
				Subnet     *map[string]struct {
					NisServer     *IPv6 `json:"nis-server,omitempty"`
					StaticMapping *map[string]struct {
						Ipv6Address *IPv6   `json:"ipv6-address,omitempty"`
						Identifier  *string `json:"identifier,omitempty"`
					} `json:"static-mapping,omitempty"`
					SntpServer       *IPv6 `json:"sntp-server,omitempty"`
					PrefixDelegation *struct {
						Start *map[string]struct {
							Stop *map[string]struct {
								PrefixLength *string `json:"prefix-length,omitempty"`
							} `json:"stop,omitempty"`
						} `json:"start,omitempty"`
					} `json:"prefix-delegation,omitempty"`
					NisplusDomain    *string `json:"nisplus-domain,omitempty"`
					SipServerAddress *IPv6   `json:"sip-server-address,omitempty"`
					SipServerName    *string `json:"sip-server-name,omitempty"`
					NameServer       *IPv6   `json:"name-server,omitempty"`
					NisDomain        *string `json:"nis-domain,omitempty"`
					DomainSearch     *string `json:"domain-search,omitempty"`
					LeaseTime        *struct {
						Maximum *int `json:"maximum,omitempty"`
						Default *int `json:"default,omitempty"`
						Minimum *int `json:"minimum,omitempty"`
					} `json:"lease-time,omitempty"`
					NisplusServer *IPv6 `json:"nisplus-server,omitempty"`
					AddressRange  *struct {
						Prefix *map[string]struct {
							Temporary *string `json:"temporary,omitempty"`
						} `json:"prefix,omitempty"`
						Start *map[string]struct {
							Stop *IPv6 `json:"stop,omitempty"`
						} `json:"start,omitempty"`
					} `json:"address-range,omitempty"`
				} `json:"subnet,omitempty"`
			} `json:"shared-network-name,omitempty"`
		} `json:"dhcpv6-server,omitempty"`
		Upnp *struct {
			ListenOn *map[string]struct {
				OutboundInterface *string `json:"outbound-interface,omitempty"`
			} `json:"listen-on,omitempty"`
		} `json:"upnp,omitempty"`
		Lldp *struct {
			LegacyProtocols *struct {
				Cdp   *string `json:"cdp,omitempty"`
				Sonmp *string `json:"sonmp,omitempty"`
				Edp   *string `json:"edp,omitempty"`
				Fdp   *string `json:"fdp,omitempty"`
			} `json:"legacy-protocols,omitempty"`
			Interface *map[string]struct {
				Disable  *string `json:"disable,omitempty"`
				Location *struct {
					CivicBased *struct {
						CountryCode *string `json:"country-code,omitempty"`
						CaType      *map[string]struct {
							CaValue *string `json:"ca-value,omitempty"`
						} `json:"ca-type,omitempty"`
					} `json:"civic-based,omitempty"`
					Elin            *string `json:"elin,omitempty"`
					CoordinateBased *struct {
						Datum     *string `json:"datum,omitempty"`
						Longitude *string `json:"longitude,omitempty"`
						Altitude  *string `json:"altitude,omitempty"`
						Latitude  *string `json:"latitude,omitempty"`
					} `json:"coordinate-based,omitempty"`
				} `json:"location,omitempty"`
			} `json:"interface,omitempty"`
			ManagementAddress *IPv4   `json:"management-address,omitempty"`
			ListenVlan        *string `json:".listen-vlan,omitempty"`
		} `json:"lldp,omitempty"`
		Nat *struct {
			Rule *map[string]struct {
				OutsideAddress *struct {
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"outside-address,omitempty"`
				Disable          *string `json:"disable,omitempty"`
				InboundInterface *string `json:"inbound-interface,omitempty"`
				Exclude          *string `json:"exclude,omitempty"`
				Source           *struct {
					Group *struct {
						AddressGroup *string `json:"address-group,omitempty"`
						PortGroup    *string `json:"port-group,omitempty"`
						NetworkGroup *string `json:"network-group,omitempty"`
					} `json:"group,omitempty"`
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"source,omitempty"`
				OutboundInterface *string `json:"outbound-interface,omitempty"`
				Destination       *struct {
					Group *struct {
						AddressGroup *string `json:"address-group,omitempty"`
						PortGroup    *string `json:"port-group,omitempty"`
						NetworkGroup *string `json:"network-group,omitempty"`
					} `json:"group,omitempty"`
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"destination,omitempty"`
				Protocol      *string `json:"protocol,omitempty"`
				Type          *string `json:"type,omitempty"`
				Description   *string `json:"description,omitempty"`
				Log           *string `json:"log,omitempty"`
				InsideAddress *struct {
					Address *string `json:"address,omitempty"`
					Port    *string `json:"port,omitempty"`
				} `json:"inside-address,omitempty"`
			} `json:"rule,omitempty"`
		} `json:"nat,omitempty"`
		Webproxy *struct {
			DomainBlock       *string `json:"domain-block,omitempty"`
			MinimumObjectSize *int    `json:"minimum-object-size,omitempty"`
			ProxyBypass       *string `json:"proxy-bypass,omitempty"`
			ProxyBypassSource *string `json:"proxy-bypass-source,omitempty"`
			ListenAddress     *map[string]struct {
				DisableTransparent *string `json:"disable-transparent,omitempty"`
				Port               *int    `json:"port,omitempty"`
			} `json:"listen-address,omitempty"`
			DomainNoncache    *string `json:"domain-noncache,omitempty"`
			MemCacheSize      *int    `json:"mem-cache-size,omitempty"`
			MaximumObjectSize *int    `json:"maximum-object-size,omitempty"`
			DefaultPort       *int    `json:"default-port,omitempty"`
			AppendDomain      *string `json:"append-domain,omitempty"`
			UrlFiltering      *struct {
				Disable    *string `json:"disable,omitempty"`
				Squidguard *struct {
					AutoUpdate *struct {
						UpdateHour *int `json:"update-hour,omitempty"`
					} `json:"auto-update,omitempty"`
					DefaultAction    *string `json:"default-action,omitempty"`
					EnableSafeSearch *string `json:"enable-safe-search,omitempty"`
					SourceGroup      *map[string]struct {
						Description *string `json:"description,omitempty"`
						Address     *string `json:"address,omitempty"`
						Domain      *string `json:"domain,omitempty"`
					} `json:"source-group,omitempty"`
					RedirectUrl   *string `json:"redirect-url,omitempty"`
					LocalBlock    *string `json:"local-block,omitempty"`
					BlockCategory *string `json:"block-category,omitempty"`
					LocalOk       *string `json:"local-ok,omitempty"`
					TimePeriod    *map[string]struct {
						Description *string `json:"description,omitempty"`
						Days        *map[string]struct {
							Time *string `json:"time,omitempty"`
						} `json:"days,omitempty"`
					} `json:"time-period,omitempty"`
					LocalOkUrl     *string `json:"local-ok-url,omitempty"`
					AllowIpaddrUrl *string `json:"allow-ipaddr-url,omitempty"`
					Rule           *map[string]struct {
						DefaultAction     *string `json:"default-action,omitempty"`
						EnableSafeSearch  *string `json:"enable-safe-search,omitempty"`
						SourceGroup       *string `json:"source-group,omitempty"`
						RedirectUrl       *string `json:"redirect-url,omitempty"`
						LocalBlock        *string `json:"local-block,omitempty"`
						BlockCategory     *string `json:"block-category,omitempty"`
						LocalOk           *string `json:"local-ok,omitempty"`
						TimePeriod        *string `json:"time-period,omitempty"`
						LocalOkUrl        *string `json:"local-ok-url,omitempty"`
						AllowIpaddrUrl    *string `json:"allow-ipaddr-url,omitempty"`
						Description       *string `json:"description,omitempty"`
						LocalBlockKeyword *string `json:"local-block-keyword,omitempty"`
						AllowCategory     *string `json:"allow-category,omitempty"`
						Log               *string `json:"log,omitempty"`
						LocalBlockUrl     *string `json:"local-block-url,omitempty"`
					} `json:"rule,omitempty"`
					LocalBlockKeyword *string `json:"local-block-keyword,omitempty"`
					AllowCategory     *string `json:"allow-category,omitempty"`
					Log               *string `json:"log,omitempty"`
					LocalBlockUrl     *string `json:"local-block-url,omitempty"`
				} `json:"squidguard,omitempty"`
			} `json:"url-filtering,omitempty"`
			EnableAccessLog  *string `json:"enable-access-log,omitempty"`
			Administrator    *string `json:"administrator,omitempty"`
			CacheSize        *int    `json:"cache-size,omitempty"`
			ReplyBlockMime   *string `json:"reply-block-mime,omitempty"`
			ReplyBodyMaxSize *int    `json:"reply-body-max-size,omitempty"`
		} `json:"webproxy,omitempty"`
		Suspend *struct {
			ForwardTo *struct {
				HttpPort  *int  `json:"http-port,omitempty"`
				Address   *IPv4 `json:"address,omitempty"`
				HttpsPort *int  `json:"https-port,omitempty"`
			} `json:"forward-to,omitempty"`
			AllowDomain *string `json:"allow-domain,omitempty"`
			UserIp      *IPv4   `json:"user-ip,omitempty"`
			Redirect    *struct {
				HttpPort  *int    `json:"http-port,omitempty"`
				Url       *string `json:"url,omitempty"`
				HttpsPort *int    `json:"https-port,omitempty"`
			} `json:"redirect,omitempty"`
			AllowIp *IPv4 `json:"allow-ip,omitempty"`
		} `json:"suspend,omitempty"`
		Unms *struct {
			Disable    *string `json:"disable,omitempty"`
			Connection *string `json:"connection,omitempty"`
			Lldp       *struct {
				Disable *string `json:"disable,omitempty"`
			} `json:"lldp,omitempty"`
			RestApi *struct {
				Interface *string `json:"interface,omitempty"`
				Port      *int    `json:"port,omitempty"`
			} `json:"rest-api,omitempty"`
		} `json:"unms,omitempty"`
		Mdns *struct {
			Reflector *string `json:"reflector,omitempty"`
			Repeater  *struct {
				Interface *string `json:"interface,omitempty"`
			} `json:"repeater,omitempty"`
		} `json:"mdns,omitempty"`
		UbntDiscoverServer *struct {
			Disable  *string `json:"disable,omitempty"`
			Protocol *string `json:"protocol,omitempty"`
		} `json:"ubnt-discover-server,omitempty"`
		DhcpServer *struct {
			UseDnsmasq        *string `json:"use-dnsmasq,omitempty"`
			StaticArp         *string `json:"static-arp,omitempty"`
			HostfileUpdate    *string `json:"hostfile-update,omitempty"`
			SharedNetworkName *map[string]struct {
				Disable                 *string `json:"disable,omitempty"`
				SharedNetworkParameters *string `json:"shared-network-parameters,omitempty"`
				Authoritative           *string `json:"authoritative,omitempty"`
				Description             *string `json:"description,omitempty"`
				Subnet                  *map[string]struct {
					StaticMapping *map[string]struct {
						Disable                 *string  `json:"disable,omitempty"`
						IpAddress               *IPv4    `json:"ip-address,omitempty"`
						StaticMappingParameters *string  `json:"static-mapping-parameters,omitempty"`
						MacAddress              *MacAddr `json:"mac-address,omitempty"`
					} `json:"static-mapping,omitempty"`
					BootfileName   *string `json:"bootfile-name,omitempty"`
					BootfileServer *string `json:"bootfile-server,omitempty"`
					PopServer      *IPv4   `json:"pop-server,omitempty"`
					Exclude        *IPv4   `json:"exclude,omitempty"`
					DomainName     *string `json:"domain-name,omitempty"`
					StaticRoute    *struct {
						DestinationSubnet *IPv4Net `json:"destination-subnet,omitempty"`
						Router            *IPv4    `json:"router,omitempty"`
					} `json:"static-route,omitempty"`
					SubnetParameters *string `json:"subnet-parameters,omitempty"`
					Start            *map[string]struct {
						Stop *IPv4 `json:"stop,omitempty"`
					} `json:"start,omitempty"`
					TimeServer      *IPv4   `json:"time-server,omitempty"`
					WpadUrl         *string `json:"wpad-url,omitempty"`
					UnifiController *IPv4   `json:"unifi-controller,omitempty"`
					Lease           *int    `json:"lease,omitempty"`
					DefaultRouter   *IPv4   `json:"default-router,omitempty"`
					TftpServerName  *string `json:"tftp-server-name,omitempty"`
					IpForwarding    *struct {
						Enable *bool `json:"enable,omitempty"`
					} `json:"ip-forwarding,omitempty"`
					DnsServer          *IPv4   `json:"dns-server,omitempty"`
					NtpServer          *IPv4   `json:"ntp-server,omitempty"`
					TimeOffset         *string `json:"time-offset,omitempty"`
					SmtpServer         *IPv4   `json:"smtp-server,omitempty"`
					WinsServer         *IPv4   `json:"wins-server,omitempty"`
					ClientPrefixLength *int    `json:"client-prefix-length,omitempty"`
					Failover           *struct {
						PeerAddress  *IPv4   `json:"peer-address,omitempty"`
						Status       *string `json:"status,omitempty"`
						LocalAddress *IPv4   `json:"local-address,omitempty"`
						Name         *string `json:"name,omitempty"`
					} `json:"failover,omitempty"`
					ServerIdentifier *IPv4 `json:"server-identifier,omitempty"`
				} `json:"subnet,omitempty"`
			} `json:"shared-network-name,omitempty"`
			Disabled         *bool `json:"disabled,omitempty"`
			DynamicDnsUpdate *struct {
				Enable *bool `json:"enable,omitempty"`
			} `json:"dynamic-dns-update,omitempty"`
			GlobalParameters *string `json:"global-parameters,omitempty"`
		} `json:"dhcp-server,omitempty"`
		Ssh *struct {
			DisablePasswordAuthentication *string `json:"disable-password-authentication,omitempty"`
			ListenAddress                 *IP     `json:"listen-address,omitempty"`
			AllowRoot                     *string `json:"allow-root,omitempty"`
			ProtocolVersion               *string `json:"protocol-version,omitempty"`
			DisableHostValidation         *string `json:"disable-host-validation,omitempty"`
			Port                          *int    `json:"port,omitempty"`
		} `json:"ssh,omitempty"`
		Gui *struct {
			CaFile        *string `json:"ca-file,omitempty"`
			HttpPort      *int    `json:"http-port,omitempty"`
			ListenAddress *IP     `json:"listen-address,omitempty"`
			HttpsPort     *int    `json:"https-port,omitempty"`
			DhFile        *string `json:"dh-file,omitempty"`
			CertFile      *string `json:"cert-file,omitempty"`
			OlderCiphers  *string `json:"older-ciphers,omitempty"`
			Debug         *string `json:"debug,omitempty"`
		} `json:"gui,omitempty"`
		PppoeServer *struct {
			Encryption  *string `json:"encryption,omitempty"`
			ServiceName *string `json:"service-name,omitempty"`
			WinsServers *struct {
				Server2 *IPv4 `json:"server-2,omitempty"`
				Server1 *IPv4 `json:"server-1,omitempty"`
			} `json:"wins-servers,omitempty"`
			Interface  *string `json:"interface,omitempty"`
			DnsServers *struct {
				Server2 *IPv4 `json:"server-2,omitempty"`
				Server1 *IPv4 `json:"server-1,omitempty"`
			} `json:"dns-servers,omitempty"`
			Mtu          *int `json:"mtu,omitempty"`
			ClientIpPool *struct {
				Start *IPv4 `json:"start,omitempty"`
				Stop  *IPv4 `json:"stop,omitempty"`
			} `json:"client-ip-pool,omitempty"`
			Radius *struct {
				DefaultInterimInterval *int `json:"default-interim-interval,omitempty"`
			} `json:"radius,omitempty"`
			LocalIp        *IPv4 `json:"local-ip,omitempty"`
			Authentication *struct {
				Mode       *string `json:"mode,omitempty"`
				LocalUsers *struct {
					Username *map[string]struct {
						Disable  *string `json:"disable,omitempty"`
						Password *string `json:"password,omitempty"`
						StaticIp *IPv4   `json:"static-ip,omitempty"`
					} `json:"username,omitempty"`
				} `json:"local-users,omitempty"`
				RadiusServer *map[string]struct {
					Key *string `json:"key,omitempty"`
				} `json:"radius-server,omitempty"`
			} `json:"authentication,omitempty"`
			AccessConcentrator *string `json:"access-concentrator,omitempty"`
		} `json:"pppoe-server,omitempty"`
		SshRecovery *struct {
			ListenOn *string `json:"listen-on,omitempty"`
			Lifetime *string `json:"lifetime,omitempty"`
			Disabled *string `json:"disabled,omitempty"`
			Port     *int    `json:"port,omitempty"`
		} `json:"ssh-recovery,omitempty"`
		Dns *struct {
			Dynamic *struct {
				Interface *map[string]struct {
					Web     *string `json:"web,omitempty"`
					WebSkip *string `json:"web-skip,omitempty"`
					Service *map[string]struct {
						Options  *string `json:"options,omitempty"`
						Password *string `json:"password,omitempty"`
						Server   *string `json:"server,omitempty"`
						HostName *string `json:"host-name,omitempty"`
						Protocol *string `json:"protocol,omitempty"`
						Login    *string `json:"login,omitempty"`
					} `json:"service,omitempty"`
				} `json:"interface,omitempty"`
			} `json:"dynamic,omitempty"`
			Forwarding *struct {
				Options             *string `json:"options,omitempty"`
				ExceptInterface     *string `json:"except-interface,omitempty"`
				ForcePublicDnsBoost *string `json:"force-public-dns-boost,omitempty"`
				ListenOn            *string `json:"listen-on,omitempty"`
				NameServer          *IP     `json:"name-server,omitempty"`
				System              *string `json:"system,omitempty"`
				Dhcp                *string `json:"dhcp,omitempty"`
				CacheSize           *int    `json:"cache-size,omitempty"`
			} `json:"forwarding,omitempty"`
		} `json:"dns,omitempty"`
		DhcpRelay *struct {
			Interface    *string `json:"interface,omitempty"`
			RelayOptions *struct {
				HopCount           *int    `json:"hop-count,omitempty"`
				MaxSize            *int    `json:"max-size,omitempty"`
				Port               *int    `json:"port,omitempty"`
				RelayAgentsPackets *string `json:"relay-agents-packets,omitempty"`
			} `json:"relay-options,omitempty"`
			Server *IPv4 `json:"server,omitempty"`
		} `json:"dhcp-relay,omitempty"`
		Upnp2 *struct {
			ListenOn *string `json:"listen-on,omitempty"`
			NatPmp   *string `json:"nat-pmp,omitempty"`
			BitRate  *struct {
				Up   *int `json:"up,omitempty"`
				Down *int `json:"down,omitempty"`
			} `json:"bit-rate,omitempty"`
			Wan        *string `json:"wan,omitempty"`
			Port       *int    `json:"port,omitempty"`
			SecureMode *string `json:"secure-mode,omitempty"`
			Acl        *struct {
				Rule *map[string]struct {
					Action       *string  `json:"action,omitempty"`
					Description  *string  `json:"description,omitempty"`
					ExternalPort *string  `json:"external-port,omitempty"`
					LocalPort    *string  `json:"local-port,omitempty"`
					Subnet       *IPv4Net `json:"subnet,omitempty"`
				} `json:"rule,omitempty"`
			} `json:"acl,omitempty"`
		} `json:"upnp2,omitempty"`
		Telnet *struct {
			ListenAddress *IP     `json:"listen-address,omitempty"`
			AllowRoot     *string `json:"allow-root,omitempty"`
			Port          *int    `json:"port,omitempty"`
		} `json:"telnet,omitempty"`
		Dhcpv6Relay *struct {
			ListenInterface *map[string]struct {
				Address *IPv6 `json:"address,omitempty"`
			} `json:"listen-interface,omitempty"`
			MaxHopCount          *int    `json:"max-hop-count,omitempty"`
			UseInterfaceIdOption *string `json:"use-interface-id-option,omitempty"`
			UpstreamInterface    *map[string]struct {
				Address *IPv6 `json:"address,omitempty"`
			} `json:"upstream-interface,omitempty"`
			ListenPort *int `json:"listen-port,omitempty"`
		} `json:"dhcpv6-relay,omitempty"`
	} `json:"service,omitempty"`
	Protocols *struct {
		Rip *struct {
			Interface *string  `json:"interface,omitempty"`
			Neighbor  *IPv4    `json:"neighbor,omitempty"`
			Route     *IPv4Net `json:"route,omitempty"`
			Bfd       *struct {
				Neighbor *map[string]struct {
					FallOver *string `json:"fall-over,omitempty"`
				} `json:"neighbor,omitempty"`
				AllInterfaces *string `json:"all-interfaces,omitempty"`
			} `json:"bfd,omitempty"`
			DefaultDistance *int `json:"default-distance,omitempty"`
			Timers          *struct {
				Update            *int `json:"update,omitempty"`
				Timeout           *int `json:"timeout,omitempty"`
				GarbageCollection *int `json:"garbage-collection,omitempty"`
			} `json:"timers,omitempty"`
			Network       *IPv4Net `json:"network,omitempty"`
			DefaultMetric *int     `json:"default-metric,omitempty"`
			Vrf           *map[string]struct {
				Interface *string `json:"interface,omitempty"`
				Bfd       *struct {
					Neighbor *map[string]struct {
						FallOver *string `json:"fall-over,omitempty"`
					} `json:"neighbor,omitempty"`
					AllInterfaces *string `json:"all-interfaces,omitempty"`
				} `json:"bfd,omitempty"`
				DefaultDistance *int     `json:"default-distance,omitempty"`
				Network         *IPv4Net `json:"network,omitempty"`
				DefaultMetric   *int     `json:"default-metric,omitempty"`
				NetworkDistance *map[string]struct {
					Distance   *int    `json:"distance,omitempty"`
					AccessList *string `json:"access-list,omitempty"`
				} `json:"network-distance,omitempty"`
				Redistribute *struct {
					Connected *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"connected,omitempty"`
					Static *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"static,omitempty"`
					Bgp *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"bgp,omitempty"`
					Ospf *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"redistribute,omitempty"`
				DistributeList *struct {
					Interface *map[string]struct {
						AccessList *struct {
							Out *int `json:"out,omitempty"`
							In  *int `json:"in,omitempty"`
						} `json:"access-list,omitempty"`
						PrefixList *struct {
							Out *string `json:"out,omitempty"`
							In  *string `json:"in,omitempty"`
						} `json:"prefix-list,omitempty"`
					} `json:"interface,omitempty"`
					AccessList *struct {
						Out *int `json:"out,omitempty"`
						In  *int `json:"in,omitempty"`
					} `json:"access-list,omitempty"`
					PrefixList *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"prefix-list,omitempty"`
				} `json:"distribute-list,omitempty"`
				DefaultInformation *struct {
					Originate *string `json:"originate,omitempty"`
				} `json:"default-information,omitempty"`
			} `json:".vrf,omitempty"`
			NetworkDistance *map[string]struct {
				Distance   *int    `json:"distance,omitempty"`
				AccessList *string `json:"access-list,omitempty"`
			} `json:"network-distance,omitempty"`
			PassiveInterface *string `json:"passive-interface,omitempty"`
			Redistribute     *struct {
				Connected *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"connected,omitempty"`
				Static *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"static,omitempty"`
				Bgp *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"bgp,omitempty"`
				Kernel *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"kernel,omitempty"`
				Ospf *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"redistribute,omitempty"`
			DistributeList *struct {
				Interface *map[string]struct {
					AccessList *struct {
						Out *int `json:"out,omitempty"`
						In  *int `json:"in,omitempty"`
					} `json:"access-list,omitempty"`
					PrefixList *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"prefix-list,omitempty"`
				} `json:"interface,omitempty"`
				AccessList *struct {
					Out *int `json:"out,omitempty"`
					In  *int `json:"in,omitempty"`
				} `json:"access-list,omitempty"`
				PrefixList *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"prefix-list,omitempty"`
			} `json:"distribute-list,omitempty"`
			DefaultInformation *struct {
				Originate *string `json:"originate,omitempty"`
			} `json:"default-information,omitempty"`
		} `json:"rip,omitempty"`
		Mpls *struct {
			LspTunneling *struct {
				Interface *map[string]struct {
					InLabel *map[string]struct {
						OutLabel *map[string]struct {
							NetworkFec *IPv4Net `json:"network-fec,omitempty"`
						} `json:"out-label,omitempty"`
					} `json:"in-label,omitempty"`
				} `json:"interface,omitempty"`
			} `json:"lsp-tunneling,omitempty"`
			AcGroup *map[string]struct {
				GroupId *int `json:"group-id,omitempty"`
			} `json:"ac-group,omitempty"`
			LocalPacketHandling *string `json:"local-packet-handling,omitempty"`
			Interface           *map[string]struct {
				MulticastHellos  *string `json:"multicast-hellos,omitempty"`
				KeepaliveTimeout *int    `json:"keepalive-timeout,omitempty"`
				VcMode           *struct {
					Standby   *string `json:"standby,omitempty"`
					Revertive *string `json:"revertive,omitempty"`
				} `json:"vc-mode,omitempty"`
				LdpIgp *struct {
					Sync *struct {
						Ospf *struct {
							HolddownTimer *int `json:"holddown-timer,omitempty"`
						} `json:"ospf,omitempty"`
					} `json:"sync,omitempty"`
					SyncDelay *int `json:"sync-delay,omitempty"`
				} `json:"ldp-igp,omitempty"`
				MaxPduLength       *int `json:"max-pdu-length,omitempty"`
				LabelRetentionMode *struct {
					Liberal      *string `json:"liberal,omitempty"`
					Conservative *string `json:"conservative,omitempty"`
				} `json:"label-retention-mode,omitempty"`
				AdminGroup *string `json:"admin-group,omitempty"`
				L2Circuit  *map[string]struct {
					Hdlc *struct {
						Primary   *string `json:"primary,omitempty"`
						Secondary *string `json:"secondary,omitempty"`
					} `json:".hdlc,omitempty"`
					Ppp *struct {
						Primary   *string `json:"primary,omitempty"`
						Secondary *string `json:"secondary,omitempty"`
					} `json:".ppp,omitempty"`
					Ethernet *struct {
						Primary   *string `json:"primary,omitempty"`
						Secondary *string `json:"secondary,omitempty"`
					} `json:".ethernet,omitempty"`
				} `json:"l2-circuit,omitempty"`
				LabelSwitching    *string `json:"label-switching,omitempty"`
				HoldTime          *int    `json:"hold-time,omitempty"`
				KeepaliveInterval *int    `json:"keepalive-interval,omitempty"`
				AdvertisementMode *struct {
					DownstreamOnDemand    *string `json:"downstream-on-demand,omitempty"`
					DownstreamUnsolicited *string `json:"downstream-unsolicited,omitempty"`
				} `json:"advertisement-mode,omitempty"`
				HelloInterval *int `json:"hello-interval,omitempty"`
			} `json:"interface,omitempty"`
			L2CircuitFibEntry *map[string]struct {
				InLabel *map[string]struct {
					OutLabel *map[string]struct {
						Ipv4 *map[string]struct {
							Int *map[string]struct {
								Int *string `json:"int,omitempty"`
							} `json:"int,omitempty"`
						} `json:"ipv4,omitempty"`
						Ipv6 *map[string]struct {
							Int *map[string]struct {
								Int *string `json:"int,omitempty"`
							} `json:"int,omitempty"`
						} `json:"ipv6,omitempty"`
					} `json:"out-label,omitempty"`
				} `json:"in-label,omitempty"`
			} `json:".l2-circuit-fib-entry,omitempty"`
			EnableAllInterfaces *string `json:"enable-all-interfaces,omitempty"`
			MsPw                *map[string]struct {
				Description *string `json:"description,omitempty"`
			} `json:"ms-pw,omitempty"`
			IngressTtl *int `json:"ingress-ttl,omitempty"`
			TeClass    *map[string]struct {
				Name *map[string]struct {
					Priority *int `json:"priority,omitempty"`
				} `json:"name,omitempty"`
			} `json:"te-class,omitempty"`
			LspModel *struct {
				Pipe *string `json:"pipe,omitempty"`
			} `json:"lsp-model,omitempty"`
			FtnEntry *struct {
				TunnelId *map[string]struct {
					Ip *map[string]struct {
						Mask *map[string]struct {
							OutLabel *map[string]struct {
								Nexthop *map[string]struct {
									Interface *map[string]struct {
										Primary   *string `json:"primary,omitempty"`
										Secondary *string `json:"secondary,omitempty"`
									} `json:"interface,omitempty"`
								} `json:"nexthop,omitempty"`
							} `json:"out-label,omitempty"`
						} `json:"mask,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6mask *map[string]struct {
						OutLabel *map[string]struct {
							Nexthop *map[string]struct {
								Interface *map[string]struct {
									Primary   *string `json:"primary,omitempty"`
									Secondary *string `json:"secondary,omitempty"`
								} `json:"interface,omitempty"`
							} `json:"nexthop,omitempty"`
						} `json:"out-label,omitempty"`
					} `json:"ipv6mask,omitempty"`
					Ipv4mask *map[string]struct {
						OutLabel *map[string]struct {
							Nexthop *map[string]struct {
								Interface *map[string]struct {
									Primary   *string `json:"primary,omitempty"`
									Secondary *string `json:"secondary,omitempty"`
								} `json:"interface,omitempty"`
							} `json:"nexthop,omitempty"`
						} `json:"out-label,omitempty"`
					} `json:"ipv4mask,omitempty"`
				} `json:"tunnel-id,omitempty"`
			} `json:"ftn-entry,omitempty"`
			ClassToExp *map[string]struct {
				Bit *int `json:"bit,omitempty"`
			} `json:"class-to-exp,omitempty"`
			L2Circuit *map[string]struct {
				Ipv4 *map[string]struct {
					Agi *map[string]struct {
						Saii *map[string]struct {
							Taii *map[string]struct {
								Manual    *string `json:"manual,omitempty"`
								Groupname *map[string]struct {
									GroupId *int `json:"group-id,omitempty"`
								} `json:"groupname,omitempty"`
								ControlWord *struct {
									Manual   *string `json:"manual,omitempty"`
									TunnelId *map[string]struct {
										Passive *string `json:"passive,omitempty"`
										Reverse *struct {
											Passive *string `json:"passive,omitempty"`
											Manual  *string `json:"manual,omitempty"`
										} `json:"reverse,omitempty"`
										Manual  *string `json:"manual,omitempty"`
										Forward *struct {
											Passive *string `json:"passive,omitempty"`
											Manual  *string `json:"manual,omitempty"`
										} `json:"forward,omitempty"`
									} `json:"tunnel-id,omitempty"`
								} `json:"control-word,omitempty"`
								TunnelId *map[string]struct {
									Passive *string `json:"passive,omitempty"`
									Reverse *struct {
										Passive *string `json:"passive,omitempty"`
										Manual  *string `json:"manual,omitempty"`
									} `json:"reverse,omitempty"`
									Manual  *string `json:"manual,omitempty"`
									Forward *struct {
										Passive *string `json:"passive,omitempty"`
										Manual  *string `json:"manual,omitempty"`
									} `json:"forward,omitempty"`
								} `json:"tunnel-id,omitempty"`
							} `json:"taii,omitempty"`
						} `json:"saii,omitempty"`
					} `json:"agi,omitempty"`
				} `json:"ipv4,omitempty"`
				Id *map[string]struct {
					Ipv4 *map[string]struct {
						Passive   *string `json:"passive,omitempty"`
						Manual    *string `json:"manual,omitempty"`
						Groupname *map[string]struct {
							ControlWord *struct {
								Manual *string `json:"manual,omitempty"`
							} `json:"control-word,omitempty"`
						} `json:"groupname,omitempty"`
						ControlWord *struct {
							Passive  *string `json:"passive,omitempty"`
							Manual   *string `json:"manual,omitempty"`
							TunnelId *map[string]struct {
								Passive *string `json:"passive,omitempty"`
								Reverse *struct {
									Passive *string `json:"passive,omitempty"`
									Manual  *string `json:"manual,omitempty"`
								} `json:"reverse,omitempty"`
								Manual  *string `json:"manual,omitempty"`
								Forward *struct {
									Passive *string `json:"passive,omitempty"`
									Manual  *string `json:"manual,omitempty"`
								} `json:"forward,omitempty"`
							} `json:"tunnel-id,omitempty"`
						} `json:"control-word,omitempty"`
						TunnelId *map[string]struct {
							Passive *string `json:"passive,omitempty"`
							Reverse *struct {
								Passive *string `json:"passive,omitempty"`
								Manual  *string `json:"manual,omitempty"`
							} `json:"reverse,omitempty"`
							Manual  *string `json:"manual,omitempty"`
							Forward *struct {
								Passive *string `json:"passive,omitempty"`
								Manual  *string `json:"manual,omitempty"`
							} `json:"forward,omitempty"`
						} `json:"tunnel-id,omitempty"`
					} `json:"ipv4,omitempty"`
					Ipv6 *map[string]struct {
						Manual *string `json:"manual,omitempty"`
					} `json:"ipv6,omitempty"`
				} `json:"id,omitempty"`
			} `json:".l2-circuit,omitempty"`
			EgressTtl     *int `json:"egress-ttl,omitempty"`
			MinLabelValue *map[string]struct {
				LabelSpace *int `json:"label-space,omitempty"`
			} `json:"min-label-value,omitempty"`
			AdminGroup *map[string]struct {
				Value *int `json:"value,omitempty"`
			} `json:"admin-group,omitempty"`
			MsPwStitch *map[string]struct {
				Vc1 *map[string]struct {
					Vc2 *map[string]struct {
						Mtu *map[string]struct {
							Ethernet *string `json:"ethernet,omitempty"`
							Vlan     *int    `json:"vlan,omitempty"`
						} `json:"mtu,omitempty"`
					} `json:"vc2,omitempty"`
				} `json:"vc1,omitempty"`
			} `json:"ms-pw-stitch,omitempty"`
			ClassType *map[string]struct {
				Name *string `json:"name,omitempty"`
			} `json:"class-type,omitempty"`
			IlmEntry *map[string]struct {
				Interface *map[string]struct {
					Pop  *string `json:"pop,omitempty"`
					Swap *map[string]struct {
						Interface *map[string]struct {
							Ip *map[string]struct {
								Fec *map[string]struct {
									Mask *IPv4 `json:"mask,omitempty"`
								} `json:"fec,omitempty"`
							} `json:"ip,omitempty"`
						} `json:"interface,omitempty"`
					} `json:"swap,omitempty"`
				} `json:"interface,omitempty"`
			} `json:"ilm-entry,omitempty"`
			SupportDiffservClass *string `json:"support-diffserv-class,omitempty"`
			MapRoute             *map[string]struct {
				Fec *IPv4Net `json:"fec,omitempty"`
			} `json:"map-route,omitempty"`
			Rsvp *struct {
				MinLabelValue *map[string]struct {
					LabelSpace *int `json:"label-space,omitempty"`
				} `json:"min-label-value,omitempty"`
				MaxLabelValue *map[string]struct {
					LabelSpace *int `json:"label-space,omitempty"`
				} `json:"max-label-value,omitempty"`
			} `json:"rsvp,omitempty"`
			Ldp *struct {
				MinLabelValue *map[string]struct {
					LabelSpace *int `json:"label-space,omitempty"`
				} `json:"min-label-value,omitempty"`
				MaxLabelValue *map[string]struct {
					LabelSpace *int `json:"label-space,omitempty"`
				} `json:"max-label-value,omitempty"`
			} `json:"ldp,omitempty"`
			Bgp *struct {
				MinLabelValue *map[string]struct {
					LabelSpace *int `json:"label-space,omitempty"`
				} `json:"min-label-value,omitempty"`
				MaxLabelValue *map[string]struct {
					LabelSpace *int `json:"label-space,omitempty"`
				} `json:"max-label-value,omitempty"`
			} `json:"bgp,omitempty"`
			MaxLabelValue *map[string]struct {
				LabelSpace *int `json:"label-space,omitempty"`
			} `json:"max-label-value,omitempty"`
			PropagateTtl         *string `json:"propagate-ttl,omitempty"`
			DisableAllInterfaces *string `json:"disable-all-interfaces,omitempty"`
		} `json:"mpls,omitempty"`
		Bfd *struct {
			Interface *map[string]struct {
				Enable *string `json:"enable,omitempty"`
				Echo   *struct {
					Interval *int `json:"interval,omitempty"`
				} `json:"echo,omitempty"`
				Auth *struct {
					Key  *string `json:"key,omitempty"`
					Type *string `json:"type,omitempty"`
				} `json:"auth,omitempty"`
				Interval *map[string]struct {
					Minrx *map[string]struct {
						Multiplier *int `json:"multiplier,omitempty"`
					} `json:"minrx,omitempty"`
				} `json:"interval,omitempty"`
				Session *struct {
					Source *map[string]struct {
						Dest *map[string]struct {
							Multihop *struct {
								AdminDown  *string `json:"admin-down,omitempty"`
								DemandMode *struct {
									AdminDown     *string `json:"admin-down,omitempty"`
									NonPersistent *struct {
										AdminDown *string `json:"admin-down,omitempty"`
									} `json:"non-persistent,omitempty"`
								} `json:"demand-mode,omitempty"`
							} `json:"multihop,omitempty"`
							AdminDown  *string `json:"admin-down,omitempty"`
							DemandMode *struct {
								AdminDown     *string `json:"admin-down,omitempty"`
								NonPersistent *struct {
									AdminDown *string `json:"admin-down,omitempty"`
								} `json:"non-persistent,omitempty"`
							} `json:"demand-mode,omitempty"`
							NonPersistent *struct {
								AdminDown *string `json:"admin-down,omitempty"`
							} `json:"non-persistent,omitempty"`
						} `json:"dest,omitempty"`
					} `json:"source,omitempty"`
				} `json:"session,omitempty"`
			} `json:"interface,omitempty"`
			Echo         *string `json:"echo,omitempty"`
			Notification *struct {
				Enable *string `json:"enable,omitempty"`
			} `json:"notification,omitempty"`
			SlowTimer *int `json:"slow-timer,omitempty"`
			Gtsm      *struct {
				Enable *string `json:"enable,omitempty"`
				Ttl    *int    `json:"ttl,omitempty"`
			} `json:"gtsm,omitempty"`
			MultihopPeer *map[string]struct {
				Auth *struct {
					Key  *string `json:"key,omitempty"`
					Type *string `json:"type,omitempty"`
				} `json:"auth,omitempty"`
				Interval *map[string]struct {
					Minrx *map[string]struct {
						Multiplier *int `json:"multiplier,omitempty"`
					} `json:"minrx,omitempty"`
				} `json:"interval,omitempty"`
			} `json:"multihop-peer,omitempty"`
		} `json:"bfd,omitempty"`
		Ripng *struct {
			Interface *string  `json:"interface,omitempty"`
			Route     *IPv6Net `json:"route,omitempty"`
			Timers    *struct {
				Update            *int `json:"update,omitempty"`
				Timeout           *int `json:"timeout,omitempty"`
				GarbageCollection *int `json:"garbage-collection,omitempty"`
			} `json:"timers,omitempty"`
			Network          *IPv6Net `json:"network,omitempty"`
			DefaultMetric    *int     `json:"default-metric,omitempty"`
			AggregateAddress *IPv6Net `json:"aggregate-address,omitempty"`
			Vrf              *map[string]struct {
				Interface *string  `json:"interface,omitempty"`
				Route     *IPv6Net `json:"route,omitempty"`
				Timers    *struct {
					Update            *int `json:"update,omitempty"`
					Timeout           *int `json:"timeout,omitempty"`
					GarbageCollection *int `json:"garbage-collection,omitempty"`
				} `json:"timers,omitempty"`
				Network          *IPv6Net `json:"network,omitempty"`
				DefaultMetric    *int     `json:"default-metric,omitempty"`
				AggregateAddress *IPv6Net `json:"aggregate-address,omitempty"`
				PassiveInterface *string  `json:"passive-interface,omitempty"`
				Redistribute     *struct {
					Connected *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"connected,omitempty"`
					Static *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"static,omitempty"`
					Bgp *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"bgp,omitempty"`
					Ospfv3 *struct {
						RouteMap *string `json:"route-map,omitempty"`
						Metric   *int    `json:"metric,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"redistribute,omitempty"`
				DistributeList *struct {
					Interface *map[string]struct {
						AccessList *struct {
							Out *int `json:"out,omitempty"`
							In  *int `json:"in,omitempty"`
						} `json:"access-list,omitempty"`
						PrefixList *struct {
							Out *string `json:"out,omitempty"`
							In  *string `json:"in,omitempty"`
						} `json:"prefix-list,omitempty"`
					} `json:"interface,omitempty"`
					AccessList *struct {
						Out *int `json:"out,omitempty"`
						In  *int `json:"in,omitempty"`
					} `json:"access-list,omitempty"`
					PrefixList *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"prefix-list,omitempty"`
				} `json:"distribute-list,omitempty"`
				DefaultInformation *struct {
					Originate *string `json:"originate,omitempty"`
				} `json:"default-information,omitempty"`
			} `json:".vrf,omitempty"`
			PassiveInterface *string `json:"passive-interface,omitempty"`
			Redistribute     *struct {
				Connected *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"connected,omitempty"`
				Static *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"static,omitempty"`
				Bgp *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"bgp,omitempty"`
				Ospfv3 *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"ospfv3,omitempty"`
				Kernel *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"kernel,omitempty"`
			} `json:"redistribute,omitempty"`
			DistributeList *struct {
				Interface *map[string]struct {
					AccessList *struct {
						Out *int `json:"out,omitempty"`
						In  *int `json:"in,omitempty"`
					} `json:"access-list,omitempty"`
					PrefixList *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"prefix-list,omitempty"`
				} `json:"interface,omitempty"`
				AccessList *struct {
					Out *int `json:"out,omitempty"`
					In  *int `json:"in,omitempty"`
				} `json:"access-list,omitempty"`
				PrefixList *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"prefix-list,omitempty"`
			} `json:"distribute-list,omitempty"`
			DefaultInformation *struct {
				Originate *string `json:"originate,omitempty"`
			} `json:"default-information,omitempty"`
		} `json:"ripng,omitempty"`
		Vrf *map[string]struct {
			Interface   *string `json:"interface,omitempty"`
			RouterId    *IPv4   `json:"router-id,omitempty"`
			RouteTarget *struct {
				Both   *string `json:"both,omitempty"`
				Export *string `json:"export,omitempty"`
				Import *string `json:"import,omitempty"`
			} `json:"route-target,omitempty"`
			Description *string `json:"description,omitempty"`
			Import      *struct {
				Map *string `json:"map,omitempty"`
			} `json:"import,omitempty"`
			Rd *struct {
				Int *string `json:"int,omitempty"`
				Ip  *string `json:"ip,omitempty"`
			} `json:"rd,omitempty"`
		} `json:".vrf,omitempty"`
		Static *struct {
			InterfaceRoute6 *map[string]struct {
				NextHopInterface *map[string]struct {
					Disable     *string `json:"disable,omitempty"`
					Distance    *int    `json:"distance,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"next-hop-interface,omitempty"`
			} `json:"interface-route6,omitempty"`
			Route *map[string]struct {
				NextHop *map[string]struct {
					Disable     *string `json:"disable,omitempty"`
					Bfd         *string `json:"bfd,omitempty"`
					Distance    *int    `json:"distance,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"next-hop,omitempty"`
				Blackhole *struct {
					Disable     *string `json:"disable,omitempty"`
					Distance    *int    `json:"distance,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"blackhole,omitempty"`
			} `json:"route,omitempty"`
			Bfd *struct {
				Interface *map[string]struct {
					Ipv4 *string `json:"ipv4,omitempty"`
					Ipv6 *string `json:"ipv6,omitempty"`
				} `json:"interface,omitempty"`
				AllInterfaces *struct {
					Ipv4 *string `json:"ipv4,omitempty"`
					Ipv6 *string `json:"ipv6,omitempty"`
				} `json:"all-interfaces,omitempty"`
			} `json:"bfd,omitempty"`
			Vrf *map[string]struct {
				InterfaceRoute6 *map[string]struct {
					NextHopInterface *map[string]struct {
						Gw *map[string]struct {
							Disable *string `json:"disable,omitempty"`
						} `json:"gw,omitempty"`
					} `json:"next-hop-interface,omitempty"`
				} `json:"interface-route6,omitempty"`
				Route *map[string]struct {
					NextHop *map[string]struct {
						Disable   *string `json:"disable,omitempty"`
						Interface *string `json:"interface,omitempty"`
					} `json:"next-hop,omitempty"`
					Blackhole *struct {
						Disable   *string `json:"disable,omitempty"`
						Interface *string `json:"interface,omitempty"`
					} `json:"blackhole,omitempty"`
				} `json:"route,omitempty"`
				InterfaceRoute *map[string]struct {
					NextHopInterface *map[string]struct {
						Disable *string `json:"disable,omitempty"`
					} `json:"next-hop-interface,omitempty"`
				} `json:"interface-route,omitempty"`
				Ip *struct {
					Forwarding *string `json:"forwarding,omitempty"`
				} `json:"ip,omitempty"`
				Route6 *map[string]struct {
					NextHop *map[string]struct {
						Disable   *string `json:"disable,omitempty"`
						Interface *string `json:"interface,omitempty"`
					} `json:"next-hop,omitempty"`
				} `json:"route6,omitempty"`
			} `json:".vrf,omitempty"`
			Table *map[string]struct {
				InterfaceRoute6 *map[string]struct {
					NextHopInterface *map[string]struct {
						Disable     *string `json:"disable,omitempty"`
						Distance    *int    `json:"distance,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"next-hop-interface,omitempty"`
				} `json:"interface-route6,omitempty"`
				Route *map[string]struct {
					NextHop *map[string]struct {
						Disable     *string `json:"disable,omitempty"`
						Distance    *int    `json:"distance,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"next-hop,omitempty"`
					Blackhole *struct {
						Distance    *int    `json:"distance,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"blackhole,omitempty"`
				} `json:"route,omitempty"`
				Mark           *int    `json:"mark,omitempty"`
				Description    *string `json:"description,omitempty"`
				InterfaceRoute *map[string]struct {
					NextHopInterface *map[string]struct {
						Disable     *string `json:"disable,omitempty"`
						Distance    *int    `json:"distance,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"next-hop-interface,omitempty"`
				} `json:"interface-route,omitempty"`
				Route6 *map[string]struct {
					NextHop *map[string]struct {
						Disable     *string `json:"disable,omitempty"`
						Distance    *int    `json:"distance,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"next-hop,omitempty"`
					Blackhole *struct {
						Distance    *int    `json:"distance,omitempty"`
						Description *string `json:"description,omitempty"`
					} `json:"blackhole,omitempty"`
				} `json:"route6,omitempty"`
			} `json:"table,omitempty"`
			InterfaceRoute *map[string]struct {
				NextHopInterface *map[string]struct {
					Disable     *string `json:"disable,omitempty"`
					Distance    *int    `json:"distance,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"next-hop-interface,omitempty"`
			} `json:"interface-route,omitempty"`
			Arp *map[string]struct {
				Hwaddr *MacAddr `json:"hwaddr,omitempty"`
			} `json:"arp,omitempty"`
			Route6 *map[string]struct {
				NextHop *map[string]struct {
					Disable     *string `json:"disable,omitempty"`
					Interface   *string `json:"interface,omitempty"`
					Bfd         *string `json:"bfd,omitempty"`
					Distance    *int    `json:"distance,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"next-hop,omitempty"`
				Blackhole *struct {
					Disable     *string `json:"disable,omitempty"`
					Distance    *int    `json:"distance,omitempty"`
					Description *string `json:"description,omitempty"`
				} `json:"blackhole,omitempty"`
			} `json:"route6,omitempty"`
		} `json:"static,omitempty"`
		Rsvp *struct {
			HelloTimeout *int `json:"hello-timeout,omitempty"`
			Interface    *map[string]struct {
				HelloTimeout     *int    `json:"hello-timeout,omitempty"`
				Disable          *string `json:"disable,omitempty"`
				AckWaitTimeout   *int    `json:"ack-wait-timeout,omitempty"`
				MessageAck       *string `json:"message-ack,omitempty"`
				RefreshReduction *string `json:"refresh-reduction,omitempty"`
				RefreshTime      *int    `json:"refresh-time,omitempty"`
				HelloReceipt     *string `json:"hello-receipt,omitempty"`
				KeepMultiplier   *int    `json:"keep-multiplier,omitempty"`
				NonIANAHello     *string `json:"non-IANA-hello,omitempty"`
				HelloInterval    *int    `json:"hello-interval,omitempty"`
			} `json:"interface,omitempty"`
			Neighbor                 *IP     `json:"neighbor,omitempty"`
			BundleSend               *string `json:"bundle-send,omitempty"`
			ExplicitNull             *string `json:"explicit-null,omitempty"`
			OverrideDiffserv         *string `json:"override-diffserv,omitempty"`
			PreprogramSuggestedLabel *string `json:"preprogram-suggested-label,omitempty"`
			Notification             *string `json:"notification,omitempty"`
			Path                     *map[string]struct {
				Mpls *struct {
					Loose      *IP `json:"loose,omitempty"`
					Unnumbered *map[string]struct {
						LinkId *IPv4 `json:"link-id,omitempty"`
					} `json:".unnumbered,omitempty"`
					Strict    *IP `json:"strict,omitempty"`
					StrictHop *IP `json:".strict-hop,omitempty"`
				} `json:"mpls,omitempty"`
				Gmpls *struct {
					StrictHop  *IP `json:"strict-hop,omitempty"`
					Unnumbered *map[string]struct {
						LinkId *IPv4 `json:"link-id,omitempty"`
					} `json:"unnumbered,omitempty"`
					Strict *IP `json:".strict,omitempty"`
					Loose  *IP `json:".loose,omitempty"`
				} `json:".gmpls,omitempty"`
			} `json:"path,omitempty"`
			From               *IP     `json:"from,omitempty"`
			AckWaitTimeout     *int    `json:"ack-wait-timeout,omitempty"`
			RefreshPathParsing *string `json:"refresh-path-parsing,omitempty"`
			Cspf               *string `json:"cspf,omitempty"`
			GracefulRestart    *struct {
				Enable       *string `json:"enable,omitempty"`
				RestartTime  *int    `json:"restart-time,omitempty"`
				RecoveryTime *int    `json:"recovery-time,omitempty"`
			} `json:"graceful-restart,omitempty"`
			RefreshResvParsing *string `json:"refresh-resv-parsing,omitempty"`
			MessageAck         *string `json:"message-ack,omitempty"`
			RefreshReduction   *string `json:"refresh-reduction,omitempty"`
			LocalProtection    *string `json:"local-protection,omitempty"`
			RefreshTime        *int    `json:"refresh-time,omitempty"`
			NoPhp              *string `json:"no-php,omitempty"`
			HelloReceipt       *string `json:"hello-receipt,omitempty"`
			KeepMultiplier     *int    `json:"keep-multiplier,omitempty"`
			LoopDetection      *string `json:"loop-detection,omitempty"`
			HelloInterval      *int    `json:"hello-interval,omitempty"`
			Trunk              *map[string]struct {
				Gmpls *struct {
					ExtTunnelId *IP `json:"ext-tunnel-id,omitempty"`
					LspMetric   *struct {
						Relative *int `json:"relative,omitempty"`
						Absolute *int `json:"absolute,omitempty"`
					} `json:"lsp-metric,omitempty"`
					EnableIgpShortcut *string `json:".enable-igp-shortcut,omitempty"`
					Capability        *struct {
						Psc1  *string `json:"psc-1,omitempty"`
						PbbTe *string `json:"pbb-te,omitempty"`
						Psc4  *string `json:"psc-4,omitempty"`
						Psc3  *string `json:"psc-3,omitempty"`
						Psc2  *string `json:"psc-2,omitempty"`
					} `json:"capability,omitempty"`
					From *IP `json:"from,omitempty"`
					Gpid *struct {
						Ethernet *string `json:"ethernet,omitempty"`
						Ipv4     *string `json:"ipv4,omitempty"`
					} `json:"gpid,omitempty"`
					RsvpTrunkRestart *string `json:"rsvp-trunk-restart,omitempty"`
					GmplsLabelSet    *struct {
						Range *struct {
							StartRange *map[string]struct {
								EndRange *int `json:"end_range,omitempty"`
							} `json:"start_range,omitempty"`
						} `json:"range,omitempty"`
						Packet *struct {
							Range *struct {
								StartRange *map[string]struct {
									EndRange *int `json:"end_range,omitempty"`
								} `json:"start_range,omitempty"`
							} `json:"range,omitempty"`
						} `json:"packet,omitempty"`
					} `json:"gmpls-label-set,omitempty"`
					Direction *struct {
						Bidirectional  *string `json:"bidirectional,omitempty"`
						Unidirectional *string `json:"unidirectional,omitempty"`
					} `json:"direction,omitempty"`
					UpdateType *struct {
						MakeBeforeBreak *string `json:"make-before-break,omitempty"`
						BreakBeforeMake *string `json:"break-before-make,omitempty"`
					} `json:"update-type,omitempty"`
					DisableIgpShortcut *string `json:".disable-igp-shortcut,omitempty"`
					Primary            *struct {
						Traffic *struct {
							ControlledLoad *string `json:"controlled-load,omitempty"`
							Guaranteed     *string `json:"guaranteed,omitempty"`
						} `json:"traffic,omitempty"`
						Bandwidth         *int    `json:"bandwidth,omitempty"`
						SetupPriority     *int    `json:"setup-priority,omitempty"`
						Record            *string `json:"record,omitempty"`
						IncludeAny        *string `json:"include-any,omitempty"`
						Affinity          *string `json:"affinity,omitempty"`
						ReuseRouteRecord  *string `json:"reuse-route-record,omitempty"`
						ElspPreconfigured *string `json:"elsp-preconfigured,omitempty"`
						Path              *string `json:"path,omitempty"`
						HoldPriority      *int    `json:"hold-priority,omitempty"`
						HopLimit          *int    `json:"hop-limit,omitempty"`
						Cspf              *string `json:"cspf,omitempty"`
						LabelRecord       *string `json:"label-record,omitempty"`
						NoAffinity        *string `json:"no-affinity,omitempty"`
						Protection        *struct {
							Unprotected         *string `json:"unprotected,omitempty"`
							DedicatedOneToOne   *string `json:"dedicated-one-to-one,omitempty"`
							Shared              *string `json:"shared,omitempty"`
							ExtraTraffic        *string `json:"extra-traffic,omitempty"`
							DedicatedOnePlusOne *string `json:"dedicated-one-plus-one,omitempty"`
							Ehanced             *string `json:"ehanced,omitempty"`
						} `json:"protection,omitempty"`
						RetryLimit      *int    `json:"retry-limit,omitempty"`
						CspfRetryTimer  *int    `json:"cspf-retry-timer,omitempty"`
						ClassType       *string `json:"class-type,omitempty"`
						ElspSignaled    *string `json:"elsp-signaled,omitempty"`
						LocalProtection *string `json:"local-protection,omitempty"`
						ClassToExpBit   *map[string]struct {
							Bit *int `json:"bit,omitempty"`
						} `json:"class-to-exp-bit,omitempty"`
						Filter *struct {
							SharedExplicit *string `json:"shared-explicit,omitempty"`
							Fixed          *string `json:"fixed,omitempty"`
						} `json:"filter,omitempty"`
						ExplicitLabel *map[string]struct {
							Reverse *string `json:"reverse,omitempty"`
							Packet  *struct {
								Reverse *string `json:"reverse,omitempty"`
								Forward *string `json:"forward,omitempty"`
							} `json:"packet,omitempty"`
							Forward *string `json:"forward,omitempty"`
						} `json:"explicit-label,omitempty"`
						CspfRetryLimit *int    `json:"cspf-retry-limit,omitempty"`
						ExcludeAny     *string `json:"exclude-any,omitempty"`
						RetryTimer     *int    `json:"retry-timer,omitempty"`
						NoRecord       *string `json:"no-record,omitempty"`
						Llsp           *string `json:"llsp,omitempty"`
					} `json:"primary,omitempty"`
					To        *IP `json:"to,omitempty"`
					Secondary *struct {
						Traffic *struct {
							ControlledLoad *string `json:"controlled-load,omitempty"`
							Guaranteed     *string `json:"guaranteed,omitempty"`
						} `json:"traffic,omitempty"`
						Bandwidth         *int    `json:"bandwidth,omitempty"`
						SetupPriority     *int    `json:"setup-priority,omitempty"`
						Record            *string `json:"record,omitempty"`
						IncludeAny        *string `json:"include-any,omitempty"`
						Affinity          *string `json:"affinity,omitempty"`
						ReuseRouteRecord  *string `json:"reuse-route-record,omitempty"`
						ElspPreconfigured *string `json:"elsp-preconfigured,omitempty"`
						Path              *string `json:"path,omitempty"`
						HoldPriority      *int    `json:"hold-priority,omitempty"`
						HopLimit          *int    `json:"hop-limit,omitempty"`
						Cspf              *string `json:"cspf,omitempty"`
						LabelRecord       *string `json:"label-record,omitempty"`
						NoAffinity        *string `json:"no-affinity,omitempty"`
						Protection        *struct {
							Unprotected         *string `json:"unprotected,omitempty"`
							DedicatedOneToOne   *string `json:"dedicated-one-to-one,omitempty"`
							Shared              *string `json:"shared,omitempty"`
							ExtraTraffic        *string `json:"extra-traffic,omitempty"`
							DedicatedOnePlusOne *string `json:"dedicated-one-plus-one,omitempty"`
							Ehanced             *string `json:"ehanced,omitempty"`
						} `json:"protection,omitempty"`
						RetryLimit      *int    `json:"retry-limit,omitempty"`
						CspfRetryTimer  *int    `json:"cspf-retry-timer,omitempty"`
						ClassType       *string `json:"class-type,omitempty"`
						ElspSignaled    *string `json:"elsp-signaled,omitempty"`
						LocalProtection *string `json:"local-protection,omitempty"`
						ClassToExpBit   *map[string]struct {
							Bit *int `json:"bit,omitempty"`
						} `json:"class-to-exp-bit,omitempty"`
						Filter *struct {
							SharedExplicit *string `json:"shared-explicit,omitempty"`
							Fixed          *string `json:"fixed,omitempty"`
						} `json:"filter,omitempty"`
						ExplicitLabel *map[string]struct {
							Reverse *string `json:"reverse,omitempty"`
							Packet  *struct {
								Reverse *string `json:"reverse,omitempty"`
								Forward *string `json:"forward,omitempty"`
							} `json:"packet,omitempty"`
							Forward *string `json:"forward,omitempty"`
						} `json:"explicit-label,omitempty"`
						CspfRetryLimit *int    `json:"cspf-retry-limit,omitempty"`
						ExcludeAny     *string `json:"exclude-any,omitempty"`
						RetryTimer     *int    `json:"retry-timer,omitempty"`
						NoRecord       *string `json:"no-record,omitempty"`
						Llsp           *string `json:"llsp,omitempty"`
					} `json:"secondary,omitempty"`
				} `json:".gmpls,omitempty"`
				Ipv4 *struct {
					ExtTunnelId *IP `json:"ext-tunnel-id,omitempty"`
					LspMetric   *struct {
						Relative *int `json:"relative,omitempty"`
						Absolute *int `json:"absolute,omitempty"`
					} `json:"lsp-metric,omitempty"`
					From             *IPv4   `json:"from,omitempty"`
					RsvpTrunkRestart *string `json:".rsvp-trunk-restart,omitempty"`
					Capability       *struct {
						Psc1 *string `json:"psc-1,omitempty"`
						Psc4 *string `json:"psc-4,omitempty"`
						Psc3 *string `json:"psc-3,omitempty"`
						Psc2 *string `json:"psc-2,omitempty"`
					} `json:".capability,omitempty"`
					Direction *struct {
						Bidirectional  *string `json:"bidirectional,omitempty"`
						Unidirectional *string `json:"unidirectional,omitempty"`
					} `json:".direction,omitempty"`
					MapRoute *map[string]struct {
						Class *string `json:"class,omitempty"`
					} `json:"map-route,omitempty"`
					UpdateType *string `json:"update-type,omitempty"`
					Primary    *struct {
						Traffic       *string `json:"traffic,omitempty"`
						Bandwidth     *string `json:"bandwidth,omitempty"`
						SetupPriority *int    `json:"setup-priority,omitempty"`
						Record        *string `json:"record,omitempty"`
						IncludeAny    *string `json:"include-any,omitempty"`
						Protection    *struct {
							Unprotected         *string `json:"unprotected,omitempty"`
							DedicatedOneToOne   *string `json:"dedicated-one-to-one,omitempty"`
							Shared              *string `json:"shared,omitempty"`
							ExtraTraffic        *string `json:"extra-traffic,omitempty"`
							DedicatedOnePlusOne *string `json:"dedicated-one-plus-one,omitempty"`
							Ehanced             *string `json:"ehanced,omitempty"`
						} `json:".protection,omitempty"`
						ReuseRouteRecord  *string `json:"reuse-route-record,omitempty"`
						ElspPreconfigured *string `json:"elsp-preconfigured,omitempty"`
						Path              *string `json:"path,omitempty"`
						ExplicitLabel     *map[string]struct {
							Reverse *string `json:"reverse,omitempty"`
							Packet  *struct {
								Reverse *string `json:"reverse,omitempty"`
								Forward *string `json:"forward,omitempty"`
							} `json:"packet,omitempty"`
							Forward *string `json:"forward,omitempty"`
						} `json:".explicit-label,omitempty"`
						ClassToExp *map[string]struct {
							Bit *int `json:"bit,omitempty"`
						} `json:"class-to-exp,omitempty"`
						HoldPriority    *int    `json:"hold-priority,omitempty"`
						HopLimit        *int    `json:"hop-limit,omitempty"`
						Cspf            *string `json:"cspf,omitempty"`
						LabelRecord     *string `json:"label-record,omitempty"`
						NoAffinity      *string `json:"no-affinity,omitempty"`
						RetryLimit      *int    `json:"retry-limit,omitempty"`
						CspfRetryTimer  *int    `json:"cspf-retry-timer,omitempty"`
						ClassType       *string `json:"class-type,omitempty"`
						NoRecord        *string `json:".no-record,omitempty"`
						ElspSignaled    *string `json:"elsp-signaled,omitempty"`
						LocalProtection *string `json:"local-protection,omitempty"`
						Filter          *string `json:"filter,omitempty"`
						CspfRetryLimit  *int    `json:"cspf-retry-limit,omitempty"`
						ExcludeAny      *string `json:"exclude-any,omitempty"`
						RetryTimer      *int    `json:"retry-timer,omitempty"`
						Llsp            *string `json:"llsp,omitempty"`
					} `json:"primary,omitempty"`
					To                *IPv4   `json:"to,omitempty"`
					EnableIgpShortcut *string `json:"enable-igp-shortcut,omitempty"`
					Secondary         *struct {
						Traffic       *string `json:"traffic,omitempty"`
						Bandwidth     *string `json:"bandwidth,omitempty"`
						SetupPriority *int    `json:"setup-priority,omitempty"`
						Record        *string `json:"record,omitempty"`
						IncludeAny    *string `json:"include-any,omitempty"`
						Protection    *struct {
							Unprotected         *string `json:"unprotected,omitempty"`
							DedicatedOneToOne   *string `json:"dedicated-one-to-one,omitempty"`
							Shared              *string `json:"shared,omitempty"`
							ExtraTraffic        *string `json:"extra-traffic,omitempty"`
							DedicatedOnePlusOne *string `json:"dedicated-one-plus-one,omitempty"`
							Ehanced             *string `json:"ehanced,omitempty"`
						} `json:".protection,omitempty"`
						ReuseRouteRecord  *string `json:"reuse-route-record,omitempty"`
						ElspPreconfigured *string `json:"elsp-preconfigured,omitempty"`
						Path              *string `json:"path,omitempty"`
						ExplicitLabel     *map[string]struct {
							Reverse *string `json:"reverse,omitempty"`
							Packet  *struct {
								Reverse *string `json:"reverse,omitempty"`
								Forward *string `json:"forward,omitempty"`
							} `json:"packet,omitempty"`
							Forward *string `json:"forward,omitempty"`
						} `json:".explicit-label,omitempty"`
						ClassToExp *map[string]struct {
							Bit *int `json:"bit,omitempty"`
						} `json:"class-to-exp,omitempty"`
						HoldPriority    *int    `json:"hold-priority,omitempty"`
						HopLimit        *int    `json:"hop-limit,omitempty"`
						Cspf            *string `json:"cspf,omitempty"`
						LabelRecord     *string `json:"label-record,omitempty"`
						NoAffinity      *string `json:"no-affinity,omitempty"`
						RetryLimit      *int    `json:"retry-limit,omitempty"`
						CspfRetryTimer  *int    `json:"cspf-retry-timer,omitempty"`
						ClassType       *string `json:"class-type,omitempty"`
						NoRecord        *string `json:".no-record,omitempty"`
						ElspSignaled    *string `json:"elsp-signaled,omitempty"`
						LocalProtection *string `json:"local-protection,omitempty"`
						Filter          *string `json:"filter,omitempty"`
						CspfRetryLimit  *int    `json:"cspf-retry-limit,omitempty"`
						ExcludeAny      *string `json:"exclude-any,omitempty"`
						RetryTimer      *int    `json:"retry-timer,omitempty"`
						Llsp            *string `json:"llsp,omitempty"`
					} `json:"secondary,omitempty"`
					GmplsLabelSet *struct {
						Range *struct {
							StartRange *map[string]struct {
								EndRange *int `json:"end_range,omitempty"`
							} `json:"start_range,omitempty"`
						} `json:"range,omitempty"`
						Packet *struct {
							Range *struct {
								StartRange *map[string]struct {
									EndRange *int `json:"end_range,omitempty"`
								} `json:"start_range,omitempty"`
							} `json:"range,omitempty"`
						} `json:"packet,omitempty"`
					} `json:".gmpls-label-set,omitempty"`
				} `json:"ipv4,omitempty"`
				Ipv6 *struct {
					ExtTunnelId *IP `json:"ext-tunnel-id,omitempty"`
					LspMetric   *struct {
						Relative *int `json:"relative,omitempty"`
						Absolute *int `json:"absolute,omitempty"`
					} `json:"lsp-metric,omitempty"`
					From             *IP     `json:"from,omitempty"`
					Ethernet         *string `json:"ethernet,omitempty"`
					RsvpTrunkRestart *string `json:"rsvp-trunk-restart,omitempty"`
					Capability       *struct {
						Psc1 *string `json:"psc-1,omitempty"`
						Psc4 *string `json:"psc-4,omitempty"`
						Psc3 *string `json:"psc-3,omitempty"`
						Psc2 *string `json:"psc-2,omitempty"`
					} `json:".capability,omitempty"`
					Direction *struct {
						Bidirectional  *string `json:"bidirectional,omitempty"`
						Unidirectional *string `json:"unidirectional,omitempty"`
					} `json:".direction,omitempty"`
					MapRoute *struct {
						Prefix *map[string]struct {
							Mask *map[string]struct {
								Class *string `json:"class,omitempty"`
							} `json:"mask,omitempty"`
						} `json:"prefix,omitempty"`
						Mask *map[string]struct {
							Class *string `json:"class,omitempty"`
						} `json:"mask,omitempty"`
					} `json:"map-route,omitempty"`
					DisableIgpShortcut *string `json:"disable-igp-shortcut,omitempty"`
					UpdateType         *struct {
						MakeBeforeBreak *string `json:"make-before-break,omitempty"`
						BreakBeforeMake *string `json:"break-before-make,omitempty"`
					} `json:"update-type,omitempty"`
					Primary *struct {
						Traffic *struct {
							ControlledLoad *string `json:"controlled-load,omitempty"`
							Guaranteed     *string `json:"guaranteed,omitempty"`
						} `json:"traffic,omitempty"`
						Bandwidth     *int    `json:"bandwidth,omitempty"`
						SetupPriority *int    `json:"setup-priority,omitempty"`
						Record        *string `json:"record,omitempty"`
						IncludeAny    *string `json:"include-any,omitempty"`
						Protection    *struct {
							Unprotected         *string `json:"unprotected,omitempty"`
							DedicatedOneToOne   *string `json:"dedicated-one-to-one,omitempty"`
							Shared              *string `json:"shared,omitempty"`
							ExtraTraffic        *string `json:"extra-traffic,omitempty"`
							DedicatedOnePlusOne *string `json:"dedicated-one-plus-one,omitempty"`
							Ehanced             *string `json:"ehanced,omitempty"`
						} `json:".protection,omitempty"`
						Affinity          *string `json:"affinity,omitempty"`
						ReuseRouteRecord  *string `json:"reuse-route-record,omitempty"`
						ElspPreconfigured *string `json:"elsp-preconfigured,omitempty"`
						Path              *string `json:"path,omitempty"`
						ExplicitLabel     *map[string]struct {
							Reverse *string `json:"reverse,omitempty"`
							Packet  *struct {
								Reverse *string `json:"reverse,omitempty"`
								Forward *string `json:"forward,omitempty"`
							} `json:"packet,omitempty"`
							Forward *string `json:"forward,omitempty"`
						} `json:".explicit-label,omitempty"`
						HoldPriority    *int    `json:"hold-priority,omitempty"`
						HopLimit        *int    `json:"hop-limit,omitempty"`
						Cspf            *string `json:"cspf,omitempty"`
						LabelRecord     *string `json:"label-record,omitempty"`
						RetryLimit      *int    `json:"retry-limit,omitempty"`
						CspfRetryTimer  *int    `json:"cspf-retry-timer,omitempty"`
						ClassType       *string `json:"class-type,omitempty"`
						NoRecord        *string `json:".no-record,omitempty"`
						ElspSignaled    *string `json:"elsp-signaled,omitempty"`
						NoAffinity      *string `json:".no-affinity,omitempty"`
						LocalProtection *string `json:"local-protection,omitempty"`
						ClassToExpBit   *map[string]struct {
							Bit *int `json:"bit,omitempty"`
						} `json:"class-to-exp-bit,omitempty"`
						Filter *struct {
							SharedExplicit *string `json:"shared-explicit,omitempty"`
							Fixed          *string `json:"fixed,omitempty"`
						} `json:"filter,omitempty"`
						CspfRetryLimit *int    `json:"cspf-retry-limit,omitempty"`
						ExcludeAny     *string `json:"exclude-any,omitempty"`
						RetryTimer     *int    `json:"retry-timer,omitempty"`
						Llsp           *string `json:"llsp,omitempty"`
					} `json:"primary,omitempty"`
					To                *IP     `json:"to,omitempty"`
					EnableIgpShortcut *string `json:"enable-igp-shortcut,omitempty"`
					Secondary         *struct {
						Traffic *struct {
							ControlledLoad *string `json:"controlled-load,omitempty"`
							Guaranteed     *string `json:"guaranteed,omitempty"`
						} `json:"traffic,omitempty"`
						Bandwidth     *int    `json:"bandwidth,omitempty"`
						SetupPriority *int    `json:"setup-priority,omitempty"`
						Record        *string `json:"record,omitempty"`
						IncludeAny    *string `json:"include-any,omitempty"`
						Protection    *struct {
							Unprotected         *string `json:"unprotected,omitempty"`
							DedicatedOneToOne   *string `json:"dedicated-one-to-one,omitempty"`
							Shared              *string `json:"shared,omitempty"`
							ExtraTraffic        *string `json:"extra-traffic,omitempty"`
							DedicatedOnePlusOne *string `json:"dedicated-one-plus-one,omitempty"`
							Ehanced             *string `json:"ehanced,omitempty"`
						} `json:".protection,omitempty"`
						Affinity          *string `json:"affinity,omitempty"`
						ReuseRouteRecord  *string `json:"reuse-route-record,omitempty"`
						ElspPreconfigured *string `json:"elsp-preconfigured,omitempty"`
						Path              *string `json:"path,omitempty"`
						ExplicitLabel     *map[string]struct {
							Reverse *string `json:"reverse,omitempty"`
							Packet  *struct {
								Reverse *string `json:"reverse,omitempty"`
								Forward *string `json:"forward,omitempty"`
							} `json:"packet,omitempty"`
							Forward *string `json:"forward,omitempty"`
						} `json:".explicit-label,omitempty"`
						HoldPriority    *int    `json:"hold-priority,omitempty"`
						HopLimit        *int    `json:"hop-limit,omitempty"`
						Cspf            *string `json:"cspf,omitempty"`
						LabelRecord     *string `json:"label-record,omitempty"`
						RetryLimit      *int    `json:"retry-limit,omitempty"`
						CspfRetryTimer  *int    `json:"cspf-retry-timer,omitempty"`
						ClassType       *string `json:"class-type,omitempty"`
						NoRecord        *string `json:".no-record,omitempty"`
						ElspSignaled    *string `json:"elsp-signaled,omitempty"`
						NoAffinity      *string `json:".no-affinity,omitempty"`
						LocalProtection *string `json:"local-protection,omitempty"`
						ClassToExpBit   *map[string]struct {
							Bit *int `json:"bit,omitempty"`
						} `json:"class-to-exp-bit,omitempty"`
						Filter *struct {
							SharedExplicit *string `json:"shared-explicit,omitempty"`
							Fixed          *string `json:"fixed,omitempty"`
						} `json:"filter,omitempty"`
						CspfRetryLimit *int    `json:"cspf-retry-limit,omitempty"`
						ExcludeAny     *string `json:"exclude-any,omitempty"`
						RetryTimer     *int    `json:"retry-timer,omitempty"`
						Llsp           *string `json:"llsp,omitempty"`
					} `json:"secondary,omitempty"`
					GmplsLabelSet *struct {
						Range *struct {
							StartRange *map[string]struct {
								EndRange *int `json:"end_range,omitempty"`
							} `json:"start_range,omitempty"`
						} `json:"range,omitempty"`
						Packet *struct {
							Range *struct {
								StartRange *map[string]struct {
									EndRange *int `json:"end_range,omitempty"`
								} `json:"start_range,omitempty"`
							} `json:"range,omitempty"`
						} `json:"packet,omitempty"`
					} `json:".gmpls-label-set,omitempty"`
				} `json:".ipv6,omitempty"`
			} `json:"trunk,omitempty"`
		} `json:"rsvp,omitempty"`
		Vpls *struct {
			Interface *map[string]struct {
				VlanInstance *map[string]struct {
					Vlan *map[string]struct {
					} `json:"vlan,omitempty"`
				} `json:"vlan-instance,omitempty"`
				Instance *string `json:"instance,omitempty"`
			} `json:"interface,omitempty"`
			FibEntry *map[string]struct {
				Peer *map[string]struct {
					InLabel *map[string]struct {
						OutInterface *map[string]struct {
							OutLabel *int `json:"out-label,omitempty"`
						} `json:"out-interface,omitempty"`
					} `json:"in-label,omitempty"`
				} `json:"peer,omitempty"`
				SpokeVc *map[string]struct {
					InLabel *map[string]struct {
						OutInterface *map[string]struct {
							OutLabel *int `json:"out-label,omitempty"`
						} `json:"out-interface,omitempty"`
					} `json:"in-label,omitempty"`
				} `json:".spoke-vc,omitempty"`
			} `json:"fib-entry,omitempty"`
			Instance *map[string]struct {
				Id *map[string]struct {
					VplsAcGroup *string `json:"vpls-ac-group,omitempty"`
					VplsPeer    *map[string]struct {
						Manual   *string `json:"manual,omitempty"`
						TunnelId *map[string]struct {
							Reverse *struct {
								Manual *string `json:"manual,omitempty"`
							} `json:"reverse,omitempty"`
							Manual  *string `json:"manual,omitempty"`
							Forward *struct {
								Manual *string `json:"manual,omitempty"`
							} `json:"forward,omitempty"`
						} `json:"tunnel-id,omitempty"`
					} `json:"vpls-peer,omitempty"`
					Learning *struct {
						Disable *string `json:"disable,omitempty"`
						Limit   *int    `json:"limit,omitempty"`
					} `json:"learning,omitempty"`
					VplsVc *map[string]struct {
						Ethernet *string `json:"ethernet,omitempty"`
						Vlan     *string `json:"vlan,omitempty"`
						Normal   *string `json:"normal,omitempty"`
					} `json:"vpls-vc,omitempty"`
					VplsDescription *string `json:"vpls-description,omitempty"`
					Signaling       *struct {
						Ldp *struct {
							VplsPeer *map[string]struct {
								Agi *map[string]struct {
									Saii *map[string]struct {
										Taii *map[string]struct {
											Normal   *string `json:"normal,omitempty"`
											TunnelId *map[string]struct {
												Reverse *string `json:"reverse,omitempty"`
												Normal  *string `json:"normal,omitempty"`
												Forward *string `json:"forward,omitempty"`
											} `json:"tunnel-id,omitempty"`
										} `json:"taii,omitempty"`
									} `json:"saii,omitempty"`
								} `json:"agi,omitempty"`
								TunnelId *map[string]struct {
									Reverse *string `json:"reverse,omitempty"`
									Forward *string `json:"forward,omitempty"`
								} `json:"tunnel-id,omitempty"`
							} `json:"vpls-peer,omitempty"`
						} `json:"ldp,omitempty"`
						Bgp *struct {
							VeRange     *int    `json:"ve-range,omitempty"`
							VeId        *int    `json:"ve-id,omitempty"`
							RouteTarget *string `json:"route-target,omitempty"`
							Rd          *string `json:"rd,omitempty"`
						} `json:"bgp,omitempty"`
					} `json:"signaling,omitempty"`
					VplsType *string `json:"vpls-type,omitempty"`
					VplsMtu  *int    `json:"vpls-mtu,omitempty"`
				} `json:"id,omitempty"`
			} `json:"instance,omitempty"`
		} `json:"vpls,omitempty"`
		Ldp *struct {
			LdpOptimization           *string `json:"ldp-optimization,omitempty"`
			TargetedPeerHelloInterval *int    `json:"targeted-peer-hello-interval,omitempty"`
			Interface                 *map[string]struct {
				Enable *struct {
					Both *string `json:"both,omitempty"`
					Ipv4 *string `json:"ipv4,omitempty"`
					Ipv6 *string `json:"ipv6,omitempty"`
				} `json:"enable,omitempty"`
				KeepaliveTimeout   *int `json:"keepalive-timeout,omitempty"`
				LabelRetentionMode *struct {
					Liberal      *string `json:"liberal,omitempty"`
					Conservative *string `json:"conservative,omitempty"`
				} `json:"label-retention-mode,omitempty"`
				HoldTime          *int `json:"hold-time,omitempty"`
				KeepaliveInterval *int `json:"keepalive-interval,omitempty"`
				AdvertisementMode *struct {
					DownstreamOnDemand    *string `json:"downstream-on-demand,omitempty"`
					DownstreamUnsolicited *string `json:"downstream-unsolicited,omitempty"`
				} `json:"advertisement-mode,omitempty"`
				HelloInterval *int `json:"hello-interval,omitempty"`
			} `json:"interface,omitempty"`
			Neighbor *map[string]struct {
				Auth *struct {
					Md5 *struct {
						Password *map[string]struct {
							Type *int `json:"type,omitempty"`
						} `json:"password,omitempty"`
					} `json:"md5,omitempty"`
				} `json:"auth,omitempty"`
			} `json:"neighbor,omitempty"`
			MulticastHellos *string `json:"multicast-hellos,omitempty"`
			ExplicitNull    *string `json:"explicit-null,omitempty"`
			ImportBgpRoutes *string `json:"import-bgp-routes,omitempty"`
			AdvertiseLabels *struct {
				ForAcl *map[string]struct {
					To *struct {
						Any *string `json:"any,omitempty"`
					} `json:"to,omitempty"`
				} `json:"for-acl,omitempty"`
				For *struct {
					PeerAcl *map[string]struct {
						To *struct {
							PeerAcl *string `json:"peer-acl,omitempty"`
							Any     *string `json:"any,omitempty"`
						} `json:"to,omitempty"`
					} `json:"peer-acl,omitempty"`
					Any *struct {
						To *struct {
							None *string `json:"none,omitempty"`
						} `json:"to,omitempty"`
					} `json:"any,omitempty"`
				} `json:"for,omitempty"`
			} `json:"advertise-labels,omitempty"`
			KeepaliveTimeout *int    `json:"keepalive-timeout,omitempty"`
			PropagateRelease *string `json:"propagate-release,omitempty"`
			TransportAddress *struct {
				Ipv4 *map[string]struct {
					Labelspace *string `json:"labelspace,omitempty"`
				} `json:"ipv4,omitempty"`
				Ipv6 *map[string]struct {
					Labelspace *string `json:"labelspace,omitempty"`
				} `json:".ipv6,omitempty"`
			} `json:"transport-address,omitempty"`
			RouterId    *IP `json:"router-id,omitempty"`
			ControlMode *struct {
				Independent *string `json:"independent,omitempty"`
				Ordered     *string `json:"ordered,omitempty"`
			} `json:"control-mode,omitempty"`
			LabelRetentionMode *struct {
				Liberal      *string `json:"liberal,omitempty"`
				Conservative *string `json:"conservative,omitempty"`
			} `json:"label-retention-mode,omitempty"`
			RequestRetryTimeout *int `json:"request-retry-timeout,omitempty"`
			GracefulRestart     *struct {
				Enable  *string `json:"enable,omitempty"`
				Disable *string `json:"disable,omitempty"`
				Timers  *struct {
					MaxRecovery      *int `json:"max-recovery,omitempty"`
					NeighborLiveness *int `json:"neighbor-liveness,omitempty"`
				} `json:"timers,omitempty"`
			} `json:"graceful-restart,omitempty"`
			TargetedPeerHoldTime      *int    `json:"targeted-peer-hold-time,omitempty"`
			LoopDetectionPathVecCount *int    `json:"loop-detection-path-vec-count,omitempty"`
			HoldTime                  *int    `json:"hold-time,omitempty"`
			RequestRetry              *string `json:"request-retry,omitempty"`
			LoopDetection             *string `json:"loop-detection,omitempty"`
			TargetedPeer              *struct {
				Ipv4 *map[string]struct {
				} `json:"ipv4,omitempty"`
				Ipv6 *IPv6 `json:".ipv6,omitempty"`
			} `json:"targeted-peer,omitempty"`
			GlobalMergeCapability *struct {
				NonMergeCapable *string `json:"non-merge-capable,omitempty"`
				MergeCapable    *string `json:"merge-capable,omitempty"`
			} `json:"global-merge-capability,omitempty"`
			KeepaliveInterval *int `json:"keepalive-interval,omitempty"`
			AdvertisementMode *struct {
				DownstreamOnDemand    *string `json:"downstream-on-demand,omitempty"`
				DownstreamUnsolicited *string `json:"downstream-unsolicited,omitempty"`
			} `json:"advertisement-mode,omitempty"`
			LoopDetectionHopCount *int    `json:"loop-detection-hop-count,omitempty"`
			HelloInterval         *int    `json:"hello-interval,omitempty"`
			PwStatusTlv           *string `json:"pw-status-tlv,omitempty"`
		} `json:"ldp,omitempty"`
		IgmpProxy *struct {
			Disable   *string `json:"disable,omitempty"`
			Interface *map[string]struct {
				Whitelist *IPv4Net `json:"whitelist,omitempty"`
				Role      *string  `json:"role,omitempty"`
				AltSubnet *IPv4Net `json:"alt-subnet,omitempty"`
				Threshold *int     `json:"threshold,omitempty"`
			} `json:"interface,omitempty"`
			DisableQuickleave *string `json:"disable-quickleave,omitempty"`
		} `json:"igmp-proxy,omitempty"`
		Bgp *map[string]struct {
			Neighbor *map[string]struct {
				Weight        *int    `json:"weight,omitempty"`
				NoActivate    *string `json:"no-activate,omitempty"`
				EbgpMultihop  *int    `json:"ebgp-multihop,omitempty"`
				Password      *string `json:"password,omitempty"`
				MaximumPrefix *int    `json:"maximum-prefix,omitempty"`
				FilterList    *struct {
					Export *string `json:"export,omitempty"`
					Import *string `json:"import,omitempty"`
				} `json:"filter-list,omitempty"`
				AllowasIn *struct {
					Number *int `json:"number,omitempty"`
				} `json:"allowas-in,omitempty"`
				RouteReflectorClient  *string `json:"route-reflector-client,omitempty"`
				OverrideCapability    *string `json:"override-capability,omitempty"`
				Shutdown              *string `json:"shutdown,omitempty"`
				StrictCapabilityMatch *string `json:"strict-capability-match,omitempty"`
				DisableSendCommunity  *struct {
					Standard *string `json:"standard,omitempty"`
					Extended *string `json:"extended,omitempty"`
				} `json:"disable-send-community,omitempty"`
				Timers *struct {
					Holdtime  *int `json:"holdtime,omitempty"`
					Keepalive *int `json:"keepalive,omitempty"`
					Connect   *int `json:"connect,omitempty"`
				} `json:"timers,omitempty"`
				DefaultOriginate *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"default-originate,omitempty"`
				RouteServerClient *string `json:"route-server-client,omitempty"`
				Capability        *struct {
					Dynamic *string `json:"dynamic,omitempty"`
					Orf     *struct {
						PrefixList *struct {
							Both    *string `json:"both,omitempty"`
							Receive *string `json:"receive,omitempty"`
							Send    *string `json:"send,omitempty"`
						} `json:"prefix-list,omitempty"`
					} `json:"orf,omitempty"`
					GracefulRestart *string `json:"graceful-restart,omitempty"`
				} `json:"capability,omitempty"`
				UpdateSource *string `json:"update-source,omitempty"`
				TtlSecurity  *struct {
					Hops *int `json:"hops,omitempty"`
				} `json:"ttl-security,omitempty"`
				UnsuppressMap *string `json:"unsuppress-map,omitempty"`
				FallOver      *struct {
					Bfd *struct {
						Multihop *string `json:"multihop,omitempty"`
					} `json:"bfd,omitempty"`
				} `json:"fall-over,omitempty"`
				Passive       *string `json:"passive,omitempty"`
				AddressFamily *struct {
					Ipv6Unicast *struct {
						MaximumPrefix *int `json:"maximum-prefix,omitempty"`
						FilterList    *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"filter-list,omitempty"`
						AllowasIn *struct {
							Number *int `json:"number,omitempty"`
						} `json:"allowas-in,omitempty"`
						RouteReflectorClient *string `json:"route-reflector-client,omitempty"`
						NexthopLocal         *struct {
							Unchanged *string `json:"unchanged,omitempty"`
						} `json:"nexthop-local,omitempty"`
						DisableSendCommunity *struct {
							Standard *string `json:"standard,omitempty"`
							Extended *string `json:"extended,omitempty"`
						} `json:"disable-send-community,omitempty"`
						DefaultOriginate *struct {
							RouteMap *string `json:"route-map,omitempty"`
						} `json:"default-originate,omitempty"`
						RouteServerClient *string `json:"route-server-client,omitempty"`
						Capability        *struct {
							Orf *struct {
								PrefixList *struct {
									Receive *string `json:"receive,omitempty"`
									Send    *string `json:"send,omitempty"`
								} `json:"prefix-list,omitempty"`
							} `json:"orf,omitempty"`
							GracefulRestart *string `json:"graceful-restart,omitempty"`
						} `json:"capability,omitempty"`
						UnsuppressMap       *string `json:"unsuppress-map,omitempty"`
						SoftReconfiguration *struct {
							Inbound *string `json:"inbound,omitempty"`
						} `json:"soft-reconfiguration,omitempty"`
						AttributeUnchanged *struct {
							AsPath  *string `json:"as-path,omitempty"`
							NextHop *string `json:"next-hop,omitempty"`
							Med     *string `json:"med,omitempty"`
						} `json:"attribute-unchanged,omitempty"`
						RouteMap *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"route-map,omitempty"`
						NexthopSelf     *string `json:"nexthop-self,omitempty"`
						RemovePrivateAs *string `json:"remove-private-as,omitempty"`
						PrefixList      *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"prefix-list,omitempty"`
						DistributeList *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"distribute-list,omitempty"`
						PeerGroup *string `json:"peer-group,omitempty"`
					} `json:"ipv6-unicast,omitempty"`
				} `json:"address-family,omitempty"`
				Description         *string `json:"description,omitempty"`
				SoftReconfiguration *struct {
					Inbound *string `json:"inbound,omitempty"`
				} `json:"soft-reconfiguration,omitempty"`
				LocalAs *map[string]struct {
					NoPrepend *string `json:"no-prepend,omitempty"`
				} `json:"local-as,omitempty"`
				AttributeUnchanged *struct {
					AsPath  *string `json:"as-path,omitempty"`
					NextHop *string `json:"next-hop,omitempty"`
					Med     *string `json:"med,omitempty"`
				} `json:"attribute-unchanged,omitempty"`
				RouteMap *struct {
					Export *string `json:"export,omitempty"`
					Import *string `json:"import,omitempty"`
				} `json:"route-map,omitempty"`
				RemoteAs                     *int    `json:"remote-as,omitempty"`
				NexthopSelf                  *string `json:"nexthop-self,omitempty"`
				DisableConnectedCheck        *string `json:"disable-connected-check,omitempty"`
				DisableCapabilityNegotiation *string `json:"disable-capability-negotiation,omitempty"`
				Port                         *int    `json:"port,omitempty"`
				AdvertisementInterval        *int    `json:"advertisement-interval,omitempty"`
				RemovePrivateAs              *string `json:"remove-private-as,omitempty"`
				PrefixList                   *struct {
					Export *string `json:"export,omitempty"`
					Import *string `json:"import,omitempty"`
				} `json:"prefix-list,omitempty"`
				DistributeList *struct {
					Word *map[string]struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"word,omitempty"`
					Export *int `json:"export,omitempty"`
					Import *int `json:"import,omitempty"`
				} `json:"distribute-list,omitempty"`
				PeerGroup *string `json:"peer-group,omitempty"`
			} `json:"neighbor,omitempty"`
			Timers *struct {
				Holdtime  *int `json:"holdtime,omitempty"`
				Keepalive *int `json:"keepalive,omitempty"`
			} `json:"timers,omitempty"`
			MaximumPaths *struct {
				Ibgp *int `json:"ibgp,omitempty"`
				Ebgp *int `json:"ebgp,omitempty"`
			} `json:"maximum-paths,omitempty"`
			Network *map[string]struct {
				Backdoor *string `json:"backdoor,omitempty"`
				RouteMap *string `json:"route-map,omitempty"`
			} `json:"network,omitempty"`
			AggregateAddress *map[string]struct {
				SummaryOnly *string `json:"summary-only,omitempty"`
				AsSet       *string `json:"as-set,omitempty"`
			} `json:"aggregate-address,omitempty"`
			AddressFamily *struct {
				L2vpn *struct {
					Vpls *struct {
						Neighbor *struct {
							Ipv4 *map[string]struct {
								Activate *string `json:"activate,omitempty"`
							} `json:"ipv4,omitempty"`
							Ipv6 *map[string]struct {
								Activate *string `json:"activate,omitempty"`
							} `json:"ipv6,omitempty"`
							Tag *map[string]struct {
								Activate *string `json:"activate,omitempty"`
							} `json:"tag,omitempty"`
						} `json:"neighbor,omitempty"`
					} `json:"vpls,omitempty"`
				} `json:"l2vpn,omitempty"`
				Ipv4Unicast *struct {
					Vrf *map[string]struct {
						Neighbor *map[string]struct {
							Weight        *int `json:"weight,omitempty"`
							EbgpMultihop  *int `json:"ebgp-multihop,omitempty"`
							MaximumPrefix *int `json:"maximum-prefix,omitempty"`
							FilterList    *struct {
								Export *string `json:"export,omitempty"`
								Import *string `json:"import,omitempty"`
							} `json:"filter-list,omitempty"`
							AllowasIn *struct {
								Number *int `json:"number,omitempty"`
							} `json:"allowas-in,omitempty"`
							RouteReflectorClient *string `json:"route-reflector-client,omitempty"`
							Shutdown             *string `json:"shutdown,omitempty"`
							Timers               *struct {
								Holdtime  *int `json:"holdtime,omitempty"`
								Keepalive *int `json:"keepalive,omitempty"`
								Connect   *int `json:"connect,omitempty"`
							} `json:"timers,omitempty"`
							DefaultOriginate *struct {
								RouteMap *string `json:"route-map,omitempty"`
							} `json:"default-originate,omitempty"`
							Capability *struct {
								Dynamic *string `json:"dynamic,omitempty"`
								Orf     *struct {
									PrefixList *struct {
										Both    *string `json:"both,omitempty"`
										Receive *string `json:"receive,omitempty"`
										Send    *string `json:"send,omitempty"`
									} `json:"prefix-list,omitempty"`
								} `json:"orf,omitempty"`
								GracefulRestart *string `json:"graceful-restart,omitempty"`
							} `json:"capability,omitempty"`
							UpdateSource        *string `json:"update-source,omitempty"`
							UnsuppressMap       *string `json:"unsuppress-map,omitempty"`
							Passive             *string `json:"passive,omitempty"`
							Description         *string `json:"description,omitempty"`
							SoftReconfiguration *struct {
								Inbound *string `json:"inbound,omitempty"`
							} `json:"soft-reconfiguration,omitempty"`
							LocalAs *map[string]struct {
								NoPrepend *string `json:"no-prepend,omitempty"`
							} `json:"local-as,omitempty"`
							AttributeUnchanged *struct {
								AsPath  *string `json:"as-path,omitempty"`
								NextHop *string `json:"next-hop,omitempty"`
								Med     *string `json:"med,omitempty"`
							} `json:"attribute-unchanged,omitempty"`
							RouteMap *struct {
								Export *string `json:"export,omitempty"`
								Import *string `json:"import,omitempty"`
							} `json:"route-map,omitempty"`
							RemoteAs              *int    `json:"remote-as,omitempty"`
							Activate              *string `json:"activate,omitempty"`
							Port                  *int    `json:"port,omitempty"`
							AdvertisementInterval *int    `json:"advertisement-interval,omitempty"`
							RemovePrivateAs       *string `json:"remove-private-as,omitempty"`
							PrefixList            *struct {
								Export *string `json:"export,omitempty"`
								Import *string `json:"import,omitempty"`
							} `json:"prefix-list,omitempty"`
							DistributeList *struct {
								Word *map[string]struct {
									Out *string `json:"out,omitempty"`
									In  *string `json:"in,omitempty"`
								} `json:"word,omitempty"`
							} `json:"distribute-list,omitempty"`
							PeerGroup *string `json:"peer-group,omitempty"`
						} `json:"neighbor,omitempty"`
						Network *map[string]struct {
							RouteMap *string `json:"route-map,omitempty"`
						} `json:"network,omitempty"`
						Parameters *struct {
							Dampening *struct {
								MaxSuppressTime   *int `json:"max-suppress-time,omitempty"`
								StartSuppressTime *int `json:"start-suppress-time,omitempty"`
								ReUse             *int `json:"re-use,omitempty"`
								HalfLife          *int `json:"half-life,omitempty"`
							} `json:"dampening,omitempty"`
							Confederation *struct {
								Identifier *int `json:"identifier,omitempty"`
								Peers      *int `json:"peers,omitempty"`
							} `json:"confederation,omitempty"`
						} `json:"parameters,omitempty"`
						Redistribute *struct {
							Rip *struct {
								RouteMap *string `json:"route-map,omitempty"`
								Metric   *int    `json:"metric,omitempty"`
							} `json:"rip,omitempty"`
							Connected *struct {
								RouteMap *string `json:"route-map,omitempty"`
								Metric   *int    `json:"metric,omitempty"`
							} `json:"connected,omitempty"`
							Static *struct {
								RouteMap *string `json:"route-map,omitempty"`
								Metric   *int    `json:"metric,omitempty"`
							} `json:"static,omitempty"`
							Kernel *struct {
								RouteMap *string `json:"route-map,omitempty"`
								Metric   *int    `json:"metric,omitempty"`
							} `json:"kernel,omitempty"`
							Ospf *struct {
								RouteMap *string `json:"route-map,omitempty"`
								Metric   *int    `json:"metric,omitempty"`
							} `json:"ospf,omitempty"`
						} `json:"redistribute,omitempty"`
						PeerGroup *map[string]struct {
							Weight        *int `json:"weight,omitempty"`
							EbgpMultihop  *int `json:"ebgp-multihop,omitempty"`
							MaximumPrefix *int `json:"maximum-prefix,omitempty"`
							FilterList    *struct {
								Export *string `json:"export,omitempty"`
								Import *string `json:"import,omitempty"`
							} `json:"filter-list,omitempty"`
							AllowasIn *struct {
								Number *int `json:"number,omitempty"`
							} `json:"allowas-in,omitempty"`
							RouteReflectorClient *string `json:"route-reflector-client,omitempty"`
							OverrideCapability   *string `json:"override-capability,omitempty"`
							Shutdown             *string `json:"shutdown,omitempty"`
							DisableSendCommunity *struct {
								Standard *string `json:"standard,omitempty"`
								Extended *string `json:"extended,omitempty"`
							} `json:"disable-send-community,omitempty"`
							DefaultOriginate *struct {
								RouteMap *string `json:"route-map,omitempty"`
							} `json:"default-originate,omitempty"`
							Capability *struct {
								Dynamic *string `json:"dynamic,omitempty"`
								Orf     *struct {
									PrefixList *struct {
										Receive *string `json:"receive,omitempty"`
										Send    *string `json:"send,omitempty"`
									} `json:"prefix-list,omitempty"`
								} `json:"orf,omitempty"`
							} `json:"capability,omitempty"`
							UpdateSource  *string `json:"update-source,omitempty"`
							UnsuppressMap *string `json:"unsuppress-map,omitempty"`
							Passive       *string `json:"passive,omitempty"`
							Timers        *struct {
								Holdtime  *int `json:"holdtime,omitempty"`
								Keepalive *int `json:"keepalive,omitempty"`
							} `json:".timers,omitempty"`
							Description         *string `json:"description,omitempty"`
							SoftReconfiguration *struct {
								Inbound *string `json:"inbound,omitempty"`
							} `json:"soft-reconfiguration,omitempty"`
							LocalAs *map[string]struct {
								NoPrepend *string `json:"no-prepend,omitempty"`
							} `json:"local-as,omitempty"`
							AttributeUnchanged *struct {
								AsPath  *string `json:"as-path,omitempty"`
								NextHop *string `json:"next-hop,omitempty"`
								Med     *string `json:"med,omitempty"`
							} `json:"attribute-unchanged,omitempty"`
							RouteMap *struct {
								Export *string `json:"export,omitempty"`
								Import *string `json:"import,omitempty"`
							} `json:"route-map,omitempty"`
							RemoteAs                     *int    `json:"remote-as,omitempty"`
							DisableConnectedCheck        *string `json:"disable-connected-check,omitempty"`
							DisableCapabilityNegotiation *string `json:"disable-capability-negotiation,omitempty"`
							RemovePrivateAs              *string `json:"remove-private-as,omitempty"`
							PrefixList                   *struct {
								Export *string `json:"export,omitempty"`
								Import *string `json:"import,omitempty"`
							} `json:"prefix-list,omitempty"`
							DistributeList *struct {
								Export *int `json:"export,omitempty"`
								Import *int `json:"import,omitempty"`
							} `json:"distribute-list,omitempty"`
						} `json:"peer-group,omitempty"`
					} `json:"vrf,omitempty"`
				} `json:".ipv4-unicast,omitempty"`
				Ipv6Unicast *struct {
					Network *map[string]struct {
						RouteMap  *string `json:"route-map,omitempty"`
						PathLimit *int    `json:"path-limit,omitempty"`
					} `json:"network,omitempty"`
					AggregateAddress *map[string]struct {
						SummaryOnly *string `json:"summary-only,omitempty"`
					} `json:"aggregate-address,omitempty"`
					Redistribute *struct {
						Connected *struct {
							RouteMap *string `json:"route-map,omitempty"`
							Metric   *int    `json:"metric,omitempty"`
						} `json:"connected,omitempty"`
						Ripng *struct {
							RouteMap *string `json:"route-map,omitempty"`
							Metric   *int    `json:"metric,omitempty"`
						} `json:"ripng,omitempty"`
						Static *struct {
							RouteMap *string `json:"route-map,omitempty"`
							Metric   *int    `json:"metric,omitempty"`
						} `json:"static,omitempty"`
						Ospfv3 *struct {
							RouteMap *string `json:"route-map,omitempty"`
							Metric   *int    `json:"metric,omitempty"`
						} `json:"ospfv3,omitempty"`
						Kernel *struct {
							RouteMap *string `json:"route-map,omitempty"`
							Metric   *int    `json:"metric,omitempty"`
						} `json:"kernel,omitempty"`
					} `json:"redistribute,omitempty"`
				} `json:"ipv6-unicast,omitempty"`
			} `json:"address-family,omitempty"`
			Dampening *struct {
				RouteMap *string `json:"route-map,omitempty"`
				HalfLife *map[string]struct {
					ReuseRoute *map[string]struct {
						SupRoute *map[string]struct {
							Time *map[string]struct {
								HalfTime *int `json:"half-time,omitempty"`
							} `json:"time,omitempty"`
						} `json:"sup-route,omitempty"`
					} `json:"reuse-route,omitempty"`
				} `json:"half-life,omitempty"`
			} `json:"dampening,omitempty"`
			Parameters *struct {
				ClusterId                  *IPv4   `json:"cluster-id,omitempty"`
				DisableNetworkImportCheck  *string `json:"disable-network-import-check,omitempty"`
				NoClientToClientReflection *string `json:"no-client-to-client-reflection,omitempty"`
				EnforceFirstAs             *string `json:"enforce-first-as,omitempty"`
				RouterId                   *IPv4   `json:"router-id,omitempty"`
				Distance                   *struct {
					Prefix *map[string]struct {
						Distance *int `json:"distance,omitempty"`
					} `json:"prefix,omitempty"`
					Global *struct {
						Internal *int `json:"internal,omitempty"`
						Local    *int `json:"local,omitempty"`
						External *int `json:"external,omitempty"`
					} `json:"global,omitempty"`
				} `json:"distance,omitempty"`
				Default *struct {
					NoIpv4Unicast *string `json:"no-ipv4-unicast,omitempty"`
					LocalPref     *int    `json:"local-pref,omitempty"`
				} `json:"default,omitempty"`
				AlwaysCompareMed *string `json:"always-compare-med,omitempty"`
				GracefulRestart  *struct {
					StalepathTime *int `json:"stalepath-time,omitempty"`
				} `json:"graceful-restart,omitempty"`
				Dampening *struct {
					MaxSuppressTime   *int `json:"max-suppress-time,omitempty"`
					StartSuppressTime *int `json:"start-suppress-time,omitempty"`
					ReUse             *int `json:"re-use,omitempty"`
					HalfLife          *int `json:"half-life,omitempty"`
				} `json:"dampening,omitempty"`
				DeterministicMed *string `json:"deterministic-med,omitempty"`
				Bestpath         *struct {
					AsPath *struct {
						Confed *string `json:"confed,omitempty"`
						Ignore *string `json:"ignore,omitempty"`
					} `json:"as-path,omitempty"`
					CompareRouterid *string `json:"compare-routerid,omitempty"`
					Med             *struct {
						Confed         *string `json:"confed,omitempty"`
						MissingAsWorst *string `json:"missing-as-worst,omitempty"`
					} `json:"med,omitempty"`
				} `json:"bestpath,omitempty"`
				LogNeighborChanges *string `json:"log-neighbor-changes,omitempty"`
				ScanTime           *int    `json:"scan-time,omitempty"`
				Confederation      *struct {
					Identifier *int `json:"identifier,omitempty"`
					Peers      *int `json:"peers,omitempty"`
				} `json:"confederation,omitempty"`
				NoFastExternalFailover *string `json:"no-fast-external-failover,omitempty"`
			} `json:"parameters,omitempty"`
			Redistribute *struct {
				Rip *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"rip,omitempty"`
				Connected *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"connected,omitempty"`
				Static *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"static,omitempty"`
				Kernel *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"kernel,omitempty"`
				Ospf *struct {
					RouteMap *string `json:"route-map,omitempty"`
					Metric   *int    `json:"metric,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"redistribute,omitempty"`
			PeerGroup *map[string]struct {
				Weight        *int    `json:"weight,omitempty"`
				EbgpMultihop  *int    `json:"ebgp-multihop,omitempty"`
				Password      *string `json:"password,omitempty"`
				MaximumPrefix *int    `json:"maximum-prefix,omitempty"`
				FilterList    *struct {
					Export *string `json:"export,omitempty"`
					Import *string `json:"import,omitempty"`
				} `json:"filter-list,omitempty"`
				AllowasIn *struct {
					Number *int `json:"number,omitempty"`
				} `json:"allowas-in,omitempty"`
				RouteReflectorClient *string `json:"route-reflector-client,omitempty"`
				OverrideCapability   *string `json:"override-capability,omitempty"`
				Shutdown             *string `json:"shutdown,omitempty"`
				DisableSendCommunity *struct {
					Standard *string `json:"standard,omitempty"`
					Extended *string `json:"extended,omitempty"`
				} `json:"disable-send-community,omitempty"`
				DefaultOriginate *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"default-originate,omitempty"`
				RouteServerClient *string `json:"route-server-client,omitempty"`
				Capability        *struct {
					Dynamic *string `json:"dynamic,omitempty"`
					Orf     *struct {
						PrefixList *struct {
							Receive *string `json:"receive,omitempty"`
							Send    *string `json:"send,omitempty"`
						} `json:"prefix-list,omitempty"`
					} `json:"orf,omitempty"`
					GracefulRestart *string `json:"graceful-restart,omitempty"`
				} `json:"capability,omitempty"`
				UpdateSource *string `json:"update-source,omitempty"`
				TtlSecurity  *struct {
					Hops *int `json:"hops,omitempty"`
				} `json:"ttl-security,omitempty"`
				UnsuppressMap *string `json:"unsuppress-map,omitempty"`
				Passive       *string `json:"passive,omitempty"`
				Timers        *struct {
					Holdtime  *int `json:"holdtime,omitempty"`
					Keepalive *int `json:"keepalive,omitempty"`
				} `json:".timers,omitempty"`
				AddressFamily *struct {
					Ipv6Unicast *struct {
						MaximumPrefix *int `json:"maximum-prefix,omitempty"`
						FilterList    *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"filter-list,omitempty"`
						AllowasIn *struct {
							Number *int `json:"number,omitempty"`
						} `json:"allowas-in,omitempty"`
						RouteReflectorClient *string `json:"route-reflector-client,omitempty"`
						NexthopLocal         *struct {
							Unchanged *string `json:"unchanged,omitempty"`
						} `json:"nexthop-local,omitempty"`
						DisableSendCommunity *struct {
							Standard *string `json:"standard,omitempty"`
							Extended *string `json:"extended,omitempty"`
						} `json:"disable-send-community,omitempty"`
						DefaultOriginate *struct {
							RouteMap *string `json:"route-map,omitempty"`
						} `json:"default-originate,omitempty"`
						RouteServerClient *string `json:"route-server-client,omitempty"`
						Capability        *struct {
							Orf *struct {
								PrefixList *struct {
									Receive *string `json:"receive,omitempty"`
									Send    *string `json:"send,omitempty"`
								} `json:"prefix-list,omitempty"`
							} `json:"orf,omitempty"`
							GracefulRestart *string `json:"graceful-restart,omitempty"`
						} `json:"capability,omitempty"`
						UnsuppressMap       *string `json:"unsuppress-map,omitempty"`
						SoftReconfiguration *struct {
							Inbound *string `json:"inbound,omitempty"`
						} `json:"soft-reconfiguration,omitempty"`
						AttributeUnchanged *struct {
							AsPath  *string `json:"as-path,omitempty"`
							NextHop *string `json:"next-hop,omitempty"`
							Med     *string `json:"med,omitempty"`
						} `json:"attribute-unchanged,omitempty"`
						RouteMap *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"route-map,omitempty"`
						NexthopSelf     *string `json:"nexthop-self,omitempty"`
						RemovePrivateAs *string `json:"remove-private-as,omitempty"`
						PrefixList      *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"prefix-list,omitempty"`
						DistributeList *struct {
							Export *string `json:"export,omitempty"`
							Import *string `json:"import,omitempty"`
						} `json:"distribute-list,omitempty"`
					} `json:"ipv6-unicast,omitempty"`
				} `json:"address-family,omitempty"`
				Description         *string `json:"description,omitempty"`
				SoftReconfiguration *struct {
					Inbound *string `json:"inbound,omitempty"`
				} `json:"soft-reconfiguration,omitempty"`
				LocalAs *map[string]struct {
					NoPrepend *string `json:"no-prepend,omitempty"`
				} `json:"local-as,omitempty"`
				AttributeUnchanged *struct {
					AsPath  *string `json:"as-path,omitempty"`
					NextHop *string `json:"next-hop,omitempty"`
					Med     *string `json:"med,omitempty"`
				} `json:"attribute-unchanged,omitempty"`
				RouteMap *struct {
					Export *string `json:"export,omitempty"`
					Import *string `json:"import,omitempty"`
				} `json:"route-map,omitempty"`
				RemoteAs                     *int    `json:"remote-as,omitempty"`
				NexthopSelf                  *string `json:"nexthop-self,omitempty"`
				DisableConnectedCheck        *string `json:"disable-connected-check,omitempty"`
				DisableCapabilityNegotiation *string `json:"disable-capability-negotiation,omitempty"`
				RemovePrivateAs              *string `json:"remove-private-as,omitempty"`
				PrefixList                   *struct {
					Export *string `json:"export,omitempty"`
					Import *string `json:"import,omitempty"`
				} `json:"prefix-list,omitempty"`
				DistributeList *struct {
					Export *int `json:"export,omitempty"`
					Import *int `json:"import,omitempty"`
				} `json:"distribute-list,omitempty"`
			} `json:"peer-group,omitempty"`
		} `json:"bgp,omitempty"`
		Ospfv3 *struct {
			Bfd *struct {
				Interface     *string `json:"interface,omitempty"`
				AllInterfaces *string `json:"all-interfaces,omitempty"`
			} `json:"bfd,omitempty"`
			Area *map[string]struct {
				ExportList *string `json:"export-list,omitempty"`
				Interface  *string `json:"interface,omitempty"`
				FilterList *map[string]struct {
				} `json:".filter-list,omitempty"`
				ImportList *string `json:"import-list,omitempty"`
				AreaType   *struct {
					Stub *struct {
						DefaultCost *int    `json:"default-cost,omitempty"`
						NoSummary   *string `json:"no-summary,omitempty"`
					} `json:"stub,omitempty"`
					Normal *string `json:"normal,omitempty"`
					Nssa   *struct {
						DefaultCost                 *int    `json:"default-cost,omitempty"`
						Translate                   *string `json:"translate,omitempty"`
						NoSummary                   *string `json:"no-summary,omitempty"`
						StabilityInterval           *int    `json:"stability-interval,omitempty"`
						DefaultInformationOriginate *struct {
							RouteMap *string `json:"route-map,omitempty"`
							Metric   *map[string]struct {
								Type *string `json:"type,omitempty"`
							} `json:"metric,omitempty"`
						} `json:"default-information-originate,omitempty"`
						NoRedistribution *string `json:"no-redistribution,omitempty"`
					} `json:"nssa,omitempty"`
				} `json:"area-type,omitempty"`
				VirtualLink *map[string]struct {
					Bfd *string `json:"bfd,omitempty"`
				} `json:"virtual-link,omitempty"`
				Range *map[string]struct {
					NotAdvertise *string `json:"not-advertise,omitempty"`
				} `json:"range,omitempty"`
			} `json:"area,omitempty"`
			Timers *struct {
				SfpExpDelay *struct {
					Min *map[string]struct {
						Max *int `json:"max,omitempty"`
					} `json:"min,omitempty"`
				} `json:"sfp-exp-delay,omitempty"`
			} `json:"timers,omitempty"`
			Capability *struct {
				DbSummaryOpt    *string `json:"db-summary-opt,omitempty"`
				Te              *string `json:"te,omitempty"`
				Cspf            *string `json:"cspf,omitempty"`
				GracefulRestart *string `json:"graceful-restart,omitempty"`
			} `json:"capability,omitempty"`
			DefaultMetric *int `json:"default-metric,omitempty"`
			Distance      *struct {
				Global *int `json:"global,omitempty"`
				Ospfv3 *struct {
					InterArea *int `json:"inter-area,omitempty"`
					External  *int `json:"external,omitempty"`
					IntraArea *int `json:"intra-area,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"distance,omitempty"`
			LogAdjacencyChanges *struct {
				Detail *string `json:"detail,omitempty"`
			} `json:"log-adjacency-changes,omitempty"`
			SummaryAddress *IPv6Net `json:"summary-address,omitempty"`
			Cspf           *struct {
				TieBreak             *string `json:"tie-break,omitempty"`
				DefaultRetryInterval *int    `json:"default-retry-interval,omitempty"`
			} `json:"cspf,omitempty"`
			AutoCost *struct {
				ReferenceBandwidth *int `json:"reference-bandwidth,omitempty"`
			} `json:"auto-cost,omitempty"`
			PassiveInterfaceExclude *string `json:"passive-interface-exclude,omitempty"`
			Vrf                     *map[string]struct {
				Bfd *struct {
					AllInterfaces *string `json:"all-interfaces,omitempty"`
				} `json:"bfd,omitempty"`
				Area *map[string]struct {
					ExportList *string `json:"export-list,omitempty"`
					Interface  *string `json:"interface,omitempty"`
					FilterList *map[string]struct {
					} `json:".filter-list,omitempty"`
					ImportList  *string `json:"import-list,omitempty"`
					VirtualLink *map[string]struct {
						Bfd *string `json:"bfd,omitempty"`
					} `json:"virtual-link,omitempty"`
					Range *map[string]struct {
						Advertise    *string `json:"advertise,omitempty"`
						NotAdvertise *string `json:"not-advertise,omitempty"`
					} `json:"range,omitempty"`
				} `json:"area,omitempty"`
				Parameters *struct {
					RouterId *IPv4 `json:"router-id,omitempty"`
				} `json:"parameters,omitempty"`
				Redistribute *struct {
					Connected *struct {
						RouteMap *string `json:"route-map,omitempty"`
					} `json:"connected,omitempty"`
					Ripng *struct {
						RouteMap *string `json:"route-map,omitempty"`
					} `json:"ripng,omitempty"`
					Static *struct {
						RouteMap *string `json:"route-map,omitempty"`
					} `json:"static,omitempty"`
					Bgp *struct {
						RouteMap *string `json:"route-map,omitempty"`
					} `json:"bgp,omitempty"`
					Kernel *struct {
						RouteMap *string `json:"route-map,omitempty"`
					} `json:"kernel,omitempty"`
				} `json:"redistribute,omitempty"`
			} `json:".vrf,omitempty"`
			Parameters *struct {
				RouterId *IPv4   `json:"router-id,omitempty"`
				AbrType  *string `json:"abr-type,omitempty"`
			} `json:"parameters,omitempty"`
			PassiveInterface *string `json:"passive-interface,omitempty"`
			MaxConcurrentDd  *int    `json:"max-concurrent-dd,omitempty"`
			Redistribute     *struct {
				Connected *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"connected,omitempty"`
				Ripng *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"ripng,omitempty"`
				Static *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"static,omitempty"`
				Bgp *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"bgp,omitempty"`
				Kernel *struct {
					RouteMap *string `json:"route-map,omitempty"`
				} `json:"kernel,omitempty"`
			} `json:"redistribute,omitempty"`
			DistributeList *map[string]struct {
				Out *struct {
					Rip       *string `json:"rip,omitempty"`
					Connected *string `json:"connected,omitempty"`
					Static    *string `json:"static,omitempty"`
					Bgp       *string `json:"bgp,omitempty"`
					Kernel    *string `json:"kernel,omitempty"`
					Ospf      *int    `json:"ospf,omitempty"`
					Isis      *string `json:"isis,omitempty"`
				} `json:"out,omitempty"`
				In *string `json:"in,omitempty"`
			} `json:"distribute-list,omitempty"`
			DefaultInformation *struct {
				Originate *struct {
					Always     *string `json:"always,omitempty"`
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *string `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"originate,omitempty"`
			} `json:"default-information,omitempty"`
		} `json:"ospfv3,omitempty"`
		Ospf *struct {
			Neighbor *map[string]struct {
				PollInterval *int `json:"poll-interval,omitempty"`
				Priority     *int `json:"priority,omitempty"`
			} `json:"neighbor,omitempty"`
			Bfd *struct {
				Interface     *string `json:"interface,omitempty"`
				AllInterfaces *string `json:"all-interfaces,omitempty"`
			} `json:"bfd,omitempty"`
			Area *map[string]struct {
				Shortcut *string  `json:"shortcut,omitempty"`
				Network  *IPv4Net `json:"network,omitempty"`
				AreaType *struct {
					Stub *struct {
						DefaultCost *int    `json:"default-cost,omitempty"`
						NoSummary   *string `json:"no-summary,omitempty"`
					} `json:"stub,omitempty"`
					Normal *string `json:"normal,omitempty"`
					Nssa   *struct {
						DefaultCost *int    `json:"default-cost,omitempty"`
						Translate   *string `json:"translate,omitempty"`
						NoSummary   *string `json:"no-summary,omitempty"`
					} `json:"nssa,omitempty"`
				} `json:"area-type,omitempty"`
				VirtualLink *map[string]struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Bfd                *string `json:"bfd,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"virtual-link,omitempty"`
				Range *map[string]struct {
					Cost         *int     `json:"cost,omitempty"`
					Substitute   *IPv4Net `json:"substitute,omitempty"`
					NotAdvertise *string  `json:"not-advertise,omitempty"`
				} `json:"range,omitempty"`
				Authentication *string `json:"authentication,omitempty"`
			} `json:"area,omitempty"`
			Refresh *struct {
				Timers *int `json:"timers,omitempty"`
			} `json:"refresh,omitempty"`
			Timers *struct {
				Throttle *struct {
					Spf *struct {
						MaxHoldtime     *int `json:"max-holdtime,omitempty"`
						Delay           *int `json:"delay,omitempty"`
						InitialHoldtime *int `json:"initial-holdtime,omitempty"`
					} `json:"spf,omitempty"`
				} `json:"throttle,omitempty"`
			} `json:"timers,omitempty"`
			DefaultMetric *int `json:"default-metric,omitempty"`
			Distance      *struct {
				Global *int `json:"global,omitempty"`
				Ospf   *struct {
					InterArea *int `json:"inter-area,omitempty"`
					External  *int `json:"external,omitempty"`
					IntraArea *int `json:"intra-area,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"distance,omitempty"`
			LogAdjacencyChanges *struct {
				Detail *string `json:"detail,omitempty"`
			} `json:"log-adjacency-changes,omitempty"`
			MplsTe *struct {
				Enable        *string `json:"enable,omitempty"`
				RouterAddress *IPv4   `json:"router-address,omitempty"`
			} `json:"mpls-te,omitempty"`
			AutoCost *struct {
				ReferenceBandwidth *int `json:"reference-bandwidth,omitempty"`
			} `json:"auto-cost,omitempty"`
			PassiveInterfaceExclude *string `json:"passive-interface-exclude,omitempty"`
			AccessList              *map[string]struct {
				Export *string `json:"export,omitempty"`
				Import *string `json:"import,omitempty"`
			} `json:"access-list,omitempty"`
			InstanceId *map[string]struct {
				Vrf *map[string]struct {
					Neighbor *map[string]struct {
						PollInterval *int `json:"poll-interval,omitempty"`
						Priority     *int `json:"priority,omitempty"`
					} `json:"neighbor,omitempty"`
					Bfd *struct {
						AllInterfaces *string `json:"all-interfaces,omitempty"`
					} `json:"bfd,omitempty"`
					Area *map[string]struct {
						Shortcut *string  `json:"shortcut,omitempty"`
						Network  *IPv4Net `json:"network,omitempty"`
						AreaType *struct {
							Stub *struct {
								DefaultCost *int    `json:"default-cost,omitempty"`
								NoSummary   *string `json:"no-summary,omitempty"`
							} `json:"stub,omitempty"`
							Normal *string `json:"normal,omitempty"`
							Nssa   *struct {
								DefaultCost *int    `json:"default-cost,omitempty"`
								Translate   *string `json:"translate,omitempty"`
								NoSummary   *string `json:"no-summary,omitempty"`
							} `json:"nssa,omitempty"`
						} `json:"area-type,omitempty"`
						VirtualLink *map[string]struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Bfd                *string `json:"bfd,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							Authentication     *struct {
								Md5 *struct {
									KeyId *map[string]struct {
										Md5Key *string `json:"md5-key,omitempty"`
									} `json:"key-id,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
							HelloInterval *int `json:"hello-interval,omitempty"`
						} `json:"virtual-link,omitempty"`
						Range *map[string]struct {
							Cost         *int     `json:"cost,omitempty"`
							Substitute   *IPv4Net `json:"substitute,omitempty"`
							NotAdvertise *string  `json:"not-advertise,omitempty"`
						} `json:"range,omitempty"`
						Authentication *string `json:"authentication,omitempty"`
					} `json:"area,omitempty"`
					Refresh *struct {
						Timers *int `json:"timers,omitempty"`
					} `json:"refresh,omitempty"`
					Timers *struct {
						Throttle *struct {
							Spf *struct {
								MaxHoldtime     *int `json:"max-holdtime,omitempty"`
								Delay           *int `json:"delay,omitempty"`
								InitialHoldtime *int `json:"initial-holdtime,omitempty"`
							} `json:"spf,omitempty"`
						} `json:"throttle,omitempty"`
					} `json:"timers,omitempty"`
					Capability *struct {
						Cspf *struct {
							EnableBetterProtection *string `json:"enable-better-protection,omitempty"`
							TieBreak               *struct {
								MostFill  *string `json:"most-fill,omitempty"`
								LeastFill *string `json:"least-fill,omitempty"`
								Random    *string `json:"random,omitempty"`
							} `json:"tie-break,omitempty"`
							DisableBetterProtection *string `json:"disable-better-protection,omitempty"`
							DefaultRetryInterval    *int    `json:"default-retry-interval,omitempty"`
						} `json:"cspf,omitempty"`
						TrafficEngineering *string `json:"traffic-engineering,omitempty"`
					} `json:"capability,omitempty"`
					DefaultMetric *int `json:"default-metric,omitempty"`
					Distance      *struct {
						Global *int `json:"global,omitempty"`
						Ospf   *struct {
							InterArea *int `json:"inter-area,omitempty"`
							External  *int `json:"external,omitempty"`
							IntraArea *int `json:"intra-area,omitempty"`
						} `json:"ospf,omitempty"`
					} `json:"distance,omitempty"`
					LogAdjacencyChanges *struct {
						Detail *string `json:"detail,omitempty"`
					} `json:"log-adjacency-changes,omitempty"`
					MplsTe *struct {
						Enable        *string `json:"enable,omitempty"`
						RouterAddress *IPv4   `json:"router-address,omitempty"`
					} `json:"mpls-te,omitempty"`
					AutoCost *struct {
						ReferenceBandwidth *int `json:"reference-bandwidth,omitempty"`
					} `json:"auto-cost,omitempty"`
					PassiveInterfaceExclude *string `json:"passive-interface-exclude,omitempty"`
					AccessList              *map[string]struct {
						Export *string `json:"export,omitempty"`
					} `json:"access-list,omitempty"`
					Parameters *struct {
						Rfc1583Compatibility *string `json:"rfc1583-compatibility,omitempty"`
						RouterId             *IPv4   `json:"router-id,omitempty"`
						AbrType              *string `json:"abr-type,omitempty"`
						OpaqueLsa            *string `json:"opaque-lsa,omitempty"`
					} `json:"parameters,omitempty"`
					PassiveInterface *string `json:"passive-interface,omitempty"`
					Redistribute     *struct {
						Rip *struct {
							RouteMap   *string `json:"route-map,omitempty"`
							MetricType *int    `json:"metric-type,omitempty"`
							Metric     *int    `json:"metric,omitempty"`
						} `json:"rip,omitempty"`
						Connected *struct {
							RouteMap   *string `json:"route-map,omitempty"`
							MetricType *int    `json:"metric-type,omitempty"`
							Metric     *int    `json:"metric,omitempty"`
						} `json:"connected,omitempty"`
						Static *struct {
							RouteMap   *string `json:"route-map,omitempty"`
							MetricType *int    `json:"metric-type,omitempty"`
							Metric     *int    `json:"metric,omitempty"`
						} `json:"static,omitempty"`
						Bgp *struct {
							RouteMap   *string `json:"route-map,omitempty"`
							MetricType *int    `json:"metric-type,omitempty"`
							Metric     *int    `json:"metric,omitempty"`
						} `json:"bgp,omitempty"`
						Kernel *struct {
							RouteMap   *string `json:"route-map,omitempty"`
							MetricType *int    `json:"metric-type,omitempty"`
							Metric     *int    `json:"metric,omitempty"`
						} `json:"kernel,omitempty"`
					} `json:"redistribute,omitempty"`
					MaxMetric *struct {
						RouterLsa *struct {
							OnStartup      *int    `json:"on-startup,omitempty"`
							Administrative *string `json:"administrative,omitempty"`
							OnShutdown     *int    `json:"on-shutdown,omitempty"`
						} `json:"router-lsa,omitempty"`
					} `json:"max-metric,omitempty"`
					DefaultInformation *struct {
						Originate *struct {
							Always     *string `json:"always,omitempty"`
							RouteMap   *string `json:"route-map,omitempty"`
							MetricType *int    `json:"metric-type,omitempty"`
							Metric     *int    `json:"metric,omitempty"`
						} `json:"originate,omitempty"`
					} `json:"default-information,omitempty"`
				} `json:"vrf,omitempty"`
			} `json:".instance-id,omitempty"`
			Parameters *struct {
				Rfc1583Compatibility *string `json:"rfc1583-compatibility,omitempty"`
				RouterId             *IPv4   `json:"router-id,omitempty"`
				AbrType              *string `json:"abr-type,omitempty"`
				OpaqueLsa            *string `json:"opaque-lsa,omitempty"`
			} `json:"parameters,omitempty"`
			PassiveInterface *string `json:"passive-interface,omitempty"`
			Redistribute     *struct {
				Rip *struct {
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *int    `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"rip,omitempty"`
				Connected *struct {
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *int    `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"connected,omitempty"`
				Static *struct {
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *int    `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"static,omitempty"`
				Bgp *struct {
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *int    `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"bgp,omitempty"`
				Kernel *struct {
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *int    `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"kernel,omitempty"`
			} `json:"redistribute,omitempty"`
			MaxMetric *struct {
				RouterLsa *struct {
					OnStartup      *int    `json:"on-startup,omitempty"`
					Administrative *string `json:"administrative,omitempty"`
					OnShutdown     *int    `json:"on-shutdown,omitempty"`
				} `json:"router-lsa,omitempty"`
			} `json:"max-metric,omitempty"`
			DefaultInformation *struct {
				Originate *struct {
					Always     *string `json:"always,omitempty"`
					RouteMap   *string `json:"route-map,omitempty"`
					MetricType *int    `json:"metric-type,omitempty"`
					Metric     *int    `json:"metric,omitempty"`
				} `json:"originate,omitempty"`
			} `json:"default-information,omitempty"`
		} `json:"ospf,omitempty"`
	} `json:"protocols,omitempty"`
	Policy *struct {
		AsPathList *map[string]struct {
			Rule *map[string]struct {
				Regex       *string `json:"regex,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"as-path-list,omitempty"`
		AccessList *map[string]struct {
			Rule *map[string]struct {
				Source *struct {
					Host        *IPv4   `json:"host,omitempty"`
					Network     *IPv4   `json:"network,omitempty"`
					Any         *string `json:"any,omitempty"`
					InverseMask *IPv4   `json:"inverse-mask,omitempty"`
				} `json:"source,omitempty"`
				Destination *struct {
					Host        *IPv4   `json:"host,omitempty"`
					Network     *IPv4   `json:"network,omitempty"`
					Any         *string `json:"any,omitempty"`
					InverseMask *IPv4   `json:"inverse-mask,omitempty"`
				} `json:"destination,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"access-list,omitempty"`
		RouteMap *map[string]struct {
			Rule *map[string]struct {
				Match *struct {
					AsPath       *string `json:"as-path,omitempty"`
					Interface    *string `json:"interface,omitempty"`
					Extcommunity *struct {
						ExactMatch       *string `json:"exact-match,omitempty"`
						ExtcommunityList *int    `json:"extcommunity-list,omitempty"`
					} `json:"extcommunity,omitempty"`
					Peer      *string `json:"peer,omitempty"`
					Origin    *string `json:"origin,omitempty"`
					Community *struct {
						ExactMatch    *string `json:"exact-match,omitempty"`
						CommunityList *int    `json:"community-list,omitempty"`
					} `json:"community,omitempty"`
					Ip *struct {
						RouteSource *struct {
							AccessList *int    `json:"access-list,omitempty"`
							PrefixList *string `json:"prefix-list,omitempty"`
						} `json:"route-source,omitempty"`
						Nexthop *struct {
							AccessList *int    `json:"access-list,omitempty"`
							PrefixList *string `json:"prefix-list,omitempty"`
						} `json:"nexthop,omitempty"`
						Address *struct {
							AccessList *int    `json:"access-list,omitempty"`
							PrefixList *string `json:"prefix-list,omitempty"`
						} `json:"address,omitempty"`
					} `json:"ip,omitempty"`
					Metric *int `json:"metric,omitempty"`
					Ipv6   *struct {
						Nexthop *struct {
							AccessList *string `json:"access-list,omitempty"`
							PrefixList *string `json:"prefix-list,omitempty"`
						} `json:"nexthop,omitempty"`
						Address *struct {
							AccessList *string `json:"access-list,omitempty"`
							PrefixList *string `json:"prefix-list,omitempty"`
						} `json:"address,omitempty"`
					} `json:"ipv6,omitempty"`
					Tag *int `json:"tag,omitempty"`
				} `json:"match,omitempty"`
				OnMatch *struct {
					Next *string `json:"next,omitempty"`
					Goto *int    `json:"goto,omitempty"`
				} `json:"on-match,omitempty"`
				Action      *string `json:"action,omitempty"`
				Call        *string `json:"call,omitempty"`
				Description *string `json:"description,omitempty"`
				Set         *struct {
					Weight        *int    `json:"weight,omitempty"`
					AsPathPrepend *string `json:"as-path-prepend,omitempty"`
					Ipv6NextHop   *struct {
						Local  *IPv6 `json:"local,omitempty"`
						Global *IPv6 `json:"global,omitempty"`
					} `json:"ipv6-next-hop,omitempty"`
					CommList *struct {
						CommList *int    `json:"comm-list,omitempty"`
						Delete   *string `json:"delete,omitempty"`
					} `json:"comm-list,omitempty"`
					OriginatorId *IPv4 `json:"originator-id,omitempty"`
					Extcommunity *struct {
						Rt *string `json:"rt,omitempty"`
						Ro *string `json:"ro,omitempty"`
					} `json:"extcommunity,omitempty"`
					Aggregator *struct {
						As *int  `json:"as,omitempty"`
						Ip *IPv4 `json:"ip,omitempty"`
					} `json:"aggregator,omitempty"`
					AtomicAggregate *string `json:"atomic-aggregate,omitempty"`
					LocalPreference *int    `json:"local-preference,omitempty"`
					MetricType      *string `json:"metric-type,omitempty"`
					Origin          *string `json:"origin,omitempty"`
					Community       *string `json:"community,omitempty"`
					Metric          *string `json:"metric,omitempty"`
					IpNextHop       *IPv4   `json:"ip-next-hop,omitempty"`
					Tag             *int    `json:"tag,omitempty"`
				} `json:"set,omitempty"`
				Continue *int `json:"continue,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"route-map,omitempty"`
		AccessList6 *map[string]struct {
			Rule *map[string]struct {
				Source *struct {
					Network    *IPv6Net `json:"network,omitempty"`
					Any        *string  `json:"any,omitempty"`
					ExactMatch *string  `json:"exact-match,omitempty"`
				} `json:"source,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"access-list6,omitempty"`
		PrefixList6 *map[string]struct {
			Rule *map[string]struct {
				Prefix      *IPv6Net `json:"prefix,omitempty"`
				Le          *int     `json:"le,omitempty"`
				Action      *string  `json:"action,omitempty"`
				Description *string  `json:"description,omitempty"`
				Ge          *int     `json:"ge,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"prefix-list6,omitempty"`
		CommunityList *map[string]struct {
			Rule *map[string]struct {
				Regex       *string `json:"regex,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"community-list,omitempty"`
		ExtcommunityList *map[string]struct {
			Rule *map[string]struct {
				Rt          *string `json:"rt,omitempty"`
				Regex       *string `json:"regex,omitempty"`
				Ro          *string `json:"ro,omitempty"`
				Action      *string `json:"action,omitempty"`
				Description *string `json:"description,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"extcommunity-list,omitempty"`
		PrefixList *map[string]struct {
			Rule *map[string]struct {
				Prefix      *IPv4Net `json:"prefix,omitempty"`
				Le          *int     `json:"le,omitempty"`
				Action      *string  `json:"action,omitempty"`
				Description *string  `json:"description,omitempty"`
				Ge          *int     `json:"ge,omitempty"`
			} `json:"rule,omitempty"`
			Description *string `json:"description,omitempty"`
		} `json:"prefix-list,omitempty"`
	} `json:"policy,omitempty"`
	Interfaces *struct {
		Wirelessmodem *map[string]struct {
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Ondemand      *string `json:"ondemand,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			Network       *string `json:"network,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			NoDns             *string `json:"no-dns,omitempty"`
			DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Description *string `json:"description,omitempty"`
			Redirect    *string `json:"redirect,omitempty"`
			Device      *string `json:"device,omitempty"`
			Backup      *struct {
				Distance *int `json:"distance,omitempty"`
			} `json:"backup,omitempty"`
			Ip *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"wirelessmodem,omitempty"`
		Ipv6Tunnel *map[string]struct {
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Encapsulation *string `json:"encapsulation,omitempty"`
			Multicast     *string `json:"multicast,omitempty"`
			Ttl           *int    `json:"ttl,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Key               *int    `json:"key,omitempty"`
			DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Tos         *int    `json:"tos,omitempty"`
			Description *string `json:"description,omitempty"`
			Address     *IPNet  `json:"address,omitempty"`
			Redirect    *string `json:"redirect,omitempty"`
			LocalIp     *IPv6   `json:"local-ip,omitempty"`
			RemoteIp    *IPv6   `json:"remote-ip,omitempty"`
			Ip          *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				Ripng *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"ipv6-tunnel,omitempty"`
		Bonding *map[string]struct {
			BridgeGroup *struct {
				Bridge   *string `json:"bridge,omitempty"`
				Cost     *int    `json:"cost,omitempty"`
				Priority *int    `json:"priority,omitempty"`
			} `json:"bridge-group,omitempty"`
			HashPolicy *string `json:"hash-policy,omitempty"`
			Disable    *string `json:"disable,omitempty"`
			Bandwidth  *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Mode          *string `json:"mode,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Vrrp *struct {
				VrrpGroup *map[string]struct {
					Disable              *string `json:"disable,omitempty"`
					VirtualAddress       *string `json:"virtual-address,omitempty"`
					AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
					SyncGroup            *string `json:"sync-group,omitempty"`
					PreemptDelay         *int    `json:"preempt-delay,omitempty"`
					RunTransitionScripts *struct {
						Master *string `json:"master,omitempty"`
						Fault  *string `json:"fault,omitempty"`
						Backup *string `json:"backup,omitempty"`
					} `json:"run-transition-scripts,omitempty"`
					Preempt            *bool   `json:"preempt,omitempty"`
					Description        *string `json:"description,omitempty"`
					HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					Authentication     *struct {
						Password *string `json:"password,omitempty"`
						Type     *string `json:"type,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"vrrp-group,omitempty"`
			} `json:"vrrp,omitempty"`
			Dhcpv6Pd *struct {
				Pd *map[string]struct {
					Interface *map[string]struct {
						StaticMapping *map[string]struct {
							Identifier  *string `json:"identifier,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
						} `json:"static-mapping,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						PrefixId    *string `json:"prefix-id,omitempty"`
						HostAddress *string `json:"host-address,omitempty"`
						Service     *string `json:"service,omitempty"`
					} `json:"interface,omitempty"`
					PrefixLength *string `json:"prefix-length,omitempty"`
				} `json:"pd,omitempty"`
				Duid        *string `json:"duid,omitempty"`
				NoDns       *string `json:"no-dns,omitempty"`
				RapidCommit *string `json:"rapid-commit,omitempty"`
				PrefixOnly  *string `json:"prefix-only,omitempty"`
			} `json:"dhcpv6-pd,omitempty"`
			DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Mac         *MacAddr `json:"mac,omitempty"`
			DhcpOptions *struct {
				NameServer           *string `json:"name-server,omitempty"`
				DefaultRoute         *string `json:"default-route,omitempty"`
				ClientOption         *string `json:"client-option,omitempty"`
				DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
				GlobalOption         *string `json:"global-option,omitempty"`
			} `json:"dhcp-options,omitempty"`
			Description *string `json:"description,omitempty"`
			Vif         *map[string]struct {
				BridgeGroup *struct {
					Bridge   *string `json:"bridge,omitempty"`
					Cost     *int    `json:"cost,omitempty"`
					Priority *int    `json:"priority,omitempty"`
				} `json:"bridge-group,omitempty"`
				Disable   *string `json:"disable,omitempty"`
				Bandwidth *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Mtu           *int `json:"mtu,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				Vrrp *struct {
					VrrpGroup *map[string]struct {
						Disable              *string `json:"disable,omitempty"`
						VirtualAddress       *string `json:"virtual-address,omitempty"`
						AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
						SyncGroup            *string `json:"sync-group,omitempty"`
						PreemptDelay         *int    `json:"preempt-delay,omitempty"`
						RunTransitionScripts *struct {
							Master *string `json:"master,omitempty"`
							Fault  *string `json:"fault,omitempty"`
							Backup *string `json:"backup,omitempty"`
						} `json:"run-transition-scripts,omitempty"`
						Preempt            *bool   `json:"preempt,omitempty"`
						Description        *string `json:"description,omitempty"`
						HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						Authentication     *struct {
							Password *string `json:"password,omitempty"`
							Type     *string `json:"type,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"vrrp-group,omitempty"`
				} `json:"vrrp,omitempty"`
				Dhcpv6Pd *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
				Firewall          *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				DhcpOptions *struct {
					NameServer           *string `json:"name-server,omitempty"`
					DefaultRoute         *string `json:"default-route,omitempty"`
					ClientOption         *string `json:"client-option,omitempty"`
					DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
					GlobalOption         *string `json:"global-option,omitempty"`
				} `json:"dhcp-options,omitempty"`
				Description   *string `json:"description,omitempty"`
				Address       *string `json:"address,omitempty"`
				Redirect      *string `json:"redirect,omitempty"`
				Dhcpv6Options *struct {
					ParametersOnly *string `json:"parameters-only,omitempty"`
					Temporary      *string `json:"temporary,omitempty"`
				} `json:"dhcpv6-options,omitempty"`
				Ip *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					ProxyArpPvlan    *string `json:"proxy-arp-pvlan,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64    *IPv6Net `json:"eui64,omitempty"`
						Autoconf *string  `json:"autoconf,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
			} `json:"vif,omitempty"`
			Address    *string `json:"address,omitempty"`
			Redirect   *string `json:"redirect,omitempty"`
			ArpMonitor *struct {
				Target   *IPv4 `json:"target,omitempty"`
				Interval *int  `json:"interval,omitempty"`
			} `json:"arp-monitor,omitempty"`
			Dhcpv6Options *struct {
				ParametersOnly *string `json:"parameters-only,omitempty"`
				Temporary      *string `json:"temporary,omitempty"`
			} `json:"dhcpv6-options,omitempty"`
			Ip *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				EnableProxyArp   *string `json:"enable-proxy-arp,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				ProxyArpPvlan    *string `json:"proxy-arp-pvlan,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
			Primary *string `json:"primary,omitempty"`
		} `json:"bonding,omitempty"`
		L2tpv3 *map[string]struct {
			BridgeGroup *struct {
				Bridge   *string `json:"bridge,omitempty"`
				Cost     *int    `json:"cost,omitempty"`
				Priority *int    `json:"priority,omitempty"`
			} `json:"bridge-group,omitempty"`
			Disable       *string `json:"disable,omitempty"`
			PeerSessionId *int    `json:"peer-session-id,omitempty"`
			Bandwidth     *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Encapsulation *string `json:"encapsulation,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			SourcePort *int `json:"source-port,omitempty"`
			Firewall   *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			PeerTunnelId *int    `json:"peer-tunnel-id,omitempty"`
			Description  *string `json:"description,omitempty"`
			Address      *IPNet  `json:"address,omitempty"`
			Redirect     *string `json:"redirect,omitempty"`
			LocalIp      *IP     `json:"local-ip,omitempty"`
			RemoteIp     *IP     `json:"remote-ip,omitempty"`
			Ip           *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			DestinationPort *int `json:"destination-port,omitempty"`
			Ipv6            *struct {
				Ripng *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
			TunnelId  *int `json:"tunnel-id,omitempty"`
			SessionId *int `json:"session-id,omitempty"`
		} `json:"l2tpv3,omitempty"`
		Vti *map[string]struct {
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Mtu           *int `json:"mtu,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Firewall *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Description *string  `json:"description,omitempty"`
			Address     *IPv4Net `json:"address,omitempty"`
			Redirect    *string  `json:"redirect,omitempty"`
			Ip          *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				Ripng *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"vti,omitempty"`
		Input *map[string]struct {
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Firewall *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Description *string `json:"description,omitempty"`
			Redirect    *string `json:"redirect,omitempty"`
		} `json:"input,omitempty"`
		Bridge *map[string]struct {
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Multicast *string `json:"multicast,omitempty"`
			Pppoe     *map[string]struct {
				ServiceName *string `json:"service-name,omitempty"`
				Bandwidth   *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Password      *string `json:"password,omitempty"`
				RemoteAddress *IPv4   `json:"remote-address,omitempty"`
				HostUniq      *string `json:"host-uniq,omitempty"`
				Mtu           *int    `json:"mtu,omitempty"`
				NameServer    *string `json:"name-server,omitempty"`
				DefaultRoute  *string `json:"default-route,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				IdleTimeout *int `json:"idle-timeout,omitempty"`
				Dhcpv6Pd    *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
				Firewall        *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				UserId       *string `json:"user-id,omitempty"`
				Description  *string `json:"description,omitempty"`
				LocalAddress *IPv4   `json:"local-address,omitempty"`
				Redirect     *string `json:"redirect,omitempty"`
				Ip           *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					Enable *struct {
						RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
						LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
					} `json:"enable,omitempty"`
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64     *IPv6Net `json:"eui64,omitempty"`
						Autoconf  *string  `json:"autoconf,omitempty"`
						Secondary *IPv6Net `json:"secondary,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
				Multilink          *string `json:"multilink,omitempty"`
				AccessConcentrator *string `json:"access-concentrator,omitempty"`
			} `json:"pppoe,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Vrrp *struct {
				VrrpGroup *map[string]struct {
					Disable              *string `json:"disable,omitempty"`
					VirtualAddress       *string `json:"virtual-address,omitempty"`
					AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
					SyncGroup            *string `json:"sync-group,omitempty"`
					PreemptDelay         *int    `json:"preempt-delay,omitempty"`
					RunTransitionScripts *struct {
						Master *string `json:"master,omitempty"`
						Fault  *string `json:"fault,omitempty"`
						Backup *string `json:"backup,omitempty"`
					} `json:"run-transition-scripts,omitempty"`
					Preempt            *bool   `json:"preempt,omitempty"`
					Description        *string `json:"description,omitempty"`
					HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					Authentication     *struct {
						Password *string `json:"password,omitempty"`
						Type     *string `json:"type,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"vrrp-group,omitempty"`
			} `json:"vrrp,omitempty"`
			Dhcpv6Pd *struct {
				Pd *map[string]struct {
					Interface *map[string]struct {
						StaticMapping *map[string]struct {
							Identifier  *string `json:"identifier,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
						} `json:"static-mapping,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						PrefixId    *string `json:"prefix-id,omitempty"`
						HostAddress *string `json:"host-address,omitempty"`
						Service     *string `json:"service,omitempty"`
					} `json:"interface,omitempty"`
					PrefixLength *string `json:"prefix-length,omitempty"`
				} `json:"pd,omitempty"`
				Duid        *string `json:"duid,omitempty"`
				NoDns       *string `json:"no-dns,omitempty"`
				RapidCommit *string `json:"rapid-commit,omitempty"`
				PrefixOnly  *string `json:"prefix-only,omitempty"`
			} `json:"dhcpv6-pd,omitempty"`
			Stp               *bool   `json:"stp,omitempty"`
			DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			MaxAge           *int    `json:"max-age,omitempty"`
			BridgedConntrack *string `json:"bridged-conntrack,omitempty"`
			DhcpOptions      *struct {
				NameServer           *string `json:"name-server,omitempty"`
				DefaultRoute         *string `json:"default-route,omitempty"`
				ClientOption         *string `json:"client-option,omitempty"`
				DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
				GlobalOption         *string `json:"global-option,omitempty"`
			} `json:"dhcp-options,omitempty"`
			HelloTime   *int    `json:"hello-time,omitempty"`
			Description *string `json:"description,omitempty"`
			Vif         *map[string]struct {
				Disable   *string `json:"disable,omitempty"`
				Bandwidth *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Pppoe *map[string]struct {
					ServiceName *string `json:"service-name,omitempty"`
					Bandwidth   *struct {
						Maximum    *string `json:"maximum,omitempty"`
						Reservable *string `json:"reservable,omitempty"`
						Constraint *struct {
							ClassType *map[string]struct {
								Bandwidth *string `json:"bandwidth,omitempty"`
							} `json:"class-type,omitempty"`
						} `json:"constraint,omitempty"`
					} `json:"bandwidth,omitempty"`
					Password      *string `json:"password,omitempty"`
					RemoteAddress *IPv4   `json:"remote-address,omitempty"`
					HostUniq      *string `json:"host-uniq,omitempty"`
					Mtu           *int    `json:"mtu,omitempty"`
					NameServer    *string `json:"name-server,omitempty"`
					DefaultRoute  *string `json:"default-route,omitempty"`
					TrafficPolicy *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"traffic-policy,omitempty"`
					IdleTimeout *int `json:"idle-timeout,omitempty"`
					Dhcpv6Pd    *struct {
						Pd *map[string]struct {
							Interface *map[string]struct {
								StaticMapping *map[string]struct {
									Identifier  *string `json:"identifier,omitempty"`
									HostAddress *string `json:"host-address,omitempty"`
								} `json:"static-mapping,omitempty"`
								NoDns       *string `json:"no-dns,omitempty"`
								PrefixId    *string `json:"prefix-id,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
								Service     *string `json:"service,omitempty"`
							} `json:"interface,omitempty"`
							PrefixLength *string `json:"prefix-length,omitempty"`
						} `json:"pd,omitempty"`
						Duid        *string `json:"duid,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						RapidCommit *string `json:"rapid-commit,omitempty"`
						PrefixOnly  *string `json:"prefix-only,omitempty"`
					} `json:"dhcpv6-pd,omitempty"`
					ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
					Firewall        *struct {
						Out *struct {
							Modify     *string `json:"modify,omitempty"`
							Ipv6Modify *string `json:"ipv6-modify,omitempty"`
							Name       *string `json:"name,omitempty"`
							Ipv6Name   *string `json:"ipv6-name,omitempty"`
						} `json:"out,omitempty"`
						In *struct {
							Modify     *string `json:"modify,omitempty"`
							Ipv6Modify *string `json:"ipv6-modify,omitempty"`
							Name       *string `json:"name,omitempty"`
							Ipv6Name   *string `json:"ipv6-name,omitempty"`
						} `json:"in,omitempty"`
						Local *struct {
							Name     *string `json:"name,omitempty"`
							Ipv6Name *string `json:"ipv6-name,omitempty"`
						} `json:"local,omitempty"`
					} `json:"firewall,omitempty"`
					UserId       *string `json:"user-id,omitempty"`
					Description  *string `json:"description,omitempty"`
					LocalAddress *IPv4   `json:"local-address,omitempty"`
					Redirect     *string `json:"redirect,omitempty"`
					Ip           *struct {
						Rip *struct {
							SplitHorizon *struct {
								Disable       *string `json:"disable,omitempty"`
								PoisonReverse *string `json:"poison-reverse,omitempty"`
							} `json:"split-horizon,omitempty"`
							Authentication *struct {
								Md5 *map[string]struct {
									Password *string `json:"password,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
						} `json:"rip,omitempty"`
						SourceValidation *string `json:"source-validation,omitempty"`
						Ospf             *struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Network            *string `json:"network,omitempty"`
							Cost               *int    `json:"cost,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							Priority           *int    `json:"priority,omitempty"`
							MtuIgnore          *string `json:"mtu-ignore,omitempty"`
							Authentication     *struct {
								Md5 *struct {
									KeyId *map[string]struct {
										Md5Key *string `json:"md5-key,omitempty"`
									} `json:"key-id,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
							HelloInterval *int `json:"hello-interval,omitempty"`
						} `json:"ospf,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Enable *struct {
							RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
							LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
						} `json:"enable,omitempty"`
						DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
						DisableForwarding      *string `json:"disable-forwarding,omitempty"`
						Ripng                  *struct {
							SplitHorizon *struct {
								Disable       *string `json:"disable,omitempty"`
								PoisonReverse *string `json:"poison-reverse,omitempty"`
							} `json:"split-horizon,omitempty"`
						} `json:"ripng,omitempty"`
						Address *struct {
							Eui64     *IPv6Net `json:"eui64,omitempty"`
							Autoconf  *string  `json:"autoconf,omitempty"`
							Secondary *IPv6Net `json:"secondary,omitempty"`
						} `json:"address,omitempty"`
						RouterAdvert *struct {
							DefaultPreference *string `json:"default-preference,omitempty"`
							MinInterval       *int    `json:"min-interval,omitempty"`
							MaxInterval       *int    `json:"max-interval,omitempty"`
							ReachableTime     *int    `json:"reachable-time,omitempty"`
							Prefix            *map[string]struct {
								AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
								OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
								ValidLifetime     *string `json:"valid-lifetime,omitempty"`
								PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
							} `json:"prefix,omitempty"`
							NameServer      *IPv6   `json:"name-server,omitempty"`
							RetransTimer    *int    `json:"retrans-timer,omitempty"`
							SendAdvert      *bool   `json:"send-advert,omitempty"`
							RadvdOptions    *string `json:"radvd-options,omitempty"`
							ManagedFlag     *bool   `json:"managed-flag,omitempty"`
							OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
							DefaultLifetime *int    `json:"default-lifetime,omitempty"`
							CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
							LinkMtu         *int    `json:"link-mtu,omitempty"`
						} `json:"router-advert,omitempty"`
						Ospfv3 *struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Cost               *int    `json:"cost,omitempty"`
							Passive            *string `json:"passive,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							InstanceId         *int    `json:"instance-id,omitempty"`
							Ifmtu              *int    `json:"ifmtu,omitempty"`
							Priority           *int    `json:"priority,omitempty"`
							MtuIgnore          *string `json:"mtu-ignore,omitempty"`
							HelloInterval      *int    `json:"hello-interval,omitempty"`
						} `json:"ospfv3,omitempty"`
					} `json:"ipv6,omitempty"`
					Multilink          *string `json:"multilink,omitempty"`
					AccessConcentrator *string `json:"access-concentrator,omitempty"`
				} `json:"pppoe,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				Vrrp *struct {
					VrrpGroup *map[string]struct {
						Disable              *string `json:"disable,omitempty"`
						VirtualAddress       *string `json:"virtual-address,omitempty"`
						AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
						SyncGroup            *string `json:"sync-group,omitempty"`
						PreemptDelay         *int    `json:"preempt-delay,omitempty"`
						RunTransitionScripts *struct {
							Master *string `json:"master,omitempty"`
							Fault  *string `json:"fault,omitempty"`
							Backup *string `json:"backup,omitempty"`
						} `json:"run-transition-scripts,omitempty"`
						Preempt            *bool   `json:"preempt,omitempty"`
						Description        *string `json:"description,omitempty"`
						HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						Authentication     *struct {
							Password *string `json:"password,omitempty"`
							Type     *string `json:"type,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"vrrp-group,omitempty"`
				} `json:"vrrp,omitempty"`
				Dhcpv6Pd *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
				Firewall          *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				DhcpOptions *struct {
					NameServer           *string `json:"name-server,omitempty"`
					DefaultRoute         *string `json:"default-route,omitempty"`
					ClientOption         *string `json:"client-option,omitempty"`
					DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
					GlobalOption         *string `json:"global-option,omitempty"`
				} `json:"dhcp-options,omitempty"`
				Description   *string `json:"description,omitempty"`
				Address       *string `json:"address,omitempty"`
				Redirect      *string `json:"redirect,omitempty"`
				Dhcpv6Options *struct {
					ParametersOnly *string `json:"parameters-only,omitempty"`
					Temporary      *string `json:"temporary,omitempty"`
				} `json:"dhcpv6-options,omitempty"`
				Ip *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64    *IPv6Net `json:"eui64,omitempty"`
						Autoconf *string  `json:"autoconf,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
			} `json:"vif,omitempty"`
			Address         *string `json:"address,omitempty"`
			Redirect        *string `json:"redirect,omitempty"`
			ForwardingDelay *int    `json:"forwarding-delay,omitempty"`
			Dhcpv6Options   *struct {
				ParametersOnly *string `json:"parameters-only,omitempty"`
				Temporary      *string `json:"temporary,omitempty"`
			} `json:"dhcpv6-options,omitempty"`
			Priority    *int    `json:"priority,omitempty"`
			Promiscuous *string `json:"promiscuous,omitempty"`
			Ip          *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
			Aging *int `json:"aging,omitempty"`
		} `json:"bridge,omitempty"`
		L2tpClient *map[string]struct {
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			NameServer    *string `json:"name-server,omitempty"`
			DefaultRoute  *string `json:"default-route,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Firewall *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			ServerIp    *string `json:"server-ip,omitempty"`
			Description *string `json:"description,omitempty"`
			Compression *struct {
				ProtocolField *string `json:"protocol-field,omitempty"`
				Bsd           *string `json:"bsd,omitempty"`
				TcpHeader     *string `json:"tcp-header,omitempty"`
				Deflate       *string `json:"deflate,omitempty"`
				Control       *string `json:"control,omitempty"`
			} `json:"compression,omitempty"`
			Redirect     *string `json:"redirect,omitempty"`
			RequireIpsec *string `json:"require-ipsec,omitempty"`
			Ip           *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				Ripng *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
			Authentication *struct {
				Password    *string `json:"password,omitempty"`
				Refuse      *string `json:"refuse,omitempty"`
				UserId      *string `json:"user-id,omitempty"`
				RequireMppe *string `json:"require-mppe,omitempty"`
			} `json:"authentication,omitempty"`
		} `json:"l2tp-client,omitempty"`
		PptpClient *map[string]struct {
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Password      *string `json:"password,omitempty"`
			RemoteAddress *IPv4   `json:"remote-address,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			NameServer    *string `json:"name-server,omitempty"`
			DefaultRoute  *string `json:"default-route,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			IdleTimeout     *int    `json:"idle-timeout,omitempty"`
			ConnectOnDemand *string `json:".connect-on-demand,omitempty"`
			Firewall        *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			UserId       *string `json:"user-id,omitempty"`
			ServerIp     *string `json:"server-ip,omitempty"`
			Description  *string `json:"description,omitempty"`
			LocalAddress *IPv4   `json:"local-address,omitempty"`
			RequireMppe  *string `json:"require-mppe,omitempty"`
			Redirect     *string `json:"redirect,omitempty"`
			Ip           *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				Enable *struct {
					RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
					LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
				} `json:"enable,omitempty"`
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64     *IPv6Net `json:"eui64,omitempty"`
					Autoconf  *string  `json:"autoconf,omitempty"`
					Secondary *IPv6Net `json:"secondary,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"pptp-client,omitempty"`
		Ethernet *map[string]struct {
			BridgeGroup *struct {
				Bridge   *string `json:"bridge,omitempty"`
				Cost     *int    `json:"cost,omitempty"`
				Priority *int    `json:"priority,omitempty"`
			} `json:"bridge-group,omitempty"`
			Poe *struct {
				Output   *string `json:"output,omitempty"`
				Watchdog *struct {
					Disable      *string `json:"disable,omitempty"`
					FailureCount *int    `json:"failure-count,omitempty"`
					OffDelay     *int    `json:"off-delay,omitempty"`
					Interval     *int    `json:"interval,omitempty"`
					StartDelay   *int    `json:"start-delay,omitempty"`
					Address      *IP     `json:"address,omitempty"`
				} `json:"watchdog,omitempty"`
			} `json:"poe,omitempty"`
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Pppoe *map[string]struct {
				ServiceName *string `json:"service-name,omitempty"`
				Bandwidth   *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Password      *string `json:"password,omitempty"`
				RemoteAddress *IPv4   `json:"remote-address,omitempty"`
				HostUniq      *string `json:"host-uniq,omitempty"`
				Mtu           *int    `json:"mtu,omitempty"`
				NameServer    *string `json:"name-server,omitempty"`
				DefaultRoute  *string `json:"default-route,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				IdleTimeout *int `json:"idle-timeout,omitempty"`
				Dhcpv6Pd    *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
				Firewall        *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				UserId       *string `json:"user-id,omitempty"`
				Description  *string `json:"description,omitempty"`
				LocalAddress *IPv4   `json:"local-address,omitempty"`
				Redirect     *string `json:"redirect,omitempty"`
				Ip           *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					Enable *struct {
						RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
						LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
					} `json:"enable,omitempty"`
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64     *IPv6Net `json:"eui64,omitempty"`
						Autoconf  *string  `json:"autoconf,omitempty"`
						Secondary *IPv6Net `json:"secondary,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
				Multilink          *string `json:"multilink,omitempty"`
				AccessConcentrator *string `json:"access-concentrator,omitempty"`
			} `json:"pppoe,omitempty"`
			Speed         *string `json:"speed,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Vrrp *struct {
				VrrpGroup *map[string]struct {
					Disable              *string `json:"disable,omitempty"`
					VirtualAddress       *string `json:"virtual-address,omitempty"`
					AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
					SyncGroup            *string `json:"sync-group,omitempty"`
					PreemptDelay         *int    `json:"preempt-delay,omitempty"`
					RunTransitionScripts *struct {
						Master *string `json:"master,omitempty"`
						Fault  *string `json:"fault,omitempty"`
						Backup *string `json:"backup,omitempty"`
					} `json:"run-transition-scripts,omitempty"`
					Preempt            *bool   `json:"preempt,omitempty"`
					Description        *string `json:"description,omitempty"`
					HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					Authentication     *struct {
						Password *string `json:"password,omitempty"`
						Type     *string `json:"type,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"vrrp-group,omitempty"`
			} `json:"vrrp,omitempty"`
			Dhcpv6Pd *struct {
				Pd *map[string]struct {
					Interface *map[string]struct {
						StaticMapping *map[string]struct {
							Identifier  *string `json:"identifier,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
						} `json:"static-mapping,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						PrefixId    *string `json:"prefix-id,omitempty"`
						HostAddress *string `json:"host-address,omitempty"`
						Service     *string `json:"service,omitempty"`
					} `json:"interface,omitempty"`
					PrefixLength *string `json:"prefix-length,omitempty"`
				} `json:"pd,omitempty"`
				Duid        *string `json:"duid,omitempty"`
				NoDns       *string `json:"no-dns,omitempty"`
				RapidCommit *string `json:"rapid-commit,omitempty"`
				PrefixOnly  *string `json:"prefix-only,omitempty"`
			} `json:"dhcpv6-pd,omitempty"`
			DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
			Duplex            *string `json:"duplex,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			DisableFlowControl *string  `json:".disable-flow-control,omitempty"`
			Mac                *MacAddr `json:"mac,omitempty"`
			DhcpOptions        *struct {
				NameServer           *string `json:"name-server,omitempty"`
				DefaultRoute         *string `json:"default-route,omitempty"`
				ClientOption         *string `json:"client-option,omitempty"`
				DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
				GlobalOption         *string `json:"global-option,omitempty"`
			} `json:"dhcp-options,omitempty"`
			Description *string `json:"description,omitempty"`
			BondGroup   *string `json:"bond-group,omitempty"`
			Vif         *map[string]struct {
				BridgeGroup *struct {
					Bridge   *string `json:"bridge,omitempty"`
					Cost     *int    `json:"cost,omitempty"`
					Priority *int    `json:"priority,omitempty"`
				} `json:"bridge-group,omitempty"`
				Disable   *string `json:"disable,omitempty"`
				Bandwidth *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				EgressQos *string `json:"egress-qos,omitempty"`
				Pppoe     *map[string]struct {
					ServiceName *string `json:"service-name,omitempty"`
					Bandwidth   *struct {
						Maximum    *string `json:"maximum,omitempty"`
						Reservable *string `json:"reservable,omitempty"`
						Constraint *struct {
							ClassType *map[string]struct {
								Bandwidth *string `json:"bandwidth,omitempty"`
							} `json:"class-type,omitempty"`
						} `json:"constraint,omitempty"`
					} `json:"bandwidth,omitempty"`
					Password      *string `json:"password,omitempty"`
					RemoteAddress *IPv4   `json:"remote-address,omitempty"`
					HostUniq      *string `json:"host-uniq,omitempty"`
					Mtu           *int    `json:"mtu,omitempty"`
					NameServer    *string `json:"name-server,omitempty"`
					DefaultRoute  *string `json:"default-route,omitempty"`
					TrafficPolicy *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"traffic-policy,omitempty"`
					IdleTimeout *int `json:"idle-timeout,omitempty"`
					Dhcpv6Pd    *struct {
						Pd *map[string]struct {
							Interface *map[string]struct {
								StaticMapping *map[string]struct {
									Identifier  *string `json:"identifier,omitempty"`
									HostAddress *string `json:"host-address,omitempty"`
								} `json:"static-mapping,omitempty"`
								NoDns       *string `json:"no-dns,omitempty"`
								PrefixId    *string `json:"prefix-id,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
								Service     *string `json:"service,omitempty"`
							} `json:"interface,omitempty"`
							PrefixLength *string `json:"prefix-length,omitempty"`
						} `json:"pd,omitempty"`
						Duid        *string `json:"duid,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						RapidCommit *string `json:"rapid-commit,omitempty"`
						PrefixOnly  *string `json:"prefix-only,omitempty"`
					} `json:"dhcpv6-pd,omitempty"`
					ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
					Firewall        *struct {
						Out *struct {
							Modify     *string `json:"modify,omitempty"`
							Ipv6Modify *string `json:"ipv6-modify,omitempty"`
							Name       *string `json:"name,omitempty"`
							Ipv6Name   *string `json:"ipv6-name,omitempty"`
						} `json:"out,omitempty"`
						In *struct {
							Modify     *string `json:"modify,omitempty"`
							Ipv6Modify *string `json:"ipv6-modify,omitempty"`
							Name       *string `json:"name,omitempty"`
							Ipv6Name   *string `json:"ipv6-name,omitempty"`
						} `json:"in,omitempty"`
						Local *struct {
							Name     *string `json:"name,omitempty"`
							Ipv6Name *string `json:"ipv6-name,omitempty"`
						} `json:"local,omitempty"`
					} `json:"firewall,omitempty"`
					UserId       *string `json:"user-id,omitempty"`
					Description  *string `json:"description,omitempty"`
					LocalAddress *IPv4   `json:"local-address,omitempty"`
					Redirect     *string `json:"redirect,omitempty"`
					Ip           *struct {
						Rip *struct {
							SplitHorizon *struct {
								Disable       *string `json:"disable,omitempty"`
								PoisonReverse *string `json:"poison-reverse,omitempty"`
							} `json:"split-horizon,omitempty"`
							Authentication *struct {
								Md5 *map[string]struct {
									Password *string `json:"password,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
						} `json:"rip,omitempty"`
						SourceValidation *string `json:"source-validation,omitempty"`
						Ospf             *struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Network            *string `json:"network,omitempty"`
							Cost               *int    `json:"cost,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							Priority           *int    `json:"priority,omitempty"`
							MtuIgnore          *string `json:"mtu-ignore,omitempty"`
							Authentication     *struct {
								Md5 *struct {
									KeyId *map[string]struct {
										Md5Key *string `json:"md5-key,omitempty"`
									} `json:"key-id,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
							HelloInterval *int `json:"hello-interval,omitempty"`
						} `json:"ospf,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Enable *struct {
							RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
							LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
						} `json:"enable,omitempty"`
						DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
						DisableForwarding      *string `json:"disable-forwarding,omitempty"`
						Ripng                  *struct {
							SplitHorizon *struct {
								Disable       *string `json:"disable,omitempty"`
								PoisonReverse *string `json:"poison-reverse,omitempty"`
							} `json:"split-horizon,omitempty"`
						} `json:"ripng,omitempty"`
						Address *struct {
							Eui64     *IPv6Net `json:"eui64,omitempty"`
							Autoconf  *string  `json:"autoconf,omitempty"`
							Secondary *IPv6Net `json:"secondary,omitempty"`
						} `json:"address,omitempty"`
						RouterAdvert *struct {
							DefaultPreference *string `json:"default-preference,omitempty"`
							MinInterval       *int    `json:"min-interval,omitempty"`
							MaxInterval       *int    `json:"max-interval,omitempty"`
							ReachableTime     *int    `json:"reachable-time,omitempty"`
							Prefix            *map[string]struct {
								AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
								OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
								ValidLifetime     *string `json:"valid-lifetime,omitempty"`
								PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
							} `json:"prefix,omitempty"`
							NameServer      *IPv6   `json:"name-server,omitempty"`
							RetransTimer    *int    `json:"retrans-timer,omitempty"`
							SendAdvert      *bool   `json:"send-advert,omitempty"`
							RadvdOptions    *string `json:"radvd-options,omitempty"`
							ManagedFlag     *bool   `json:"managed-flag,omitempty"`
							OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
							DefaultLifetime *int    `json:"default-lifetime,omitempty"`
							CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
							LinkMtu         *int    `json:"link-mtu,omitempty"`
						} `json:"router-advert,omitempty"`
						Ospfv3 *struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Cost               *int    `json:"cost,omitempty"`
							Passive            *string `json:"passive,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							InstanceId         *int    `json:"instance-id,omitempty"`
							Ifmtu              *int    `json:"ifmtu,omitempty"`
							Priority           *int    `json:"priority,omitempty"`
							MtuIgnore          *string `json:"mtu-ignore,omitempty"`
							HelloInterval      *int    `json:"hello-interval,omitempty"`
						} `json:"ospfv3,omitempty"`
					} `json:"ipv6,omitempty"`
					Multilink          *string `json:"multilink,omitempty"`
					AccessConcentrator *string `json:"access-concentrator,omitempty"`
				} `json:"pppoe,omitempty"`
				Mtu           *int `json:"mtu,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				Vrrp *struct {
					VrrpGroup *map[string]struct {
						Disable              *string `json:"disable,omitempty"`
						VirtualAddress       *string `json:"virtual-address,omitempty"`
						AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
						SyncGroup            *string `json:"sync-group,omitempty"`
						PreemptDelay         *int    `json:"preempt-delay,omitempty"`
						RunTransitionScripts *struct {
							Master *string `json:"master,omitempty"`
							Fault  *string `json:"fault,omitempty"`
							Backup *string `json:"backup,omitempty"`
						} `json:"run-transition-scripts,omitempty"`
						Preempt            *bool   `json:"preempt,omitempty"`
						Description        *string `json:"description,omitempty"`
						HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						Authentication     *struct {
							Password *string `json:"password,omitempty"`
							Type     *string `json:"type,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"vrrp-group,omitempty"`
				} `json:"vrrp,omitempty"`
				Dhcpv6Pd *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
				Firewall          *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				Mac         *MacAddr `json:"mac,omitempty"`
				DhcpOptions *struct {
					NameServer           *string `json:"name-server,omitempty"`
					DefaultRoute         *string `json:"default-route,omitempty"`
					ClientOption         *string `json:"client-option,omitempty"`
					DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
					GlobalOption         *string `json:"global-option,omitempty"`
				} `json:"dhcp-options,omitempty"`
				Description   *string `json:"description,omitempty"`
				Address       *string `json:"address,omitempty"`
				Redirect      *string `json:"redirect,omitempty"`
				Dhcpv6Options *struct {
					ParametersOnly *string `json:"parameters-only,omitempty"`
					Temporary      *string `json:"temporary,omitempty"`
				} `json:"dhcpv6-options,omitempty"`
				Ip *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					EnableProxyArp   *string `json:"enable-proxy-arp,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					ProxyArpPvlan    *string `json:"proxy-arp-pvlan,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64    *IPv6Net `json:"eui64,omitempty"`
						Autoconf *string  `json:"autoconf,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
			} `json:"vif,omitempty"`
			Address       *string `json:"address,omitempty"`
			Redirect      *string `json:"redirect,omitempty"`
			SmpAffinity   *string `json:".smp_affinity,omitempty"`
			Dhcpv6Options *struct {
				ParametersOnly *string `json:"parameters-only,omitempty"`
				Temporary      *string `json:"temporary,omitempty"`
			} `json:"dhcpv6-options,omitempty"`
			Ip *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				EnableProxyArp   *string `json:"enable-proxy-arp,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				ProxyArpPvlan    *string `json:"proxy-arp-pvlan,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
			Mirror *string `json:"mirror,omitempty"`
		} `json:"ethernet,omitempty"`
		Tunnel *map[string]struct {
			BridgeGroup *struct {
				Bridge   *string `json:"bridge,omitempty"`
				Cost     *int    `json:"cost,omitempty"`
				Priority *int    `json:"priority,omitempty"`
			} `json:"bridge-group,omitempty"`
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Encapsulation *string `json:"encapsulation,omitempty"`
			Multicast     *string `json:"multicast,omitempty"`
			Ttl           *int    `json:"ttl,omitempty"`
			Mtu           *int    `json:"mtu,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Key               *int     `json:"key,omitempty"`
			DisableLinkDetect *string  `json:"disable-link-detect,omitempty"`
			SixrdPrefix       *IPv6Net `json:"6rd-prefix,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Tos              *int     `json:"tos,omitempty"`
			SixrdRelayPrefix *IPv4Net `json:"6rd-relay_prefix,omitempty"`
			Description      *string  `json:"description,omitempty"`
			Address          *IPNet   `json:"address,omitempty"`
			Redirect         *string  `json:"redirect,omitempty"`
			LocalIp          *IPv4    `json:"local-ip,omitempty"`
			RemoteIp         *IPv4    `json:"remote-ip,omitempty"`
			SixrdDefaultGw   *IPv6    `json:"6rd-default-gw,omitempty"`
			Ip               *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"tunnel,omitempty"`
		Openvpn *map[string]struct {
			BridgeGroup *struct {
				Bridge   *string `json:"bridge,omitempty"`
				Cost     *int    `json:"cost,omitempty"`
				Priority *int    `json:"priority,omitempty"`
			} `json:"bridge-group,omitempty"`
			Encryption *string `json:"encryption,omitempty"`
			Disable    *string `json:"disable,omitempty"`
			RemoteHost *string `json:"remote-host,omitempty"`
			Bandwidth  *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			ReplaceDefaultRoute *struct {
				Local *string `json:"local,omitempty"`
			} `json:"replace-default-route,omitempty"`
			OpenvpnOption       *string `json:"openvpn-option,omitempty"`
			RemoteAddress       *IPv4   `json:"remote-address,omitempty"`
			Mode                *string `json:"mode,omitempty"`
			Hash                *string `json:"hash,omitempty"`
			DeviceType          *string `json:"device-type,omitempty"`
			SharedSecretKeyFile *string `json:"shared-secret-key-file,omitempty"`
			LocalHost           *IPv4   `json:"local-host,omitempty"`
			TrafficPolicy       *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Server *struct {
				PushRoute      *IPv4Net `json:"push-route,omitempty"`
				Topology       *string  `json:"topology,omitempty"`
				NameServer     *IPv4    `json:"name-server,omitempty"`
				DomainName     *string  `json:"domain-name,omitempty"`
				MaxConnections *int     `json:"max-connections,omitempty"`
				Subnet         *IPv4Net `json:"subnet,omitempty"`
				Client         *map[string]struct {
					PushRoute *IPv4Net `json:"push-route,omitempty"`
					Disable   *string  `json:"disable,omitempty"`
					Ip        *IPv4    `json:"ip,omitempty"`
					Subnet    *IPv4Net `json:"subnet,omitempty"`
				} `json:"client,omitempty"`
			} `json:"server,omitempty"`
			Protocol *string `json:"protocol,omitempty"`
			Firewall *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Tls *struct {
				CrlFile    *string `json:"crl-file,omitempty"`
				Role       *string `json:"role,omitempty"`
				KeyFile    *string `json:"key-file,omitempty"`
				DhFile     *string `json:"dh-file,omitempty"`
				CaCertFile *string `json:"ca-cert-file,omitempty"`
				CertFile   *string `json:"cert-file,omitempty"`
			} `json:"tls,omitempty"`
			Description  *string `json:"description,omitempty"`
			LocalAddress *map[string]struct {
				SubnetMask *IPv4 `json:"subnet-mask,omitempty"`
			} `json:"local-address,omitempty"`
			LocalPort *int    `json:"local-port,omitempty"`
			Redirect  *string `json:"redirect,omitempty"`
			Ip        *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
			RemotePort *int    `json:"remote-port,omitempty"`
			ConfigFile *string `json:"config-file,omitempty"`
		} `json:"openvpn,omitempty"`
		Loopback *map[string]struct {
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Description *string `json:"description,omitempty"`
			Address     *IPNet  `json:"address,omitempty"`
			Redirect    *string `json:"redirect,omitempty"`
			Ip          *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				Ripng *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"loopback,omitempty"`
		Switch *map[string]struct {
			BridgeGroup *struct {
				Bridge   *string `json:"bridge,omitempty"`
				Cost     *int    `json:"cost,omitempty"`
				Priority *int    `json:"priority,omitempty"`
			} `json:"bridge-group,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Pppoe *map[string]struct {
				ServiceName *string `json:"service-name,omitempty"`
				Bandwidth   *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Password      *string `json:"password,omitempty"`
				RemoteAddress *IPv4   `json:"remote-address,omitempty"`
				HostUniq      *string `json:"host-uniq,omitempty"`
				Mtu           *int    `json:"mtu,omitempty"`
				NameServer    *string `json:"name-server,omitempty"`
				DefaultRoute  *string `json:"default-route,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				IdleTimeout *int `json:"idle-timeout,omitempty"`
				Dhcpv6Pd    *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
				Firewall        *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				UserId       *string `json:"user-id,omitempty"`
				Description  *string `json:"description,omitempty"`
				LocalAddress *IPv4   `json:"local-address,omitempty"`
				Redirect     *string `json:"redirect,omitempty"`
				Ip           *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					Enable *struct {
						RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
						LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
					} `json:"enable,omitempty"`
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64     *IPv6Net `json:"eui64,omitempty"`
						Autoconf  *string  `json:"autoconf,omitempty"`
						Secondary *IPv6Net `json:"secondary,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
				Multilink          *string `json:"multilink,omitempty"`
				AccessConcentrator *string `json:"access-concentrator,omitempty"`
			} `json:"pppoe,omitempty"`
			Mtu        *int `json:"mtu,omitempty"`
			SwitchPort *struct {
				Interface *map[string]struct {
					Vlan *struct {
						Vid  *int `json:"vid,omitempty"`
						Pvid *int `json:"pvid,omitempty"`
					} `json:"vlan,omitempty"`
				} `json:"interface,omitempty"`
				VlanAware *string `json:"vlan-aware,omitempty"`
			} `json:"switch-port,omitempty"`
			TrafficPolicy *struct {
				Out *string `json:"out,omitempty"`
				In  *string `json:"in,omitempty"`
			} `json:"traffic-policy,omitempty"`
			Vrrp *struct {
				VrrpGroup *map[string]struct {
					Disable              *string `json:"disable,omitempty"`
					VirtualAddress       *string `json:"virtual-address,omitempty"`
					AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
					SyncGroup            *string `json:"sync-group,omitempty"`
					PreemptDelay         *int    `json:"preempt-delay,omitempty"`
					RunTransitionScripts *struct {
						Master *string `json:"master,omitempty"`
						Fault  *string `json:"fault,omitempty"`
						Backup *string `json:"backup,omitempty"`
					} `json:"run-transition-scripts,omitempty"`
					Preempt            *bool   `json:"preempt,omitempty"`
					Description        *string `json:"description,omitempty"`
					HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					Authentication     *struct {
						Password *string `json:"password,omitempty"`
						Type     *string `json:"type,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"vrrp-group,omitempty"`
			} `json:"vrrp,omitempty"`
			Dhcpv6Pd *struct {
				Pd *map[string]struct {
					Interface *map[string]struct {
						StaticMapping *map[string]struct {
							Identifier  *string `json:"identifier,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
						} `json:"static-mapping,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						PrefixId    *string `json:"prefix-id,omitempty"`
						HostAddress *string `json:"host-address,omitempty"`
						Service     *string `json:"service,omitempty"`
					} `json:"interface,omitempty"`
					PrefixLength *string `json:"prefix-length,omitempty"`
				} `json:"pd,omitempty"`
				Duid        *string `json:"duid,omitempty"`
				NoDns       *string `json:"no-dns,omitempty"`
				RapidCommit *string `json:"rapid-commit,omitempty"`
				PrefixOnly  *string `json:"prefix-only,omitempty"`
			} `json:"dhcpv6-pd,omitempty"`
			Firewall *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			DhcpOptions *struct {
				NameServer           *string `json:"name-server,omitempty"`
				DefaultRoute         *string `json:"default-route,omitempty"`
				ClientOption         *string `json:"client-option,omitempty"`
				DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
				GlobalOption         *string `json:"global-option,omitempty"`
			} `json:"dhcp-options,omitempty"`
			Description *string `json:"description,omitempty"`
			Vif         *map[string]struct {
				BridgeGroup *struct {
					Bridge   *string `json:"bridge,omitempty"`
					Cost     *int    `json:"cost,omitempty"`
					Priority *int    `json:"priority,omitempty"`
				} `json:"bridge-group,omitempty"`
				Disable   *string `json:"disable,omitempty"`
				Bandwidth *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Pppoe *map[string]struct {
					ServiceName *string `json:"service-name,omitempty"`
					Bandwidth   *struct {
						Maximum    *string `json:"maximum,omitempty"`
						Reservable *string `json:"reservable,omitempty"`
						Constraint *struct {
							ClassType *map[string]struct {
								Bandwidth *string `json:"bandwidth,omitempty"`
							} `json:"class-type,omitempty"`
						} `json:"constraint,omitempty"`
					} `json:"bandwidth,omitempty"`
					Password      *string `json:"password,omitempty"`
					RemoteAddress *IPv4   `json:"remote-address,omitempty"`
					HostUniq      *string `json:"host-uniq,omitempty"`
					Mtu           *int    `json:"mtu,omitempty"`
					NameServer    *string `json:"name-server,omitempty"`
					DefaultRoute  *string `json:"default-route,omitempty"`
					TrafficPolicy *struct {
						Out *string `json:"out,omitempty"`
						In  *string `json:"in,omitempty"`
					} `json:"traffic-policy,omitempty"`
					IdleTimeout *int `json:"idle-timeout,omitempty"`
					Dhcpv6Pd    *struct {
						Pd *map[string]struct {
							Interface *map[string]struct {
								StaticMapping *map[string]struct {
									Identifier  *string `json:"identifier,omitempty"`
									HostAddress *string `json:"host-address,omitempty"`
								} `json:"static-mapping,omitempty"`
								NoDns       *string `json:"no-dns,omitempty"`
								PrefixId    *string `json:"prefix-id,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
								Service     *string `json:"service,omitempty"`
							} `json:"interface,omitempty"`
							PrefixLength *string `json:"prefix-length,omitempty"`
						} `json:"pd,omitempty"`
						Duid        *string `json:"duid,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						RapidCommit *string `json:"rapid-commit,omitempty"`
						PrefixOnly  *string `json:"prefix-only,omitempty"`
					} `json:"dhcpv6-pd,omitempty"`
					ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
					Firewall        *struct {
						Out *struct {
							Modify     *string `json:"modify,omitempty"`
							Ipv6Modify *string `json:"ipv6-modify,omitempty"`
							Name       *string `json:"name,omitempty"`
							Ipv6Name   *string `json:"ipv6-name,omitempty"`
						} `json:"out,omitempty"`
						In *struct {
							Modify     *string `json:"modify,omitempty"`
							Ipv6Modify *string `json:"ipv6-modify,omitempty"`
							Name       *string `json:"name,omitempty"`
							Ipv6Name   *string `json:"ipv6-name,omitempty"`
						} `json:"in,omitempty"`
						Local *struct {
							Name     *string `json:"name,omitempty"`
							Ipv6Name *string `json:"ipv6-name,omitempty"`
						} `json:"local,omitempty"`
					} `json:"firewall,omitempty"`
					UserId       *string `json:"user-id,omitempty"`
					Description  *string `json:"description,omitempty"`
					LocalAddress *IPv4   `json:"local-address,omitempty"`
					Redirect     *string `json:"redirect,omitempty"`
					Ip           *struct {
						Rip *struct {
							SplitHorizon *struct {
								Disable       *string `json:"disable,omitempty"`
								PoisonReverse *string `json:"poison-reverse,omitempty"`
							} `json:"split-horizon,omitempty"`
							Authentication *struct {
								Md5 *map[string]struct {
									Password *string `json:"password,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
						} `json:"rip,omitempty"`
						SourceValidation *string `json:"source-validation,omitempty"`
						Ospf             *struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Network            *string `json:"network,omitempty"`
							Cost               *int    `json:"cost,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							Priority           *int    `json:"priority,omitempty"`
							MtuIgnore          *string `json:"mtu-ignore,omitempty"`
							Authentication     *struct {
								Md5 *struct {
									KeyId *map[string]struct {
										Md5Key *string `json:"md5-key,omitempty"`
									} `json:"key-id,omitempty"`
								} `json:"md5,omitempty"`
								PlaintextPassword *string `json:"plaintext-password,omitempty"`
							} `json:"authentication,omitempty"`
							HelloInterval *int `json:"hello-interval,omitempty"`
						} `json:"ospf,omitempty"`
					} `json:"ip,omitempty"`
					Ipv6 *struct {
						Enable *struct {
							RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
							LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
						} `json:"enable,omitempty"`
						DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
						DisableForwarding      *string `json:"disable-forwarding,omitempty"`
						Ripng                  *struct {
							SplitHorizon *struct {
								Disable       *string `json:"disable,omitempty"`
								PoisonReverse *string `json:"poison-reverse,omitempty"`
							} `json:"split-horizon,omitempty"`
						} `json:"ripng,omitempty"`
						Address *struct {
							Eui64     *IPv6Net `json:"eui64,omitempty"`
							Autoconf  *string  `json:"autoconf,omitempty"`
							Secondary *IPv6Net `json:"secondary,omitempty"`
						} `json:"address,omitempty"`
						RouterAdvert *struct {
							DefaultPreference *string `json:"default-preference,omitempty"`
							MinInterval       *int    `json:"min-interval,omitempty"`
							MaxInterval       *int    `json:"max-interval,omitempty"`
							ReachableTime     *int    `json:"reachable-time,omitempty"`
							Prefix            *map[string]struct {
								AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
								OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
								ValidLifetime     *string `json:"valid-lifetime,omitempty"`
								PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
							} `json:"prefix,omitempty"`
							NameServer      *IPv6   `json:"name-server,omitempty"`
							RetransTimer    *int    `json:"retrans-timer,omitempty"`
							SendAdvert      *bool   `json:"send-advert,omitempty"`
							RadvdOptions    *string `json:"radvd-options,omitempty"`
							ManagedFlag     *bool   `json:"managed-flag,omitempty"`
							OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
							DefaultLifetime *int    `json:"default-lifetime,omitempty"`
							CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
							LinkMtu         *int    `json:"link-mtu,omitempty"`
						} `json:"router-advert,omitempty"`
						Ospfv3 *struct {
							RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
							TransmitDelay      *int    `json:"transmit-delay,omitempty"`
							Cost               *int    `json:"cost,omitempty"`
							Passive            *string `json:"passive,omitempty"`
							DeadInterval       *int    `json:"dead-interval,omitempty"`
							InstanceId         *int    `json:"instance-id,omitempty"`
							Ifmtu              *int    `json:"ifmtu,omitempty"`
							Priority           *int    `json:"priority,omitempty"`
							MtuIgnore          *string `json:"mtu-ignore,omitempty"`
							HelloInterval      *int    `json:"hello-interval,omitempty"`
						} `json:"ospfv3,omitempty"`
					} `json:"ipv6,omitempty"`
					Multilink          *string `json:"multilink,omitempty"`
					AccessConcentrator *string `json:"access-concentrator,omitempty"`
				} `json:"pppoe,omitempty"`
				Mtu           *int `json:"mtu,omitempty"`
				TrafficPolicy *struct {
					Out *string `json:"out,omitempty"`
					In  *string `json:"in,omitempty"`
				} `json:"traffic-policy,omitempty"`
				Vrrp *struct {
					VrrpGroup *map[string]struct {
						Disable              *string `json:"disable,omitempty"`
						VirtualAddress       *string `json:"virtual-address,omitempty"`
						AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
						SyncGroup            *string `json:"sync-group,omitempty"`
						PreemptDelay         *int    `json:"preempt-delay,omitempty"`
						RunTransitionScripts *struct {
							Master *string `json:"master,omitempty"`
							Fault  *string `json:"fault,omitempty"`
							Backup *string `json:"backup,omitempty"`
						} `json:"run-transition-scripts,omitempty"`
						Preempt            *bool   `json:"preempt,omitempty"`
						Description        *string `json:"description,omitempty"`
						HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						Authentication     *struct {
							Password *string `json:"password,omitempty"`
							Type     *string `json:"type,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"vrrp-group,omitempty"`
				} `json:"vrrp,omitempty"`
				Dhcpv6Pd *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				Firewall *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				Mac         *MacAddr `json:"mac,omitempty"`
				DhcpOptions *struct {
					NameServer           *string `json:"name-server,omitempty"`
					DefaultRoute         *string `json:"default-route,omitempty"`
					ClientOption         *string `json:"client-option,omitempty"`
					DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
					GlobalOption         *string `json:"global-option,omitempty"`
				} `json:"dhcp-options,omitempty"`
				Description   *string `json:"description,omitempty"`
				Address       *string `json:"address,omitempty"`
				Redirect      *string `json:"redirect,omitempty"`
				Dhcpv6Options *struct {
					ParametersOnly *string `json:"parameters-only,omitempty"`
					Temporary      *string `json:"temporary,omitempty"`
				} `json:"dhcpv6-options,omitempty"`
				Ip *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					EnableProxyArp   *string `json:"enable-proxy-arp,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64    *IPv6Net `json:"eui64,omitempty"`
						Autoconf *string  `json:"autoconf,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
			} `json:"vif,omitempty"`
			Address       *string `json:"address,omitempty"`
			Redirect      *string `json:"redirect,omitempty"`
			Dhcpv6Options *struct {
				ParametersOnly *string `json:"parameters-only,omitempty"`
				Temporary      *string `json:"temporary,omitempty"`
			} `json:"dhcpv6-options,omitempty"`
			Ip *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				EnableProxyArp   *string `json:"enable-proxy-arp,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"switch,omitempty"`
		PseudoEthernet *map[string]struct {
			Disable   *string `json:"disable,omitempty"`
			Bandwidth *struct {
				Maximum    *string `json:"maximum,omitempty"`
				Reservable *string `json:"reservable,omitempty"`
				Constraint *struct {
					ClassType *map[string]struct {
						Bandwidth *string `json:"bandwidth,omitempty"`
					} `json:"class-type,omitempty"`
				} `json:"constraint,omitempty"`
			} `json:"bandwidth,omitempty"`
			Pppoe *map[string]struct {
				ServiceName *string `json:"service-name,omitempty"`
				Bandwidth   *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Password      *string `json:"password,omitempty"`
				RemoteAddress *IPv4   `json:"remote-address,omitempty"`
				HostUniq      *string `json:"host-uniq,omitempty"`
				Mtu           *int    `json:"mtu,omitempty"`
				NameServer    *string `json:"name-server,omitempty"`
				DefaultRoute  *string `json:"default-route,omitempty"`
				IdleTimeout   *int    `json:"idle-timeout,omitempty"`
				Dhcpv6Pd      *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				ConnectOnDemand *string `json:"connect-on-demand,omitempty"`
				Firewall        *struct {
					Out *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"out,omitempty"`
					In *struct {
						Modify     *string `json:"modify,omitempty"`
						Ipv6Modify *string `json:"ipv6-modify,omitempty"`
						Name       *string `json:"name,omitempty"`
						Ipv6Name   *string `json:"ipv6-name,omitempty"`
					} `json:"in,omitempty"`
					Local *struct {
						Name     *string `json:"name,omitempty"`
						Ipv6Name *string `json:"ipv6-name,omitempty"`
					} `json:"local,omitempty"`
				} `json:"firewall,omitempty"`
				UserId       *string `json:"user-id,omitempty"`
				Description  *string `json:"description,omitempty"`
				LocalAddress *IPv4   `json:"local-address,omitempty"`
				Ip           *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					Enable *struct {
						RemoteIdentifier *IPv6 `json:"remote-identifier,omitempty"`
						LocalIdentifier  *IPv6 `json:"local-identifier,omitempty"`
					} `json:"enable,omitempty"`
					DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
					DisableForwarding      *string `json:"disable-forwarding,omitempty"`
					Ripng                  *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Address *struct {
						Eui64     *IPv6Net `json:"eui64,omitempty"`
						Autoconf  *string  `json:"autoconf,omitempty"`
						Secondary *IPv6Net `json:"secondary,omitempty"`
					} `json:"address,omitempty"`
					RouterAdvert *struct {
						DefaultPreference *string `json:"default-preference,omitempty"`
						MinInterval       *int    `json:"min-interval,omitempty"`
						MaxInterval       *int    `json:"max-interval,omitempty"`
						ReachableTime     *int    `json:"reachable-time,omitempty"`
						Prefix            *map[string]struct {
							AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
							OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
							ValidLifetime     *string `json:"valid-lifetime,omitempty"`
							PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
						} `json:"prefix,omitempty"`
						NameServer      *IPv6   `json:"name-server,omitempty"`
						RetransTimer    *int    `json:"retrans-timer,omitempty"`
						SendAdvert      *bool   `json:"send-advert,omitempty"`
						RadvdOptions    *string `json:"radvd-options,omitempty"`
						ManagedFlag     *bool   `json:"managed-flag,omitempty"`
						OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
						DefaultLifetime *int    `json:"default-lifetime,omitempty"`
						CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
						LinkMtu         *int    `json:"link-mtu,omitempty"`
					} `json:"router-advert,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
				Multilink          *string `json:"multilink,omitempty"`
				AccessConcentrator *string `json:"access-concentrator,omitempty"`
			} `json:"pppoe,omitempty"`
			Vrrp *struct {
				VrrpGroup *map[string]struct {
					Disable              *string `json:"disable,omitempty"`
					VirtualAddress       *string `json:"virtual-address,omitempty"`
					AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
					SyncGroup            *string `json:"sync-group,omitempty"`
					PreemptDelay         *int    `json:"preempt-delay,omitempty"`
					RunTransitionScripts *struct {
						Master *string `json:"master,omitempty"`
						Fault  *string `json:"fault,omitempty"`
						Backup *string `json:"backup,omitempty"`
					} `json:"run-transition-scripts,omitempty"`
					Preempt            *bool   `json:"preempt,omitempty"`
					Description        *string `json:"description,omitempty"`
					HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					Authentication     *struct {
						Password *string `json:"password,omitempty"`
						Type     *string `json:"type,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"vrrp-group,omitempty"`
			} `json:"vrrp,omitempty"`
			Dhcpv6Pd *struct {
				Pd *map[string]struct {
					Interface *map[string]struct {
						StaticMapping *map[string]struct {
							Identifier  *string `json:"identifier,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
						} `json:"static-mapping,omitempty"`
						NoDns       *string `json:"no-dns,omitempty"`
						PrefixId    *string `json:"prefix-id,omitempty"`
						HostAddress *string `json:"host-address,omitempty"`
						Service     *string `json:"service,omitempty"`
					} `json:"interface,omitempty"`
					PrefixLength *string `json:"prefix-length,omitempty"`
				} `json:"pd,omitempty"`
				Duid        *string `json:"duid,omitempty"`
				NoDns       *string `json:"no-dns,omitempty"`
				RapidCommit *string `json:"rapid-commit,omitempty"`
				PrefixOnly  *string `json:"prefix-only,omitempty"`
			} `json:"dhcpv6-pd,omitempty"`
			DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
			Firewall          *struct {
				Out *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"out,omitempty"`
				In *struct {
					Modify     *string `json:"modify,omitempty"`
					Ipv6Modify *string `json:"ipv6-modify,omitempty"`
					Name       *string `json:"name,omitempty"`
					Ipv6Name   *string `json:"ipv6-name,omitempty"`
				} `json:"in,omitempty"`
				Local *struct {
					Name     *string `json:"name,omitempty"`
					Ipv6Name *string `json:"ipv6-name,omitempty"`
				} `json:"local,omitempty"`
			} `json:"firewall,omitempty"`
			Mac         *MacAddr `json:"mac,omitempty"`
			DhcpOptions *struct {
				NameServer           *string `json:"name-server,omitempty"`
				DefaultRoute         *string `json:"default-route,omitempty"`
				ClientOption         *string `json:"client-option,omitempty"`
				DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
				GlobalOption         *string `json:"global-option,omitempty"`
			} `json:"dhcp-options,omitempty"`
			Link        *string `json:"link,omitempty"`
			Description *string `json:"description,omitempty"`
			Vif         *map[string]struct {
				Disable   *string `json:"disable,omitempty"`
				Bandwidth *struct {
					Maximum    *string `json:"maximum,omitempty"`
					Reservable *string `json:"reservable,omitempty"`
					Constraint *struct {
						ClassType *map[string]struct {
							Bandwidth *string `json:"bandwidth,omitempty"`
						} `json:"class-type,omitempty"`
					} `json:"constraint,omitempty"`
				} `json:"bandwidth,omitempty"`
				Vrrp *struct {
					VrrpGroup *map[string]struct {
						Disable              *string `json:"disable,omitempty"`
						VirtualAddress       *string `json:"virtual-address,omitempty"`
						AdvertiseInterval    *int    `json:"advertise-interval,omitempty"`
						SyncGroup            *string `json:"sync-group,omitempty"`
						PreemptDelay         *int    `json:"preempt-delay,omitempty"`
						RunTransitionScripts *struct {
							Master *string `json:"master,omitempty"`
							Fault  *string `json:"fault,omitempty"`
							Backup *string `json:"backup,omitempty"`
						} `json:"run-transition-scripts,omitempty"`
						Preempt            *bool   `json:"preempt,omitempty"`
						Description        *string `json:"description,omitempty"`
						HelloSourceAddress *IPv4   `json:"hello-source-address,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						Authentication     *struct {
							Password *string `json:"password,omitempty"`
							Type     *string `json:"type,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"vrrp-group,omitempty"`
				} `json:"vrrp,omitempty"`
				Dhcpv6Pd *struct {
					Pd *map[string]struct {
						Interface *map[string]struct {
							StaticMapping *map[string]struct {
								Identifier  *string `json:"identifier,omitempty"`
								HostAddress *string `json:"host-address,omitempty"`
							} `json:"static-mapping,omitempty"`
							NoDns       *string `json:"no-dns,omitempty"`
							PrefixId    *string `json:"prefix-id,omitempty"`
							HostAddress *string `json:"host-address,omitempty"`
							Service     *string `json:"service,omitempty"`
						} `json:"interface,omitempty"`
						PrefixLength *string `json:"prefix-length,omitempty"`
					} `json:"pd,omitempty"`
					Duid        *string `json:"duid,omitempty"`
					NoDns       *string `json:"no-dns,omitempty"`
					RapidCommit *string `json:"rapid-commit,omitempty"`
					PrefixOnly  *string `json:"prefix-only,omitempty"`
				} `json:"dhcpv6-pd,omitempty"`
				DisableLinkDetect *string `json:"disable-link-detect,omitempty"`
				DhcpOptions       *struct {
					NameServer           *string `json:"name-server,omitempty"`
					DefaultRoute         *string `json:"default-route,omitempty"`
					ClientOption         *string `json:"client-option,omitempty"`
					DefaultRouteDistance *int    `json:"default-route-distance,omitempty"`
					GlobalOption         *string `json:"global-option,omitempty"`
				} `json:"dhcp-options,omitempty"`
				Description   *string `json:"description,omitempty"`
				Address       *string `json:"address,omitempty"`
				Dhcpv6Options *struct {
					ParametersOnly *string `json:"parameters-only,omitempty"`
					Temporary      *string `json:"temporary,omitempty"`
				} `json:"dhcpv6-options,omitempty"`
				Ip *struct {
					Rip *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
						Authentication *struct {
							Md5 *map[string]struct {
								Password *string `json:"password,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
					} `json:"rip,omitempty"`
					SourceValidation *string `json:"source-validation,omitempty"`
					ProxyArpPvlan    *string `json:"proxy-arp-pvlan,omitempty"`
					Ospf             *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Network            *string `json:"network,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						Authentication     *struct {
							Md5 *struct {
								KeyId *map[string]struct {
									Md5Key *string `json:"md5-key,omitempty"`
								} `json:"key-id,omitempty"`
							} `json:"md5,omitempty"`
							PlaintextPassword *string `json:"plaintext-password,omitempty"`
						} `json:"authentication,omitempty"`
						HelloInterval *int `json:"hello-interval,omitempty"`
					} `json:"ospf,omitempty"`
				} `json:"ip,omitempty"`
				Ipv6 *struct {
					Ripng *struct {
						SplitHorizon *struct {
							Disable       *string `json:"disable,omitempty"`
							PoisonReverse *string `json:"poison-reverse,omitempty"`
						} `json:"split-horizon,omitempty"`
					} `json:"ripng,omitempty"`
					Ospfv3 *struct {
						RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
						TransmitDelay      *int    `json:"transmit-delay,omitempty"`
						Cost               *int    `json:"cost,omitempty"`
						Passive            *string `json:"passive,omitempty"`
						DeadInterval       *int    `json:"dead-interval,omitempty"`
						InstanceId         *int    `json:"instance-id,omitempty"`
						Ifmtu              *int    `json:"ifmtu,omitempty"`
						Priority           *int    `json:"priority,omitempty"`
						MtuIgnore          *string `json:"mtu-ignore,omitempty"`
						HelloInterval      *int    `json:"hello-interval,omitempty"`
					} `json:"ospfv3,omitempty"`
				} `json:"ipv6,omitempty"`
			} `json:"vif,omitempty"`
			Address       *string `json:"address,omitempty"`
			Dhcpv6Options *struct {
				ParametersOnly *string `json:"parameters-only,omitempty"`
				Temporary      *string `json:"temporary,omitempty"`
			} `json:"dhcpv6-options,omitempty"`
			Ip *struct {
				Rip *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
					Authentication *struct {
						Md5 *map[string]struct {
							Password *string `json:"password,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
				} `json:"rip,omitempty"`
				SourceValidation *string `json:"source-validation,omitempty"`
				ProxyArpPvlan    *string `json:"proxy-arp-pvlan,omitempty"`
				Ospf             *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Network            *string `json:"network,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					Authentication     *struct {
						Md5 *struct {
							KeyId *map[string]struct {
								Md5Key *string `json:"md5-key,omitempty"`
							} `json:"key-id,omitempty"`
						} `json:"md5,omitempty"`
						PlaintextPassword *string `json:"plaintext-password,omitempty"`
					} `json:"authentication,omitempty"`
					HelloInterval *int `json:"hello-interval,omitempty"`
				} `json:"ospf,omitempty"`
			} `json:"ip,omitempty"`
			Ipv6 *struct {
				DupAddrDetectTransmits *int    `json:"dup-addr-detect-transmits,omitempty"`
				DisableForwarding      *string `json:"disable-forwarding,omitempty"`
				Ripng                  *struct {
					SplitHorizon *struct {
						Disable       *string `json:"disable,omitempty"`
						PoisonReverse *string `json:"poison-reverse,omitempty"`
					} `json:"split-horizon,omitempty"`
				} `json:"ripng,omitempty"`
				Address *struct {
					Eui64    *IPv6Net `json:"eui64,omitempty"`
					Autoconf *string  `json:"autoconf,omitempty"`
				} `json:"address,omitempty"`
				RouterAdvert *struct {
					DefaultPreference *string `json:"default-preference,omitempty"`
					MinInterval       *int    `json:"min-interval,omitempty"`
					MaxInterval       *int    `json:"max-interval,omitempty"`
					ReachableTime     *int    `json:"reachable-time,omitempty"`
					Prefix            *map[string]struct {
						AutonomousFlag    *bool   `json:"autonomous-flag,omitempty"`
						OnLinkFlag        *bool   `json:"on-link-flag,omitempty"`
						ValidLifetime     *string `json:"valid-lifetime,omitempty"`
						PreferredLifetime *string `json:"preferred-lifetime,omitempty"`
					} `json:"prefix,omitempty"`
					NameServer      *IPv6   `json:"name-server,omitempty"`
					RetransTimer    *int    `json:"retrans-timer,omitempty"`
					SendAdvert      *bool   `json:"send-advert,omitempty"`
					RadvdOptions    *string `json:"radvd-options,omitempty"`
					ManagedFlag     *bool   `json:"managed-flag,omitempty"`
					OtherConfigFlag *bool   `json:"other-config-flag,omitempty"`
					DefaultLifetime *int    `json:"default-lifetime,omitempty"`
					CurHopLimit     *int    `json:"cur-hop-limit,omitempty"`
					LinkMtu         *int    `json:"link-mtu,omitempty"`
				} `json:"router-advert,omitempty"`
				Ospfv3 *struct {
					RetransmitInterval *int    `json:"retransmit-interval,omitempty"`
					TransmitDelay      *int    `json:"transmit-delay,omitempty"`
					Cost               *int    `json:"cost,omitempty"`
					Passive            *string `json:"passive,omitempty"`
					DeadInterval       *int    `json:"dead-interval,omitempty"`
					InstanceId         *int    `json:"instance-id,omitempty"`
					Ifmtu              *int    `json:"ifmtu,omitempty"`
					Priority           *int    `json:"priority,omitempty"`
					MtuIgnore          *string `json:"mtu-ignore,omitempty"`
					HelloInterval      *int    `json:"hello-interval,omitempty"`
				} `json:"ospfv3,omitempty"`
			} `json:"ipv6,omitempty"`
		} `json:"pseudo-ethernet,omitempty"`
	} `json:"interfaces,omitempty"`
	CustomAttribute *map[string]struct {
		Value *string `json:"value,omitempty"`
	} `json:"custom-attribute,omitempty"`
}
