package sdk

import (
	"encoding/json"
	"fmt"
	"net"

	libcalico "github.com/projectcalico/libcalico-go/lib/net"
)

type IP struct {
	net.IP
}

type IPv4 struct {
	net.IP
}

type IPv6 struct {
	net.IP
}

type IPNet struct {
	libcalico.IPNet
}

type IPv6Net struct {
	libcalico.IPNet
}

type IPv4Net struct {
	libcalico.IPNet
}

type MacAddr struct {
	libcalico.MAC
}

func (i *IPv4) UnmarshalJSON(data []byte) error {
	if err := i.UnmarshalText(data); err != nil {
		return fmt.Errorf("Unable to parse IP from JSON: %v\n", data)
	}
	if ip := i.To4(); ip == nil {
		return fmt.Errorf("IP was not IPv4: %v\n", data)
	}
	return nil
}

func (i *IPv4Net) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	ipnet, err := ParseCIDRv4(s)
	if err != nil {
		return err
	}
	i.IP = ipnet.IP
	i.Mask = ipnet.Mask
	return nil
}

func (i *IPv6) UnmarshalJSON(data []byte) error {
	if err := i.UnmarshalText(data); err != nil {
		return fmt.Errorf("Unable to parse IP from JSON: %v\n", data)
	}
	if ip4 := i.To4(); ip4 == nil {
		if ip6 := i.To16(); ip6 == nil {
			return fmt.Errorf("IP was not IPv6: %v\n", data)
		}
	} else {
		return fmt.Errorf("IP was not IPv6: %v\n", data)
	}
	return nil
}

func (i *IPv6Net) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	ipnet, err := ParseCIDRv6(s)
	if err != nil {
		return err
	}
	i.IP = ipnet.IP
	i.Mask = ipnet.Mask
	return nil
}

func ParseCIDRv4(data string) (*net.IPNet, error) {
	netIP, netIPNet, err := net.ParseCIDR(data)
	if netIPNet == nil || err != nil {
		return nil, err
	}

	if ip := netIP.To4(); ip == nil {
		return nil, fmt.Errorf("IP net was not IPv4: %v\n", data)
	}

	return netIPNet, nil
}

func ParseCIDRv6(data string) (*net.IPNet, error) {
	netIP, netIPNet, err := net.ParseCIDR(data)
	if netIPNet == nil || err != nil {
		return nil, err
	}

	if ip4 := netIP.To4(); ip4 == nil {
		if ip6 := netIP.To16(); ip6 == nil {
			return nil, fmt.Errorf("IP was not IPv6: %v\n", data)
		}
	} else {
		return nil, fmt.Errorf("IP was not IPv6: %v\n", data)
	}

	return netIPNet, nil
}
