package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v2"
)

func postIGDGetIPRequest(url string, command string) ([]byte, error) {
	data := `<?xml version='1.0' encoding='utf-8'?>
<s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'>
	<s:Body>
		<u:` + command + `xmlns:u='urn:schemas-upnp-org:service:WANIPConnection:1' />
	</s:Body>
</s:Envelope>`
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(data))
	if err != nil {
		return nil, err
	}
	req.Header.Add("SoapAction", "urn:schemas-upnp-org:service:WANIPConnection:1#"+command)
	req.Header.Add("Content-Type", "text/xml; charset='utf-8'")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func getExternalIPv4FromIGD(url string) (string, error) {
	response, err := postIGDGetIPRequest(url, "GetExternalIPAddress")
	if err != nil {
		return "", err
	}

	type Response struct {
		XMLName              xml.Name `xml:"Envelope"`
		NewExternalIPAddress string   `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	r := &Response{}
	err = xml.Unmarshal(response, r)
	if err != nil {
		return "", err
	}

	if len(r.NewExternalIPAddress) == 0 {
		return "", fmt.Errorf("IGD XML response does not contain IPv4 address")
	}

	return r.NewExternalIPAddress, nil
}

func getExternalIPv6FromIGD(url string) (string, error) {
	response, err := postIGDGetIPRequest(url, "X_AVM_DE_GetExternalIPv6Address")
	if err != nil {
		return "", err
	}

	type Response struct {
		XMLName                xml.Name `xml:"Envelope"`
		NewExternalIPv6Address string   `xml:"Body>X_AVM_DE_GetExternalIPv6AddressResponse>NewExternalIPv6Address"`
	}
	r := &Response{}
	err = xml.Unmarshal(response, r)
	if err != nil {
		return "", err
	}

	if len(r.NewExternalIPv6Address) == 0 {
		return "", fmt.Errorf("IGD XML response does not contain IPv6 address")
	}

	return r.NewExternalIPv6Address, nil
}

func listDeviceIPs(deviceName string, family int) ([]netlink.Addr, error) {
	device, err := netlink.LinkByName(deviceName)
	if err != nil {
		return nil, err
	}
	addrList, err := netlink.AddrList(device, family)
	if err != nil {
		return nil, err
	}
	return addrList, nil
}

func getExternalIPv4FromDevice(deviceName string) (string, error) {
	addrList, err := listDeviceIPs(deviceName, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, addr := range addrList {
		ip := addr.IP
		isPrivate := ip[0] == 10 ||
			(ip[0] == 172 && ip[1]&0xf0 == 16) ||
			(ip[0] == 192 && ip[1] == 168)
		if !isPrivate && ip.IsGlobalUnicast() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no public IPv4 address found on device %s", deviceName)
}

func getExternalIPv6FromDevice(deviceName string) (string, error) {
	addrList, err := listDeviceIPs(deviceName, netlink.FAMILY_V6)
	if len(addrList) == 0 {
		return "", err
	}
	for _, addr := range addrList {
		ip := addr.IP
		isTemporary := (addr.Flags & syscall.IFA_F_TEMPORARY) > 0
		isPrivate := ip[0]&0xfe == 0xfc
		if !isPrivate && !isTemporary && ip.IsGlobalUnicast() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no public IPv6 address found on device '%s'", deviceName)
}

type Server struct {
	URL          string `yaml:"url"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"`
}

type Config struct {
	IP4Provider  string   `yaml:"ip4provider"`
	IP6Provider  string   `yaml:"ip6provider"`
	IGDAddress   string   `yaml:"igdAddress"`
	DevName      string   `yaml:"devName"`
	PollInterval int      `yaml:"pollInterval"`
	Servers      []Server `yaml:"servers"`
}

type Addresses struct {
	ip4 string
	ip6 string
}

func sendUpdate(srv Server, addr Addresses) error {
	url := srv.URL
	url = strings.ReplaceAll(url, "<ipaddr>", addr.ip4)
	url = strings.ReplaceAll(url, "<ip6addr>", addr.ip6)

	password := srv.Password
	if srv.PasswordFile != "" {
		passwordBytes, err := ioutil.ReadFile(srv.PasswordFile)
		if err != nil {
			return err
		}
		password = string(passwordBytes)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if srv.Username != "" {
		req.SetBasicAuth(srv.Username, password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to update IP address. HTTP status: %s", resp.Status)
	}

	return nil
}

func update(cfg Config, lastSyncedAddr []Addresses) bool {
	var err error

	ip4 := ""
	if cfg.IP4Provider == "igd" {
		ip4, err = getExternalIPv4FromIGD(cfg.IGDAddress)
		if err != nil {
			log.Println("Failed to retrieve IPv4 from IGD at", cfg.IGDAddress)
		}
	} else if cfg.IP4Provider == "dev" {
		ip4, err = getExternalIPv4FromDevice(cfg.DevName)
		if err != nil {
			log.Println("Failed to retrieve IPv4 from device", cfg.DevName)
		}
	}

	ip6 := ""
	if cfg.IP6Provider == "igd" {
		ip6, err = getExternalIPv6FromIGD(cfg.IGDAddress)
		if err != nil {
			log.Println("Failed to retrieve IPv6 from IGD at", cfg.IGDAddress)
		}
	} else if cfg.IP6Provider == "dev" {
		ip6, err = getExternalIPv6FromDevice(cfg.DevName)
		if err != nil {
			log.Println("Failed to retrieve IPv6 from device", cfg.DevName)
		}
	}

	success := true

	for i := 0; i < len(lastSyncedAddr); i++ {
		newAddr := Addresses{ip4: ip4, ip6: ip6}
		if newAddr.ip4 == "" {
			newAddr.ip4 = lastSyncedAddr[i].ip4
		}
		if newAddr.ip6 == "" {
			newAddr.ip6 = lastSyncedAddr[i].ip6
		}
		if newAddr.ip4 != lastSyncedAddr[i].ip4 || newAddr.ip6 != lastSyncedAddr[i].ip6 {
			err := sendUpdate(cfg.Servers[0], newAddr)
			if err == nil {
				lastSyncedAddr[i] = newAddr
				log.Println("IP address update successful.")
			} else {
				log.Println("Failed to update address:", err)
				success = false
			}
		}
	}

	return success
}

func loadConfig(filename string) (Config, error) {
	f, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

	cfg := &Config{}
	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		return Config{}, err
	}

	return *cfg, nil
}

func main() {
	configFilename := os.Getenv("DYNDUC_CONFIG_FILE")
	if configFilename == "" {
		configFilename = "config.yml"
	}
	flag.StringVar(&configFilename, "config", configFilename, "config file")
	flag.Parse()

	log.Printf("Reading %s\n", configFilename)
	cfg, err := loadConfig(configFilename)
	if err != nil {
		log.Fatal(err)
	}

	lastSyncedAddr := make([]Addresses, len(cfg.Servers))
	if !update(cfg, lastSyncedAddr) {
		log.Fatal("Update failed. Exiting.")
	}

	ticker := time.NewTicker(time.Duration(cfg.PollInterval) * time.Second)
	netlinkAddrUpdate := make(chan netlink.AddrUpdate)

	go func() {
		for {
			select {
			case <-netlinkAddrUpdate:
				update(cfg, lastSyncedAddr)
			case <-ticker.C:
				update(cfg, lastSyncedAddr)
			}
		}
	}()

	netlinkDone := make(chan struct{})
	netlink.AddrSubscribe(netlinkAddrUpdate, netlinkDone)
	<-netlinkDone
}
