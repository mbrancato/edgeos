package sdk

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"

	"golang.org/x/net/publicsuffix"
)

type Session struct {
	authenticated bool
	client        *http.Client
	currentConfig Config
	apiUrl        string
}

func NewSession() (Session, error) {
	var s Session
	s.authenticated = false

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return s, fmt.Errorf("unable to setup cookie jar: %v\n", err)
	}

	s.client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	if err = s.Login(); err != nil {
		return s, err
	}

	return s, nil
}

func (s *Session) Login() error {
	username := os.Getenv("EDGEOS_USERNAME")
	password := os.Getenv("EDGEOS_PASSWORD")
	apiurl := os.Getenv("EDGEOS_URL")

	if username == "" || password == "" {
		print("Missing username or password\n")
		os.Exit(1)
	}

	if apiurl == "" {
		print("Missing API URL\n")
		os.Exit(1)
	}

	s.apiUrl = apiurl

	resp, err := s.client.PostForm(apiurl, url.Values{
		"username": {username},
		"password": {password}})
	if err != nil {
		return fmt.Errorf("error making login request to EdgeOS: %v, %v", err, resp)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 303 {
		s.authenticated = true
	}

	_ = s.ReadConfig()

	return nil
}

func (s *Session) get(path string) ([]byte, error) {
	if resp, err := s.client.Get(s.apiUrl + path); err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	} else if resp == nil {
		return nil, nil
	} else {

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var confBytes []byte
			confBytes, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response bytes: %v", err)
			}
			return confBytes, nil
		} else {
			return nil, fmt.Errorf("did not get a 2xx HTTP response")
		}
	}
}

func (s *Session) ReadConfig() error {
	var configResponse struct {
		Get       *Config `json:"GET"`
		SessionID string  `json:"SESSION_ID"`
		Success   bool    `json:"success"`
	}

	if conf, err := s.get("/api/edge/get.json"); conf == nil {
		return fmt.Errorf("failed to read config: config was empty")
	} else if err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	} else {

		if err = json.Unmarshal(conf, &configResponse); err != nil {
			return fmt.Errorf("unable to parse config: %w\n", err)
		}
		s.currentConfig = *configResponse.Get
	}
	return nil
}
