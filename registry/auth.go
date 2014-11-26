package registry

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/docker/docker/utils"
)

const (
	// Where we store the config file
	CONFIGFILE = ".dockercfg"

	REGISTRYSERVER = "https://registry-1.docker.io/v2/"

	// INDEXSERVER = "https://registry-stage.hub.docker.com/v1/"
)

var (
	ErrConfigFileMissing = errors.New("The Auth config file is missing")
	RegistryServerURL    *url.URL
)

// Octet types from RFC 2616.
var octetTypes [256]octetType

type octetType byte

const (
	isToken octetType = 1 << iota
	isSpace
)

func init() {
	url, err := url.Parse(REGISTRYSERVER)
	if err != nil {
		panic(err)
	}
	RegistryServerURL = url

	// OCTET      = <any 8-bit sequence of data>
	// CHAR       = <any US-ASCII character (octets 0 - 127)>
	// CTL        = <any US-ASCII control character (octets 0 - 31) and DEL (127)>
	// CR         = <US-ASCII CR, carriage return (13)>
	// LF         = <US-ASCII LF, linefeed (10)>
	// SP         = <US-ASCII SP, space (32)>
	// HT         = <US-ASCII HT, horizontal-tab (9)>
	// <">        = <US-ASCII double-quote mark (34)>
	// CRLF       = CR LF
	// LWS        = [CRLF] 1*( SP | HT )
	// TEXT       = <any OCTET except CTLs, but including LWS>
	// separators = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" | <">
	//              | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT
	// token      = 1*<any CHAR except CTLs or separators>
	// qdtext     = <any TEXT except <">>

	for c := 0; c < 256; c++ {
		var t octetType
		isCtl := c <= 31 || c == 127
		isChar := 0 <= c && c <= 127
		isSeparator := strings.IndexRune(" \t\"(),/:;<=>?@[]\\{}", rune(c)) >= 0
		if strings.IndexRune(" \t\r\n", rune(c)) >= 0 {
			t |= isSpace
		}
		if isChar && !isCtl && !isSeparator {
			t |= isToken
		}
		octetTypes[c] = t
	}
}

type AuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Auth          string `json:"auth"`
	Email         string `json:"email"`
	ServerAddress string `json:"serveraddress,omitempty"`
}

type ConfigFile struct {
	Configs  map[string]AuthConfig `json:"configs,omitempty"`
	rootPath string
}

func OfficialRegistryAddress() string {
	return REGISTRYSERVER
}

// create a base64 encoded auth string to store in config
func encodeAuth(authConfig *AuthConfig) string {
	authStr := authConfig.Username + ":" + authConfig.Password
	msg := []byte(authStr)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(msg)))
	base64.StdEncoding.Encode(encoded, msg)
	return string(encoded)
}

// decode the auth string
func decodeAuth(authStr string) (string, string, error) {
	decLen := base64.StdEncoding.DecodedLen(len(authStr))
	decoded := make([]byte, decLen)
	authByte := []byte(authStr)
	n, err := base64.StdEncoding.Decode(decoded, authByte)
	if err != nil {
		return "", "", err
	}
	if n > decLen {
		return "", "", fmt.Errorf("Something went wrong decoding auth config")
	}
	arr := strings.SplitN(string(decoded), ":", 2)
	if len(arr) != 2 {
		return "", "", fmt.Errorf("Invalid auth configuration file")
	}
	password := strings.Trim(arr[1], "\x00")
	return arr[0], password, nil
}

// load up the auth config information and return values
// FIXME: use the internal golang config parser
func LoadConfig(rootPath string) (*ConfigFile, error) {
	configFile := ConfigFile{Configs: make(map[string]AuthConfig), rootPath: rootPath}
	confFile := path.Join(rootPath, CONFIGFILE)
	if _, err := os.Stat(confFile); err != nil {
		return &configFile, nil //missing file is not an error
	}
	b, err := ioutil.ReadFile(confFile)
	if err != nil {
		return &configFile, err
	}

	if err := json.Unmarshal(b, &configFile.Configs); err != nil {
		arr := strings.Split(string(b), "\n")
		if len(arr) < 2 {
			return &configFile, fmt.Errorf("The Auth config file is empty")
		}
		authConfig := AuthConfig{}
		origAuth := strings.Split(arr[0], " = ")
		if len(origAuth) != 2 {
			return &configFile, fmt.Errorf("Invalid Auth config file")
		}
		authConfig.Username, authConfig.Password, err = decodeAuth(origAuth[1])
		if err != nil {
			return &configFile, err
		}
		origEmail := strings.Split(arr[1], " = ")
		if len(origEmail) != 2 {
			return &configFile, fmt.Errorf("Invalid Auth config file")
		}
		authConfig.Email = origEmail[1]
		authConfig.ServerAddress = OfficialRegistryAddress()
		configFile.Configs[OfficialRegistryAddress()] = authConfig
	} else {
		for k, authConfig := range configFile.Configs {
			authConfig.Username, authConfig.Password, err = decodeAuth(authConfig.Auth)
			if err != nil {
				return &configFile, err
			}
			authConfig.Auth = ""
			authConfig.ServerAddress = k
			configFile.Configs[k] = authConfig
		}
	}
	return &configFile, nil
}

// save the auth config
func SaveConfig(configFile *ConfigFile) error {
	confFile := path.Join(configFile.rootPath, CONFIGFILE)
	if len(configFile.Configs) == 0 {
		os.Remove(confFile)
		return nil
	}

	configs := make(map[string]AuthConfig, len(configFile.Configs))
	for k, authConfig := range configFile.Configs {
		authCopy := authConfig

		authCopy.Auth = encodeAuth(&authCopy)
		authCopy.Username = ""
		authCopy.Password = ""
		authCopy.ServerAddress = ""
		configs[k] = authCopy
	}

	b, err := json.Marshal(configs)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(confFile, b, 0600)
	if err != nil {
		return err
	}
	return nil
}

// try to register/login to the registry server
func Login(authConfig *AuthConfig, factory *utils.HTTPRequestFactory) (string, error) {
	var (
		status  string
		reqBody []byte
		err     error
		client  = &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				Proxy:             http.ProxyFromEnvironment,
			},
			CheckRedirect: AddRequiredHeadersToRedirectedRequests,
		}
		reqStatusCode = 0
		serverAddress = authConfig.ServerAddress
	)

	if serverAddress == "" {
		serverAddress = REGISTRYSERVER
	}

	// to avoid sending the server address to the server it should be removed before being marshalled
	authCopy := *authConfig
	authCopy.ServerAddress = ""

	jsonBody, err := json.Marshal(authCopy)
	if err != nil {
		return "", fmt.Errorf("Config Error: %s", err)
	}

	req, err := factory.NewRequest("GET", serverAddress, nil)
	if err != nil {
		return "", fmt.Errorf("Server Error: %s", err)
	}
	req.SetBasicAuth(authConfig.Username, authConfig.Password)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Server Error: %s", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		// v1 endpoint, fall through to old workflow below
	case http.StatusOK:
		// v2 authorized
		return "Login Succeeded", nil
	case http.StatusUnauthorized:
		// v2 unauthorized
		challenges := parseAuthHeader(resp.Header)
		token, err := getAuthToken(client, authConfig.Username, authConfig.Password, challenges)
		if err != nil {
			return "", err
		}
		if token == "" {
			return "", fmt.Errorf("Failed to receive auth token from authentication service")
		}
		return "Login Succeeded", nil
	default:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("Login: %s (Code: %d; Headers: %s)", body,
			resp.StatusCode, resp.Header)
	}

	// using `bytes.NewReader(jsonBody)` here causes the server to respond with a 411 status.
	b := strings.NewReader(string(jsonBody))
	req1, err := http.Post(serverAddress+"users/", "application/json; charset=utf-8", b)
	if err != nil {
		return "", fmt.Errorf("Server Error: %s", err)
	}
	reqStatusCode = req1.StatusCode
	defer req1.Body.Close()
	reqBody, err = ioutil.ReadAll(req1.Body)
	if err != nil {
		return "", fmt.Errorf("Server Error: [%#v] %s", reqStatusCode, err)
	}

	if reqStatusCode == 201 {
		status = "Account created. Please see the documentation of the registry " + serverAddress + " for instructions how to activate it."
	} else if reqStatusCode == 400 {
		if string(reqBody) == "\"Username or email already exists\"" {
			req, err := factory.NewRequest("GET", serverAddress+"users/", nil)
			req.SetBasicAuth(authConfig.Username, authConfig.Password)
			resp, err := client.Do(req)
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return "", err
			}
			if resp.StatusCode == 200 {
				return "Login Succeeded", nil
			} else if resp.StatusCode == 401 {
				return "", fmt.Errorf("Wrong login/password, please try again")
			} else if resp.StatusCode == 403 {
				return "", fmt.Errorf("Login: Account is not Active. Please see the documentation of the registry %s for instructions how to activate it.", serverAddress)
			}
			return "", fmt.Errorf("Login: %s (Code: %d; Headers: %s)", body, resp.StatusCode, resp.Header)
		}
		return "", fmt.Errorf("Registration: %s", reqBody)

	} else if reqStatusCode == 401 {
		// This case would happen with private registries where /v1/users is
		// protected, so people can use `docker login` as an auth check.
		req, err := factory.NewRequest("GET", serverAddress+"users/", nil)
		req.SetBasicAuth(authConfig.Username, authConfig.Password)
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 200 {
			return "Login Succeeded", nil
		} else if resp.StatusCode == 401 {
			return "", fmt.Errorf("Wrong login/password, please try again")
		} else {
			return "", fmt.Errorf("Login: %s (Code: %d; Headers: %s)", body,
				resp.StatusCode, resp.Header)
		}
	} else {
		return "", fmt.Errorf("Unexpected status code [%d] : %s", reqStatusCode, reqBody)
	}
	return status, nil
}

// this method matches a auth configuration to a server address or a url
func (config *ConfigFile) ResolveAuthConfig(hostname string) AuthConfig {
	if hostname == OfficialRegistryAddress() || len(hostname) == 0 {
		// default to the index server
		return config.Configs[OfficialRegistryAddress()]
	}

	// First try the happy case
	if c, found := config.Configs[hostname]; found {
		return c
	}

	convertToHostname := func(url string) string {
		stripped := url
		if strings.HasPrefix(url, "http://") {
			stripped = strings.Replace(url, "http://", "", 1)
		} else if strings.HasPrefix(url, "https://") {
			stripped = strings.Replace(url, "https://", "", 1)
		}

		nameParts := strings.SplitN(stripped, "/", 2)

		return nameParts[0]
	}

	// Maybe they have a legacy config file, we will iterate the keys converting
	// them to the new format and testing
	normalizedHostename := convertToHostname(hostname)
	for registry, config := range config.Configs {
		if registryHostname := convertToHostname(registry); registryHostname == normalizedHostename {
			return config
		}
	}

	// When all else fails, return an empty auth config
	return AuthConfig{}
}

type challenge struct {
	Scheme     string
	Parameters map[string]string
}

func getAuthToken(client *http.Client, username, password string, challenges []challenge) (string, error) {
	for _, challenge := range challenges {
		if challenge.Scheme == "token" {
			realm, ok := challenge.Parameters["realm"]
			if !ok {
				continue
			}
			service := challenge.Parameters["service"]
			scope := challenge.Parameters["scope"]

			req, err := http.NewRequest("GET", realm+"token/", nil)
			if err != nil {
				return "", fmt.Errorf("Server Error: %s", err)
			}
			reqParams := req.URL.Query()
			if service != "" {
				reqParams.Add("service", service)
			}
			if scope != "" {
				reqParams.Add("scope", scope)
			}
			reqParams.Add("account", username)
			req.URL = &url.URL{
				Scheme:   req.URL.Scheme,
				Opaque:   req.URL.Opaque,
				User:     req.URL.User,
				Host:     req.URL.Host,
				Path:     req.URL.Path,
				RawQuery: reqParams.Encode(),
			}
			req.SetBasicAuth(username, password)
			resp, err := client.Do(req)
			if err != nil {
				return "", fmt.Errorf("Server Error: %s", err)
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK, http.StatusNoContent:
				token := resp.Header.Get("X-Auth-Token")
				if token != "" {
					return token, nil

				}
			}
		}
	}
	return "", fmt.Errorf("Wrong login/password, please try again")
}

func parseAuthHeader(header http.Header) []challenge {
	var challenges []challenge
	for _, h := range header[http.CanonicalHeaderKey("WWW-Authenticate")] {
		v, p := parseValueAndParams(h)
		if v != "" {
			challenges = append(challenges, challenge{Scheme: v, Parameters: p})
		}
	}
	return challenges
}

func parseValueAndParams(header string) (value string, params map[string]string) {
	params = make(map[string]string)
	value, s := expectToken(header)
	if value == "" {
		return
	}
	value = strings.ToLower(value)
	s = "," + skipSpace(s)
	for strings.HasPrefix(s, ",") {
		var pkey string
		pkey, s = expectToken(skipSpace(s[1:]))
		if pkey == "" {
			return
		}
		if !strings.HasPrefix(s, "=") {
			return
		}
		var pvalue string
		pvalue, s = expectTokenOrQuoted(s[1:])
		if pvalue == "" {
			return
		}
		pkey = strings.ToLower(pkey)
		params[pkey] = pvalue
		s = skipSpace(s)
	}
	return
}

func skipSpace(s string) (rest string) {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isSpace == 0 {
			break
		}
	}
	return s[i:]
}

func expectToken(s string) (token, rest string) {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isToken == 0 {
			break
		}
	}
	return s[:i], s[i:]
}

func expectTokenOrQuoted(s string) (value string, rest string) {
	if !strings.HasPrefix(s, "\"") {
		return expectToken(s)
	}
	s = s[1:]
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[:i], s[i+1:]
		case '\\':
			p := make([]byte, len(s)-1)
			j := copy(p, s[:i])
			escape := true
			for i = i + i; i < len(s); i++ {
				b := s[i]
				switch {
				case escape:
					escape = false
					p[j] = b
					j += 1
				case b == '\\':
					escape = true
				case b == '"':
					return string(p[:j]), s[i+1:]
				default:
					p[j] = b
					j += 1
				}
			}
			return "", ""
		}
	}
	return "", ""
}
