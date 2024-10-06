package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"time"

	"github.com/grepplabs/kafka-proxy/config"
	"github.com/grepplabs/kafka-proxy/pkg/apis"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Conn represents a connection from a client to a specific instance.
type Conn struct {
	BrokerAddress   string
	LocalConnection net.Conn
}

type CertStore interface {
	Get(clientID string) (tls.Certificate, bool)
}

type SingleCertStore struct {
	cert tls.Certificate
}

func (s *SingleCertStore) Get(clientID string) (tls.Certificate, bool) {
	return s.cert, true
}

type InMemoryCertStore struct {
	mutex        sync.Mutex
	byCommonName map[string]tls.Certificate
}

func NewInMemoryCertStore() *InMemoryCertStore {
	return &InMemoryCertStore{
		byCommonName: make(map[string]tls.Certificate),
	}
}

func (cs *InMemoryCertStore) Add(clientID string, cert tls.Certificate) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.byCommonName[clientID] = cert
}

func (cs *InMemoryCertStore) Get(clientID string) (tls.Certificate, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cert, ok := cs.byCommonName[clientID]
	return cert, ok
}

// Client is a type to handle connecting to a Server. All fields are required
// unless otherwise specified.
type Client struct {
	conns *ConnSet

	// Kafka Net configuration
	config *config.Config

	// config of Proxy request-response processor (instance p)
	processorConfig ProcessorConfig

	dialer         DialerWithContext
	tcpConnOptions TCPConnOptions

	stopRun  chan struct{}
	stopOnce sync.Once

	saslAuthByProxy SASLAuthByProxy
	authClient      *AuthClient

	dialAddressMapping map[string]config.DialAddressMapping
	kafkaClientCert      *x509.Certificate
}

type ConnectionContext struct {
	clientID *string
}

func NewClient(conns *ConnSet, c *config.Config, netAddressMappingFunc config.NetAddressMappingFunc, localPasswordAuthenticator apis.PasswordAuthenticator, localTokenAuthenticator apis.TokenInfo, saslTokenProvider apis.TokenProvider, gatewayTokenProvider apis.TokenProvider, gatewayTokenInfo apis.TokenInfo) (*Client, error) {
	tlsConfig, err := newTLSClientConfig(c)
	if err != nil {
		return nil, err
	}

	var kafkaClientCert *x509.Certificate = nil
	if c.Kafka.TLS.SameClientCertEnable {
		kafkaClientCert, err = parseCertificate(c.Kafka.TLS.ClientCertFile)
		if err != nil {
			return nil, err
		}
	}

	dialer, err := newDialer(c, tlsConfig)
	if err != nil {
		return nil, err
	}
	tcpConnOptions := TCPConnOptions{
		KeepAlive:       c.Kafka.KeepAlive,
		WriteBufferSize: c.Kafka.ConnectionWriteBufferSize,
		ReadBufferSize:  c.Kafka.ConnectionReadBufferSize,
	}

	forbiddenApiKeys := make(map[int16]struct{})
	if len(c.Kafka.ForbiddenApiKeys) != 0 {
		logrus.Warnf("Kafka operations for Api Keys %v will be forbidden.", c.Kafka.ForbiddenApiKeys)
		for _, apiKey := range c.Kafka.ForbiddenApiKeys {
			forbiddenApiKeys[int16(apiKey)] = struct{}{}
		}
	}
	if c.Auth.Local.Enable && (localPasswordAuthenticator == nil && localTokenAuthenticator == nil) {
		return nil, errors.New("Auth.Local.Enable is enabled but passwordAuthenticator and localTokenAuthenticator are nil")
	}

	if c.Auth.Gateway.Client.Enable && gatewayTokenProvider == nil {
		return nil, errors.New("Auth.Gateway.Client.Enable is enabled but tokenProvider is nil")
	}
	if c.Auth.Gateway.Server.Enable && gatewayTokenInfo == nil {
		return nil, errors.New("Auth.Gateway.Server.Enable is enabled but tokenInfo is nil")
	}
	var saslAuthByProxy SASLAuthByProxy
	if c.Kafka.SASL.Plugin.Enable {
		if c.Kafka.SASL.Plugin.Mechanism == SASLOAuthBearer && saslTokenProvider != nil {
			saslAuthByProxy = &SASLOAuthBearerAuth{
				clientID:      c.Kafka.ClientID,
				writeTimeout:  c.Kafka.WriteTimeout,
				readTimeout:   c.Kafka.ReadTimeout,
				tokenProvider: saslTokenProvider,
			}
		} else {
			return nil, errors.Errorf("SASLAuthByProxy plugin unsupported or plugin misconfiguration for mechanism '%s' ", c.Kafka.SASL.Plugin.Mechanism)
		}

	} else if c.Kafka.SASL.Enable {
		if c.Kafka.SASL.Method == SASLPlain {
			saslAuthByProxy = &SASLPlainAuth{
				clientID:     c.Kafka.ClientID,
				writeTimeout: c.Kafka.WriteTimeout,
				readTimeout:  c.Kafka.ReadTimeout,
				username:     c.Kafka.SASL.Username,
				password:     c.Kafka.SASL.Password,
			}
		} else if c.Kafka.SASL.Method == SASLSCRAM256 || c.Kafka.SASL.Method == SASLSCRAM512 {
			saslAuthByProxy = &SASLSCRAMAuth{
				clientID:     c.Kafka.ClientID,
				writeTimeout: c.Kafka.WriteTimeout,
				readTimeout:  c.Kafka.ReadTimeout,
				username:     c.Kafka.SASL.Username,
				password:     c.Kafka.SASL.Password,
				mechanism:    c.Kafka.SASL.Method,
			}
		} else if c.Kafka.SASL.Method == SASLSGSSAPI {
			saslAuthByProxy = &SASLGSSAPIAuth{
				writeTimeout: c.Kafka.WriteTimeout,
				readTimeout:  c.Kafka.ReadTimeout,
				gssapiConfig: &c.Kafka.SASL.GSSAPI,
			}
		} else if c.Kafka.SASL.Method == SASLIAMAAUTH {
			if saslAuthByProxy, err = NewAwsMSKIamAuth(
				c.Kafka.ClientID,
				c.Kafka.ReadTimeout,
				c.Kafka.WriteTimeout,
				&c.Kafka.SASL.AWSConfig,
			); err != nil {
				return nil, errors.Errorf("Failed to create IAM Auth: %v", err)
			}
		} else {
			return nil, errors.Errorf("SASL Mechanism not valid '%s'", c.Kafka.SASL.Method)
		}
	}

	dialAddressMapping, err := getAddressToDialAddressMapping(c)
	if err != nil {
		return nil, err
	}

	return &Client{conns: conns, config: c, dialer: dialer, tcpConnOptions: tcpConnOptions, stopRun: make(chan struct{}, 1),
		saslAuthByProxy: saslAuthByProxy,
		authClient: &AuthClient{
			enabled:       c.Auth.Gateway.Client.Enable,
			magic:         c.Auth.Gateway.Client.Magic,
			method:        c.Auth.Gateway.Client.Method,
			timeout:       c.Auth.Gateway.Client.Timeout,
			tokenProvider: gatewayTokenProvider,
		},
		processorConfig: ProcessorConfig{
			MaxOpenRequests:       c.Kafka.MaxOpenRequests,
			NetAddressMappingFunc: netAddressMappingFunc,
			RequestBufferSize:     c.Proxy.RequestBufferSize,
			ResponseBufferSize:    c.Proxy.ResponseBufferSize,
			ReadTimeout:           c.Kafka.ReadTimeout,
			WriteTimeout:          c.Kafka.WriteTimeout,
			LocalSasl: NewLocalSasl(LocalSaslParams{
				enabled:               c.Auth.Local.Enable,
				timeout:               c.Auth.Local.Timeout,
				passwordAuthenticator: localPasswordAuthenticator,
				tokenAuthenticator:    localTokenAuthenticator,
			}),
			AuthServer: &AuthServer{
				enabled:   c.Auth.Gateway.Server.Enable,
				magic:     c.Auth.Gateway.Server.Magic,
				method:    c.Auth.Gateway.Server.Method,
				timeout:   c.Auth.Gateway.Server.Timeout,
				tokenInfo: gatewayTokenInfo,
			},
			ForbiddenApiKeys:      forbiddenApiKeys,
			ProducerAcks0Disabled: c.Kafka.Producer.Acks0Disabled,
		},
		dialAddressMapping: dialAddressMapping,
		kafkaClientCert:      kafkaClientCert,
	}, nil
}

func getAddressToDialAddressMapping(cfg *config.Config) (map[string]config.DialAddressMapping, error) {
	addressToDialAddressMapping := make(map[string]config.DialAddressMapping)

	for _, v := range cfg.Proxy.DialAddressMappings {
		if lc, ok := addressToDialAddressMapping[v.SourceAddress]; ok {
			if lc.SourceAddress != v.SourceAddress || lc.DestinationAddress != v.DestinationAddress {
				return nil, fmt.Errorf("dial address mapping %s configured twice: %v and %v", v.SourceAddress, v, lc)
			}
			continue
		}
		logrus.Infof("Dial address mapping src %s dst %s", v.SourceAddress, v.DestinationAddress)
		addressToDialAddressMapping[v.SourceAddress] = v
	}
	return addressToDialAddressMapping, nil
}

func newDialer(c *config.Config, tlsConfig *tls.Config) (DialerWithContext, error) {
	directDialer := directDialer{
		dialTimeout: c.Kafka.DialTimeout,
		keepAlive:   c.Kafka.KeepAlive,
	}

	var rawDialer DialerWithContext
	if c.ForwardProxy.Url != "" {
		switch c.ForwardProxy.Scheme {
		case "socks5":
			logrus.Infof("Kafka clients will connect through the SOCKS5 proxy %s", c.ForwardProxy.Address)
			rawDialer = &socks5Dialer{
				directDialer: directDialer,
				proxyNetwork: "tcp",
				proxyAddr:    c.ForwardProxy.Address,
				username:     c.ForwardProxy.Username,
				password:     c.ForwardProxy.Password,
			}
		case "http":
			logrus.Infof("Kafka clients will connect through the HTTP proxy %s using CONNECT", c.ForwardProxy.Address)

			rawDialer = &httpProxy{
				forwardDialer: directDialer,
				network:       "tcp",
				hostPort:      c.ForwardProxy.Address,
				username:      c.ForwardProxy.Username,
				password:      c.ForwardProxy.Password,
			}
		default:
			return nil, errors.New("Only http or socks5 proxy is supported")
		}
	} else {
		rawDialer = directDialer
	}
	if c.Kafka.TLS.Enable {
		if tlsConfig == nil {
			return nil, errors.New("tlsConfig must not be nil")
		}

		certStore, err := hardcodedCertStore()
		if err != nil {	
			return nil, err
		}

		tlsDialer := tlsDialer{
			timeout:   c.Kafka.DialTimeout,
			rawDialer: rawDialer,
			config:    tlsConfig,
			certStore: certStore,
		}
		return tlsDialer, nil
	}
	return rawDialer, nil
}

func hardcodedCertStore() (CertStore, error) {
	certStore := NewInMemoryCertStore()

	password := os.Getenv("KAFKA_PROXY_TENANT_CERT_PASSWORD")

	test1CertPEMBlock := []byte(`-----BEGIN CERTIFICATE-----
MIICTTCCAfSgAwIBAgIQe0c53LlySgb0cufM1P4g3jAKBggqhkjOPQQDAjAOMQww
CgYDVQQDEwNkc2gwHhcNMjQxMDA0MTkxNjM1WhcNMjUwMTAyMTkxNjM1WjA2MQww
CgYDVQQKEwNkc2gxDzANBgNVBAsTBmRzaGRldjEVMBMGA1UEAxMMdGVzdDEuZHNo
ZGV2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuHIRYhPET8Ld6t5r
Rxw+ePomU4uvkbPYzMmLVg3ZXltCEQ170DQIau3tta58kZ6SEBzPlY+VtmGpCPtE
DgxzGSJ2taZ+bz7nDMXUgbfkFSpxNXmpXM7ocGVz2Z5LY6WxBOKVNLfniwrUF90D
UREXTuYapOZJt6GIT63fpK5qcKgfpeguY1uzcR/osW3GH+XMSf3NF9C16isETiln
jItvJVkvDzHj+FnWqiMLfJSUDwx/SitY2VsRZypRebkkjCfYuI2GAPFiab4B2EQ7
V1IV7OWzo5oO8qTudxo+2zOS3+cCyIlrsdCJsttGnhTS0ynppTrNiFPBcCCiX7/9
bp5+LwIDAQABo0EwPzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAfBgNV
HSMEGDAWgBTxIYWFLoLlgRtlNV1hi+qYr0IRgTAKBggqhkjOPQQDAgNHADBEAiAq
MtASNx0uCd95OiF2SQPCu7YirK4miqwkYjtd1AIxSAIgR4JzCWT16T9Lr4J2Px+g
ZSyrD5WACTsmItrFi2RdvXs=
-----END CERTIFICATE-----`)
	test1KeyPEMBlock := []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQRGFFglOXZbGlFxFB
liawFAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELsNBLQU6jYcUn/T
xuObc8QEggTQOpMV/zfdXW20c0tilq+iHvbiE0HqBI9KKOYW/YA4Hy2cUPZCQp4R
32BWQLnCeY0lAbySPe3+4DzN6mWlIaYMLAh0MwukEcRyKqx7U8v8IpnB/Ebzhd/9
ZCw7WLju6dmjuRXWB8kIDz2v6TlEQyJoqcaTWWNmONkF3KmxjtUb8WW+ADaJOQt5
F4ZulquiBi2qeCh85B9dvk3uoE69/vRc8O7rBvE3bikMLo+js1tq+aNq6tqboD4D
Zjlwz/9DgwrCxKAm2qYO8cYKeZSZilP3SBDScznq6aqYNsv2/6MQ+xhYDua6wde8
Qoe8tojm3pv1UBFKv433582V5RMqv2t8S0GZGr7l1wMkWzduKWmrEN/fdkyQxpMn
TT3eOyns6MfAV59M1gdx5znoyhRTKbicfERtA0m6hAJc1XAyM1ZmZ55fMqWnp8Iy
nPsSgS7RMknVmB9cvIP8zm2Kita2I45z2rutoiw3cKQHuSzqyziNlSu+CWL/nlGu
pbGhhcMTKBybhbEexdey2q0mvw9skQVwrjeZJGoI1iItmLWxQGIY0DumtBUaL3RL
6AWIOIEe8VvaOct3iIUdAucsf6PPhHSPaZNlfrbC1MQoGWPH3jBtsLhTaQ3BHP/u
sUZBcl3XEpAKp8htV/HLERMtj/HzC81wWojZcDsvJnpMhCqeWHR2hEr6zEiI5tU1
fo8KM/4BTrW1vZN5blRhGT2/7OVTjVrr8h4PxNcElm6AtT5KlL32msfTcVof25SH
ktVq9UAj9o+e4GyUdP3ECIy093kSdq0OIJC01FmbtztdkPLK/6qRIYw2EkkSG/n4
rkkX2f+fvQ8PGYEwWAKGfi7DAfeGeL6BCA+0MSYK1IQFI+QNcWkK4c44kPlRNBsc
hB364PjmlTFUXYpHl1zFaFPnsqRLUvNOouZjf0ZPfrZxoxkKgraiA0GRWM7W9MP0
0J9Zm37SoYOGiTip73zBYTrpKBwdrapVUWSIznO8HrGXQcNqxokzDYIw4XJNBqDq
KQwc8XkKMk2K8QEk/BKDMhtp169TvFO71LbuMDnQ0o9edIAiVdEKJFVhNEqQcQiB
MrBYljcPD9hUM9vza0aZjcubbTlEmpMhCZdkW+eNcxAoPhZqyq9hKMERj/jlQ1N3
0kgoIEQ33m398a3w3KiWXuWUjSSEXjePzUCUwixviWcoOy1wGHx7BhMcu+Ji48A7
bUrlTN2k3F/D6Zoi5rt5rvm4Xty9prQH2+QH7VHOlZ+Xq+U/TvtK6ln+OekHOQGu
gWqSGXANBMnFyosxZMFVpA7sKzEcpyemoNRCKaeKQBkjDLlsPdoRUkHQgTKxACRh
9CJHB8zJhRqkd8uSpE+x2foWc1luV3roJBmHiYfClwhbjH0dmnDPVayLuflf5eLX
Li59qMXNAgrauFlPDm8z4Ob3KDiwP/6R4Y+kyQDP9vFKEOqD5JL7xsLlfrmx3CCb
obF5FTeMi0+GkHi24hpVRrkTvN4FGaHevGbCkpfuk+4jYyckgV2lQuJXpaqj+Wib
8AQI/5vxgJB92EbPs1wL4gpOjUhERWEwxo5eYoZQ1ZdSTVU9tvbISGIBed7ZLIHI
QWCfsLrpwmPLYkEG9bKfsg11fW72jBPx+RLs/4ucjBcDI6kI5eGHkZU=
-----END ENCRYPTED PRIVATE KEY-----
`)
	test1KeyPEMBlock, err := decryptPEM(test1KeyPEMBlock, password )
	if err != nil {
		return nil, err
	}

	test1, err := tls.X509KeyPair(test1CertPEMBlock, test1KeyPEMBlock)
	if err != nil {
		return nil, err
	}

	certStore.Add("test1", test1)
	test2CertPEMBlock := []byte(`-----BEGIN CERTIFICATE-----
MIICTjCCAfWgAwIBAgIRAIHHXqg/VV7LNeakO6qlr00wCgYIKoZIzj0EAwIwDjEM
MAoGA1UEAxMDZHNoMB4XDTI0MTAwNDE5MTYzNVoXDTI1MDEwMjE5MTYzNVowNjEM
MAoGA1UEChMDZHNoMQ8wDQYDVQQLEwZkc2hkZXYxFTATBgNVBAMTDHRlc3QyLmRz
aGRldjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANpKJ/lQIKxWdSM7
rqrcZVI+37GhMFgqt4Bo/A61qbjYHr1QD/Sf5cjN5s7+D7VGNj195am3cuwQbNX4
X/sQYZLs/7BlBNRgl8XR3+aMZWP1q/PIFsIS95TeJvreUkhg18tWaWDrN3n1+sJX
5WU9BAFkkwWSIYS5wE1mRa7pLHpW6GwHf6TZjGOUrcQOamW2oZz15g6iTwtXrnY/
oFAvHm9UaiYgAAiv5yOjHacyPHMEOAFLfeiaBLLhRvkB/CTjL9rqaS1SkciF5QHT
oIVpi/SnaLLTTCe56pyzP+AWA712/RmcqprfI8RaXPCvxRj39WvAWA5iImraQLcR
0JW+JG8CAwEAAaNBMD8wDgYDVR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwHwYD
VR0jBBgwFoAU8SGFhS6C5YEbZTVdYYvqmK9CEYEwCgYIKoZIzj0EAwIDRwAwRAIg
VBTbGbkxeiCyYZZQXWEpTi74+nYvvb7OwXpEaek0amgCIB6CtckF5QCFrmYXkJ3g
vepmYaCBf0ltAa6LF4WkqthA
-----END CERTIFICATE-----`)
	test2KeyPEMBlock := []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQoZBZN2ffiH5uZjNs
G/CVgwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELd9Q46y0aB1etfV
Wp9KYDcEggTQExaJ8gtsDi33ZIJgsEouOmMK61XFfmiNPmL4Wo2mAqbECaA3TISX
GE0cPBHWDFwEgJO2Yd0dn/bl0m9kzJlg29dwOPHbVz9akdw6gVX10j0rPRQ0Yy0A
nSyc7yNW/P9hhZ8WW8UvpYXpaf2o9M4au2WFnrWt07ezkppl0gErjk7zBylBcGMU
ivHJFfmmg+0CDhW0VFclSDpifRZ7AN8btw8SU8HYucGoqIIkZEBypgTp7I/hYIaK
UcYV3KFTVhK1w7dp6+aT1gxoZtyqTvfYVWG0dW5op2AUAHfbmdu9lM8RDYPSvA85
blZdupjYdAlT3mDgW8lPKVXU+3K1Em8HK+U3u1n2kNNsKTdyg/blSUmg2k30ENP5
vl/oe0aKN9IWfTrnXtqxLQQVneeU6TfzBx8n6sl0M64VC7t03A3IUw1sL2hCLAy8
shBOb1cPF/Lgkh4q6sgqQc8nIPUHHTUClMU38PO7bmZiLx+rARHKgYURfPrSmKHj
UC15E8P4gAWRnuhVwCVs6cuD2Qfl+P1zLP7YfUnYrWgdZOm16NZfasfsmwWo4EEd
N4iclWpf3rSlNP5tkXsVqBwedhOJrnBrIQkCHHEwOn01qmGo3N8MZnl7bssPDtzK
86p2mPvkaKs1XazJILPeN/iTNU9jDeKPE2foz/wLfK7BZQqq+usfBqaa2TlVFjoe
CoTkR3Yp8bkfQH4O8ZBl+9sUSmZsyGuqLRG/QeucWexaAwburXiG8IPiL83e6QkG
5W0hQ6f5RCRgf5zqHmefBa0aLb4kAJTxAJsemKqzHHYD5JwkGx5iUhdDAbCGxiRu
30y3n3j++jnVRDtW3gOt2LtTcBBYl7GABgu8+Nxue+m8tKaK1FQXPSMyQmjlHSX/
7Te0BQwz0UfRMkOCnOFm00WKkVb3FmGWEUCTN+W5QvZ5kjAeRbSJX2Bu63/vxSrU
ZacSN+Uu7UWbGRpA88lXsRW8p6y5Fda0WxgFsLAotXSV7uhJBq0MljmSuG7QyYYR
ukaYlaZvIQCZsL+88VIL7I7sui01oYhb3AjrtVNGlhIS+T1vlRvJDJx+nubox6lQ
XzYzsviPWtvtzX93TxtBv5JINxOR2NL/wryxDU+O8NlnZHCoSQhCHDc3qPihCgvZ
ZslAHL6Fuqt5omkZMargs/fdCKS8R8EPseRuGUx7gajfrBSAvi7kwEqQjKDM491Z
TbP6MBxf3AN0LUmjcZCj2AJ+rjYOf5rNl+Nq/xg31WAQ6FjA56q9wZvKmZ11jsJj
+9G54fg0k6OhlEVgc73grVfOttkunrXCjy2DscmNrLLTIo8HhbiwjuC/C3ByHhaa
UJ3F7zLnrBJSlzhvsOFnabnxoMc0DAdqgB9s58WoL6cBHsKlYmkpYmGtVLA9Vcaw
sZ31Fdtkb42nPI6OdmDl0V3qN3/ULDCXvXIvwfqbTy2gnz1E+DOLAAt06h29Nm27
3u62LD6eukc1orGxC/coU/eI8D/Oh0B6oFMAnuOrqQNiUVP6A03hVpWicn5wszZA
dmr8Zsm8ItAk7IA1aYCCpfI813gNtMs5aBg7ckrbW25KybFsc3NpqumbxoyaUfsc
tlImLNAe4zfg1Q5bsvwp0KCg3PtW3ErwH+M19TbtEcc2kojz3kVg4Rg=
-----END ENCRYPTED PRIVATE KEY-----`)
	test2KeyPEMBlock, err = decryptPEM(test2KeyPEMBlock, password )
	if err != nil {
		return nil, err
	}

	test2, err := tls.X509KeyPair(test2CertPEMBlock, test2KeyPEMBlock)
	if err != nil {
		return nil, err
	}

	certStore.Add("test2", test2)
	return certStore, nil
}

func createCertStore(c *config.Config) (CertStore, error) {
	if c.Kafka.TLS.ClientCertFile != "" && c.Kafka.TLS.ClientKeyFile != "" {
		certPEMBlock, err := ioutil.ReadFile(c.Kafka.TLS.ClientCertFile)
		if err != nil {
			return nil, err
		}
		keyPEMBlock, err := ioutil.ReadFile(c.Kafka.TLS.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		keyPEMBlock, err = decryptPEM(keyPEMBlock, c.Kafka.TLS.ClientKeyPassword)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
		if err != nil {
			return nil, err
		}
		
		return &SingleCertStore{cert: cert}, nil
	} else {
		return nil, errors.Errorf( "Client cert and key files must not be empty")
	}
}

// Run causes the client to start waiting for new connections to connSrc and
// proxy them to the destination instance. It blocks until connSrc is closed.
func (c *Client) Run(connSrc <-chan Conn) error {
STOP:
	for {
		select {
		case conn := <-connSrc:
			go withRecover(func() { c.handleConn(conn) })
		case <-c.stopRun:
			break STOP
		}
	}

	logrus.Info("Closing connections")

	if err := c.conns.Close(); err != nil {
		logrus.Infof("closing client had error: %v", err)
	}

	logrus.Info("Proxy is stopped")
	return nil
}

func (c *Client) Close() {
	c.stopOnce.Do(func() {
		close(c.stopRun)
	})
}

func (c *Client) handleConn(conn Conn) {
	localConn := conn.LocalConnection
	if c.kafkaClientCert != nil {
		err := handshakeAsTLSAndValidateClientCert(localConn, c.kafkaClientCert, c.config.Kafka.DialTimeout)

		if err != nil {
			logrus.Info(err.Error())
			_ = localConn.Close()
			return
		}
	}

	var clientID *string

	tlsConn, ok := conn.LocalConnection.(*tls.Conn)
	if ok {
		err := tlsConn.HandshakeContext(context.TODO())
		if err != nil {
			logrus.Info(err)
			return
		}

		if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
			commonName := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
			clientID = &commonName
		}
	}
	clientConnContext := &ConnectionContext{
		clientID: clientID,
	}

	proxyConnectionsTotal.WithLabelValues(conn.BrokerAddress).Inc()

	dialAddress := conn.BrokerAddress
	if addressMapping, ok := c.dialAddressMapping[dialAddress]; ok {
		dialAddress = addressMapping.DestinationAddress
		logrus.Infof("Dial address changed from %s to %s", conn.BrokerAddress, dialAddress)
	}

	server, err := c.DialAndAuth(dialAddress, clientConnContext)
	if err != nil {
		logrus.Infof("couldn't connect to %s(%s): %v", dialAddress, conn.BrokerAddress, err)
		_ = conn.LocalConnection.Close()
		return
	}
	if tcpConn, ok := server.(*net.TCPConn); ok {
		if err := c.tcpConnOptions.setTCPConnOptions(tcpConn); err != nil {
			logrus.Infof("WARNING: Error while setting TCP options for kafka connection %s on %v: %v", conn.BrokerAddress, server.LocalAddr(), err)
		}
	}
	c.conns.Add(conn.BrokerAddress, conn.LocalConnection)
	localDesc := "local connection on " + conn.LocalConnection.LocalAddr().String() + " from " + conn.LocalConnection.RemoteAddr().String() + " (" + conn.BrokerAddress + ")"

	copyThenClose(c.processorConfig, server, conn.LocalConnection, conn.BrokerAddress, conn.BrokerAddress, localDesc)
	if err := c.conns.Remove(conn.BrokerAddress, conn.LocalConnection); err != nil {
		logrus.Info(err)
	}
}

func (c *Client) DialAndAuth(brokerAddress string, ctx *ConnectionContext) (net.Conn, error) {
	conn, err := c.dialer.DialWithContext("tcp", brokerAddress, ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	err = c.auth(conn, brokerAddress)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) auth(conn net.Conn, brokerAddress string) error {
	if c.config.Auth.Gateway.Client.Enable {
		if err := c.authClient.sendAndReceiveGatewayAuth(conn); err != nil {
			_ = conn.Close()
			return err
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return err
		}
	}
	if c.config.Kafka.SASL.Enable {
		err := c.saslAuthByProxy.sendAndReceiveSASLAuth(conn, brokerAddress)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return err
		}
	}
	return nil
}
