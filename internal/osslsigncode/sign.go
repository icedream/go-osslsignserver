package osslsigncode

import (
	"fmt"
	"time"

	"github.com/icedream/go-osslsignserver/internal/password"
)

type Certificate interface {
	generateSignSourceParameters() osslsigncodeParams
	CertificateType() string
}

func (s FileCertificate) CertificateType() string {
	return "file"
}

func (s PKCS12Certificate) CertificateType() string {
	return "pkcs12"
}

func (s PKCS11Certificate) CertificateType() string {
	return "pkcs11"
}

type FileCertificate struct {
	Certs string
	Key   string
}

func (s FileCertificate) generateSignSourceParameters() (p osslsigncodeParams) {
	p.Add("certs", s.Certs)
	p.Add("key", s.Key)
	return p
}

type PKCS12Certificate struct {
	PKCS12 string
}

func (s PKCS12Certificate) generateSignSourceParameters() (p osslsigncodeParams) {
	p.Add("pkcs12", s.PKCS12)
	return p
}

type PKCS11Certificate struct {
	Certs        string
	Key          string
	PKCS11Engine string
	PKCS11Module string
}

func (s PKCS11Certificate) generateSignSourceParameters() (p osslsigncodeParams) {
	p.Add("certs", s.Certs)
	p.Add("key", s.Key)
	p.Add("pkcs11module", s.PKCS11Module)
	p.AddOptional("pkcs11engine", s.PKCS11Engine)
	return p
}

type Timestamper interface {
	generateTimestamperParameters() osslsigncodeParams
}

type AuthorityTimestamper struct {
	URLs         []string
	Proxy        string
	NoVerifyPeer bool
}

func (s AuthorityTimestamper) generateTimestamperParameters() (p osslsigncodeParams) {
	p.AddMultiple("t", s.URLs...)
	p.AddOptional("proxy", s.Proxy)
	p.AddSwitch("noverifypeer", s.NoVerifyPeer)
	return p
}

type RFC3161AuthorityServerTimestamper struct {
	URLs         []string
	Proxy        string
	NoVerifyPeer bool
}

func (s RFC3161AuthorityServerTimestamper) generateTimestamperParameters() (p osslsigncodeParams) {
	p.AddMultiple("ts", s.URLs...)
	p.AddOptional("proxy", s.Proxy)
	p.AddSwitch("noverifypeer", s.NoVerifyPeer)
	return p
}

type HashAlgorithm string

func (ha HashAlgorithm) String() string {
	return string(ha)
}

const (
	HashDefault HashAlgorithm = ""
	HashMD5     HashAlgorithm = "md5"
	HashSHA1    HashAlgorithm = "sha1"
	HashSHA2    HashAlgorithm = "sha2"
	HashSHA256  HashAlgorithm = "sha256"
	HashSHA384  HashAlgorithm = "sha384"
	HashSHA512  HashAlgorithm = "sha512"
)

type Level string

func (l Level) String() string {
	return string(l)
}

const (
	LevelNone Level = ""
	LevelLow  Level = "low"
)

type SignOptions struct {
	Certificate            Certificate
	PasswordProvider       password.Provider
	Password               string
	AskPass                bool
	ReadPass               string
	CrossCertFile          string
	HashAlgorithm          HashAlgorithm
	Description            string
	DescriptionURL         string
	Level                  Level
	Commercial             bool
	GeneratePageHashes     bool
	Timestamper            Timestamper
	SigningTime            time.Time
	AddUnauthenticatedBlob bool
	Nest                   bool
	Verbose                bool
	AddMSIDSE              bool
	InputFile              string
	OutputFile             string
}

func (o SignOptions) Args() (p osslsigncodeParams) {
	if o.Certificate != nil {
		p.Append(o.Certificate.generateSignSourceParameters())
	}
	p.AddOptional("pass", o.Password)
	p.AddSwitch("askpass", o.AskPass)
	p.AddOptional("readpass", o.ReadPass)
	p.AddOptional("ac", o.CrossCertFile)
	p.AddOptional("hash", o.HashAlgorithm.String())
	p.AddOptional("n", o.Description)
	p.AddOptional("i", o.DescriptionURL)
	p.AddOptional("jp", o.Level.String())
	p.AddSwitch("comm", o.Commercial)
	p.AddSwitch("ph", o.GeneratePageHashes)
	if o.Timestamper != nil {
		p.Append(o.Timestamper.generateTimestamperParameters())
	}
	if !o.SigningTime.IsZero() {
		p.Add("st", fmt.Sprintf("%d", o.SigningTime.Unix()))
	}
	p.AddSwitch("addUnauthenticatedBlob", o.AddUnauthenticatedBlob)
	p.AddSwitch("nest", o.Nest)
	p.AddSwitch("verbose", o.Verbose)
	p.AddSwitch("add-msi-dse", o.AddMSIDSE)
	p.Add("in", o.InputFile)
	p.Add("out", o.OutputFile)
	return p
}
