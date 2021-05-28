package transport

import (
	origin "crypto/tls"
	origX509 "crypto/x509"
	"github.com/cetcxinlian/cryptogm/tls"
	"github.com/cetcxinlian/cryptogm/x509"
)

func cloneConnectionState(origin *origin.ConnectionState) *tls.ConnectionState {
	ret := &tls.ConnectionState{}
	ret.Version = origin.Version
	ret.HandshakeComplete = origin.HandshakeComplete
	ret.DidResume = origin.DidResume
	ret.CipherSuite = origin.CipherSuite
	ret.NegotiatedProtocol = origin.NegotiatedProtocol
	ret.NegotiatedProtocolIsMutual = origin.NegotiatedProtocolIsMutual
	ret.ServerName = origin.ServerName
	for _, cert := range origin.PeerCertificates {
		ret.PeerCertificates = append(ret.PeerCertificates, cloneCertificate(cert))
	}
	ret.VerifiedChains = make([][]*x509.Certificate, len(origin.VerifiedChains))
	for i, certs := range origin.VerifiedChains {
		for _, cert := range certs {
			ret.VerifiedChains[i] = append(ret.VerifiedChains[i], cloneCertificate(cert))
		}
	}
	ret.SignedCertificateTimestamps = origin.SignedCertificateTimestamps
	ret.OCSPResponse = origin.OCSPResponse
	ret.TLSUnique = origin.TLSUnique
	return ret
}

func cloneCertificate(orig *origX509.Certificate) *x509.Certificate {
	ret := &x509.Certificate{}
	ret.Raw = orig.Raw
	ret.RawTBSCertificate = orig.RawTBSCertificate
	ret.RawSubjectPublicKeyInfo = orig.RawSubjectPublicKeyInfo
	ret.RawSubject = orig.RawSubject
	ret.RawIssuer = orig.RawIssuer
	ret.Signature = orig.Signature
	ret.SignatureAlgorithm = x509.SignatureAlgorithm(orig.SignatureAlgorithm)
	ret.PublicKeyAlgorithm = x509.PublicKeyAlgorithm(orig.PublicKeyAlgorithm)
	ret.PublicKey = orig.PublicKey
	ret.Version = orig.Version
	ret.SerialNumber = orig.SerialNumber
	ret.Issuer = orig.Issuer
	ret.Subject = orig.Subject
	ret.NotBefore = orig.NotBefore
	ret.NotAfter = orig.NotAfter
	ret.KeyUsage = x509.KeyUsage(orig.KeyUsage)
	ret.Extensions = orig.Extensions
	ret.ExtraExtensions = orig.ExtraExtensions
	ret.UnhandledCriticalExtensions = orig.UnhandledCriticalExtensions
	for _, ku := range orig.ExtKeyUsage {
		ret.ExtKeyUsage = append(ret.ExtKeyUsage, x509.ExtKeyUsage(ku))
	}
	ret.UnknownExtKeyUsage = orig.UnknownExtKeyUsage
	ret.BasicConstraintsValid = orig.BasicConstraintsValid
	ret.IsCA = orig.IsCA
	ret.MaxPathLen = orig.MaxPathLen
	ret.MaxPathLenZero = orig.MaxPathLenZero
	ret.SubjectKeyId = orig.SubjectKeyId
	ret.AuthorityKeyId = orig.AuthorityKeyId
	ret.OCSPServer = orig.OCSPServer
	ret.IssuingCertificateURL = orig.IssuingCertificateURL
	ret.DNSNames = orig.DNSNames
	ret.EmailAddresses = orig.EmailAddresses
	ret.IPAddresses = orig.IPAddresses
	// ret.URIs                                                                            =  orig.URIs
	ret.PermittedDNSDomainsCritical = orig.PermittedDNSDomainsCritical
	ret.PermittedDNSDomains = orig.PermittedDNSDomains
	ret.ExcludedDNSDomains = orig.ExcludedDNSDomains
	// ret.PermittedIPRanges                                                               =  orig.PermittedIPRanges
	// ret.ExcludedIPRanges                                                                =  orig.ExcludedIPRanges
	// ret.PermittedEmailAddresses                                                         =  orig.PermittedEmailAddresses
	// ret.ExcludedEmailAddresses                                                          =  orig.ExcludedEmailAddresses
	// ret.PermittedURIDomains                                                             =  orig.PermittedURIDomains
	// ret.ExcludedURIDomains                                                              =  orig.ExcludedURIDomains
	ret.CRLDistributionPoints = orig.CRLDistributionPoints
	ret.PolicyIdentifiers = orig.PolicyIdentifiers
	return ret
}
