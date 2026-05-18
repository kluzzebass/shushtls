package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"strings"

	"shushtls/internal/certengine"
)

func (h *Handler) leafCertInfoFromItem(item *certengine.CertListItem, basic bool) LeafCertInfo {
	info := leafInfoFromItem(item)
	info.IsService = item.PrimarySAN == h.engine.ServiceHost()
	if basic {
		return info
	}

	cert := certForListItem(h.engine, item)
	if cert == nil {
		return info
	}

	enrichLeafCertInfo(&info, cert)
	return info
}

func certForListItem(engine *certengine.Engine, item *certengine.CertListItem) *x509.Certificate {
	if item.Leaf != nil && item.Leaf.Cert != nil {
		return item.Leaf.Cert
	}
	if leaf := engine.GetCert(item.PrimarySAN); leaf != nil {
		return leaf.Cert
	}
	return nil
}

func enrichLeafCertInfo(info *LeafCertInfo, cert *x509.Certificate) {
	info.CommonName = cert.Subject.CommonName
	info.Serial = fmt.Sprintf("%X", cert.SerialNumber)
	info.SHA256Fingerprint = certFingerprint(cert)
	info.KeyAlgorithm = leafKeyAlgorithm(cert)
	info.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	info.KeyUsage = keyUsageStrings(cert.KeyUsage)
	info.ExtendedKeyUsage = extKeyUsageStrings(cert.ExtKeyUsage)
}

func certFingerprint(cert *x509.Certificate) string {
	return fingerprint(cert)
}

func leafKeyAlgorithm(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve == elliptic.P256() {
			return "ECDSA-P256"
		}
		return "ECDSA"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		out = append(out, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		out = append(out, "DecipherOnly")
	}
	return out
}

func extKeyUsageStrings(usages []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(usages))
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			out = append(out, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			out = append(out, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			out = append(out, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			out = append(out, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			out = append(out, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			out = append(out, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			out = append(out, "MicrosoftKernelCodeSigning")
		default:
			out = append(out, strings.TrimPrefix(u.String(), "ExtKeyUsage"))
		}
	}
	return out
}
