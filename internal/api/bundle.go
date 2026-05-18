package api

import (
	"archive/tar"
	"archive/zip"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"shushtls/internal/certengine"
)

type bundleFile struct {
	name string
	data []byte
}

func rootCAPEM(ca *certengine.CACert) []byte {
	if ca == nil {
		return nil
	}
	return pemEncodeCert(ca.Raw)
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func buildBundleFiles(san string, certPEM, keyPEM, caPEM []byte, names string) []bundleFile {
	chainPEM := append(append([]byte(nil), certPEM...), caPEM...)

	if names == "generic" {
		return []bundleFile{
			{"cert.pem", certPEM},
			{"key.pem", keyPEM},
			{"ca.pem", caPEM},
			{"chain.pem", chainPEM},
		}
	}

	base := certengine.SanitizeSAN(san)
	return []bundleFile{
		{base + ".cert.pem", certPEM},
		{base + ".key.pem", keyPEM},
		{"ca.pem", caPEM},
		{"chain.pem", chainPEM},
	}
}

func writeTarBundle(w io.Writer, files []bundleFile) error {
	tw := tar.NewWriter(w)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(len(f.data))}); err != nil {
			return err
		}
		if _, err := tw.Write(f.data); err != nil {
			return err
		}
	}
	return tw.Close()
}

func writeZipBundle(w io.Writer, files []bundleFile) error {
	zw := zip.NewWriter(w)
	for _, f := range files {
		fw, err := zw.Create(f.name)
		if err != nil {
			return err
		}
		if _, err := fw.Write(f.data); err != nil {
			return err
		}
	}
	return zw.Close()
}

func k8sSecretName(san string) string {
	name := certengine.SanitizeSAN(san)
	name = strings.ReplaceAll(name, ".", "-")
	name = strings.ToLower(name)
	if len(name) > 253 {
		name = name[:253]
	}
	return name
}

func renderK8sTLSSecret(san string, certPEM, keyPEM, caPEM []byte) []byte {
	name := k8sSecretName(san)
	b64 := base64.StdEncoding.EncodeToString
	body := fmt.Sprintf(`apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: %s
data:
  tls.crt: %s
  tls.key: %s
  ca.crt: %s
`, name, b64(certPEM), b64(keyPEM), b64(caPEM))
	return []byte(body)
}

func validateBundleParams(format, names, bundleType string) error {
	if format != "" && format != "k8s-tls" {
		return fmt.Errorf("unknown format %q", format)
	}
	if names != "" && names != "san" && names != "generic" {
		return fmt.Errorf("unknown names %q", names)
	}
	if bundleType != "" && bundleType != "tar" && bundleType != "zip" {
		return fmt.Errorf("unknown type %q", bundleType)
	}
	return nil
}
