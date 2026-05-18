package api

import "testing"

func TestBuildBundleFiles_Generic(t *testing.T) {
	files := buildBundleFiles("host.example.com", []byte("cert"), []byte("key"), []byte("ca"), "generic")
	if len(files) != 4 {
		t.Fatalf("len = %d, want 4", len(files))
	}
	if files[0].name != "cert.pem" || files[1].name != "key.pem" {
		t.Errorf("names = %q, %q", files[0].name, files[1].name)
	}
}

func TestBuildBundleFiles_SAN(t *testing.T) {
	files := buildBundleFiles("*.example.com", []byte("cert"), []byte("key"), []byte("ca"), "san")
	if files[0].name != "_wildcard_.example.com.cert.pem" {
		t.Errorf("cert name = %q", files[0].name)
	}
	if files[2].name != "ca.pem" {
		t.Errorf("ca name = %q", files[2].name)
	}
}

func TestK8sSecretName(t *testing.T) {
	if got := k8sSecretName("*.example.com"); got != "_wildcard_-example-com" {
		t.Errorf("name = %q", got)
	}
}
