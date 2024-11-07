package rospkg

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

const (
	mikrotikUpgradeBaseURL = "http://upgrade.mikrotik.com/routeros"
)

var (
	packageCache   map[PkgID][]byte
	packageLock    *sync.Mutex
	getLatestCache map[string]string
	getLatestLock  *sync.RWMutex
	architectures  = []string{
		"arm64",
		"arm",
		"mipsbe",
		"mmips",
		"smips",
		"tile",
		"ppc",
		"x86_64",
		"x86",
	}
)

func init() {
	packageCache = make(map[PkgID][]byte)
	packageLock = &sync.Mutex{}
	getLatestCache = make(map[string]string)
	getLatestLock = &sync.RWMutex{}
}

type PkgID struct {
	Name         string
	Version      string
	Architecture string
}

func GetLatest(ver, branch string) (string, error) {
	str := fmt.Sprintf("NEWEST%s.%s", ver, branch)
	getLatestLock.RLock()
	c, ok := getLatestCache[str]
	getLatestLock.RUnlock()
	if ok {
		return c, nil
	}
	getLatestLock.Lock()
	defer getLatestLock.Unlock()
	resp, err := http.Get(fmt.Sprintf("%s/%s", mikrotikUpgradeBaseURL, str))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request returned: %s", resp.Status)
	}
	s, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ss := strings.Split(string(s), " ")
	getLatestCache[str] = ss[0]
	return ss[0], nil
}

func GetPackage(pkg PkgID) ([]byte, error) {
	packageLock.Lock()
	defer packageLock.Unlock()
	if bb, ok := packageCache[pkg]; ok {
		return bb, nil
	}
	pname := stripArchitectures(pkg.Name)
	fname := fmt.Sprintf("%s-%s-%s.npk", pname, pkg.Version, pkg.Architecture)
	if strings.HasPrefix(pkg.Version, "6.") {
		fname = fmt.Sprintf("%s-%s-%s.npk", pname, pkg.Architecture, pkg.Version)
	}
	fname = strings.ReplaceAll(fname, "-x86_64.npk", ".npk") // x86 does not have a suffix
	log.Printf("downloading \"%s\"", fname)
	url := fmt.Sprintf(
		"%s/%s/%s",
		mikrotikUpgradeBaseURL,
		pkg.Version, fname,
	)
	//nolint:gosec,G107
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching \"%s\": %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download of \"%s\" returned: %s", url, resp.Status)
	}
	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Printf("downloaded \"%s\" (%d bytes)", fname, len(bb))
	packageCache[pkg] = bb
	return bb, nil
}

func stripArchitectures(s string) string {
	for _, v := range architectures {
		s = strings.ReplaceAll(s, fmt.Sprintf("-%s", v), "")
	}
	return s
}
