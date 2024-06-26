package rospkg

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

type Cache struct {
	cache map[PkgID][]byte
	lock  *sync.Mutex
}

func NewCache() *Cache {
	return &Cache{
		cache: make(map[PkgID][]byte),
		lock:  &sync.Mutex{},
	}
}

type PkgID struct {
	Name         string
	Version      string
	Architecture string
}

func GetLatest() (string, error) {
	resp, err := http.Get("http://upgrade.mikrotik.com/routeros/NEWESTa7.stable")
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
	return ss[0], nil
}

func (c *Cache) GetPackage(pkg PkgID) ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if bb, ok := c.cache[pkg]; ok {
		return bb, nil
	}
	fname := fmt.Sprintf("%s-%s-%s.npk", pkg.Name, pkg.Version, pkg.Architecture)
	fname = strings.ReplaceAll(fname, "-x86_64.npk", ".npk") // x86 does not have a suffix
	log.Printf("downloading \"%s\"", fname)
	url := fmt.Sprintf(
		"http://upgrade.mikrotik.com/routeros/%s/%s",
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
	c.cache[pkg] = bb
	return bb, nil
}
