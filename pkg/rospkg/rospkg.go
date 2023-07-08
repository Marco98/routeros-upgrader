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
	resp, err := http.Get("http://upgrade.mikrotik.com/routeros/NEWEST7.stable")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
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
	log.Printf("downloading \"%s\"", fname)
	resp, err := http.Get(fmt.Sprintf(
		"http://upgrade.mikrotik.com/routeros/%s/%s",
		pkg.Version, fname,
	))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	log.Printf("downloaded \"%s\" (%d bytes)", fname, len(bb))
	return bb, nil
}
