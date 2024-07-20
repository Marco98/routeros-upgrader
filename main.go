package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Marco98/routeros-upgrader/pkg/rosapi"
	"github.com/Marco98/routeros-upgrader/pkg/rospkg"
	"github.com/pkg/sftp"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

const (
	defaultSSHTimeout = 3 * time.Second
	defaultSSHPort    = 22
	defaultSSHUser    = "admin"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type RosParams struct {
	Name            string
	Address         string
	User            string
	Password        string
	Pkgs            []rosapi.RosPkg
	Arch            string
	MajorVersion    int
	CurrentFirmware string
	UpgradeFirmware string
	Conn            *ssh.Client
	Powerdep        string
	Extpkgs         []string
}

func main() {
	if err := run(); err != nil {
		logrus.Fatalf("fatal error: %s", err)
	}
}

func run() error {
	// Config
	tver := flag.String("tgt", "latest", "target package version")
	branch := flag.String("b", "stable", "set branch (stable, testing, ..)")
	noupdfw := flag.Bool("nofw", false, "dont upgrade routerboard firmware")
	cpath := flag.String("c", "routers.yml", "config path")
	tags := flag.String("t", "", "filter tags")
	limit := flag.String("l", "", "limit routers")
	forceyes := flag.Bool("y", false, "force yes")
	delaysecs := flag.Uint("d", 10, "reboot delay in seconds")
	extpkgsS := flag.String("extpkgs", "", "install additional packages")
	verbose := flag.Bool("v", false, "verbose logs")
	prversion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if *prversion {
		return printVersion()
	}
	rts, err := parseConfig(
		*cpath,
		splitparamlist(*tags),
		splitparamlist(*limit),
		splitparamlist(*extpkgsS),
	)
	if err != nil {
		return err
	}

	// Connect
	err = connectRouters(rts)
	for _, rt := range rts {
		if rt.Conn != nil {
			defer rt.Conn.Close()
		}
	}
	if err != nil {
		return err
	}

	// Plan upgrades
	logrus.Println("checking installed packages")
	if err := getRouterPkgInfo(rts); err != nil {
		return fmt.Errorf("failed fetching package info: %w", err)
	}
	rts = injectExtpkgs(rts)
	pkgupdrts, fwupdrts := planUpgrades(rts, *tver, *branch, *noupdfw)
	if len(pkgupdrts) == 0 && len(fwupdrts) == 0 {
		logrus.Println("no action required - exiting")
		return nil
	}
	if !askYN("Install?", *forceyes) {
		return nil
	}

	// Upgrade
	if err := uploadPackages(pkgupdrts); err != nil {
		return err
	}
	if err := upgradeFirmware(fwupdrts); err != nil {
		return err
	}

	// Reboot
	if !askYN("Execute synchronized reboot?", *forceyes) {
		return nil
	}
	return rebootRouters(append(pkgupdrts, fwupdrts...), *delaysecs)
}

type Conf struct {
	Routers []ConfRouter `yaml:"routers"`
}

type ConfRouter struct {
	Name     string   `yaml:"name"`
	Tag      string   `yaml:"tag"`
	Address  string   `yaml:"address"`
	User     string   `yaml:"user"`
	Password string   `yaml:"password"`
	Powerdep string   `yaml:"powerdep"`
	Extpkgs  []string `yaml:"extpkgs"`
}

func parseConfig(path string, tags, limit, extpkgs []string) ([]RosParams, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	conf := new(Conf)
	if err := d.Decode(conf); err != nil {
		return nil, err
	}
	rr := make([]RosParams, 0)
	for _, r := range conf.Routers {
		if len(r.Name) == 0 {
			r.Name = r.Address
		}
		if filtersTag(tags, r.Tag) || filtersTag(limit, r.Name) {
			continue
		}
		if len(r.User) == 0 {
			r.User = "admin"
		}
		if len(extpkgs) != 0 {
			r.Extpkgs = extpkgs
		}
		if !strings.Contains(r.Address, ":") {
			r.Address = fmt.Sprintf("%s:%d", r.Address, defaultSSHPort)
		}
		rr = append(rr, RosParams{
			Name:     r.Name,
			Address:  r.Address,
			User:     r.User,
			Password: r.Password,
			Powerdep: r.Powerdep,
			Extpkgs:  r.Extpkgs,
		})
	}
	return rr, nil
}

func filtersTag(ss []string, s string) bool {
	if len(ss) == 0 || (len(ss) == 1 && ss[0] == "") {
		return false
	}
	for _, v := range ss {
		if v == s {
			return false
		}
	}
	return true
}

func connectRouters(rts []RosParams) error {
	wg := new(errgroup.Group)
	l := new(sync.Mutex)
	for fi, frt := range rts {
		i, rt := fi, frt
		wg.Go(func() error {
			conn, err := createConn(rt.Address, rt.User, rt.Password)
			if err != nil {
				if strings.Contains(err.Error(), "i/o timeout") {
					return nil
				}
				if strings.Contains(err.Error(), "no route to host") {
					return nil
				}
				return fmt.Errorf("failed to connect to %s: %w", rt.Name, err)
			}
			l.Lock()
			rts[i].Conn = conn
			l.Unlock()
			return nil
		})
	}
	return wg.Wait()
}

func planUpgrades(rts []RosParams, tver, branch string, noupdfw bool) (pkgupdrts, fwupdrts []RosParams) {
	pkgupdrts = make([]RosParams, 0)
	fwupdrts = make([]RosParams, 0)
	for _, rt := range rts {
		pkg := false
		log := logrus.WithField("router", rt.Name)
		if rt.Conn == nil {
			log.Error("unreachable")
			continue
		}
		lver, err := resolveTargetVersion(tver, branch, rt.MajorVersion)
		if err != nil {
			log.WithError(err).Error("unknown target version")
			continue
		}
		for i, p := range rt.Pkgs {
			if p.VersionCurrent != lver {
				rt.Pkgs[i].VersionTarget = lver
				pkg = true
				continue
			}
			log.WithFields(logrus.Fields{
				"package": p.Name,
				"version": p.VersionCurrent,
			}).Debug("package is up-to-date")
		}
		if pkg {
			pkgupdrts = append(pkgupdrts, rt)
		}
		if !noupdfw && !pkg && rt.CurrentFirmware != rt.UpgradeFirmware {
			fwupdrts = append(fwupdrts, rt)
		}
	}

	// powerdeps
	pkgupdrts, fwupdrts = filterPowerdeps(pkgupdrts, fwupdrts)

	// print results
	for _, r := range pkgupdrts {
		for _, p := range r.Pkgs {
			if p.VersionCurrent == tver {
				continue
			}
			logrus.WithFields(logrus.Fields{
				"router":  r.Name,
				"package": p.Name,
				"version": p.VersionCurrent,
				"target":  p.VersionTarget,
			}).Info("will upgrade package")
		}
	}
	for _, r := range fwupdrts {
		logrus.WithFields(logrus.Fields{
			"router":  r.Name,
			"version": r.CurrentFirmware,
			"target":  r.UpgradeFirmware,
		}).Info("will upgrade firmware")
	}
	return pkgupdrts, fwupdrts
}

func filterPowerdeps(pkgupdrts []RosParams, fwupdrts []RosParams) ([]RosParams, []RosParams) {
	depped := make([]string, 0)
	for _, r := range append(pkgupdrts, fwupdrts...) {
		if len(r.Powerdep) == 0 {
			continue
		}
		for _, rc := range append(pkgupdrts, fwupdrts...) {
			if rc.Name == r.Powerdep {
				depped = append(depped, r.Name)
				break
			}
		}
	}
	return filterPowerdepList(pkgupdrts, depped), filterPowerdepList(fwupdrts, depped)
}

func filterPowerdepList(rr []RosParams, pd []string) []RosParams {
	nrr := make([]RosParams, 0)
	for _, r := range rr {
		if contiansString(pd, r.Name) {
			logrus.WithField("router", r.Name).Warn("skip due to powerdep")
			continue
		}
		nrr = append(nrr, r)
	}
	return nrr
}

func contiansString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func rebootRouters(rts []RosParams, delay uint) error {
	wg := new(errgroup.Group)
	for _, frt := range rts {
		rt := frt
		wg.Go(func() error {
			defer rt.Conn.Close()
			if err := rosapi.ExecReboot(rt.Conn, delay); err != nil {
				return err
			}
			logrus.WithFields(logrus.Fields{
				"router": rt.Name,
				"delay":  delay,
			}).Info("initiated reboot")
			return nil
		})
	}
	return wg.Wait()
}

func uploadPackages(rts []RosParams) error {
	wg := new(errgroup.Group)
	for _, frt := range rts {
		rt := frt
		wg.Go(func() error {
			client, err := sftp.NewClient(rt.Conn)
			if err != nil {
				return err
			}
			defer client.Close()
			for _, p := range rt.Pkgs {
				pkg, err := rospkg.GetPackage(rospkg.PkgID{
					Name:         p.Name,
					Version:      p.VersionTarget,
					Architecture: rt.Arch,
				})
				if err != nil {
					return err
				}
				fname := fmt.Sprintf("%s-%s-%s.npk", p.Name, p.VersionTarget, rt.Arch)
				f, err := client.Create(fname)
				if err != nil {
					return err
				}
				buf := bytes.NewBuffer(pkg)
				_, err = buf.WriteTo(f)
				if err != nil {
					return err
				}
				logrus.WithFields(logrus.Fields{
					"router": rt.Name,
					"file":   fname,
				}).Info("file uploaded")
			}
			return nil
		})
	}
	return wg.Wait()
}

func upgradeFirmware(rts []RosParams) error {
	wg := new(errgroup.Group)
	for _, frt := range rts {
		rt := frt
		wg.Go(func() error {
			if err := rosapi.DoFirmwareUpgrade(rt.Conn); err != nil {
				return err
			}
			logrus.WithField("router", rt.Name).Info("upgraded firmware")
			return nil
		})
	}
	return wg.Wait()
}

func askYN(question string, forceyes bool) bool {
	if forceyes {
		return true
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", question)
	response, err := reader.ReadString('\n')
	if err != nil {
		logrus.Fatal(err)
	}
	return strings.ToLower(strings.TrimSpace(response)) == "y"
}

func createConn(addr, user, pass string) (*ssh.Client, error) {
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         defaultSSHTimeout,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("connect failed: %w", err)
	}
	return conn, nil
}

func getRouterPkgInfo(rts []RosParams) error {
	wg := new(errgroup.Group)
	for fi, frt := range rts {
		i, rt := fi, frt
		wg.Go(func() error {
			if len(rt.Address) == 0 {
				rt.Address = rt.Name
			}
			if rt.Conn == nil {
				return nil
			}
			pp, err := rosapi.GetPackages(rt.Conn)
			if err != nil {
				return fmt.Errorf("failed GetPackages: %w", err)
			}
			rt.Pkgs = pp
			arch, err := rosapi.GetArchitecture(rt.Conn)
			if err != nil {
				return fmt.Errorf("failed GetArchitecture: %w", err)
			}
			rt.Arch = arch
			fwcurrent, err := rosapi.GetFirmwareCurrent(rt.Conn)
			if err != nil {
				return fmt.Errorf("failed GetFirmwareCurrent: %w", err)
			}
			rt.CurrentFirmware = fwcurrent
			fwnew, err := rosapi.GetFirmwareUpgrade(rt.Conn)
			if err != nil {
				return fmt.Errorf("failed GetFirmwareUpgrade: %w", err)
			}
			rt.UpgradeFirmware = fwnew
			major, err := strconv.Atoi(strings.Split(rt.Pkgs[0].VersionCurrent, ".")[0])
			if err != nil {
				return fmt.Errorf("major version unknown: %w", err)
			}
			rt.MajorVersion = major
			rts[i] = rt
			return nil
		})
	}
	return wg.Wait()
}

func injectExtpkgs(rts []RosParams) []RosParams {
	for ir, r := range rts {
		for _, ep := range r.Extpkgs {
			matched := false
			for _, p := range r.Pkgs {
				if p.Name == ep {
					matched = true
					break
				}
			}
			if !matched {
				r.Pkgs = append(r.Pkgs, rosapi.RosPkg{
					Name:           ep,
					VersionCurrent: "0.0.0",
				})
			}
		}
		rts[ir] = r
	}
	return rts
}

func splitparamlist(s string) []string {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return make([]string, 0)
	}
	return strings.Split(s, ",")
}

func printVersion() error {
	_, err := fmt.Printf("Version: %s\nCommit Hash: %s\nBuild Date: %s\n", version, commit, date)
	return err
}

func resolveTargetVersion(tver, branch string, majorVersion int) (string, error) {
	if tver != "latest" {
		return tver, nil
	}
	mv := strconv.Itoa(majorVersion)
	if majorVersion == 7 {
		mv = fmt.Sprintf("a%s", mv)
	}
	return rospkg.GetLatest(mv, branch)
}
