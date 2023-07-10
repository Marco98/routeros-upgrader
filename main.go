package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Marco98/routeros-upgrader/pkg/rosapi"
	"github.com/Marco98/routeros-upgrader/pkg/rospkg"
	"github.com/fatih/color"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	defaultSSHTimeout = 3 * time.Second
	defaultSSHPort    = 22
	defaultSSHUser    = "admin"
)

type RosParams struct {
	Name            string
	Address         string
	User            string
	Password        string
	Pkgs            []rosapi.RosPkg
	Arch            string
	CurrentFirmware string
	UpgradeFirmware string
}

func main() {
	// Config
	tver := flag.String("tgt", "latest", "target package version")
	noupdfw := flag.Bool("nofw", false, "dont upgrade routerboard firmware")
	cpath := flag.String("c", "routers.yml", "config path")
	tag := flag.String("t", "", "filter tag")
	forceyes := flag.Bool("y", false, "force yes")
	flag.Parse()
	rts, err := parseConfig(*cpath, *tag)
	if err != nil {
		log.Fatalf("%s", err)
	}

	// Get latest version
	if *tver == "latest" {
		lver, err := rospkg.GetLatest()
		if err != nil {
			log.Fatalf("%s", err)
		}
		tver = &lver
	}
	log.Printf("the target version is: %s", *tver)

	// Plan upgrades
	log.Println("checking installed packages")
	for i, rt := range rts {
		r, err := getRouterPkgInfo(rt)
		if err != nil {
			log.Fatalf("%s", err)
		}
		rts[i] = r
	}
	pkgupdrts, fwupdrts := planUpgrades(rts, tver, *noupdfw)
	if len(pkgupdrts) == 0 && len(fwupdrts) == 0 {
		log.Println("no action required - exiting")
		return
	}
	if !askYN("Install?", *forceyes) {
		return
	}

	// Upgrade
	if err := uploadPackages(pkgupdrts, *tver); err != nil {
		log.Fatalf("%s", err)
	}
	if err := upgradeFirmware(fwupdrts); err != nil {
		log.Fatalf("%s", err)
	}

	// Reboot
	if !askYN("Execute synchronized reboot?", *forceyes) {
		return
	}
	if err := rebootRouters(append(pkgupdrts, fwupdrts...)); err != nil {
		log.Fatalf("%s", err)
	}
}

type Conf struct {
	Routers []ConfRouter `yaml:"routers"`
}

type ConfRouter struct {
	Name     string `yaml:"name"`
	Tag      string `yaml:"tag"`
	Address  string `yaml:"address"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

func parseConfig(path, tag string) ([]RosParams, error) {
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
		if len(tag) != 0 && tag != r.Tag {
			continue
		}
		if len(r.Name) == 0 {
			r.Name = r.Address
		}
		if len(r.User) == 0 {
			r.User = "admin"
		}
		if !strings.Contains(r.Address, ":") {
			r.Address = fmt.Sprintf("%s:%d", r.Address, defaultSSHPort)
		}
		rr = append(rr, RosParams{
			Name:     r.Name,
			Address:  r.Address,
			User:     r.User,
			Password: r.Password,
		})
	}
	return rr, nil
}

func planUpgrades(rts []RosParams, tver *string, noupdfw bool) (pkgupdrts, fwupdrts []RosParams) {
	pkgupdrts = make([]RosParams, 0)
	fwupdrts = make([]RosParams, 0)
	for _, rt := range rts {
		pkg := false
		for _, p := range rt.Pkgs {
			if p.Version != *tver {
				color.Yellow(
					"|UP> %s: %s-%s-%s => %s-%s-%s\n",
					rt.Name,
					p.Name, p.Version, rt.Arch,
					p.Name, *tver, rt.Arch,
				)
				pkg = true
				continue
			}
			color.Green(
				"|OK> %s: %s-%s-%s\n",
				rt.Name,
				p.Name, p.Version, rt.Arch,
			)
		}
		if pkg {
			pkgupdrts = append(pkgupdrts, rt)
		}
		if !noupdfw && !pkg && rt.CurrentFirmware != rt.UpgradeFirmware {
			fwupdrts = append(fwupdrts, rt)
			color.Yellow(
				"|UP> %s: fw %s => fw %s\n",
				rt.Name, rt.CurrentFirmware, rt.UpgradeFirmware,
			)
		}
	}
	return pkgupdrts, fwupdrts
}

func rebootRouters(rts []RosParams) error {
	for _, rt := range rts {
		conn, err := createConn(rt.Address, rt.User, rt.Password)
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := rosapi.ExecReboot(conn, 10); err != nil {
			return err
		}
		log.Printf("%s: rebooting in 10s", rt.Name)
	}
	return nil
}

func uploadPackages(rts []RosParams, lver string) error {
	cache := rospkg.NewCache()
	for _, rt := range rts {
		conn, err := createConn(rt.Address, rt.User, rt.Password)
		defer func() {
			if conn.Close(); err != nil {
				log.Printf("%s", err)
			}
		}()
		if err != nil {
			return err
		}
		client, err := sftp.NewClient(conn)
		if err != nil {
			return err
		}
		defer client.Close()
		for _, p := range rt.Pkgs {
			pkg, err := cache.GetPackage(rospkg.PkgID{
				Name:         p.Name,
				Version:      lver,
				Architecture: rt.Arch,
			})
			if err != nil {
				return err
			}
			fname := fmt.Sprintf("%s-%s-%s.npk", p.Name, lver, rt.Arch)
			f, err := client.Create(fname)
			if err != nil {
				return err
			}
			buf := bytes.NewBuffer(pkg)
			_, err = buf.WriteTo(f)
			if err != nil {
				return err
			}
			log.Printf("%s: uploaded %s", rt.Name, fname)
		}
	}
	return nil
}

func upgradeFirmware(rts []RosParams) error {
	for _, rt := range rts {
		conn, err := createConn(rt.Address, rt.User, rt.Password)
		defer func() {
			if conn.Close(); err != nil {
				log.Printf("%s", err)
			}
		}()
		if err != nil {
			return err
		}
		if err := rosapi.DoFirmwareUpgrade(conn); err != nil {
			return err
		}
		log.Printf("%s: upgraded firmware", rt.Name)
	}
	return nil
}

func askYN(question string, forceyes bool) bool {
	if forceyes {
		return true
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", question)
	response, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
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

func getRouterPkgInfo(rt RosParams) (RosParams, error) {
	if len(rt.Address) == 0 {
		rt.Address = rt.Name
	}
	conn, err := createConn(rt.Address, rt.User, rt.Password)
	if err != nil {
		return rt, err
	}
	defer conn.Close()
	pp, err := rosapi.GetPackages(conn)
	if err != nil {
		return rt, err
	}
	rt.Pkgs = pp
	arch, err := rosapi.GetArchitecture(conn)
	if err != nil {
		return rt, err
	}
	rt.Arch = arch
	fwcurrent, err := rosapi.GetFirmwareCurrent(conn)
	if err != nil {
		return rt, err
	}
	rt.CurrentFirmware = fwcurrent
	fwnew, err := rosapi.GetFirmwareUpgrade(conn)
	if err != nil {
		return rt, err
	}
	rt.UpgradeFirmware = fwnew
	return rt, nil
}
