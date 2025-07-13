package rosapi

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type RosPkg struct {
	Name           string
	VersionCurrent string
	VersionTarget  string
	BuildTime      string
	GitCommit      string
	Scheduled      string
}

const (
	commandGetPackages        = "/system package print terse"
	commandGetArchitecture    = ":put [/system resource get architecture-name]"
	commandGetFirmwareCurrent = ":put [/system routerboard get current-firmware]"
	commandGetFirmwareUpgrade = ":put [/system routerboard get upgrade-firmware]"
	commandDoFirmwareUpgrade  = "/system routerboard upgrade"
	commandExecReboot         = ":delay %ds;/system reboot"
)

func GetPackages(conn *ssh.Client) ([]RosPkg, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out, err := sess.Output(commandGetPackages)
	if err != nil {
		return nil, err
	}
	sout, err := parseTerse(string(out))
	if err != nil {
		return nil, err
	}
	pkgs := make([]RosPkg, 0)
	for _, v := range sout {
		if len(v["version"]) == 0 {
			continue
		}
		pkgs = append(pkgs, RosPkg{
			Name:           v["name"],
			VersionCurrent: v["version"],
			BuildTime:      v["build-time"],
			GitCommit:      v["git-commit"],
			Scheduled:      v["scheduled"],
		})
	}
	return pkgs, nil
}

func GetArchitecture(conn *ssh.Client) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(commandGetArchitecture)
	if err != nil {
		return "", err
	}
	sout := strings.ReplaceAll(string(out), "\r", "")
	soutt := strings.Split(sout, "\n")
	return soutt[0], nil
}

func GetFirmwareCurrent(conn *ssh.Client) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(commandGetFirmwareCurrent)
	if err != nil {
		if strings.Contains(string(out), "syntax error") {
			return "", nil
		}
		if strings.Contains(string(out), "bad command name") {
			return "", nil
		}
		return "", err
	}
	sout := strings.ReplaceAll(string(out), "\r", "")
	sout = strings.ReplaceAll(sout, "\n", "")
	return sout, nil
}

func GetFirmwareUpgrade(conn *ssh.Client) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(commandGetFirmwareUpgrade)
	if err != nil {
		if strings.Contains(string(out), "syntax error") {
			return "", nil
		}
		if strings.Contains(string(out), "bad command name") {
			return "", nil
		}
		return "", err
	}
	sout := strings.ReplaceAll(string(out), "\r", "")
	sout = strings.ReplaceAll(sout, "\n", "")
	return sout, nil
}

func DoFirmwareUpgrade(conn *ssh.Client) error {
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	return sess.Run(commandDoFirmwareUpgrade)
}

func ExecReboot(conn *ssh.Client, secs uint) error {
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	return sess.Start(fmt.Sprintf(commandExecReboot, secs))
}

func parseTerse(terse string) (map[int]map[string]string, error) {
	pkgs := make(map[int]map[string]string, 0)
	terse = strings.ReplaceAll(terse, "\r", "")
	for _, l := range strings.Split(terse, "\n") {
		l = strings.TrimSpace(l)
		v := strings.Split(l, " ")
		if len(v) <= 1 {
			continue
		}
		num, err := strconv.Atoi(v[0])
		if err != nil {
			return nil, err
		}
		pkgs[num] = make(map[string]string)
		var lastval string
		for i := 1; i < len(v); i++ {
			if !strings.Contains(v[i], "=") {
				pkgs[num][lastval] = fmt.Sprintf("%s %s", pkgs[num][lastval], v[i])
				continue
			}
			vv := strings.Split(v[i], "=")
			pkgs[num][vv[0]] = vv[1]
			lastval = vv[0]
		}
	}
	return pkgs, nil
}
