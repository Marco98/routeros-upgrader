package rosapi

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type RosPkg struct {
	Name      string
	Version   string
	BuildTime string
	GitCommit string
	Scheduled string
}

func GetPackages(conn *ssh.Client) ([]RosPkg, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	out, err := sess.Output("/system/package/print terse")
	if err != nil {
		return nil, err
	}
	sout, err := parseTerse(string(out))
	if err != nil {
		return nil, err
	}
	pkgs := make([]RosPkg, len(sout))
	for i := 0; i < len(sout); i++ {
		pkgs[i] = RosPkg{
			Name:      sout[i]["name"],
			Version:   sout[i]["version"],
			BuildTime: sout[i]["build-time"],
			GitCommit: sout[i]["git-commit"],
			Scheduled: sout[i]["scheduled"],
		}
	}
	return pkgs, nil
}

func GetArchitecture(conn *ssh.Client) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(":put [/system/resource/get architecture-name]")
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
	out, err := sess.Output(":put [/system/routerboard/get current-firmware]")
	if err != nil {
		if strings.Contains(string(out), "syntax error") {
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
	out, err := sess.Output(":put [/system/routerboard/get upgrade-firmware]")
	if err != nil {
		if strings.Contains(string(out), "syntax error") {
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
	return sess.Run("/system/routerboard/upgrade")
}

func ExecReboot(conn *ssh.Client, secs uint16) error {
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	return sess.Start(fmt.Sprintf(":delay %ds;/system/reboot", secs))
}

func parseTerse(terse string) (map[int]map[string]string, error) {
	pkgs := make(map[int]map[string]string, 0)
	terse = strings.ReplaceAll(terse, "\r", "")
	for _, l := range strings.Split(terse, "\n") {
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
