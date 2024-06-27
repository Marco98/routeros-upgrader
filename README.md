# routeros-upgrader

Mass-Upgrade Mikrotik RouterOS devices synchronized

## Demo

https://github.com/Marco98/routeros-upgrader/assets/24938492/33cb2a66-91d8-4fe6-b195-984e1124cba8

## Usage

### Download

Download the latest release [[>>HERE<<]](https://github.com/Marco98/routeros-upgrader/releases/latest)

### routers.yml

Create a configuration file that contains your assets and credentials

```yaml
routers:
  - address: 192.168.1.2 # address to ssh into (required)
    name: router1 # name to be shown in the app (optional, default: address)
    user: dieter # username to use (optional, default: admin)
    password: admin # password to use (required)
    tag: failover # tag to filter with the -t parameter (optional)
  - address: rtr.example.com
    user: dieter
    password: passw0rd
    tag: failover
  - address: 192.168.5.6:2222
    name: router3
    user: admin
    password: insecure
    powerdep: router1
```

### Parameters

Run the tool!

```shell
Usage of routeros-upgrader:
  -c string
        config path (default "routers.yml")
  -d uint
        reboot delay in seconds (default 10)
  -extpkgs string
        install additional packages
  -l string
        limit routers
  -nofw
        dont upgrade routerboard firmware
  -t string
        filter tags
  -tgt string
        target package version (default "latest")
  -v    print version
  -y    force yes
```

## Special Cases

### PoE-Power Dependencies (powerdep)

Most Mikrotik devices with a PoE-out-port will switch off power when updating/rebooting (except for some CRS-Models).
If you power another mikrotik device (for example a access point) with that and both devices will be updated and rebooted at the same time, the update of the device getting updated will fail or even get bricked.
To prevent such risky conditions, you can specify a power dependency, so both devices wont get updated at the same time.
See the following example:

```yaml
routers:
  - address: 10.0.0.1
    name: poesw01
    password: imProvidingPower
  - address: 10.0.0.2
    name: ap02
    password: imReceiveingPower
    powerdep: poesw01 # this will prevent that both devices will be updated at the same time
```

### Extra Packages (extpkgs)

If you want to install a new package at the same time as you update you can specify it with `-extpkgs` or yaml.
For example the prominent RouterOS 7.13 Release forces you by default to the unstable new CAPsMAN where some basic features like Datapath-VLAN Support for AC-Devices are still missing.
To install the stable wireless package alongside RouterOS 7.13 just specify `wireless` or if you need to install the ax-driver package for wave2 just `wifi-qcom` or even if you have old ac-devices and are feeling lucky you can use `wifi-qcom-ac` to install wave2.
You can also specify multiple packages by listing them comma-seperated.

#### via yaml

```yaml
routers:
  - address: 10.0.0.1
    name: capsman
    password: manOfTheCaps
    extpkgs: ["wireless"]
  - address: 10.0.0.2
    name: wapac01
    password: oldAndReliable
    extpkgs: ["wifi-qcom-ac"]
  - address: 10.0.0.3
    name: hapax01
    password: newAndShiny
    extpkgs: ["wifi-qcom"]
  - address: 10.0.0.4
    name: iot01
    password: internetOfBeautifulThings
    extpkgs:
      - gps
      - iot
```

#### via cli-parameter (will overwrite yaml)

```shell
.\routeros-upgrader -t capsmans -extpkgs wireless # installs stable wireless package
.\routeros-upgrader -t aps_ac -extpkgs wifi-qcom-ac # installs wave2 on ac
.\routeros-upgrader -t aps_ax -extpkgs wifi-qcom # installs wave2 on ax
.\routeros-upgrader -t iotgw -extpkgs gps,iot # installs gps and iot
```
