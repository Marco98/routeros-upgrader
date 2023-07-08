# routeros-upgrader

Mass-Upgrade Mikrotik RouterOS devices synchronized

## Usage

### routers.yml

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
  - address: 192.168.5.6:2222
    name: router3
    user: admin
    password: insecure
```

### Parameters

```shell
Usage of routeros-upgrader:
  -c string
        config path (default "routers.yml")
  -nofw
        dont upgrade routerboard firmware
  -t string
        filter tag
  -tgt string
        target package version (default "latest")
```
