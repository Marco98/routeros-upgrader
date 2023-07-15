# routeros-upgrader

Mass-Upgrade Mikrotik RouterOS devices synchronized

## Demo

https://github.com/Marco98/routeros-upgrader/assets/24938492/33cb2a66-91d8-4fe6-b195-984e1124cba8

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
    tag: failover
  - address: 192.168.5.6:2222
    name: router3
    user: admin
    password: insecure
    powerdep: router1
```

### Parameters

```shell
Usage of routeros-upgrader:
  -c string
        config path (default "routers.yml")
  -d uint
        reboot delay in seconds (default 10)
  -l string
        limit routers
  -nofw
        dont upgrade routerboard firmware
  -t string
        filter tags
  -tgt string
        target package version (default "latest")
  -y    force yes
```
