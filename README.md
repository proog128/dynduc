# dynduc

*dynduc* is a dynamic DNS (DDNS) update client. dynduc retrieves the public IPv4 and IPv6 addresses from a network device on the host or via the Internet Gateway Device Protocol (IGD) from an external device (Fritzbox). IP address changes are detected through polling at regular intervals and by subscribing to notifications from the Linux kernel's netlink interface. dynduc sends a configurable GET request containing the new IP address to one or more servers to update the DNS records.

## Usage

The configuration is stored in a YAML file. Edit `config.yml.sample` and rename it to config.yml.

Use `-c` to specify the config file on the command line. Alternatively, specify the filename via environment variable `DYNDUC_CONFIG_FILE`.

## Docker

When started through Docker, dynduc is typically connected to the host network. This is necessary to give dynduc access to the network devices and, thus, the IP addresses of the host.

```sh
docker run -d --name dynduc \
    --mount type=bind,src=$(pwd)/config.yml,dst=/config.yml,ro \
    --network host \
    -e DYNDUC_CONFIG_FILE=/config.yml \
    proog128/dynduc:latest
```

## License

MIT License
