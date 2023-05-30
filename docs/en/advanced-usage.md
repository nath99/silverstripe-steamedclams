# Advanced usage

## Running clamd on separate server

You can connect to a separate server by configuring and using `clamdscan`.

### Install ClamAV

Run the following on the ClamAV server.

1) Install ClamAV in Unix/Linux.
```
sudo apt install clamav clamav-daemon
```
run ``` sudo apt-get install apt-get update``` when necessary.

2) Start clamav-daemon
```
sudo service clamav-freshclam restart
# wait ~2 minutes
sudo service clamav-daemon start
```
And check the clamav-daemon is running.
```
 sudo service clamav-daemon status
```

### Install clamdscan

1) Install `clamdscan` on the webserver.
```
sudo apt install -y clamdscan
```

2) Remove extra dependencies
```
sudo apt remove -y clamav-daemon clamav-freshclam
```

3) Configure clamd.conf by commenting out/removing the `LocalSocket` config and adding the `TCPAddr` and `TCPSocket` of the remote server.
```
# The default is 3310 but if mapped to a different port update
TCPSocket 3310
# This can be an IP address or a hostname
TCPAddr 127.0.0.1
```

### Update steamedclams configuration

1) Find the path to the local clamdscan binary (default is `/usr/bin/clamdscan`).
Run `which clamdscan` to confirm.

2) Update `yml` config
```yml
Symbiote\SteamedClams\ClamAV:
  clamd:
    LocalBinary: '/usr/bin/clamdscan'
  # Set to true to use the LocalBinary path for scans
  use_clamscan: false
```

3) Run a `dev/build` to pick up the changes.
