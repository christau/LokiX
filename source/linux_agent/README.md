# This is the linux agent for the LokiX web app
## Installation of python modules
python -m pip install yara-python psutil rfc5424-logging-handler future colorama netaddr
## Usage
```
./lokix.py <server/ip>
```
## Installation
As a systemd timer

`/etc/systemd/system/lokix.timer`
```
[Unit]
Description=Timer to regularily execute a Loki scan. Daily at 4am
[Timer]
OnCalendar=*-*-* 04:00
```
`/etc/systemd/system/lokix.service`
```
[Unit]
Description Lokix scanner
[Service]
type=oneshot
ExecStart=/usr/local/bin/lokix.py lokix.local
```