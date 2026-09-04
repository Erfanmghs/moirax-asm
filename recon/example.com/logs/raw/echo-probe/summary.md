# echo-probe

command: sh -c mkdir -p "$1/logs/raw/echo-probe" && printf "%s\n" "{\"schema_version\":1,\"module\":\"echo-probe\",\"hosts\":[{\"host\":\"$2\",\"fqdn\":\"alt.$2\",\"ips\":[\"203.0.113.50\"]}],\"candidates\":[{\"host\":\"$2\",\"sources\":[\"echo-probe\"],\"ips\":[\"203.0.113.50\"]}],\"sources\":[\"echo-probe\"],\"branch\":\"passive\"}" > "$1/logs/raw/echo-probe/data.json" && cat "$1/logs/raw/echo-probe/data.json" echo-probe example.com probe2.example.com
runtime_sec: 0.679
counts: 1
