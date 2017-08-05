### threatconnect-go

A go SDK for the [ThreatConnect](https://threatconnect.com) [API](https://docs.threatconnect.com)

## Install
`go get github.com/xandout/threatconnect-go`

## Configure
A file located at `$HOME/.threatconnect/config` containing "profiles"

```
[profile_name]
base_url=<TC API URL>
api_id=<YOUR API ID>
api_secret=<YOUR API SECRET>
```

## Usage
See [example.go](example.go)

## Results
```
go@pher$ go run example.go
{"status":"Success","data":{"user":{"userName":"<MY API ID>","firstName":"mitchAPI","lastName":"mitchAPI","pseudonym":"mitchAPI","role":"Api User"}}}
```
