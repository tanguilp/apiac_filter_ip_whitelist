# APISexFilterIPWhitelist

An `APISex.Filter` plug enabling IP whitelist (IPv4 & IPv6)

## Plug options

- `whitelist`: a *list* of allowed IPv4 and IPv6 addresses in CIDR notation or a
`(Plug.Conn.t -> [String])` function returning that list of addresses
- `set_filter_error_response`: if `true`, sets the HTTP status code to `403`.
If false, does not do anything. Defaults to `true`
- `halt_on_filter_failure`: if set to `true`, halts the connection and directly sends the
response. When set to `false`, does nothing and therefore allows dealing with the error
later in the code. Defaults to `true`

## Example

```elixir
Plug APISexFilterIPWhitelist, whitelist: [
  "192.168.13.0/24",
  "2001:45B8:991A::/48",
  "23.12.0.0/16",
  "20E7:4128:D4F0:0::/64",
  "91.23.251.0/24"
]
```

## Security considerations

This plug uses the `remote_ip` field of the `Plug.Conn.t` for IP filtering, which means:
- **do use** [`remote_ip`](https://github.com/ajvondrak/remote_ip) or a similar
library if you're behind a proxy
- **do not use** `remote_ip` or a similar library if you're not behind a proxy
