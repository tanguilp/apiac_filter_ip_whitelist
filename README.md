# APISexFilterIPWhitelist

An `APISex.Filter` plug enabling IP whitelist (IPv4 & IPv6)

## Plug options

- `whitelist`: a *list* of allowed IPv4 and IPv6 addresses in CIDR notation or a
`(Plug.Conn.t -> [String])` function returning that list of addresses
- `exec_cond`: a `(Plug.Conn.t() -> boolean())` function that determines whether
this filter is to be executed or not. Defaults to `fn _ -> true end`
- `send_error_response`: function called when IP address is not whitelisted.
Defaults to `APISexFilterIPWhitelist.send_error_response/3`
- `error_response_verbosity`: one of `:debug`, `:normal` or `:minimal`.
Defaults to `:normal`

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
