# privateauth-openresty
An [OpenResty](https://openresty.org/en/) script to require signing into a resource via a [PrivateAuth endpoint](https://github.com/thatoddmailbox/PrivateAuth).

## Requirements
* [lua-resty-cookie](https://github.com/cloudflare/lua-resty-cookie)
* [lua-resty-http](https://github.com/ledgetech/lua-resty-http)
* a configured DNS resolver in your OpenResty configuration
* a configured set of CA certificates, see [this GitHub issue](https://github.com/ledgetech/lua-resty-http/issues/42)
