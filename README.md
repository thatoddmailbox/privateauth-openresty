# privateauth-openresty
An [OpenResty](https://openresty.org/en/) script to require signing into a resource via a [PrivateAuth endpoint](https://github.com/thatoddmailbox/PrivateAuth).

## Requirements
* [cloudflare/lua-resty-cookie](https://github.com/cloudflare/lua-resty-cookie)
* [ledgetech/lua-resty-http](https://github.com/ledgetech/lua-resty-http)

## Configuration
There are two main configuration options, which can be set with the `privateauth-access-config.lua` file.

First, you can choose the `endpoint` used for authentication. This URL should be what you would set the `authorization_endpoint` link tag to. It probably will _not_ be your profile URL! You should make sure that you trust the endpoint that's being used, as any user that can sign into the endpoint will be given access to your resource.

Second, you can control the details of what the script protects access to with the `apps` parameter. Each entry in the `apps` table defines a different application, with its own name, client ID, and redirect URI. Each app also must have its own _slug_, which is the key used in the apps table. In the sample config file, the slug being used is `example`. The properties for each app are:
* `name`: The user-friendly name to be shown on the initial request for login. If your authorization endpoint supports the h-app microformat, it should also display this name there.
* `clientID`: The client ID used with the authorization endpoint. This will probably just be the URL of your application.
* `redirectURI`: The redirect URI used with the authorization endpoint. This can be the URL of any page where this script is active.

## Setup
Before you begin, make sure you've downloaded the two libraries listed in the Requirements section. You'll also need to copy `privateauth-access.lua` and `privateauth-access-config.example.lua` somewhere. This guide assumes this path is `/etc/openresty/scripts`, but it can be anywhere.

Make sure to also rename the config file: you should change `privateauth-access-config.example.lua` to `privateauth-access-config.lua`.

First, you need to make some changes to your main OpenResty configuration. You'll want to add the following to your main `http` block:
```
resolver 1.1.1.1;

lua_ssl_verify_depth 2;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
```
That last line tells OpenResty where to find the CA certificate store. If you're using Ubuntu, that value should be fine; otherwise, you'll need to adjust it based on your distribution. See [this page](https://github.com/ledgetech/lua-resty-http/issues/42) for more details.

Next, you should make sure that you've added the two libraries (lua-resty-cookie and lua-resty-http) and the location of this script to your lua_package_path. For example:
```
lua_package_path '/etc/openresty/libraries/lua-resty-cookie/lib/?.lua;/etc/openresty/libraries/lua-resty-http/lib/?.lua;/etc/openresty/scripts/?.lua;;';
```

And, you need to define a storage area for the script. This is where it stores session information, to keep track of who's logged in. You can do that like so:
```
lua_shared_dict privateauth-data 1m;
```

Once you've done all that, you will have set up the script for the whole server. You can then set up, in your `server` blocks, individual locations that require protection. For example, if you wanted to require requests to the path `/secret` be protected, you could do something like:
```
location ^~ /secret {
	set $privateauth-slug example;
	access_by_lua_file /etc/openresty/scripts/privateauth-access.lua;
}
```
The `$privateauth-slug` variable should correspond to the slug (which you defined in the Configuration section) of the application at this location.

After that, reload your OpenResty config, and it should be working!

## Troubleshooting
If you're running into errors, check that you've set up a DNS resolver in your OpenResty configuration. You should also ensure that the CA certificate store was set up correctly.

If you're still running into trouble, feel free to [file an issue](https://github.com/thatoddmailbox/privateauth-openresty/issues). Make sure to attach your OpenResty error log!