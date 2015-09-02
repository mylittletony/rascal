# You little Rascal!

This is a development repository which filters the incoming probe requests and sends them back to the server of your choice.

Create a config.json file in /etc/config.json with something like this:

```
{
    "mac": "my-mac",
    "lat": 54.23412312312,
    "lng": -0.937123967a6,
    "rs_url": "http://www.wowzers/com/oh-my.json",
    "rs_iface": "mon0",
    "rs_secret": "oh-top-secret",
    "rs_token": "oh-optional-token"
}
```

It will collect the data and send to the URL of your choice.

**This is most certainly not production ready**.

Run it on some linuxy thing with...

```
rascal
```

If you're feeling fancy, run it with -v.
