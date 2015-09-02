# You little Rascal!

This is a development repository which filters the incoming probe requests and sends them back to the server of your choice.

Create a config.json file in /etc/config.json with something like this:

```
{
    "url": "http://www.wowzers/com/oh-my.json",
    "mac": "my-mac",
    "iface": "mon0",
    "lat": 54.23412312312,
    "lng": -0.937123967a6,
    "secret": "oh-top-secret",
    "token": "oh-optional-token"
}
```

It will collect the data and send to the URL of your choice.

This is most certainly not production ready.
