gp-saml-gui
===========

This is a forked version of `gp-saml-gui` tailored for internal usage.


Installation
============

Install `uv` and `openconnect`.
```
$ sudo port install uv openconnect
```

Patch vpnscript.
```
$ sudo cp ./patches/vpnc-script /opt/local/etc/vpnc-scripts/vpnc-script
```

Install the dependencies.

```
$ uv sync
```

How to use
==========

Run the following command replacing `${GATEWAY}` with any of the servers listed https://chat.google.com/room/AAAADfggWQk/eAbRmhejMoI/9snhD_rm4X8?cls=10, and `${FULL_USER_ID}` with your internal user id (not your email address, and including the domain).

```
$ uv run gp-saml-gui -S -g --clientos=Mac ${GATEWAY} -- --csd-wrapper=/opt/local/libexec/openconnect/hipreport.sh --no-dtls --protocol=gp --user '${FULL_USER_ID}'
```

License
=======

GPLv3 or newer
