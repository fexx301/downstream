

# --- deprecation shim: keep accepting `proxies` for one more release ---
import functools as _functools
import warnings as _warnings


def _accept_proxies(cls, transport):
    init = cls.__init__

    @_functools.wraps(init)
    def __init__(self, *args, proxies=None, **kwargs):
        if proxies is not None:
            _warnings.warn("'proxies' is deprecated; use 'proxy' or 'mounts'", DeprecationWarning, stacklevel=2)
            if isinstance(proxies, dict):  # 0.27 per-pattern form; a None value meant "no proxy" there too
                kwargs.setdefault("mounts", {k: v and transport(proxy=v) for k, v in proxies.items()})
            else:
                kwargs.setdefault("proxy", proxies)
        init(self, *args, **kwargs)

    cls.__init__ = __init__


_accept_proxies(Client, HTTPTransport)
_accept_proxies(AsyncClient, AsyncHTTPTransport)
