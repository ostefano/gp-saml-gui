#!/usr/bin/env python3
import argparse
import binascii
import logging
import os
import re
import shlex
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from urllib import parse

import requests
import webview

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

REDIRECT_MESSAGE_TEMPLATE = """
IMPORTANT: During the SAML auth, you were redirected from {0} to {1}. This probably 
means you should specify {1} as the server for final connection, but we're not 100% 
sure about this. You should probably try both; if necessary, use the 
--ignore-redirects option to specify desired behavior.\n
"""

REDIRECT_IGNORED_MESSAGE_TEMPLATE = """
IMPORTANT: During the SAML auth, you were redirected from {0} to {1}, however the 
redirection was ignored because you specified --ignore-redirects.\n
"""

COOKIE_INTERFACE_TEMPLATE = """
IMPORTANT: We started with SAML auth to the {} interface, but received a cookie 
that's often associated with the {} interface. You should probably try both.\n
"""

DEFAULT_USER_AGENT = "PAN GlobalProtect"

IF_TO_PRELOGIN = {
    "portal": "global-protect/prelogin.esp",
    "gateway": "ssl-vpn/prelogin.esp",
}
IF_TO_AUTH = {"portal": "global-protect/getconfig.esp", "gateway": "ssl-vpn/login.esp"}

PF_TO_CLIENTOS = dict(linux="Linux", darwin="Mac", win32="Windows", cygwin="Windows")
CLIENTOS_TO_OCOS = dict(Linux="linux-64", Mac="mac-intel", Windows="win")


class SAMLLoginViewWebview:

    COOKIE_REGEX = "<(?P<header>saml-.+?|(?:prelogin-|portal-userauth)cookie)>(?P<value>.*?)</(?P=header)>"

    WINDOW_TITLE = "SAML Login"
    WINDOW_WIDTH = 800
    WINDOW_HEIGHT = 600

    def __init__(
        self, uri: str | None, html: str | None, args: argparse.Namespace
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.closed = False
        self.success = False
        self.saml_result = {}
        self.verbose = args.verbose
        self.user_agent = args.user_agent or DEFAULT_USER_AGENT
        self.lock = threading.Lock()
        window = webview.create_window(
            title=self.WINDOW_TITLE,
            width=self.WINDOW_WIDTH,
            height=self.WINDOW_HEIGHT,
        )
        if not window:
            raise ValueError
        self.window = window
        webview.start(
            func=self.create_login_window,
            args=[self.window, uri, html],
            user_agent=self.user_agent,
            debug=self.verbose > 1,
            private_mode=False,
        )

    def create_login_window(self, window, uri: str | None, html: str | None):
        window.events.closed += self.on_closed
        window.events.loaded += self.get_saml_headers
        if html:
            window.load_html(html)
        elif uri:
            window.load_url(uri)
        else:
            raise ValueError

    def on_closed(self):
        if self.verbose > 2:
            self.logger.info("[WEBVIEW] Window closed")
        self.closed = not self.success

    @classmethod
    def _extract_html(cls, window: webview.Window) -> str:
        """
        Use 'window.gui.evaluate_js' to bypass pywebview's 'var value = eval("{0}")' closure, which triggers:

            Refused to evaluate a string as JavaScript because 'unsafe-eval' is not an allowed source of
            script in the following Content Security Policy directive: "script-src 'self' 'unsafe-inline'".
        """
        if not window.gui:
            raise ValueError
        js = "var value = document.documentElement.outerHTML;\n"
        if window.gui.renderer == "cef":
            unique_id = uuid.uuid1().hex
            js += 'window.external.return_result(JSON.stringify(value), "{0}");'.format(
                unique_id
            )
            html = window.gui.evaluate_js(js, window.uid, unique_id)
        else:
            js += "JSON.stringify(value);"
            html = window.gui.evaluate_js(js, window.uid)
        return html

    @classmethod
    def _extract_headers(cls, html: str) -> dict:
        """
        In addition to their HTTP header counterparts (which aren't surfaced by pywebview), GlobalProtect adds the
            following values to the body of its response after authentication succeeds (line breaks added for clarity):

            <saml-auth-status>{{STATUS}}</saml-auth-status>
            <prelogin-cookie>{{COOKIE}}</prelogin-cookie>
            <saml-username>{{USERNAME}}</saml-username>
            <saml-slo>{{SLO}}</saml-slo>
        """
        fd = {}
        for m in re.finditer(cls.COOKIE_REGEX, html):
            fd[m.group("header")] = m.group("value")
        return fd

    def get_saml_headers(self):
        self.lock.acquire()
        if self.verbose > 1:
            self.logger.info("[PAGE] Page loaded in thread %x", threading.get_ident())

        uri = self.window.get_current_url()
        if self.verbose:
            self.logger.info("[PAGE] Loaded URI: %s", uri)
        if not uri:
            self.lock.release()
            return

        html = self._extract_html(self.window)
        if self.verbose > 2:
            self.logger.info("[PAGE] Retrieved outerHTML: %s", html)
        if not html:
            self.lock.release()
            return

        fd = self._extract_headers(html)
        if self.verbose:
            self.logger.info("[SAML] Got SAML result headers: %r", fd)
        if not fd:
            self.lock.release()
            return

        # check if we're done
        self.saml_result.update(fd, server=parse.urlparse(uri).netloc)
        self.lock.release()

        time.sleep(1)
        self.check_done()

    def check_done(self):
        self.lock.acquire()
        if "saml-username" in self.saml_result:
            if (
                "prelogin-cookie" in self.saml_result
                or "portal-userauthcookie" in self.saml_result
            ):
                if self.verbose:
                    self.logger.info("[SAML] Got all required SAML headers, done.")
                self.success = True
                self.window.destroy()
        self.lock.release()


def extract_saml_headers(
    content: bytes,
) -> tuple[str, str | None, str | None]:
    xml = ET.fromstring(content)
    if xml.tag != "prelogin-response":
        raise ValueError("This does not appear a prelogin response")

    status = xml.find("status")
    if status is not None and status.text != "Success":
        msg = xml.find("msg")
        if msg and msg.text:
            if re.fullmatch(r"GlobalProtect .* does not exist", msg.text):
                raise ValueError("Interface does not exist")
        raise ValueError("Error in prelogin response")

    sam = xml.find("saml-auth-method")
    if sam is None or sam.text is None:
        raise ValueError("Response does not contain SAML tags")

    sr = xml.find("saml-request")
    if sr is None or sr.text is None:
        raise ValueError("Error in prelogin response")

    sr = binascii.a2b_base64(sr.text).decode()
    match sam.text:
        case "POST":
            html, uri = sr, None
        case "REDIRECT":
            uri, html = sr, None
        case _:
            raise ValueError("Unknown SAML method (%s)" % sam.text)

    return sam.text, uri, html


def extract_login_page(
    user_agent: str | None,
    cert: str | None,
    client_os: str,
    server: str,
    interface: str,
    extra: dict,
    is_uri: bool = False,
    is_verbose: bool = False,
    verify: bool = False,
) -> tuple[str | None, str | None]:
    logger = logging.getLogger(__name__)
    if is_uri:
        sam, uri, html = "URI", server, None
    else:
        endpoint = f"https://{server}/{IF_TO_PRELOGIN[interface]}"
        if is_verbose:
            logger.info("Looking for SAML auth tags in response to %s...", endpoint)

        s = requests.Session()
        s.headers["User-Agent"] = user_agent or DEFAULT_USER_AGENT
        s.cert = cert
        try:
            res = s.post(
                endpoint,
                verify=verify,
                data={
                    "tmp": "tmp",
                    "kerberos-support": "yes",
                    "ipv6-support": "yes",
                    "clientVer": 4100,
                    "clientos": client_os,
                    **extra,
                },
            )
        except requests.exceptions.SSLError as ex:
            logger.error("SSL certificate error (try --no-verify to ignore): %s", ex)
            raise

        try:
            sam, uri, html = extract_saml_headers(res.content)
        except ValueError as ve:
            logger.error("Error: %s", str(ve))
            raise
    if is_verbose:
        logger.info("Got SAML %s, opening browser...", sam)
    return uri, html


def parse_saml_response(
    saml_result: dict,
) -> tuple[str | None, str | None, str, str, str]:
    username = saml_result.get("saml-username")
    if not username:
        raise ValueError
    server = saml_result.get("server")
    for cn, ifh in (
        ("prelogin-cookie", "gateway"),
        ("portal-userauthcookie", "portal"),
    ):
        cv = saml_result.get(cn)
        if cv is not None:
            break
    if not cv:
        raise ValueError("Didn't get an expected cookie. Something went wrong")
    assert isinstance(cv, str)
    return server, username, ifh, cn, cv


def parse_args(args=None) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parse arguments"""
    p = argparse.ArgumentParser()
    p.add_argument("server", help="GlobalProtect server (portal or gateway)")
    p.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        default=True,
        help="Ignore invalid server certificate",
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-C",
        "--cookies",
        default="~/.gp-saml-gui-cookies",
        help="Use and store cookies in this file (instead of default %(default)s)",
    )
    x.add_argument(
        "-K",
        "--no-cookies",
        dest="cookies",
        action="store_const",
        const=None,
        help="Don't use or store cookies at all",
    )
    x = p.add_mutually_exclusive_group()
    p.add_argument(
        "-i",
        "--ignore-redirects",
        action="store_true",
        help="Use specified gateway hostname as server, ignoring redirects",
    )
    x.add_argument(
        "-g",
        "--gateway",
        dest="interface",
        action="store_const",
        const="gateway",
        default="portal",
        help="SAML auth to gateway",
    )
    x.add_argument(
        "-p",
        "--portal",
        dest="interface",
        action="store_const",
        const="portal",
        help="SAML auth to portal (default)",
    )
    g = p.add_argument_group("Client certificate")
    g.add_argument(
        "-c",
        "--cert",
        help="PEM file containing client certificate (and optionally private key)",
    )
    g.add_argument(
        "--key",
        help="PEM file containing client private key (if not included in same file as certificate)",
    )
    g = p.add_argument_group("Debugging and advanced options")
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-v",
        "--verbose",
        default=1,
        action="count",
        help="Increase verbosity of explanatory output to stderr",
    )
    x.add_argument(
        "-q",
        "--quiet",
        dest="verbose",
        action="store_const",
        const=0,
        help="Reduce verbosity to a minimum",
    )
    x = p.add_mutually_exclusive_group()
    x.add_argument(
        "-P",
        "--pkexec-openconnect",
        action="store_const",
        dest="exec",
        const="pkexec",
        help="Use PolicyKit to exec openconnect",
    )
    x.add_argument(
        "-S",
        "--sudo-openconnect",
        action="store_const",
        dest="exec",
        const="sudo",
        help="Use sudo to exec openconnect",
    )
    x.add_argument(
        "-E",
        "--exec-openconnect",
        action="store_const",
        dest="exec",
        const="exec",
        help="Execute openconnect directly (advanced users)",
    )
    g.add_argument(
        "-u",
        "--uri",
        action="store_true",
        help="Treat server as the complete URI of the SAML entry point, rather than GlobalProtect server",
    )
    g.add_argument(
        "--clientos",
        choices=set(PF_TO_CLIENTOS.values()),
        default=PF_TO_CLIENTOS.get(sys.platform, "Windows"),
        help="clientos value to send (default is %(default)s)",
    )
    p.add_argument(
        "-f",
        "--field",
        dest="extra",
        action="append",
        default=[],
        help='Extra form field(s) to pass in the login query string (e.g. "-f magic-cookie-value=deadbeef01234567")',
    )
    p.add_argument(
        "--user-agent",
        "--useragent",
        default="PAN GlobalProtect",
        help="Use the provided string as the HTTP User-Agent header (default is %(default)r, as used by OpenConnect)",
    )
    p.add_argument(
        "--no-proxy", action="store_true", help="Disable system proxy settings"
    )
    p.add_argument(
        "openconnect_extra",
        nargs="*",
        help="Extra arguments to include in output OpenConnect command-line",
    )
    args = p.parse_args(args)

    args.ocos = CLIENTOS_TO_OCOS[args.clientos]
    args.extra = dict(x.split("=", 1) for x in args.extra)

    if args.cookies:
        args.cookies = os.path.expanduser(args.cookies)

    if args.cert and args.key:
        args.cert, args.key = (args.cert, args.key), None
    elif args.cert:
        args.cert = (args.cert, None)
    elif args.key:
        p.error("--key specified without --cert")
    else:
        args.cert = None

    return p, args


def main(args=None):
    """Main function."""
    logger = logging.getLogger(__name__)
    p, args = parse_args(args)
    uri, html = extract_login_page(
        user_agent=args.user_agent,
        cert=args.cert,
        client_os=args.clientos,
        server=args.server,
        interface=args.interface,
        extra=args.extra,
        is_uri=args.uri,
        is_verbose=args.verbose > 0,
        verify=args.verify,
    )
    slv = SAMLLoginViewWebview(uri, html, args)
    if slv.closed:
        logger.error("Login window closed by user")
    if not slv.success:
        logger.error("Login window closed without producing SAML cookies")
        return 1

    saml_server, saml_username, saml_interface, cookie_name, cookie_value = (
        parse_saml_response(slv.saml_result)
    )
    if not saml_username:
        logger.error("Missing username")
        return 1
    server = args.server if args.ignore_redirects else (saml_server or args.server)

    urlpath = args.interface + ":" + cookie_name
    openconnect_args = [
        "--protocol=gp",
        f"--user={saml_username}",
        f"--os={args.ocos}",
        f"--usergroup={urlpath}",
        "--passwd-on-stdin",
        server,
        *args.openconnect_extra,
    ]
    if args.user_agent:
        openconnect_args.insert(1, f"--useragent='{args.user_agent}'")
    if args.cert:
        cert, key = args.cert
        if key:
            openconnect_args.insert(1, f"--sslkey={key}")
        openconnect_args.insert(1, f"--certificate={cert}")
    if args.no_proxy:
        openconnect_args.insert(1, "--no-proxy")

    openconnect_command = "echo {} | sudo openconnect {}".format(
        shlex.quote(cookie_value), " ".join(map(shlex.quote, openconnect_args))
    )
    if args.verbose:
        if server != args.server and not args.uri:
            template = (
                REDIRECT_MESSAGE_TEMPLATE
                if args.ignore_redirects
                else REDIRECT_IGNORED_MESSAGE_TEMPLATE
            )
            logger.warning(template.format(args.server, server))
        if saml_interface != args.interface and not args.uri:
            logger.warning(
                COOKIE_INTERFACE_TEMPLATE.format(args.interface, saml_interface)
            )

        logger.info("\n")
        logger.info("SAML response converted to OpenConnect command line invocation:")
        logger.info("\n")
        logger.info("\t%s", openconnect_command)
        logger.info("\n")

        logger.info("\n")

    # RUN
    if args.exec:
        logger.info(
            "Launching OpenConnect with {}, equivalent to:\n{}".format(
                args.exec, openconnect_command
            )
        )
        with tempfile.TemporaryFile("w+") as tf:
            tf.write(cookie_value)
            tf.flush()
            tf.seek(0)
            # redirect stdin from this file, before it is closed by the context manager
            # (it will remain accessible via the open file descriptor)
            os.dup2(tf.fileno(), 0)
        cmd = ["openconnect", *openconnect_args]
        match args.exec:
            case "pkexec":
                cmd = ["pkexec", "--user", "root", *cmd]
            case "sudo":
                cmd = ["sudo", *cmd]
        os.execvp(cmd[0], cmd)
    else:
        varvals = {
            "HOST": shlex.quote("https://%s/%s" % (server, urlpath)),
            "USER": shlex.quote(saml_username),
            "COOKIE": shlex.quote(cookie_value),
            "OS": shlex.quote(args.ocos),
        }
        logger.info("\n".join(f"{k}={v}" for k, v in varvals.items()))

    return 0


if __name__ == "__main__":
    sys.exit(main())
