#!/usr/bin/env python3

"""log4j honeypot"""

import abc
import json
import logging
import re
import typing as t
import uuid
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import ldap  # type: ignore[import]
import requests
from elasticsearch import Elasticsearch, NotFoundError
from flask import Flask, render_template, request


class SecondStageURL(t.NamedTuple):
    """Info regarding the second stage"""

    netloc: str
    path: str


ThirdStageURL = str

FAST_PAYLOAD_REGEX = re.compile(r"\$\{")
PAYLOAD_REGEX = re.compile(  # pylint: disable-next=line-too-long
    r"(?:\$\{(?:j|\${::-j})(?:n|\${::-n})(?:d|\${::-d})(?:i|\${::-i}):(?:l|\${::-l})(?:d|\${::-d})(?:a|\${::-a})(?:p|\${::-p})|)(?P<dest>.*)}"
)


class RequestJson(t.TypedDict):
    """Serialized request"""

    headers: list[tuple[str, str]]
    form: list[tuple[str, str]]
    src_ip: str
    timestamp: str
    full_path: str


class AttackLogger(abc.ABC):
    """Base class for loggers"""

    # pylint: disable=too-few-public-methods

    @abc.abstractmethod
    def __init__(self, config: ConfigParser) -> None:
        ...

    @abc.abstractmethod
    def report(self, serialized_request: RequestJson) -> None:
        """report a (malicious) request"""


class JsonLogger(AttackLogger):
    """Log to json file"""

    # pylint: disable=too-few-public-methods

    def __init__(self, config: ConfigParser) -> None:
        super().__init__(config)
        self.dest_file = Path(config.get("JSONLogger", "file", fallback="log.json"))

    def report(self, serialized_request: RequestJson) -> None:
        with self.dest_file.open("a", encoding="utf-8") as destfile:
            json.dump(serialized_request, destfile)


class ElasticLogger(AttackLogger):
    """Log attacks, payload and stuff to elastic"""

    # pylint: disable=too-few-public-methods

    def __init__(self, config: ConfigParser) -> None:
        super().__init__(config)
        config_elastic = config["ELASTICSEARCH"]

        self.sensorname = config.get("DEFAULT", "name", fallback="honeypot1")

        if "username" in config_elastic and "password" in config_elastic:
            auth = (
                config_elastic["username"],
                config_elastic["password"],
            )
        else:
            auth = None

        self.con = Elasticsearch(
            f"{config_elastic['host']}:{config_elastic['port']}",
            http_auth=auth,
            scheme="https",
            use_ssl=True,
            ssl_show_warn=False,
            verify_certs=config_elastic.getboolean("verify_certs"),
        )
        self.index = config_elastic["index"]
        self.pipeline = config_elastic["pipeline"]
        self._setup()

    def _setup(self) -> None:
        self._check_index()
        self._check_geoip_mapping()
        self._check_geoip_pipeline()

    def _check_index(self) -> None:
        if not self.con.indices.exists(index=self.index):
            #  create index
            self.con.indices.create(index=self.index)

    def _check_geoip_mapping(self) -> None:
        if self.con.indices.exists(index=self.index):
            self.con.indices.put_mapping(
                index=self.index,
                body={
                    "properties": {
                        "geo": {"properties": {"location": {"type": "geo_point"}}}
                    }
                },
            )

    def _check_geoip_pipeline(self) -> None:
        try:
            self.con.ingest.get_pipeline(id=self.pipeline)
        except NotFoundError:
            body = {
                "description": "Add geoip info",
                "processors": [
                    {
                        "geoip": {
                            "field": "src_ip",
                            "target_field": "geo",
                            "database_file": "GeoLite2-City.mmdb",
                        }
                    }
                ],
            }
            self.con.ingest.put_pipeline(id=self.pipeline, body=body)

    def report(self, serialized_request: RequestJson) -> None:
        body = dict(serialized_request)
        body["sensor"] = self.sensorname

        # Elasticsearch does some weird things (@_rewrite_parameters())
        # https://elasticsearch-py.readthedocs.io/en/v7.16.2/api.html#indices
        # pylint: disable=unexpected-keyword-arg
        # pylint: disable=no-value-for-parameter
        self.con.index(
            index=self.index,
            document=body,
            doc_type="_doc",
            pipeline=self.pipeline,
        )


def read_conf() -> ConfigParser:
    """read default config (config.ini.dist) and possible custom configs (config.ini)"""
    config = ConfigParser()
    config.read("config.ini.dist")
    config.read("config.ini")
    return config


def get_secondstage(payload_str: str) -> t.Optional[SecondStageURL]:
    """Retrieve second stage payload

    >>> get_secondstage("${jndi:ldap://1.0.0.0:11/Basic/Command}")
    SecondStageURL(netloc='1.0.0.0:11', path='Basic/Command')
    """
    match = PAYLOAD_REGEX.match(payload_str)
    if match is None:
        return None

    payload_url = match.group("dest").lstrip(":")

    try:
        parts = urlparse(payload_url)
    except ValueError:
        logging.info("Error parsing URL '%s'", payload_url)
        return None

    path = parts.path + parts.query
    path = path.lstrip("/")

    return SecondStageURL(netloc=parts.netloc, path=path)


def download_secondstage(secondstage_url: SecondStageURL) -> t.Optional[ThirdStageURL]:
    """retrieve third stage URL with LDAP

    raises various LDAP Exceptions"""

    con = ldap.initialize(f"ldap://{secondstage_url.netloc}", bytes_mode=False)

    # pylint: disable=no-member
    con.protocol_version = ldap.VERSION3
    con.set_option(ldap.OPT_REFERRALS, 0)
    con.set_option(ldap.OPT_NETWORK_TIMEOUT, 2.0)

    con.simple_bind_s()

    search_q = con.search(secondstage_url.path, ldap.SCOPE_SUBTREE)
    # pylint: enable=no-member

    _status, data = con.result(search_q, 0)

    if not data:
        logging.info("No data found?")
        return None

    _search, result = data[0]
    if "javaCodeBase" not in result:
        logging.info("No javaCodeBase in result")
        return None

    if "javaFactory" not in result:
        logging.info("No javaCodeBase in result")
        return None

    logging.debug("Got result %s", result)
    logging.error("Got result %s", result)

    third_stage_url = (
        result["javaCodeBase"][0].decode("utf-8")
        + "/"
        + result["javaFactory"][0].decode("utf-8")
        + ".class"
    )

    return third_stage_url


def download_thirdstage(url: ThirdStageURL) -> None:
    """download file"""

    response = requests.get(url, stream=True, timeout=5, headers={"User-Agent": "Java"})
    if response.status_code != 200:
        return

    dest_path = (
        Path("payloads") / datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + f"{uuid.uuid4()}.class"
    )
    with dest_path.open("wb") as dest_file:
        for chunk in response.iter_content(1024):
            dest_file.write(chunk)

    logging.info("Wrote payload to %s", dest_path)


def request_to_json() -> RequestJson:
    """serialize request"""
    return {
        "headers": list(request.headers.items()),
        "form": list(request.form.items()),
        "src_ip": request.remote_addr or "",
        "timestamp": datetime.now().isoformat(),
        "full_path": request.full_path,
    }


def check_and_handle_payloads(some_str: str) -> bool:
    """check if some_str contains a payload and retrieve it"""
    if FAST_PAYLOAD_REGEX.search(some_str) is None:
        return False
    logging.debug("Found suspicious str '%s'", some_str)

    second_stage_url = get_secondstage(some_str)
    if second_stage_url is None:
        return False
    logging.debug("Found second stage url %s", second_stage_url)

    third_stage_url = None
    try:
        third_stage_url = download_secondstage(second_stage_url)
    except Exception as exception:  # pylint: disable=broad-except
        logging.exception(exception)
    if third_stage_url is None:
        logging.info("Third stage not found '%s'", some_str)
        return True

    download_thirdstage(third_stage_url)
    return True


def request_handler_factory(logger: list[AttackLogger]) -> t.Callable:
    """create handler function with logger"""

    def handle_request(_path: str = None) -> str:
        exploited = False
        for _key, value in request.args.items(multi=True):
            exploited |= check_and_handle_payloads(value)
        for _key, value in request.headers:
            exploited |= check_and_handle_payloads(value)
        if request.method == "POST":
            for _key, value in request.form.items():
                exploited |= check_and_handle_payloads(value)
        if exploited:
            for log_handler in logger:
                log_handler.report(request_to_json())
        return render_template("index.html")

    return handle_request


def app_factory() -> Flask:
    """factory for flask app"""
    config = read_conf()
    logger: list[AttackLogger] = []

    if config.getboolean("ELASTICSEARCH", "enabled", fallback=False):
        logger.append(ElasticLogger(config))
    if config.getboolean("JSONLogger", "enabled", fallback=True):
        logger.append(JsonLogger(config))
    app = Flask(__name__, template_folder="templates")

    handle_request = request_handler_factory(logger)

    app.add_url_rule(
        "/", view_func=handle_request, methods=["POST", "GET", "PUT", "DELETE"]
    )
    app.add_url_rule(
        "/<path:_path>",
        view_func=handle_request,
        methods=["POST", "GET", "PUT", "DELETE"],
    )
    return app


def _run() -> None:
    config = read_conf()
    app = app_factory()
    app.run(
        debug=config.getboolean("DEFAULT", "debug", fallback=False),
        host=config.get("DEFAULT", "ip", fallback="127.0.0.1"),
        port=config.getint("DEFAULT", "port"),
    )


if __name__ == "__main__":
    _run()
