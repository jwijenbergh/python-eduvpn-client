import enum
import json
import logging
from typing import Dict, Iterable, List, Optional, Union

from eduvpn.discovery import parse_disco_organizations, parse_disco_servers
from eduvpn.i18n import extract_translation
from eduvpn.settings import IMAGE_PREFIX

logger = logging.getLogger(__name__)
TranslatedStr = Union[str, Dict[str, str]]


def parse_locations(locations_json: str) -> List[str]:
    locations = json.loads(locations_json)
    return locations


class Profile:
    """The class that represents a server profile.
    :param: identifier: str: The identifier (id) of the profile
    :param: display_name: str: The display name of the profile
    :param: default_gateway: str: Whether or not this profile should have the default gateway set
    """

    def __init__(
        self, identifier: str, display_name: Dict[str, str], default_gateway: bool
    ):
        self.identifier = identifier
        self.display_name = display_name
        self.default_gateway = default_gateway

    def __str__(self):
        return extract_translation(self.display_name)


class Profiles:
    """The class that represents a list of profiles
    :param: profiles: List[Profile]: A list of profiles
    :param: current: int: The current profile index
    """

    def __init__(self, profiles: Dict[str, Profile], current: str):
        self.profiles = profiles
        self.current_id = current

    @property
    def current(self) -> Optional[Profile]:
        """Get the current profile if there is any
        :return: The profile if there is a current one (meaning the index is valid)
        :rtype: Optional[Profile]
        """
        if self.current_id not in self.profiles:
            return None
        return self.profiles[self.current_id]


class Server:
    """The class that represents a server. Use this for a custom server
    :param: url: str: The base URL of the server. In case of secure internet (supertype) this is the organisation ID URL
    :param: display_name: str: The display name of the server
    :param: profiles: Optional[Profiles]: The profiles if there are any already obtained, defaults to None
    """

    def __init__(
        self,
        url: str,
        display_name: Dict[str, str],
        profiles: Optional[Profiles] = None,
    ):
        self.url = url
        self.display_name = display_name
        self.profiles = profiles

    def __str__(self) -> str:
        return extract_translation(self.display_name)

    @property
    def identifier(self) -> str:
        return self.url

    @property
    def category_id(self) -> str:
        return "custom_server"

    @property
    def category(self) -> str:
        """Return the category of the server as a string
        :return: The category string, "Custom Server"
        :rtype: str
        """
        return "Custom Server"


class InstituteServer(Server):
    """The class that represents an Institute Access Server
    :param: url: str: The base URL of the Institute Access Server
    :param: display_name: str: The display name of the Institute Access Server
    :param: support_contact: List[str]: The list of support contacts
    :param: profiles: Profiles: The profiles of the server
    """

    def __init__(
        self,
        url: str,
        display_name: Dict[str, str],
        support_contact: List[str],
        profiles: Profiles,
    ):
        super().__init__(url, display_name, profiles)
        self.support_contact = support_contact

    @property
    def category(self) -> str:
        """Return the category of the institute server as a string
        :return: The category string, "Institute Access Server"
        :rtype: str
        """
        return "Institute Access Server"

    @property
    def category_id(self) -> str:
        return "institute_access"


class SecureInternetServer(Server):
    """The class that represents a Secure Internet Server
    :param: org_id: str: The organization ID of the Secure Internet Server as returned by Discovery
    :param: display_name: str: The display name of the server
    :param: support_contact: List[str]: The list of support contacts of the server
    :param: locations: List[str]: The list of secure internet locations
    :param: profiles: Profiles: The list of profiles that the server has
    :param: country_code: str: The country code of the server
    """

    def __init__(
        self,
        org_id: str,
        display_name: Dict[str, str],
        support_contact: List[str],
        profiles: Profiles,
        country_code: str,
    ):
        super().__init__(org_id, display_name, profiles)
        self.org_id = org_id
        self.support_contact = support_contact
        self.country_code = country_code

    @property
    def category_id(self) -> str:
        return "secure_internet"

    @property
    def category(self) -> str:
        """Return the category of the secure internet server as a string
        :return: The category string, "Secure Internet Server"
        :rtype: str
        """
        return "Secure Internet Server"


class ServerType(enum.IntEnum):
    UNKNOWN = 0
    INSTITUTE_ACCESS = 1
    SECURE_INTERNET = 2
    CUSTOM = 3


def parse_current_server(server_json: str) -> Optional[Server]:
    d = json.loads(server_json)
    t = ServerType(d["server_type"])
    if t == ServerType.UNKNOWN:
        return None
    if t == ServerType.INSTITUTE_ACCESS:
        i = d["institute_access_server"]
        profiles = parse_profiles(i["profiles"])
        # TODO
        return InstituteServer(i["identifier"], i["display_name"], [], profiles)
    if t == ServerType.SECURE_INTERNET:
        si = d["secure_internet_server"]
        profiles = parse_profiles(si["profiles"])
        # TODO: support contact and delisted
        return SecureInternetServer(
            si["identifier"], si["display_name"], [], profiles, si["country_code"]
        )

    if t == ServerType.CUSTOM:
        c = d["custom_server"]
        profiles = parse_profiles(c["profiles"])
        return Server(c["identifier"], c["display_name"], profiles)


def parse_profiles(profiles: dict) -> Profiles:
    returned = {}
    profile_map = profiles.get("map", {})
    for k, v in profile_map.items():
        # TODO: Default gateway
        returned[k] = Profile(k, v["display_name"], False)
    return Profiles(returned, profiles["current"])


def parse_servers(server_json: str) -> List[Server]:
    d = json.loads(server_json)

    institutes = d.get("institute_access_servers", [])
    servers = []
    for i in institutes:
        # TODO: support contact and delisted
        profiles = parse_profiles(i["profiles"])
        servers.append(
            InstituteServer(i["identifier"], i["display_name"], [], profiles)
        )

    customs = d.get("custom_servers", [])
    for i in customs:
        profiles = parse_profiles(i["profiles"])
        servers.append(Server(i["identifier"], i["display_name"], profiles))

    si = d.get("secure_internet_server", None)
    if si is not None:
        profiles = parse_profiles(si["profiles"])
        # TODO: support contact and delisted
        servers.append(
            SecureInternetServer(
                si["identifier"], si["display_name"], [], profiles, si["country_code"]
            )
        )
    return servers


class StatusImage(enum.Enum):
    # The value is the image filename.
    DEFAULT = "desktop-default.png"
    CONNECTING = "desktop-connecting.png"
    CONNECTED = "desktop-connected.png"
    NOT_CONNECTED = "desktop-not-connected.png"

    @property
    def path(self) -> str:
        return IMAGE_PREFIX + self.value


def get_search_text(server) -> List[str]:
    search_texts = [str(server)]
    if hasattr(server, "keywords"):
        keys = extract_translation(server.keywords)
        search_texts.extend(keys.split(" "))
    return search_texts


def is_search_match(server, query: str) -> bool:
    search_texts = get_search_text(server)
    return any(query.lower() in search_text.lower() for search_text in search_texts)


class ServerDatabase:
    def __init__(self, wrapper, enable_discovery=True) -> None:
        self.wrapper = wrapper
        self.enable_discovery = enable_discovery
        self.cached = []

    @property
    def disco(self):
        if not self.enable_discovery:
            return []
        disco_orgs = parse_disco_organizations(self.wrapper.get_disco_organizations())
        disco_servers = parse_disco_servers(self.wrapper.get_disco_servers())
        all_servers = disco_orgs
        all_servers.extend(disco_servers)
        self.cached = all_servers
        return all_servers

    def has(self, server) -> Optional[Server]:
        # The url attribute is always used as an identifier
        for s in self.configured:
            if server.identifier == s.identifier:
                return s
        return None

    @property
    def current(self):
        return parse_current_server(self.wrapper.get_current_server())

    @property
    def configured(self):
        return parse_servers(self.wrapper.get_servers())

    def all(self):
        "Return all servers."
        return self.cached

    def search_predefined(self, query: str):
        "Return all servers that match the search query."
        if query:
            for server in self.all():
                if is_search_match(server, query):
                    yield server
        else:
            yield from self.all()

    def search_custom(self, query: str) -> Iterable[Server]:
        yield Server(query, query)
