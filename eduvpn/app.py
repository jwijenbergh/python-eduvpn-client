import json
import logging
import os
import signal
import sys
import webbrowser
from typing import Any, Callable, Iterator, List, Optional, TextIO, Tuple

from eduvpn_common.main import EduVPN, WrappedError
from eduvpn_common.types import ReadRxBytes

from eduvpn import nm
from eduvpn.config import Configuration
from eduvpn.connection import (
    Config,
    Connection,
    Token,
    parse_config,
    parse_tokens,
    parse_expiry,
)
from eduvpn.event.machine import StateMachine
from eduvpn.event.state import State, StateType
from eduvpn.keyring import DBusKeyring, InsecureFileKeyring, TokenKeyring
from eduvpn.server import (
    SecureInternetServer,
    ServerDatabase,
    parse_current_server,
    parse_locations,
    parse_profiles,
    parse_required_transition,
    parse_secure_internet,
    Server,
)
from eduvpn.utils import model_transition, run_in_background_thread
from eduvpn.variants import ApplicationVariant

logger = logging.getLogger(__name__)


class ApplicationModelTransitions:
    def __init__(
        self, wrapper: EduVPN, machine: StateMachine, variant: ApplicationVariant
    ) -> None:
        self.wrapper = wrapper
        self.machine = machine
        self.machine.register_events(self)
        self.server_db = ServerDatabase(wrapper, variant.use_predefined_servers)

    @model_transition(State.MAIN, StateType.ENTER)
    def get_previous_servers(self, old_state: State, servers):
        logger.debug(f"Transition: NO_SERVER, old state: {old_state}")
        has_wireguard = nm.is_wireguard_supported()
        self.wrapper.set_support_wireguard(has_wireguard)
        if servers is None:
            servers = self.server_db.configured
        return servers

    @model_transition(State.SEARCHING_SERVER, StateType.ENTER)
    def parse_discovery(self, old_state: State, _):
        logger.debug(f"Transition: SEARCHING_SERVER, old state: {old_state}")
        saved_servers = self.server_db.configured
        # Whether or not the SEARCH_SERVER screen
        # should be the 'main' screen
        if saved_servers is not None:
            is_main = len(saved_servers) == 0
        else:
            is_main = True

        def update_disco():
            self.server_db.disco_update()
            return self.server_db.disco

        return (self.server_db.disco, is_main, update_disco)

    @model_transition(State.CHOSEN_SERVER, StateType.ENTER)
    def chosen_server(self, old_state: State, data: str):
        logger.debug(f"Transition: CHOSEN_SERVER, old state: {old_state}")
        return data

    @model_transition(State.LOADING_SERVER, StateType.ENTER)
    def loading_server(self, old_state: State, data: str):
        logger.debug(f"Transition: LOADING_SERVER, old state: {old_state}")
        return data

    @model_transition(State.DISCONNECTING, StateType.ENTER)
    def disconnecting(self, old_state: State, server):
        logger.debug(f"Transition: DISCONNECTING, old state: {old_state}")
        return server

    @model_transition(State.ASK_PROFILE, StateType.ENTER)
    def ask_profile(self, old_state: State, server: Server):
        logger.debug(f"Transition: ASK_PROFILE, old state: {old_state}")
        return server

    @model_transition(State.ASK_LOCATION, StateType.ENTER)
    def ask_location(self, old_state: State, data):
        logger.debug(f"Transition: ASK_LOCATION, old state: {old_state}")
        return data

    @model_transition(State.AUTHORIZED, StateType.ENTER)
    def authorized(self, old_state: State, data: str):
        logger.debug(f"Transition: AUTHORIZED, old state: {old_state}")
        return data

    @model_transition(State.OAUTH_STARTED, StateType.ENTER)
    def start_oauth(self, old_state: State, url: str):
        logger.debug(f"Transition: OAUTH_STARTED, old state: {old_state}")
        self.open_browser(url)
        return url

    @model_transition(State.DISCONNECTED, StateType.ENTER)
    def parse_config(self, old_state: State, server):
        logger.debug(f"Transition: DISCONNECTED, old state: {old_state}")
        return server

    @run_in_background_thread("open-browser")
    def open_browser(self, url):
        logger.debug(f"Opening web browser with url: {url}")
        webbrowser.open(url)
        # Explicitly wait to not have zombie processes
        # See https://bugs.python.org/issue5993
        logger.debug("Running os.wait for browser")
        try:
            os.wait()
        except ChildProcessError:
            pass
        logger.debug("Done waiting for browser")

    @model_transition(State.CONNECTED, StateType.ENTER)
    def parse_connected(self, old_state: State, server):
        logger.debug(f"Transition: CONNECTED, old state: {old_state}")
        expire_times = parse_expiry(self.wrapper.get_expiry_times())
        return (server, expire_times)

    @model_transition(State.CONNECTING, StateType.ENTER)
    def parse_connecting(self, old_state: State, server):
        logger.debug(f"Transition: CONNECTING, old state: {old_state}")
        return server


class ApplicationModel:
    def __init__(
        self,
        common: EduVPN,
        machine: StateMachine,
        config,
        variant: ApplicationVariant,
        nm_manager,
    ) -> None:
        self.common = common
        self.config = config
        self.keyring: TokenKeyring = DBusKeyring(variant)
        if not self.keyring.available:
            self.keyring = InsecureFileKeyring(variant)
        self.machine = machine
        self.transitions = ApplicationModelTransitions(common, self.machine, variant)
        self.variant = variant
        self.nm_manager = nm_manager
        self.was_tcp = False

    def transition(self, old: State, new: State, data: str):
        logger.debug(f"Got transition from eduvpn-common: {old}, to: {new}")

        data_conv = data
        if new == State.MAIN:
            data_conv = self.server_db.configured

        if new == State.ASK_LOCATION:
            cookie, locations = parse_required_transition(data, get=parse_locations)
            set_location = lambda loc: self.common.cookie_reply(cookie, loc)
            data_conv = (set_location, locations)

        if new == State.ASK_PROFILE:
            cookie, profiles = parse_required_transition(data, get=parse_profiles)
            set_location = lambda loc: self.common.cookie_reply(cookie, loc)
            data_conv = (set_location, profiles)

        self.machine.go(new, data_conv, go_transition=True, needs_lock=False)

        if new == State.GOT_CONFIG:
            self.machine.go(State.DISCONNECTED, self.server_db.current, needs_lock=False)
        return True

    def register(self, debug: bool):
        self.common.register(handler=self.transition, debug=debug)
        self.common.set_token_handler(self.load_tokens, self.save_tokens)

    def cancel(self):
        # Cancel any eduvpn-common operation
        self.common.cancel()

        # Cancel any NetworkManager operation
        self.nm_manager.cancel()

    @property
    def server_db(self):
        return self.transitions.server_db

    @property
    def current_server(self):
        return self.server_db.current

    def get_failover_rx(self, filehandler: Optional[TextIO]) -> int:
        rx_bytes = self.nm_manager.get_stats_bytes(filehandler)
        if rx_bytes is None:
            return -1
        return rx_bytes

    def should_failover(self):
        current_vpn_protocol = self.nm_manager.protocol
        if current_vpn_protocol == "WireGuard":
            logger.debug("Current protocol is WireGuard, failover should continue")
            return True

        if not self.was_tcp:
            logger.debug(
                "Protocol is not WireGuard and TCP was not previously triggered, failover should continue"
            )
            return True

        logger.debug("Failover should not continue")
        return False

    def reconnect_tcp(self, callback: Callable):
        def on_reconnected():
            self.common.set_support_wireguard(has_wireguard)
            callback(True)

        has_wireguard = nm.is_wireguard_supported()

        # Disable wireguard
        self.common.set_support_wireguard(False)
        self.reconnect(on_reconnected, prefer_tcp=True)

    def start_failover(self, callback: Callable):
        try:
            rx_bytes_file = self.nm_manager.open_stats_file("rx_bytes")
            if rx_bytes_file is None:
                logger.debug(
                    "Failed to initialize failover, failed to open rx bytes file"
                )
                callback(False)
                return
            endpoint = self.nm_manager.failover_endpoint_ip
            if endpoint is None:
                logger.debug("Failed to initialize failover, failed to get endpoint")
                callback(False)
                return
            mtu = self.nm_manager.mtu
            if mtu is None:
                logger.debug("failed to get MTU for failover, setting MTU to 1000")
                mtu = 1000
            logger.debug(
                f"starting failover with gateway {endpoint} and MTU {mtu} for protocol {self.nm_manager.protocol}"
            )
            dropped = self.common.start_failover(
                endpoint,
                mtu,
                ReadRxBytes(lambda: self.get_failover_rx(rx_bytes_file)),
            )

            if dropped:
                logger.debug("Failover exited, connection is dropped")
                if self.is_connected():
                    self.reconnect_tcp(callback)
                    return
                # Dropped but not relevant anymore
                callback(False)
                return
            else:
                logger.debug("Failover exited, connection is NOT dropped")
                callback(False)
                return
        except WrappedError as e:
            logger.debug(f"Failed to start failover, error: {e}")
            callback(False)
            return

    def change_secure_location(self):
        # get secure location server
        server = self.server_db.secure_internet

        def choose_location(location: str):
            try:
                self.set_secure_location(location)
            except Exception as e:
                self.machine.go(State.MAIN)
                raise e
            else:
                self.machine.go(State.MAIN)

        if server is None:
            logger.error("got no server when changing secure location")
            return

        self.machine.go(State.ASK_LOCATION, (choose_location, server.locations))

    def set_secure_location(self, location_id: str):
        self.common.set_secure_location(location_id)

    def set_search_server(self):
        # TODO: Fill in discovery here
        self.machine.go(State.SEARCHING_SERVER)

    def go_back(self):
        self.cancel()
        self.machine.back()

    def add(self, server, callback=None):
        # TODO: handle discovery types
        with self.machine.lock:
            self.common.add_server(server.category_id, server.identifier)
        if callback:
            callback(server)

    def remove(self, server):
        self.common.remove_server(server.category_id, server.identifier)
        # Delete tokens from the keyring
        self.clear_tokens(server)
        self.machine.back()

    def connect_get_config(self, server, prefer_tcp: bool = False) -> Config:
        # We prefer TCP if the user has set it or UDP is determined to be blocked
        # TODO: handle discovery and tokens
        config = self.common.get_config(
            server.category_id, server.identifier, prefer_tcp
        )
        return parse_config(config)

    def clear_tokens(self, server):
        attributes = {
            "server": server.url,
            "category": server.category,
        }
        try:
            cleared = self.keyring.clear(attributes)
            if not cleared:
                logger.debug("Tokens were not cleared")
        except Exception as e:
            logger.debug("Failed clearing tokens with exception")
            logger.debug(e, exc_info=True)

    def load_tokens(self, server: str) -> Optional[str]:
        server_parsed = parse_current_server(server)
        if server_parsed is None:
            logger.warning("Got empty server, not loading tokens")
            return None
        attributes = {"server": server_parsed.url, "category": server_parsed.category}
        try:
            tokens_json = self.keyring.load(attributes)
            if tokens_json is None:
                logger.debug("No tokens available")
                return None
            tokens = json.loads(tokens_json)
            d = {
                "access_token": tokens["access"],
                "refresh_token": tokens["refresh"],
                "expires_in": int(tokens["expires"]),
            }
            return json.dumps(d)
        except Exception as e:
            logger.debug("Failed loading tokens with exception:")
            logger.debug(e, exc_info=True)
            return None

    def save_tokens(self, server: str, tokens: str):
        logger.debug("Save tokens called")
        server_parsed = parse_current_server(server)
        if server_parsed is None:
            logger.warning("Got empty server, not saving token to the keyring")
            return
        tokens_parsed = parse_tokens(tokens)
        if tokens is None or (
            tokens_parsed.access == "" and tokens_parsed.refresh == ""
        ):
            logger.warning("Got empty tokens, not saving them to the keyring")
            return
        tokens_dict = {}
        tokens_dict["access"] = tokens_parsed.access
        tokens_dict["refresh"] = tokens_parsed.refresh
        tokens_dict["expires"] = str(tokens_parsed.expires)
        attributes = {
            "server": server_parsed.url,
            "category": server_parsed.category,
        }
        label = f"{server_parsed.url} - OAuth Tokens"
        try:
            self.keyring.save(label, attributes, json.dumps(tokens_dict))
        except Exception as e:
            logger.error("Failed saving tokens with exception:")
            logger.error(e, exc_info=True)

    def connect(
        self,
        server,
        callback: Optional[Callable] = None,
        prefer_tcp: bool = False,
    ) -> None:
        # Variable to be used as a last resort or for debugging
        # to override the prefer TCP setting
        if os.environ.get("EDUVPN_PREFER_TCP", "0") == "1":
            prefer_tcp = True
        config = self.connect_get_config(server, prefer_tcp=prefer_tcp)
        if not config:
            logger.warning("no configuration available")
            if callback:
                callback(False)
            return

        def on_connected(success: bool):
            if success:
                self.set_connected()
            else:
                self.set_disconnected()
            if callback:
                callback(success)

        def on_connect(success: bool):
            if success:
                self.nm_manager.activate_connection(on_connected)
            else:
                self.set_disconnected()
                if callback:
                    callback(False)

        def connect(config):
            connection = Connection.parse(config)
            connection.connect(self.nm_manager, config.default_gateway, on_connect)

        self.set_connecting()
        connect(config)

    def reconnect(self, callback: Optional[Callable] = None, prefer_tcp: bool = False):
        def on_disconnected(success: bool):
            if success:
                self.activate_connection(callback, prefer_tcp=prefer_tcp)

        # Reconnect
        self.deactivate_connection(on_disconnected)

    # https://github.com/eduvpn/documentation/blob/v3/API.md#session-expiry
    def renew_session(self, callback: Optional[Callable] = None):
        was_connected = self.is_connected()

        def reconnect():
            # Delete the OAuth access and refresh token
            # Start the OAuth authorization flow
            self.common.renew_session()
            # Automatically reconnect to the server
            self.activate_connection(callback)

        if was_connected:
            # Call /disconnect and reconnect with callback
            self.deactivate_connection(reconnect)
        else:
            reconnect()

    def disconnect(self, callback: Optional[Callable] = None) -> None:
        self.nm_manager.deactivate_connection(callback)

    def set_profile(self, profile: str, connect=False):
        was_connected = self.is_connected()

        def do_profile(success: bool = True):
            if not success:
                return
            # Set the profile ID
            self.common.set_profile(profile)

            # Connect if we should and if we were previously connected
            if connect and was_connected:
                self.set_connecting()
                self.activate_connection()

        # Deactivate connection if we are connected
        # and the connection should be modified
        # the do_profile will be called in the callback
        if was_connected and connect:
            self.deactivate_connection(do_profile)
        else:
            do_profile()

    def activate_connection(
        self, callback: Optional[Callable] = None, prefer_tcp: bool = False
    ):
        if not self.machine.in_state(State.DISCONNECTED):
            return
        if not self.current_server:
            return

        def on_connected(success: bool):
            if callback:
                callback(success)

        self.connect(self.current_server, on_connected, prefer_tcp=prefer_tcp)


    @run_in_background_thread("cleanup")
    def cleanup(self):
        # We retry this cleanup 2 times
        retries = 2

        # Try to cleanup with a number of retries
        for i in range(retries):
            logger.debug("Cleaning up tokens...")
            try:
                self.common.cleanup()
            except Exception as e:
                # We can try again
                if i < retries - 1:
                    logger.debug(
                        f"Got an error while cleaning up, try number: {i+1}. This could mean the connection was not fully disconnected yet. Trying again..."
                    )
                else:
                    # All retries are done
                    logger.debug(
                        f"Got an error while cleaning up, after full retries: {i+1}."
                    )
            else:
                break

    def deactivate_connection(self, callback: Optional[Callable] = None) -> None:
        if not self.machine.in_state(State.CONNECTED):
            return
        self.set_disconnecting()

        @run_in_background_thread("on-disconnect-cleanup")
        def on_disconnect_success():
            # Cleanup the connection by sending / disconnect
            self.cleanup()
            self.set_disconnected()
            if callback:
                callback(True)

        def on_disconnected(success: bool):
            if success:
                on_disconnect_success()
            else:
                self.set_connected()
                if callback:
                    callback(False)
        self.disconnect(on_disconnected)

    def search_predefined(self, query: str) -> Iterator[Any]:
        return self.server_db.search_predefined(query)

    def search_custom(self, query: str) -> Iterator[Any]:
        return self.server_db.search_custom(query)

    def is_main(self) -> bool:
        return self.machine.current == State.MAIN

    def set_connected(self):
        self.machine.go(State.CONNECTED, self.server_db.current)

    def set_connecting(self):
        self.machine.go(State.CONNECTING, self.server_db.current)

    def set_disconnecting(self):
        self.machine.go(State.DISCONNECTING, self.server_db.current)

    def set_disconnected(self):
        self.machine.go(State.DISCONNECTED, self.server_db.current)

    def is_searching_server(self) -> bool:
        return self.machine.current == State.SEARCHING_SERVER

    def is_connecting(self) -> bool:
        return self.machine.current == State.CONNECTING

    def is_connected(self) -> bool:
        return self.machine.current == State.CONNECTED

    def is_disconnected(self) -> bool:
        return self.machine.current == State.DISCONNECTED

    def is_disconnecting(self) -> bool:
        return self.machine.current == State.DISCONNECTING

    def is_oauth_started(self) -> bool:
        return self.machine.current == State.OAUTH_STARTED


class Application:
    def __init__(
        self, variant: ApplicationVariant, wrapper: EduVPN, machine: StateMachine
    ) -> None:
        self.variant = variant
        self.nm_manager = nm.NMManager(variant)
        self.wrapper = wrapper
        self.machine = machine
        directory = variant.config_prefix
        self.config = Configuration.load(directory)
        self.model = ApplicationModel(
            wrapper, machine, self.config, variant, self.nm_manager
        )

        def signal_handler(_signal, _frame):
            if self.model.is_oauth_started():
                self.model.cancel()
            self.wrapper.deregister()
            sys.exit(1)

        signal.signal(signal.SIGINT, signal_handler)

    def on_network_update_callback(self, state, initial=False):
        try:
            if state == nm.ConnectionState.CONNECTED:
                try:
                    self.model.set_connecting()
                except Exception as e:
                    pass
                # Already connected
                self.model.set_connected()
            elif state == nm.ConnectionState.CONNECTING:
                self.model.set_connecting()
            elif state == nm.ConnectionState.DISCONNECTED:
                try:
                    self.model.set_disconnecting()
                except Exception as e:
                    pass
                self.model.set_disconnected()
        except Exception:
            return

    def initialize_network(self, needs_update=True) -> None:
        """
        Determine the current network state.
        """
        # Check if a previous network configuration exists.
        uuid = self.nm_manager.existing_connection
        if uuid:
            self.on_network_update_callback(
                self.nm_manager.connection_state, needs_update
            )

        @run_in_background_thread("on-network-update")
        def update(state):
            self.on_network_update_callback(state, False)

        self.nm_manager.subscribe_to_status_changes(update)
