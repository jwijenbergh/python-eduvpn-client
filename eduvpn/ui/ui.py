# eduvpngui - The GNU/Linux eduVPN GUI client
#
# Copyright: 2017-2020, The Commons Conservancy eduVPN Programme
# SPDX-License-Identifier: GPL-3.0+

from typing import Optional
import os
import webbrowser
import logging
import json
from gettext import gettext as _, ngettext
import time

import gi
gi.require_version('Gtk', '3.0')  # noqa: E402
gi.require_version('NM', '1.0')  # noqa: E402
from gi.repository import Gtk, GObject, GdkPixbuf

from ..settings import HELP_URL
from .. import network as network_state
from ..server import CustomServer, Profile
from ..app import Application
from ..nm import nm_available, nm_managed
from ..utils import (
    get_prefix, run_in_background_thread, run_in_main_gtk_thread, run_periodically, cancel_at_context_end)
from . import search
from .utils import show_ui_component, link_markup, show_error_dialog
from .stats import NetworkStats
import eduvpn_common.event as common

logger = logging.getLogger(__name__)


UPDATE_EXIPRY_INTERVAL = 1.  # seconds

RENEWAL_ALLOW_FRACTION = .8

# TODO: Go, implement get_validity_text

def get_template_path(filename: str) -> str:
    return os.path.join(get_prefix(), 'share/eduvpn/builder', filename)


class EduVpnGtkWindow(Gtk.ApplicationWindow):
    __gtype_name__ = "EduVpnGtkWindow"

    def __new__(cls, application: Application):
        builder = Gtk.Builder()
        builder.add_from_file(get_template_path('mainwindow.ui'))  # type: ignore
        window = builder.get_object('eduvpn')  # type: ignore
        window.setup(builder, application)  # type: ignore
        window.set_application(application)  # type: ignore
        return window

    def setup(self, builder, application: Application):
        self.app = application.app  # type: ignore
        self.common = application.common
        handlers = {
            "on_configure_settings": self.on_configure_settings,
            "on_get_help": self.on_get_help,
            "on_go_back": self.on_go_back,
            "on_add_other_server": self.on_add_other_server,
            "on_add_custom_server": self.on_add_custom_server,
            "on_cancel_oauth_setup": self.on_cancel_oauth_setup,
            "on_select_server": self.on_select_server,
            "on_search_changed": self.on_search_changed,
            "on_search_activate": self.on_search_activate,
            "on_switch_connection_state": self.on_switch_connection_state,
            "on_toggle_connection_info": self.on_toggle_connection_info,
            "on_profile_selection_changed": self.on_profile_selection_changed,
            "on_location_selection_changed": self.on_location_selection_changed,
            "on_acknowledge_error": self.on_acknowledge_error,
            "on_renew_session_clicked": self.on_renew_session_clicked,
            "on_config_force_tcp": self.on_config_force_tcp,
            "on_close_window": self.on_close_window,
        }
        builder.connect_signals(handlers)

        self.is_selected = False

        self.app_logo = builder.get_object('appLogo')

        self.page_stack = builder.get_object('pageStack')
        self.settings_button = builder.get_object('settingsButton')
        self.back_button_container = builder.get_object('backButtonEventBox')

        self.server_list_container = builder.get_object('serverListContainer')

        self.institute_list_header = builder.get_object('instituteAccessHeader')
        self.secure_internet_list_header = builder.get_object('secureInternetHeader')
        self.other_server_list_header = builder.get_object('otherServersHeader')

        self.institute_list = builder.get_object('instituteTreeView')
        self.secure_internet_list = builder.get_object('secureInternetTreeView')
        self.other_server_list = builder.get_object('otherServersTreeView')

        self.choose_profile_page = builder.get_object('chooseProfilePage')
        self.choose_location_page = builder.get_object('chooseLocationPage')
        self.location_list = builder.get_object('locationTreeView')
        self.profile_list = builder.get_object('profileTreeView')

        self.find_server_page = builder.get_object('findServerPage')
        self.find_server_search_form = builder.get_object('findServerSearchForm')
        self.find_server_search_input = builder.get_object('findServerSearchInput')
        self.find_server_image = builder.get_object('findServerImage')
        self.find_server_label = builder.get_object('findServerLabel')

        self.add_custom_server_button_container = builder.get_object('addCustomServerRow')
        self.add_other_server_button_container = builder.get_object('addOtherServerRow')

        self.connection_page = builder.get_object('connectionPage')
        self.connection_status_image = builder.get_object('connectionStatusImage')
        self.connection_status_label = builder.get_object('connectionStatusLabel')
        self.connection_session_label = builder.get_object('connectionSessionLabel')
        self.connection_switch = builder.get_object('connectionSwitch')
        self.connection_info_expander = builder.get_object('connectionInfoExpander')
        self.connection_info_downloaded = builder.get_object('connectionInfoDownloadedText')
        self.connection_info_uploaded = builder.get_object('connectionInfoUploadedText')
        self.connection_info_ipv4address = builder.get_object('connectionInfoIpv4AddressText')
        self.connection_info_ipv6address = builder.get_object('connectionInfoIpv6AddressText')
        self.connection_info_thread_cancel = None
        self.connection_info_stats = None

        self.server_image = builder.get_object('serverImage')
        self.server_label = builder.get_object('serverLabel')
        self.server_support_label = builder.get_object('supportLabel')

        self.renew_session_button = builder.get_object('renewSessionButton')

        self.oauth_page = builder.get_object('openBrowserPage')
        self.oauth_cancel_button = builder.get_object('cancelBrowserButton')

        self.settings_page = builder.get_object('settingsPage')
        self.setting_config_force_tcp = builder.get_object('settingConfigForceTCP')

        self.loading_page = builder.get_object('loadingPage')
        self.loading_title = builder.get_object('loadingTitle')
        self.loading_message = builder.get_object('loadingMessage')

        self.error_page = builder.get_object('errorPage')
        self.error_text = builder.get_object('errorText')
        self.error_acknowledge_button = builder.get_object('errorAcknowledgeButton')

        self.set_title(self.app.variant.name)  # type: ignore
        self.set_icon_from_file(self.app.variant.icon)  # type: ignore
        if self.app.variant.logo:
            self.app_logo.set_from_file(self.app.variant.logo)
        if self.app.variant.server_image:
            self.find_server_image.set_from_file(self.app.variant.server_image)
        if not self.app.variant.use_predefined_servers:
            self.find_server_label.set_text(_("Server address"))
            self.find_server_search_input.set_placeholder_text(_("Enter the server address"))

        # Track the currently shown page so we can return to it
        # when the settings page is closed.
        self.current_shown_page = None

        # We track the switch state so we can distinguish
        # the switch being set by the ui from the user toggling it.
        self.connection_switch_state: Optional[bool] = None

    def initialize(self):
        if not nm_available():
            show_error_dialog(
                self,
                name=_("Error"),
                title=_("NetworkManager not available"),
                message=_("The application will not be able to configure the network. Please install and set up NetworkManager."))
        elif not nm_managed():
            show_error_dialog(
                self,
                name=_("Error"),
                title=_("NetworkManager not managing device"),
                message=_("The application will not be able to configure the network. NetworkManager is installed but no device of the primary connection is currently managed by it."))
        self.common.register_class_callbacks(self)
        self.common.register(debug=True)

    # ui functions

    def show_back_button(self, show: bool):
        show_ui_component(self.back_button_container, show)

    def set_search_text(self, text: str):
        self.find_server_search_input.set_text(text)

    def show_loading_page(self, title: str, message: str):
        self.show_page(self.loading_page)
        self.loading_title.set_text(title)
        self.loading_message.set_text(message)

    def hide_loading_page(self):
        self.hide_page(self.loading_page)

    def set_connection_switch_state(self, state: bool):
        self.connection_switch_state = state
        self.connection_switch.set_state(state)

    def show_page(self, page):
        """
        Show a collection of pages.
        """
        self.page_stack.set_visible_child(page)
        self.current_shown_page = page

    def hide_page(self, page):
        """
        Show a collection of pages.
        """
        self.current_shown_page = None

    def is_on_settings_page(self) -> bool:
        return self.page_stack.get_visible_child() is self.settings_page

    def enter_settings_page(self):
        assert not self.is_on_settings_page()
        self.setting_config_force_tcp.set_state(self.app.config.force_tcp)
        self.page_stack.set_visible_child(self.settings_page)
        self.show_back_button(True)

    def leave_settings_page(self):
        assert self.is_on_settings_page()
        self.page_stack.set_visible_child(self.current_shown_page)
        # TODO: Implement show_back_button with Go

    # network state transition callbacks

    # Implement with Go callback
    def default_network_transition_callback(self, old_state, new_state):
        if isinstance(self.app.interface_state, interface_state.ConnectionStatus):
            self.update_connection_status()

    def update_connection_server(self):
        # TODO: Go, return early
        server = self.app.session_state.server

        self.server_label.set_text(str(server))

        server_image_path = getattr(server, 'image_path', None)
        if server_image_path:
            self.server_image.set_from_file(server_image_path)
            self.server_image.show()
        else:
            self.server_image.hide()

        if getattr(server, 'support_contact', []):
            support_text = _("Support:") + "\n" + "\n".join(map(link_markup, server.support_contact))
            self.server_support_label.set_markup(support_text)
            self.server_support_label.show()
        else:
            self.server_support_label.hide()

    def update_connection_validity(self):
        if isinstance(self.app.session_state,
                      (session_state.InitialSessionState,
                       session_state.NoSessionState)):
            self.connection_session_label.hide()
        else:
            expiry_text = "TODO: Implement"
            self.connection_session_label.show()
            self.connection_session_label.set_markup(expiry_text)

    def update_connection_status(self, connected):
        if connected:
            # TODO: Proper text?
            self.connection_status_label.set_text(_("Connected"))
            # TODO: Uncomment this
            #self.connection_status_image.set_from_file(self.app.network_state.status_image.path)
            self.set_connection_switch_state(True)
        else:
            # TODO: Proper text?
            self.connection_status_label.set_text(_("Disconnected"))
            # TODO: Uncomment this
            #self.connection_status_image.set_from_file(self.app.network_state.status_image.path)
            self.set_connection_switch_state(False)

    # session state transition callbacks

    # Implement with Go callback
    @run_in_main_gtk_thread
    @common.class_state_transition("Connected", common.StateType.Enter)
    def default_session_transition_callback(self, old_state, data):
        if old_state == "Has_Config":
            self.update_connection_status()

    # interface state transition callbacks

    # Implement with Go callback
    def default_interface_transition_callback(self, old_state, new_state):
        # Only show the 'go back' button if
        # the corresponding transition is available.
        # TODO: Replace with Go
        self.show_back_button(new_state.has_transition('go_back'))

    # TODO: Implement with Go callback
    @run_in_main_gtk_thread
    @common.class_state_transition("Search_Server", common.StateType.Enter)
    def enter_search(self, old_state: str, data: str):
        self.find_server_search_input.grab_focus()
        search.show_result_components(self, True)
        search.show_search_components(self, True)
        search.update_results(self, self.app.server_db.servers) 
        search.init_server_search(self)

    # TODO: Implement with Go callback
    @run_in_main_gtk_thread
    @common.class_state_transition("Search_Server", common.StateType.Leave)
    def exit_search(self, new_state: str, data: str):
        search.show_result_components(self, False)
        search.show_search_components(self, False)
        search.exit_server_search(self)
        self.set_search_text('')

    # TODO: Implement with Go callback
    def exit_ConfigureCustomServer(self, old_state, new_state):
        if not self.app.variant.use_predefined_servers:
            self.add_custom_server_button_container.hide()

    @run_in_main_gtk_thread
    @common.class_state_transition("No_Server", common.StateType.Enter)
    def enter_MainState(self, old_state: str, servers: str):
        search.show_result_components(self, True)
        disco_orgs = self.common.get_disco_organizations()
        disco_servers = self.common.get_disco_servers()
        self.app.server_db.disco_parse(disco_orgs, disco_servers)
        self.add_other_server_button_container.show()
        search.update_results(self, self.app.server_db.configured) 
        search.init_server_search(self)

    @run_in_main_gtk_thread
    @common.class_state_transition("No_Server", common.StateType.Leave)
    def exit_MainState(self, old_state, new_state):
        search.show_result_components(self, False)
        self.add_other_server_button_container.hide()
        search.exit_server_search(self)

    @run_in_background_thread('browser-open')
    def open_browser(self, url):
        webbrowser.open(url)

    @run_in_main_gtk_thread
    @common.class_state_transition("OAuth_Started", common.StateType.Enter)
    def enter_oauth_setup(self, old_state, url):
        self.show_page(self.oauth_page)
        self.open_browser(url)
        self.oauth_cancel_button.show()

    # TODO: Implement with Go callback
    @run_in_main_gtk_thread
    @common.class_state_transition("OAuth_Started", common.StateType.Leave)
    def exit_oauth_setup(self, old_state, data):
        self.hide_page(self.oauth_page)
        self.oauth_cancel_button.hide()

    @run_in_main_gtk_thread
    @common.class_state_transition("Authorized", common.StateType.Enter)
    def enter_OAuthRefreshToken(self, new_state, data):
        self.show_loading_page(
            _("Finishing Authorization"),
            _("The authorization token is being finished."),
        )

    @run_in_main_gtk_thread
    @common.class_state_transition("Authorized", common.StateType.Leave)
    def exit_OAuthRefreshToken(self, old_state, data):
        self.hide_loading_page()

    @run_in_main_gtk_thread
    @common.class_state_transition("Chosen_Server", common.StateType.Enter)
    def enter_LoadingServerInformation(self, new_state, data):
        self.show_loading_page(
            _("Loading"),
            _("The server details are being loaded."),
        )

    @run_in_main_gtk_thread
    @common.class_state_transition("Chosen_Server", common.StateType.Leave)
    def exit_LoadingServerInformation(self, old_state, data):
        self.hide_loading_page()

    @run_in_main_gtk_thread
    @common.class_state_transition("Ask_Profile", common.StateType.Enter)
    def enter_ChooseProfile(self, new_state, profiles_json):
        self.show_page(self.choose_profile_page)
        self.profile_list.show()

        profile_tree_view = self.profile_list
        profiles_list_model = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_PYOBJECT)

        if len(profile_tree_view.get_columns()) == 0:
            # Only initialize this tree view once.
            text_cell = Gtk.CellRendererText()
            text_cell.set_property("size-points", 14)

            column = Gtk.TreeViewColumn(None, text_cell, text=0)
            profile_tree_view.append_column(column)

        profile_tree_view.set_model(profiles_list_model)
        profiles_list_model.clear()
        profiles_parsed = json.loads(profiles_json)['info']['profile_list']
        profiles = []
        for profile in profiles_parsed:
            profiles.append(Profile(**profile))
        for profile in profiles:
            profiles_list_model.append([str(profile), profile])

    @run_in_main_gtk_thread
    @common.class_state_transition("Ask_Profile", common.StateType.Leave)
    def exit_ChooseProfile(self, old_state, data):
        self.hide_page(self.choose_profile_page)
        self.profile_list.hide()

    # TODO: Implement with Go callback
    def enter_ChooseSecureInternetLocation(self, old_state, new_state):
        self.show_page(self.choose_location_page)
        self.location_list.show()

        location_tree_view = self.location_list
        location_list_model = Gtk.ListStore(GObject.TYPE_STRING, GdkPixbuf.Pixbuf, GObject.TYPE_PYOBJECT)

        if len(location_tree_view.get_columns()) == 0:
            # Only initialize this tree view once.
            text_cell = Gtk.CellRendererText()
            text_cell.set_property("size-points", 14)

            renderer_pixbuf = Gtk.CellRendererPixbuf()
            column = Gtk.TreeViewColumn("Image", renderer_pixbuf, pixbuf=1)
            location_tree_view.append_column(column)

            column = Gtk.TreeViewColumn(None, text_cell, text=0)
            location_tree_view.append_column(column)

            location_tree_view.set_model(location_list_model)

        location_list_model.clear()
        for location in new_state.locations:
            if location.flag_path is None:
                logger.warning(f"No flag found for country code {location.country_code}")
                flag = None
            else:
                flag = GdkPixbuf.Pixbuf.new_from_file(location.flag_path)
            location_list_model.append([location.country_name, flag, location])

    # TODO: Implement with Go callback
    def exit_ChooseSecureInternetLocation(self, old_state, new_state):
        self.hide_page(self.choose_location_page)
        self.location_list.hide()

    # TODO: Implement with Go callback
    def enter_ConfiguringConnection(self, old_state, new_state):
        self.show_loading_page(
            _("Configuring"),
            _("Your connection is being configured."),
        )

    # TODO: Implement with Go callback
    def exit_ConfiguringConnection(self, old_state, new_state):
        self.hide_loading_page()

    # TODO: Implement with Go callback
    @run_in_main_gtk_thread
    @common.class_state_transition("Connected", common.StateType.Enter)
    def enter_ConnectedState(self, old_state, data):
        is_expanded = self.connection_info_expander.get_expanded()
        if is_expanded:
            self.start_connection_info()

    # TODO: Implement with Go callback
    @run_in_main_gtk_thread
    @common.class_state_transition("Has_Config", common.StateType.Enter)
    def enter_ConnectionStatus(self, old_state, new_state):
        self.show_page(self.connection_page)
        self.update_connection_server()
        self.update_connection_status()

    @run_in_main_gtk_thread
    @common.class_state_transition("Has_Config", common.StateType.Leave)
    def exit_ConnectionStatus(self, old_state, new_state):
        self.hide_page(self.connection_page)
        self.pause_connection_info()

    # TODO: Implement with Go callback
    def context_ConnectionStatus(self, state):
        return cancel_at_context_end(run_periodically(
            run_in_main_gtk_thread(self.update_connection_validity),
            UPDATE_EXIPRY_INTERVAL,
            'update-validity',
        ))

    # TODO: Implement with Go callback
    def enter_DisconnectedState(self, old_state, new_state):
        self.stop_connection_info()

    # TODO: Implement with Go callback
    def enter_ErrorState(self, old_state, new_state):
        self.show_page(self.error_page)
        self.error_text.set_text(new_state.message)
        has_next_transition = new_state.next_transition is not None
        show_ui_component(self.error_acknowledge_button, has_next_transition)

    # TODO: Implement with Go callback
    def exit_ErrorState(self, old_state, new_state):
        self.hide_page(self.error_page)

    # ui callbacks

    def on_configure_settings(self, widget, event):
        logger.debug("clicked on configure settings")
        if self.is_on_settings_page():
            self.leave_settings_page()
        else:
            self.enter_settings_page()

    def on_get_help(self, widget, event):
        logger.debug("clicked on get help")
        webbrowser.open(HELP_URL)

    def on_go_back(self, widget, event):
        logger.debug("clicked on go back")
        if self.is_on_settings_page():
            self.leave_settings_page()
        else:
            self.app.interface_transition('go_back')

    def on_add_other_server(self, button) -> None:
        logger.debug("clicked on add other server")
        self.common.set_search_server()
        #self.app.interface_transition('configure_new_server')

    def on_add_custom_server(self, button) -> None:
        logger.debug("clicked on add custom server")
        server = CustomServer(self.app.interface_state.address)
        self.app.interface_transition('connect_to_server', server)

    def on_server_row_activated(self, widget, row, col):
        model = widget.get_model()
        server = model[row][1]
        logger.debug(f"activated server: {server!r}")
        self.app.server_db.connect(self.common, server)

    def on_cancel_oauth_setup(self, _):
        logger.debug("clicked on cancel oauth setup")
        self.common.cancel_oauth()

    def on_search_changed(self, _=None):
        query = self.find_server_search_input.get_text()
        logger.debug(f"entered server search query: {query}")
        if self.app.variant.use_predefined_servers and query.count('.') < 2:
            results = self.app.server_db.search_predefined(query)
            search.update_results(self, results)
        else:
            # Anything with two periods is interpreted
            # as a custom server address.
            results = self.app.server_db.search_custom(query)
            search.update_results(self, results)

    def on_search_activate(self, _=None):
        logger.debug("activated server search")
        # TODO

    def on_switch_connection_state(self, switch, state):
        logger.debug("clicked on switch connection state")
        if state is not self.connection_switch_state:
            self.connection_switch_state = state
            # The user has toggled the connection switch,
            # as opposed to the ui itself setting it.
            if state:
                self.app.interface_transition('activate_connection')
            else:
                self.app.interface_transition('deactivate_connection')
        return True

    def pause_connection_info(self):
        if self.connection_info_thread_cancel:
            self.connection_info_thread_cancel()
            self.connection_info_thread_cancel = None

    def stop_connection_info(self):
        # Pause the thread
        self.pause_connection_info()

        # Further cleanup
        if self.connection_info_stats:
            self.connection_info_stats.cleanup()
            self.connection_info_stats = None

    def start_connection_info(self):
        if not self.app.network_state.has_transition('disconnect'):
            logger.info("Connection Info: VPN is not active")
            return

        def update_connection_info_callback():
            # Do nothing if we have no stats object
            if not self.connection_info_stats:
                return
            download = self.connection_info_stats.download
            upload = self.connection_info_stats.upload
            ipv4 = self.connection_info_stats.ipv4
            ipv6 = self.connection_info_stats.ipv6
            self.connection_info_downloaded.set_text(download)
            self.connection_info_uploaded.set_text(upload)
            self.connection_info_ipv4address.set_text(ipv4)
            self.connection_info_ipv6address.set_text(ipv6)

        if not self.connection_info_stats:
            self.connection_info_stats = NetworkStats()

        if not self.connection_info_thread_cancel:
            # Run every second in the background
            self.connection_info_thread_cancel = run_periodically(
                update_connection_info_callback, 1
            )

    def on_toggle_connection_info(self, _):
        logger.debug("clicked on connection info")
        was_expanded = self.connection_info_expander.get_expanded()

        if not was_expanded:
            self.start_connection_info()
        else:
            self.pause_connection_info()

    def on_profile_selection_changed(self, selection):
        logger.debug("selected profile")
        (model, tree_iter) = selection.get_selected()
        selection.unselect_all()
        if tree_iter is None:
            logger.debug("selection empty")
        else:
            row = model[tree_iter]
            profile = row[1]
            logger.debug(f"selected profile: {profile!r}")
            self.common.set_profile(profile.id)

    def on_location_selection_changed(self, selection):
        logger.debug("selected location")
        (model, tree_iter) = selection.get_selected()
        selection.unselect_all()
        if tree_iter is None:
            logger.debug("selection empty")
        else:
            row = model[tree_iter]
            location = row[2]
            logger.debug(f"selected location: {location!r}")
            self.app.interface_transition('select_secure_internet_location', location)

    def on_acknowledge_error(self, event):
        logger.debug("clicked on acknowledge error")
        self.app.interface_transition('acknowledge_error')

    def on_renew_session_clicked(self, event):
        logger.debug("clicked on renew session")
        self.app.session_transition('renew')

    def on_config_force_tcp(self, switch, state: bool):
        logger.debug("clicked on setting: 'force tcp'")
        self.app.config.force_tcp = state

    def on_close_window(self, window, event):
        logger.debug("clicked on close window")
        self.hide()
        self.get_application().on_window_closed()
        return True

    def on_reopen_window(self):
        self.app.interface_transition('restart')
        self.show()
        self.present()
