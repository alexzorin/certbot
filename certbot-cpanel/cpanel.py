"""cPanel (UAPI) plugin implementing an HTTP-based authenticator and installer.

"""
import zope.interface

import logging

from certbot import interfaces
from certbot.plugins import common
from certbot import util

from acme import challenges
from uapi import UAPIClient
import os

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator, interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Configurator(common.Plugin):
    """cPanel HTTP Authenticator."""

    description = "Obtains certificates using the HTTP challenge & the cPanel UAPI"
    client = None
    vhosts = None
    installed_vhosts = None

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin uses the cPanel UAPI to configure an HTTP file.'

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Configurator, cls).add_parser_arguments(add)
        add('server', help='cPanel hostname (e.g. server1.secureserver.net).')
        add('username', help='cPanel username.')
        add('password', help='cPanel password.')

    def prepare(self):  # pylint: disable=missing-docstring
        if not self.conf('server') or not self.conf('username') or not self.conf('password'):
            raise RuntimeError(
                'cPanel server, username and password must be provided')

        self.client = UAPIClient(self.conf('server'), self.conf(
            'username'), self.conf('password'), insecure_verify=False)
        self.vhosts = self.client.domains_data()
        self.installed_vhosts = []

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []

        for achall in achalls:
            logger.debug('Authenticating %s', achall.domain)

            vhost = self._find_vhost_for_domain(achall.domain)
            if vhost is None:
                raise RuntimeError(
                    "Could not find a virtual host with the domain: {}", achall.domain)

            doc_root = vhost['documentroot']
            logger.debug("%s's document root is %s", achall.domain, doc_root)

            resp, validation = achall.response_and_validation()

            # So apparently os.path.join is hopeless
            dest_dir = doc_root + os.path.dirname(achall.chall.path)
            dest_file = os.path.basename(achall.chall.path)
            logger.debug("Will deloy challenge file to: %s",
                         os.path.join(dest_dir, dest_file))

            self.client.upload_file(
                dest_dir, dest_file, validation)

            responses.append(resp)

        return responses

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            vhost = self._find_vhost_for_domain(achall.domain)
            if vhost is None:
                continue

            to_rm = vhost['documentroot'] + achall.chall.path
            logger.debug('Will clean up %s', to_rm)
            try:
                self.client.delete_file(to_rm)
            except:
                # This errors even when it's successful ...
                pass

        return None

    def get_chall_pref(self, unused_domain):  # pylint: disable=missing-docstring,no-self-use
        return [challenges.HTTP01]

    def get_all_names(self):  # pylint: disable=missing-docstring
        all_names = set()
        for vhost in self.vhosts['data']:
            all_names.add(vhost['servername'])
            for alias in vhost['serveralias'].split():
                all_names.add(alias)
        return util.get_filtered_names(all_names)

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        vhost = self._find_vhost_for_domain(domain)
        if not vhost:
            raise RuntimeError("No vhost could be located for {}", domain)

        if vhost['domain'] in self.installed_vhosts:
            logger.debug('We already replaced the certificate for %s, skipping %s', vhost['domain'], domain)
            return

        with open(cert_path, 'r') as c, open(key_path, 'r') as k, open(chain_path, 'r') as b:
            self.client.install_ssl(
                vhost['domain'], c.read(), k.read(), b.read())
            self.installed_vhosts.append(vhost['domain'])

        return None

    def _find_vhost_for_domain(self, domain):
        """
        Identifies which virtual host a domain belongs to, given a domains_data response
        """

        return [vhost for vhost in self.vhosts['data']
                if vhost['servername'] == domain or domain in vhost['serveralias'].split()][0]

    def view_config_changes(self):
        """ Not applicable for a cPanel service """
        return None

    def supported_enhancements(self):
        """ Not applicable for a cPanel service """
        return []

    def config_test(self):
        """ Not applicable for a cPanel service """
        return None

    def recovery_routine(self):
        """ Not applicable for a cPanel service """
        return None

    def enhance(self, domain, enh, options=None):
        """ Not applicable for a cPanel service """

    def save(self, title=None, temporary=False):
        """ Not applicable for a cPanel service """

    def rollback_checkpoints(self, rollback=1):
        """ Not applicable for a cPanel service """

    def restart(self):
        """ Not applicable for a cPanel service """
