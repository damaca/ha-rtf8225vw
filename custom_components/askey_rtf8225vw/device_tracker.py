"""Support for Askey RTF8225VW Router (Smart Wifi 6 Go Movistar Spain)"""
from datetime import datetime
from requests.cookies import create_cookie
from urllib.parse import quote
from lxml import etree
import logging
import re
import requests

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import (CONF_HOST, CONF_PASSWORD)

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string
})


def get_scanner(hass, config):
    """Validate the configuration and return a scanner."""

    scanner = AskeyDeviceScanner(config[DOMAIN])
    return scanner if scanner.success_init else None


class AskeyDeviceScanner(DeviceScanner):
    """This class queries a Askey RTF8225VW Router (Smart Wifi 6 Go Movistar Spain)"""

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.password = config[CONF_PASSWORD]

        self.username = '1234'
        self.base_url = f'http://{self.host}'
        self.user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

        self.last_results = {}
        self.success_init = self._update_info()

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return self.last_results

    def get_device_name(self, device):
        """This router doesn't save the name of the wireless device."""
        return self.last_results.get(device)

    def _mess_userpass(s):
        return ''.join([chr(ord(c) ^ 0x1f) for c in s])

    def _update_info(self):
        """Ensure the information from the router is up to date.
        Return boolean if scanning successful.
        """
        _LOGGER.info('Checking Router')

        data = self.get_askey_info()
        if not data:
            return False

        self.last_results = data
        return True

    def get_askey_info(self):
        """Retrieve data from router."""

        base_headers = {
            "User-Agent": f"{self.user_agent}",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive"
        }

        headers = base_headers.copy()
        headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "es"
        })

        session = requests.Session()
        first_response = session.get(
            f"{self.base_url}/",
            headers=headers
        )

        if first_response.status_code != 200:
            _LOGGER.info('Error connecting to the router...')
            _LOGGER.info(f'First requests response: {first_response.status_code}')
            return None

        cookies = session.cookies.get_dict()

        data = {
            "curWebPage": "/te_wifi.asp",
            "loginUsername": f"{self._mess_userpass(self.username)}",
            "loginPassword": f"{self._mess_userpass(self.password)}"
        }

        headers = base_headers.copy()

        headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "es",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"{self.base_url}",
            "Referer": f"{self.base_url}/te_acceso_router.asp",
        })

        login_response = session.post(
            f"{self.base_url}/cgi-bin/te_acceso_router.cgi",
            data=data,
            headers=headers,
            cookies=cookies
        )

        if login_response.status_code != 200:
            _LOGGER.info('Error loging to the router...')
            _LOGGER.info(f'Login requests response: {login_response.status_code}')
            return None

        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='LoginName', value=quote(self._mess_userpass(self.username))))
        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='TimeOut', value='600'))
        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='LoginDate', value=quote(datetime.now().strftime('%m/%d'), safe='')))
        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='LoginTime', value=quote(datetime.now().strftime('%H:%M'))))
        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='LoginRole', value='admin'))
        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='SessionID', value='NotUsed'))
        session.cookies.set_cookie(create_cookie(domain=self.base_url, name='SessionStatus', value='Valid'))
        cookies = session.cookies.get_dict()

        headers = base_headers.copy()
        headers.update({
            "Accept": "application/xml, text/xml, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Accept-Language": "es",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"{self.base_url}",
            "Referer": f"{self.base_url}/hoststats.asp",
        })

        all_host_response = session.post(f"{self.base_url}/cgi-bin/cbGetLanHostList.xml", headers=headers, cookies=cookies)

        if all_host_response.status_code != 200:
            _LOGGER.info('Error getting devices from the router...')
            _LOGGER.info(f'Get devices requests response: {all_host_response.status_code}')
            return None

        root = etree.fromstring(all_host_response.content)

        hosts = root.findall('.//rtm_cfg_host')

        all_hosts = {}

        for host in hosts:
            mac = host.findtext('mac_addr')
            ipv4 = host.findtext('ipv4_addr')
            ipv6 = host.findtext('ipv6_addr')
            is_active = host.findtext('is_active')
            hostname = host.findtext('hostname')
            all_hosts[mac] = {
                'ipv4': ipv4,
                'ipv6': ipv6,
                'is_active': is_active,
                'hostname': hostname
            }

        headers = base_headers.copy()
        headers.update({
            "Accept": "application/xml, text/xml, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Accept-Language": "es",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": f"{self.base_url}",
            "Referer": f"{self.base_url}/dhcp.asp",
        })

        data = {
            "rtm_cfg_dhcpv4_svr_pool_id": "0",
            "all": "ALL"
        }

        response = session.post(f"{self.base_url}/cgi-bin/cbDhcpV4SvrPoolGetClt.xml", data=data, headers=headers, cookies=cookies)

        if response.status_code != 200:
            _LOGGER.info('Error getting devices from the router...')
            _LOGGER.info(f'Get devices requests response: {response.status_code}')
            return None

        devices = {}

        root = etree.fromstring(response.content)

        hosts = root.findall('.//rtm_dhcpv4_svr_pool_clt')

        for host in hosts:
            mac = host.findtext('mac_addr')
            is_active = host.findtext('is_active')
            extra = host.findall('rtm_dhcpv4_svr_pool_clt_addr')
            for e in extra:
                ip = e.findtext('ipv4_addr')
                lease_remaining = e.findtext('lease_remaining')

            hostname = ''
            if mac in all_hosts:
                hostname = all_hosts[mac]['hostname']

            devices[mac] = {
                'ipv4': ip,
                'is_active': is_active,
                'lease_remaining': lease_remaining,
                'hostname': hostname
            }

        session.close()
        _LOGGER.info('Got devices from the router')
        return devices
