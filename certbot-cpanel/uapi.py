import requests
from requests.auth import HTTPBasicAuth
from urllib import urlencode


class UAPIClient(object):
    """
    Implements an HTTP client to cPanel's UAPI json-api.
    https://documentation.cpanel.net/display/DD/Guide+to+UAPI
    """

    def __init__(self, hostname, username, password, insecure_verify=False):
        self.hostname = hostname
        self.insecure_verify = insecure_verify
        self.auth = HTTPBasicAuth(username, password)

    def uapi(self, module, method, args, body=None, files=None):
        """
        Performs an authenticated UAPI API request against a cPanel server.
        """
        url = "https://{}:2083/execute/{}/{}?{}".format(
            self.hostname, module, method, urlencode(args))

        return self._post_request(url, data=body, files=files, auth=self.auth)

    def api2(self, module, method, args):
        """
        Performs an authenticated API2 request against a cPanel server.
        Should generally not be used unless no available UAPI equivalent.
        """
        legacy_args = {
            'cpanel_jsonapi_user': self.auth.username,
            'cpanel_jsonapi_apiversion': '2',
            'cpanel_jsonapi_module': module,
            'cpanel_jsonapi_func': method
        }
        args_to_send = args.copy()
        args_to_send.update(legacy_args)

        url = "https://{}:2083/json-api/cpanel?{}".format(
            self.hostname, urlencode(args_to_send))

        return self._post_request(url, data=None, files=None, auth=self.auth)

    def _post_request(self, url, data, files, auth):
        resp = requests.post(url, data=data, files=files, auth=auth)
        resp.raise_for_status()

        as_json = resp.json()
        if as_json['status'] != 1:
            raise RuntimeError("cPanel request failed: {}", resp.text)

        return as_json

    def domains_data(self):
        """
        Retrieves the list of vhosts on the cPanel account.
        https://documentation.cpanel.net/display/DD/UAPI+Functions+-+DomainInfo%3A%3Adomains_data#e84d93922a3442f784251cbbf1d024e6
        """
        return self.uapi('DomainInfo', 'domains_data', {'format': 'list'})

    def upload_file(self, dest_dir, file_name, file_contents):
        """
        Performs a file upload using FileMan::upload_files
        https://documentation.cpanel.net/display/DD/UAPI+Functions+-+Fileman%3A%3Aupload_files
        """
        return self.uapi('Fileman', 'upload_files',
                         {'dir': dest_dir, 'file-1': file_name}, files={file_name: file_contents})

    def delete_file(self, path):
        """
        Performs a file deletion using API2 Fileman::fileop
        https://documentation.cpanel.net/display/DD/cPanel+API+2+Functions+-+Fileman%3A%3Afileop
        """
        return self.api2('Fileman', 'fileop', {
            'op': 'trash',
            'sourcefiles': path
        })
    
    def install_ssl(self, domain, cert, key, bundle):
        """
        Performs installation of an SSL certificate using UAPI SSL::install_ssl
        https://documentation.cpanel.net/display/DD/UAPI+Functions+-+SSL%3A%3Ainstall_ssl
        """
        return self.uapi('SSL', 'install_ssl', {
            'domain': domain,
            'cert': cert,
            'key': key,
            'cabundle': bundle
        })