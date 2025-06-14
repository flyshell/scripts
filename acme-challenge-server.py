#cat /usr/local/bin/acme-challenge-server.py 
#sudo chmod +x /usr/local/bin/acme-challenge-server.py
#sudo systemctl restart acme-challenge
#!/usr/bin/env python3
import http.server
import socketserver
import os

class ACMEHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/tmp/acme-challenge", **kwargs)
    
    def do_GET(self):
        if self.path.startswith('/.well-known/acme-challenge/'):
            # 提取 token
            token = self.path.split('/')[-1]
            challenge_file = f"/tmp/acme-challenge/{token}"
            
            if os.path.exists(challenge_file):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                with open(challenge_file, 'r') as f:
                    self.wfile.write(f.read().encode())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    PORT = 8888
    os.makedirs("/tmp/acme-challenge", exist_ok=True)
    
    with socketserver.TCPServer(("127.0.0.1", PORT), ACMEHandler) as httpd:
        print(f"ACME Challenge server serving at port {PORT}")
        httpd.serve_forever()
