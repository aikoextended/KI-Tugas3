from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.request
import socket
import threading

def get_local_ip():
    """Mendapatkan IP address lokal"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

class MessageRequestHandler(BaseHTTPRequestHandler):
    """Handler untuk menerima HTTP POST request"""
    
    message_callback = None
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))
        
        # Callback untuk memproses pesan yang diterima
        if MessageRequestHandler.message_callback:
            response_data = MessageRequestHandler.message_callback(data)
        else:
            response_data = {'status': 'received'}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode())
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

class HTTPCommunicator:
    """Class untuk menangani komunikasi HTTP"""
    
    def __init__(self, port=8080):
        self.port = port
        self.local_ip = get_local_ip()
        self.server = None
        self.server_thread = None
        
    def start_server(self, callback):
        """Memulai HTTP server"""
        MessageRequestHandler.message_callback = callback
        self.server = HTTPServer((self.local_ip, self.port), MessageRequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        print(f"✓ Server berjalan di {self.local_ip}:{self.port}")
    
    def send_message(self, target_ip, data):
        """Mengirim pesan ke device lain"""
        url = f'http://{target_ip}:{self.port}'
        headers = {'Content-Type': 'application/json'}
        
        try:
            req = urllib.request.Request(url, json.dumps(data).encode('utf-8'), headers)
            response = urllib.request.urlopen(req, timeout=10)
            response_data = json.loads(response.read().decode('utf-8'))
            return response_data
        except Exception as e:
            raise Exception(f"Gagal mengirim pesan: {e}")
    
    def stop_server(self):
        """Menghentikan server"""
        if self.server:
            self.server.shutdown()