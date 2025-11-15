from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.request
import socket
import threading
import time

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
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            print(f"✓ Pesan diterima: {data.get('type', 'unknown')}")
            
            # Callback untuk memproses pesan yang diterima
            if MessageRequestHandler.message_callback:
                response_data = MessageRequestHandler.message_callback(data)
            else:
                response_data = {'status': 'received'}
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())
        except Exception as e:
            print(f"Error handling POST request: {e}")
            self.send_response(500)
            self.end_headers()
    
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
        self.is_running = False
        
    def start_server(self, callback):
        """Memulai HTTP server"""
        MessageRequestHandler.message_callback = callback
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), MessageRequestHandler)
            self.is_running = True
            self.server_thread = threading.Thread(target=self._serve_forever, daemon=True)
            self.server_thread.start()
            print(f"✓ Server berjalan di {self.local_ip}:{self.port}")
        except Exception as e:
            print(f"✗ Gagal memulai server: {e}")
    
    def _serve_forever(self):
        """Serve forever"""
        while self.is_running:
            try:
                self.server.handle_request()
            except Exception as e:
                if self.is_running:  # Only log if we're supposed to be running
                    pass
    
    def send_message(self, target_ip, data):
        """Mengirim pesan ke device lain"""
        url = f'http://{target_ip}:{self.port}'
        headers = {'Content-Type': 'application/json'}
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                req = urllib.request.Request(url, json.dumps(data).encode('utf-8'), headers)
                response = urllib.request.urlopen(req, timeout=30)  # Increased timeout
                response_data = json.loads(response.read().decode('utf-8'))
                print(f"✓ Pesan berhasil dikirim ke {target_ip}")
                return response_data
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"⚠ Percobaan {attempt + 1} gagal, mencoba lagi...")
                    time.sleep(2)
                else:
                    raise Exception(f"Gagal mengirim pesan ke {target_ip} setelah {max_retries} percobaan: {e}")
    
    def stop_server(self):
        """Menghentikan server"""
        self.is_running = False
        if self.server:
            self.server.shutdown()
