import rsa
import des
from http_handler import HTTPCommunicator
import time

class DeviceKeyo:
    def __init__(self):
        self.name = "Keyo"
        self.private_key_str = "04050400"  # Private key Keyo (rahasia)
        self.communicator = HTTPCommunicator(port=8080)
        self.other_device_ip = None
        self.session_data = {}
        
    def load_private_key(self):
        """Load private key dari string"""
        p, q = 53, 61
        public_key, private_key = rsa.generate_keypair(p, q)
        self.public_key = public_key
        self.private_key = private_key
        print(f"✓ Private key loaded: {self.private_key}")
        print(f"✓ Public key: {self.public_key}")
        
    def read_public_key_from_directory(self, username):
        """Membaca public key dari public directory"""
        try:
            with open(f'public_directory/{username}.txt', 'r') as f:
                key_content = f.read().strip()
                print(f"✓ Public key {username} dari direktori: {key_content}")
                # Parse public key
                return rsa.parse_public_key(key_content)
        except FileNotFoundError:
            print(f"✗ File public key {username}.txt tidak ditemukan!")
            return None
        except Exception as e:
            print(f"✗ Error membaca public key: {e}")
            return None
    
    def handle_incoming_message(self, data):
        """Callback untuk menangani pesan masuk"""
        print("\n" + "="*60)
        print(f"📨 PESAN MASUK dari {data.get('sender', 'Unknown')}")
        print("="*60)
        
        msg_type = data.get('type')
        
        if msg_type == 'N1_N2_response':
            # Terima N1 plaintext dan N2 encrypted dari Putri
            print("Tipe: N1 (plaintext) dan N2 (encrypted) dari Putri")
            received_n1 = data['N1_plaintext']
            encrypted_n2 = data['N2_ciphertext']
            
            print(f"N1 plaintext diterima: {received_n1}")
            print(f"N1 asli              : {self.session_data.get('N1', '')}")
            
            # Verifikasi N1
            if received_n1 == self.session_data.get('N1'):
                print("✓ VERIFIKASI N1 BERHASIL! Putri terautentikasi!")
                
                # Dekripsi N2 dengan private key Keyo
                try:
                    decrypted_n2 = rsa.decrypt(self.private_key, encrypted_n2)
                    print(f"✓ Dekripsi N2 berhasil: {decrypted_n2}")
                    
                    # Kirim balik N2 plaintext ke Putri untuk verifikasi
                    print("\n📤 Mengirim N2 (plaintext) ke Putri untuk verifikasi...")
                    time.sleep(1)
                    
                    response = self.communicator.send_message(self.other_device_ip, {
                        'type': 'N2_plaintext',
                        'sender': self.name,
                        'N2_plaintext': decrypted_n2
                    })
                    
                    if response.get('status') == 'authenticated':
                        print("✓ Putri telah mengirim secret key!")
                        
                        # Dekripsi secret key
                        encrypted_secret = response['secret_key_encrypted']
                        secret_key = rsa.decrypt(self.private_key, encrypted_secret)
                        self.session_data['secret_key'] = secret_key
                        
                        print(f"✓ Secret key diterima: {secret_key}")
                        print("\n🎉 AUTENTIKASI SELESAI! Siap berkomunikasi dengan DES")
                        
                except Exception as e:
                    print(f"✗ Error: {e}")
            else:
                print("✗ VERIFIKASI N1 GAGAL!")
            
            return {'status': 'ok'}
        
        elif msg_type == 'des_message':
            # Terima pesan DES
            print("Tipe: Pesan DES")
            ciphertext = data['ciphertext']
            print(f"Ciphertext: {ciphertext}")
            
            # Dekripsi dengan secret key
            secret_key = self.session_data.get('secret_key')
            if secret_key:
                try:
                    plaintext = des.des_decrypt(ciphertext, secret_key)
                    print(f"✓ Plaintext: {plaintext}")
                    return {'status': 'received'}
                except Exception as e:
                    print(f"✗ Error dekripsi DES: {e}")
                    return {'status': 'error'}
        
        return {'status': 'ok'}
    
    def initiate_handshake(self):
        """Memulai handshake dengan mengirim N1 terenkripsi"""
        print("\n" + "="*60)
        print("🤝 MEMULAI HANDSHAKE")
        print("="*60)
        
        # Baca public key Putri dari direktori
        putri_public_key = self.read_public_key_from_directory('putri')
        
        if not putri_public_key:
            print("✗ Gagal membaca public key Putri!")
            return
        
        # Input N1
        n1_message = input("\n🔐 Masukkan pesan N1 untuk Putri: ")
        self.session_data['N1'] = n1_message
        
        # Enkripsi N1 dengan public key Putri
        print(f"\n🔒 Mengenkripsi N1 dengan public key Putri...")
        encrypted_n1 = rsa.encrypt(putri_public_key, n1_message)
        print(f"✓ N1 terenkripsi: {encrypted_n1}")
        
        # Kirim N1 terenkripsi ke Putri
        print("\n📤 Mengirim N1 terenkripsi ke Putri...")
        try:
            response = self.communicator.send_message(self.other_device_ip, {
                'type': 'N1_encrypted',
                'sender': self.name,
                'ciphertext': encrypted_n1
            })
            
            if response.get('status') == 'ok':
                print("✓ N1 berhasil dikirim!")
                print("⏳ Menunggu respons dari Putri...")
            
        except Exception as e:
            print(f"✗ Gagal mengirim N1: {e}")
    
    def send_des_message(self):
        """Mengirim pesan menggunakan DES"""
        secret_key = self.session_data.get('secret_key')
        if not secret_key:
            print("✗ Secret key belum tersedia! Lakukan handshake terlebih dahulu.")
            return
        
        plaintext = input("\n📝 Masukkan pesan (DES): ")
        
        # Enkripsi dengan DES
        ciphertext = des.des_encrypt(plaintext, secret_key)
        
        print(f"\n🔒 Plaintext : {plaintext}")
        print(f"🔒 Key      : {secret_key}")
        print(f"🔒 Ciphertext: {ciphertext}")
        
        # Kirim ke Putri
        try:
            response = self.communicator.send_message(self.other_device_ip, {
                'type': 'des_message',
                'sender': self.name,
                'ciphertext': ciphertext
            })
            print("✓ Pesan DES terkirim!")
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def run(self):
        """Menjalankan device"""
        print("="*60)
        print("DEVICE 2 - KEYO")
        print("="*60)
        
        # Load private key
        self.load_private_key()
        
        # Input IP device lain
        print(f"\nIP Address Keyo: {self.communicator.local_ip}")
        self.other_device_ip = input("Masukkan IP Address Putri (Device 1): ").strip()
        
        # Start server
        self.communicator.start_server(self.handle_incoming_message)
        
        print("\n✓ Keyo siap berkomunikasi")
        print("="*60)
        
        # Menu
        while True:
            print("\n[1] Mulai Handshake (kirim N1)")
            print("[2] Kirim pesan DES")
            print("[3] Keluar")
            choice = input("Pilih: ").strip()
            
            if choice == '1':
                self.initiate_handshake()
            elif choice == '2':
                self.send_des_message()
            elif choice == '3':
                break
            else:
                print("Pilihan tidak valid")
        
        self.communicator.stop_server()

if __name__ == "__main__":
    device = DeviceKeyo()
    device.run()