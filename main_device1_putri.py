import rsa
import des
from http_handler import HTTPCommunicator
import time

class DevicePutri:
    def __init__(self):
        self.name = "Putri"
        self.private_key_str = "23050400"  # Private key Putri (rahasia)
        self.communicator = HTTPCommunicator(port=8080)
        self.other_device_ip = None
        self.session_data = {}
        
    def load_private_key(self):
        """Load private key dari string"""
        p, q = 47, 59
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
        
        if msg_type == 'N1_encrypted':
            # Terima N1 terenkripsi dari Keyo
            print("Tipe: N1 (Challenge dari Keyo)")
            encrypted_n1 = data['ciphertext']
            print(f"Ciphertext N1: {encrypted_n1}")
            
            # Dekripsi dengan private key Putri
            try:
                decrypted_n1 = rsa.decrypt(self.private_key, encrypted_n1)
                print(f"✓ Dekripsi N1 berhasil: {decrypted_n1}")
                
                # Simpan N1
                self.session_data['N1'] = decrypted_n1
                
                # Generate N2
                n2_input = input("\n🔐 Masukkan pesan N2 untuk Keyo: ")
                self.session_data['N2'] = n2_input
                
                # Baca public key Keyo dari direktori
                keyo_public_key = self.read_public_key_from_directory('keyo')
                
                if keyo_public_key:
                    # Enkripsi N2 dengan public key Keyo
                    encrypted_n2 = rsa.encrypt(keyo_public_key, n2_input)
                    
                    # Kirim balik N1 plaintext dan N2 encrypted
                    print("\n📤 Mengirim N1 (plaintext) dan N2 (encrypted) ke Keyo...")
                    return {
                        'status': 'ok',
                        'type': 'N1_N2_response',
                        'sender': self.name,
                        'N1_plaintext': decrypted_n1,
                        'N2_ciphertext': encrypted_n2
                    }
                    
            except Exception as e:
                print(f"✗ Error: {e}")
                return {'status': 'error', 'message': str(e)}
        
        elif msg_type == 'N2_plaintext':
            # Terima N2 plaintext dari Keyo untuk verifikasi
            print("Tipe: N2 Plaintext (Verifikasi)")
            received_n2 = data['N2_plaintext']
            print(f"N2 diterima: {received_n2}")
            print(f"N2 asli    : {self.session_data.get('N2', '')}")
            
            # Verifikasi N2
            if received_n2 == self.session_data.get('N2'):
                print("✓ VERIFIKASI BERHASIL! Keyo terautentikasi!")
                
                # Generate secret key untuk DES
                secret_key = input("\n🔑 Masukkan Secret Key (8 karakter) untuk komunikasi DES: ")
                
                # Baca public key Keyo
                keyo_public_key = self.read_public_key_from_directory('keyo')
                
                if keyo_public_key:
                    # Enkripsi secret key dengan public key Keyo
                    encrypted_secret = rsa.encrypt(keyo_public_key, secret_key)
                    
                    # Simpan secret key
                    self.session_data['secret_key'] = secret_key
                    
                    print(f"✓ Secret key dienkripsi dan siap dikirim")
                    return {
                        'status': 'authenticated',
                        'type': 'secret_key',
                        'sender': self.name,
                        'secret_key_encrypted': encrypted_secret
                    }
            else:
                print("✗ VERIFIKASI GAGAL! N2 tidak cocok!")
                return {'status': 'verification_failed'}
        
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
    
    def send_des_message(self):
        """Mengirim pesan menggunakan DES"""
        secret_key = self.session_data.get('secret_key')
        if not secret_key:
            print("✗ Secret key belum tersedia!")
            return
        
        plaintext = input("\n📝 Masukkan pesan (DES): ")
        
        # Enkripsi dengan DES
        ciphertext = des.des_encrypt(plaintext, secret_key)
        
        print(f"\n🔒 Plaintext : {plaintext}")
        print(f"🔒 Key      : {secret_key}")
        print(f"🔒 Ciphertext: {ciphertext}")
        
        # Kirim ke Keyo
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
        print("DEVICE 1 - PUTRI")
        print("="*60)
        
        # Load private key
        self.load_private_key()
        
        # Input IP device lain
        print(f"\nIP Address Putri: {self.communicator.local_ip}")
        self.other_device_ip = input("Masukkan IP Address Keyo (Device 2): ").strip()
        
        # Start server
        self.communicator.start_server(self.handle_incoming_message)
        
        print("\n✓ Putri siap menerima pesan dari Keyo")
        print("="*60)
        
        # Menu
        while True:
            print("\n[1] Kirim pesan DES")
            print("[2] Keluar")
            choice = input("Pilih: ").strip()
            
            if choice == '1':
                self.send_des_message()
            elif choice == '2':
                break
            else:
                print("Pilihan tidak valid")
        
        self.communicator.stop_server()

if __name__ == "__main__":
    device = DevicePutri()
    device.run()