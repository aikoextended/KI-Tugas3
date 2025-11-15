# main_device1_putri.py - DEVICE 1 (Putri)

import rsa
import des
from http_handler import HTTPCommunicator
import time

class DevicePutri:
    def __init__(self):
        self.name = "Putri"
        self.private_key = None
        self.public_key = None
        self.communicator = HTTPCommunicator(port=8080)
        self.other_device_ip = None
        self.session_data = {}
        self.handshake_stage = 0
        self.des_mode = False
        self.is_initiator = False
        
    def load_keys(self):
        """Load private dan public key"""
        # Gunakan bilangan prima yang lebih besar
        p, q = 101, 103  # n = 10403
        self.public_key, self.private_key = rsa.generate_keypair(p, q)
        print(f"✓ Key pair loaded - n: {self.public_key[1]}")
        
    def read_public_key_from_directory(self, username):
        """Membaca public key dari public directory"""
        try:
            with open(f'public_directory/{username.lower()}.txt', 'r') as f:
                key_content = f.read().strip()
                print(f"✓ Public key {username} ditemukan: {key_content}")
                return rsa.parse_public_key(key_content)
        except:
            print(f"✗ File public_directory/{username.lower()}.txt tidak ditemukan!")
            return None
    
    def handle_incoming_message(self, data):
        """Callback untuk menangani pesan masuk"""
        msg_type = data.get('type')
        
        if msg_type == 'N1_encrypted':
            if self.is_initiator:
                print("✗ Sudah menjadi initiator, tidak bisa menerima N1")
                return {'status': 'error'}
                
            print("\n" + "="*50)
            print("Pesan Dari " + data.get('sender', 'Unknown'))
            print("="*50)
            encrypted_n1 = data['ciphertext']
            print(f"N1 Ciphertext: {encrypted_n1}")
            
            print("\nDeskripsi N1")
            
            try:
                decrypted_n1 = rsa.decrypt(self.private_key, encrypted_n1)
                print(f"N1 Plaintext: {decrypted_n1}")
                self.session_data['N1_received'] = decrypted_n1
                self.handshake_stage = 2
                print("✓ N1 berhasil didekripsi. Silakan pilih menu [2] untuk melanjutkan.")
                
            except Exception as e:
                print(f"✗ Error dekripsi N1: {e}")
            
            return {'status': 'received'}
        
        elif msg_type == 'N1_N2_response':
            if not self.is_initiator:
                print("✗ Bukan initiator, tidak bisa menerima N1_N2 response")
                return {'status': 'error'}
                
            print("\n" + "="*50)
            print("Pesan Dari " + data.get('sender', 'Unknown'))
            print("="*50)
            received_n1 = data['N1_plaintext']
            encrypted_n2 = data['N2_ciphertext']
            
            print(f"N1 Plaintext: {received_n1}")
            print(f"N2 Ciphertext: {encrypted_n2}")
            
            stored_n1 = self.session_data.get('N1_sent', '')
            print(f"Memverifikasi N1: '{received_n1}' == '{stored_n1}'")
            
            if received_n1 == stored_n1:
                print(f"✓ VERIFIKASI N1 BERHASIL! {data.get('sender', '')} terautentikasi!")
                
                print("\nDeskripsi N2")
                
                try:
                    decrypted_n2 = rsa.decrypt(self.private_key, encrypted_n2)
                    print(f"N2 Plaintext: {decrypted_n2}")
                    self.session_data['N2_received'] = decrypted_n2
                    self.handshake_stage = 3
                    print("✓ N2 berhasil didekripsi. Silakan pilih menu [3] untuk melanjutkan.")
                    
                except Exception as e:
                    print(f"✗ Error dekripsi N2: {e}")
            else:
                print(f"✗ VERIFIKASI N1 GAGAL! Diterima: '{received_n1}', Diharapkan: '{stored_n1}'")
            
            return {'status': 'received'}
        
        elif msg_type == 'N2_plaintext':
            if self.is_initiator:
                print("✗ Initiator tidak bisa menerima N2 plaintext")
                return {'status': 'error'}
                
            print("\n" + "="*50)
            print("Pesan Dari " + data.get('sender', 'Unknown'))
            print("="*50)
            received_n2 = str(data['N2_plaintext'])
            print(f"N2 Plaintext: {received_n2}")
            
            stored_n2 = str(self.session_data.get('N2_sent', ''))
            print(f"Memverifikasi N2: '{received_n2}' == '{stored_n2}'")
            
            if received_n2 == stored_n2:
                print(f"✓ VERIFIKASI N2 BERHASIL! {data.get('sender', '')} terautentikasi!")
                self.handshake_stage = 4
                print("✓ Verifikasi berhasil. Silakan pilih menu [4] untuk mengirim Secret Key.")
            else:
                print(f"✗ VERIFIKASI N2 GAGAL! Diterima: '{received_n2}', Diharapkan: '{stored_n2}'")
            
            return {'status': 'received'}
        
        elif msg_type == 'secret_key':
            if not self.is_initiator:
                print("✗ Bukan initiator, tidak bisa menerima secret key")
                return {'status': 'error'}
                
            # Secret key sekarang dikirim sebagai plaintext
            secret_key = data['secret_key']
            self.session_data['secret_key'] = secret_key
            print(f"\n✓ Secret Key: {secret_key}")
            print("🔐 Saat ini komunikasi dilakukan menggunakan Algoritma DES")
            self.des_mode = True
            print("✓ Secret Key berhasil diterima. Silakan kirim pesan DES.")
            
            return {'status': 'received'}
        
        elif msg_type == 'des_message':
            if not self.des_mode:
                print("🔐 Saat ini komunikasi dilakukan menggunakan Algoritma DES")
                self.des_mode = True
            
            print("\n" + "="*50)
            print("Pesan dari " + data.get('sender', 'Unknown'))
            print("="*50)
            ciphertext = data['ciphertext']
            print(f"Ciphertext: {ciphertext}")
            
            secret_key = self.session_data.get('secret_key')
            if secret_key:
                print(f"🔑 Secret Key: {secret_key}")
                try:
                    plaintext = des.des_decrypt(ciphertext, secret_key)
                    print(f"📝 Plaintext: {plaintext}")
                except Exception as e:
                    print(f"✗ Error dekripsi: {e}")
            else:
                print("✗ Secret key belum tersedia!")
            
            return {'status': 'received'}
        
        return {'status': 'ok'}
    
    def send_n1_encrypted(self):
        """Menu 1: Kirim N1 encrypted"""
        if self.is_initiator:
            print("✗ Sudah menjadi initiator, tidak bisa mengirim N1 lagi")
            return
            
        print("\n--- Kirim N1 Encrypted ---")
        other_name = input("Public key (nama device penerima): ")
        other_public_key = self.read_public_key_from_directory(other_name)
        
        if not other_public_key:
            return
        
        n1_plain = input("Kirim N1 Plaintext: ")
        # VALIDASI KHUSUS: N1 harus 1 karakter
        if len(n1_plain) != 1:
            print("✗ N1 harus 1 karakter!")
            return
            
        self.session_data['N1_sent'] = n1_plain
        
        try:
            encrypted_n1 = rsa.encrypt(other_public_key, n1_plain)
            print(f"N1 Ciphertext: {encrypted_n1}")
            
            self.communicator.send_message(self.other_device_ip, {
                'type': 'N1_encrypted',
                'sender': self.name,
                'ciphertext': encrypted_n1
            })
            print("✓ N1 (Ciphertext) Berhasil dikirim")
            self.handshake_stage = 1
            self.is_initiator = True
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def send_n1_n2_response(self):
        """Menu 2: Kirim N1 plaintext + N2 encrypted"""
        if self.is_initiator:
            print("✗ Initiator tidak bisa mengirim N1_N2 response")
            return
            
        if self.handshake_stage < 2:
            print("✗ Belum menerima N1. Tunggu pesan N1 terlebih dahulu.")
            return
        
        print("\n--- Kirim Respons N1 + N2 ---")
        other_name = input("Public key (nama device pengirim): ")
        other_public_key = self.read_public_key_from_directory(other_name)
        
        if not other_public_key:
            return
        
        n2_plain = input("Kirim N2 Plaintext: ")
        # VALIDASI KHUSUS: N2 harus 1 karakter
        if len(n2_plain) != 1:
            print("✗ N2 harus 1 karakter!")
            return
            
        self.session_data['N2_sent'] = n2_plain
        
        try:
            encrypted_n2 = rsa.encrypt(other_public_key, n2_plain)
            print(f"N2 Ciphertext: {encrypted_n2}")
            
            self.communicator.send_message(self.other_device_ip, {
                'type': 'N1_N2_response',
                'sender': self.name,
                'N1_plaintext': str(self.session_data['N1_received']),
                'N2_ciphertext': encrypted_n2
            })
            print("✓ N1 (Plaintext) dan N2 (Ciphertext) Berhasil dikirim")
            self.handshake_stage = 3
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def send_n2_plaintext(self):
        """Menu 3: Kirim N2 plaintext"""
        if not self.is_initiator:
            print("✗ Responder tidak bisa mengirim N2 plaintext")
            return
            
        if self.handshake_stage < 3:
            print("✗ Belum memverifikasi N1 dan mendapatkan N2. Tunggu tahap sebelumnya selesai.")
            return
        
        print("\n--- Kirim N2 Plaintext ---")
        try:
            self.communicator.send_message(self.other_device_ip, {
                'type': 'N2_plaintext',
                'sender': self.name,
                'N2_plaintext': str(self.session_data['N2_received'])
            })
            print("✓ N2 (Plaintext) Berhasil dikirim")
            self.handshake_stage = 4
            print("⏳ Menunggu secret key dari responder...")
        except Exception as e:
            print(f"✗ Gagal mengirim: {e}")
    
    def send_secret_key(self):
        """Menu 4: Kirim Secret Key"""
        if self.is_initiator:
            print("✗ Initiator tidak bisa mengirim secret key")
            return
            
        if self.handshake_stage < 4:
            print("✗ Belum verifikasi lengkap. Tunggu verifikasi N2 terlebih dahulu.")
            return
        
        print("\n--- Kirim Secret Key ---")
        secret_key = input("Kirim Secret Key (bisa 1-8 karakter): ").strip()
        
        # Validasi: secret key maksimal 8 karakter
        if len(secret_key) > 8:
            print("✗ Secret key maksimal 8 karakter! Menggunakan 8 karakter pertama.")
            secret_key = secret_key[:8]
        
        if not secret_key:
            print("✗ Secret key tidak boleh kosong!")
            return
            
        print(f"Secret Key: '{secret_key}' (panjang: {len(secret_key)} karakter)")
        
        try:
            self.session_data['secret_key'] = secret_key
            
            # Kirim secret key sebagai plaintext (tidak dienkripsi)
            self.communicator.send_message(self.other_device_ip, {
                'type': 'secret_key',
                'sender': self.name,
                'secret_key': secret_key  # Kirim sebagai plaintext
            })
            print("✓ Secret Key Berhasil dikirim")
            print("🔐 Saat ini komunikasi dilakukan menggunakan Algoritma DES")
            self.des_mode = True
        except Exception as e:
            print(f"✗ Gagal mengirim secret key: {e}")
    
    def send_des_message(self):
        """Kirim pesan DES"""
        if not self.des_mode:
            print("✗ Belum masuk mode DES. Selesaikan handshake terlebih dahulu.")
            return
            
        print("\n--- Kirim Pesan DES ---")
        
        # Minta input secret key setiap kali kirim pesan
        secret_key = input("Masukkan Secret Key: ").strip()
        if not secret_key:
            print("✗ Secret key tidak boleh kosong!")
            return
            
        # Validasi: secret key maksimal 8 karakter
        if len(secret_key) > 8:
            print("✗ Secret key maksimal 8 karakter! Menggunakan 8 karakter pertama.")
            secret_key = secret_key[:8]
        
        plaintext = input("Masukkan plaintext: ")
        if not plaintext:
            print("✗ Plaintext tidak boleh kosong!")
            return
            
        try:
            print(f"🔑 Secret Key: {secret_key}")
            
            ciphertext = des.des_encrypt(plaintext, secret_key)
            print(f"🔒 Ciphertext: {ciphertext}")
            
            self.communicator.send_message(self.other_device_ip, {
                'type': 'des_message',
                'sender': self.name,
                'ciphertext': ciphertext
            })
            print("✓ Ciphertext berhasil dikirim")
            
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def start_des_communication(self):
        """Mulai komunikasi DES"""
        print("\n" + "="*50)
        print("MODE KOMUNIKASI DES")
        print("="*50)
        print("Kedua device sekarang bisa saling mengirim pesan DES")
        print("Gunakan menu [5] untuk kirim pesan, [9] untuk keluar")
        
        while self.des_mode:
            self.show_des_menu()
            choice = input("Pilih: ").strip()
            
            if choice == '5':
                self.send_des_message()
            elif choice == '9':
                break
            else:
                print("Pilihan tidak valid")
    
    def show_des_menu(self):
        """Tampilkan menu DES"""
        print("\n" + "="*30)
        print("MENU DES - PUTRI")
        print("="*30)
        print("[5] Kirim Pesan DES")
        print("[9] Keluar")
        print("="*30)
    
    def show_menu(self):
        """Tampilkan menu berdasarkan role dan stage handshake"""
        print("\n" + "="*50)
        print("Menu Putri")
        print("="*50)
        
        if self.des_mode:
            self.start_des_communication()
            return
            
        if self.handshake_stage == 0 and not self.is_initiator:
            print("[1] Kirim N1 encrypted (jadikan initiator)")
            print("[9] Keluar")
            
        elif self.is_initiator:
            if self.handshake_stage == 1:
                print("⏳ Menunggu respons N1_N2...")
            elif self.handshake_stage == 3:
                print("[3] Kirim N2 plaintext (verifikasi)")
            elif self.handshake_stage == 4:
                print("⏳ Menunggu secret key dari responder...")
            print("[9] Keluar")
            
        else:
            if self.handshake_stage == 2:
                print("[2] Kirim N1 plaintext + N2 encrypted (respons)")
            elif self.handshake_stage == 4:
                print("[4] Kirim Secret Key")
            print("[9] Keluar")
        
        print("="*50)
    
    def run(self):
        """Menjalankan device"""
        print("="*50)
        print("DEVICE 1 - PUTRI")
        print("="*50)
        
        self.load_keys()
        
        print(f"📍 IP Address Putri: {self.communicator.local_ip}")
        self.other_device_ip = input("Masukkan IP Address device lain: ").strip()
        
        self.communicator.start_server(self.handle_incoming_message)
        print(f"✓ Terhubung dengan {self.other_device_ip}")
        
        while True:
            self.show_menu()
            if self.des_mode:
                continue
                
            choice = input("Pilih: ").strip()
            
            if choice == '1' and self.handshake_stage == 0 and not self.is_initiator:
                self.send_n1_encrypted()
            elif choice == '2' and not self.is_initiator and self.handshake_stage == 2:
                self.send_n1_n2_response()
            elif choice == '3' and self.is_initiator and self.handshake_stage == 3:
                self.send_n2_plaintext()
            elif choice == '4' and not self.is_initiator and self.handshake_stage == 4:
                self.send_secret_key()
            elif choice == '9':
                break
            else:
                print("Pilihan tidak valid atau tidak tersedia di stage ini")
        
        self.communicator.stop_server()

if __name__ == "__main__":
    device = DevicePutri()
    device.run()
