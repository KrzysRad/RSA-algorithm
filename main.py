import sys
import os
from rsa import *
from md4 import *
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QFileDialog, QLineEdit


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Szyfrowanie")
        self.setGeometry(100, 100, 400, 550)
        
# create key
        self.create_key_button = QPushButton("Stwórz klucze", self)
        self.create_key_button.setGeometry(165, 15, 95, 30)
        self.create_key_button.clicked.connect(self.create_key)

# files to encrypt
        self.file_label = QLabel("Wybierz plik do zaszyfrowania:", self)
        self.file_label.setGeometry(20, 60, 220, 40)
        self.file_path = QLineEdit(self)
        self.file_path.setGeometry(20, 100, 250, 20)
        self.browse_button = QPushButton("Przeglądaj", self)
        self.browse_button.setGeometry(300, 95, 80, 25)
        self.browse_button.clicked.connect(self.browse_file)

# selecting private key

        self.encrypt_label = QLabel("Wybierz klucz prywatny:", self)
        self.encrypt_label.setGeometry(20, 130, 150, 40)
        self.private_key_path = QLineEdit(self)
        self.private_key_path.setGeometry(20, 170, 250, 20)
        self.browse_2_button = QPushButton("Przeglądaj", self)
        self.browse_2_button.setGeometry(300, 165, 80, 25)
        self.browse_2_button.clicked.connect(self.browse_file)
        
# encrypting button       
        self.encrypt_button = QPushButton("Zaszyfruj", self)
        self.encrypt_button.setGeometry(165, 210, 95, 30)
        self.encrypt_button.clicked.connect(self.encrypt_file)

# files to decrypt

        self.file_2_label = QLabel("Wybierz plik do odszyfrowania:", self)
        self.file_2_label.setGeometry(20, 260, 220, 40)
        self.file_2_path = QLineEdit(self)
        self.file_2_path.setGeometry(20, 300, 250, 20)
        self.browse_3_button = QPushButton("Przeglądaj", self)
        self.browse_3_button.setGeometry(300, 295, 80, 25)
        self.browse_3_button.clicked.connect(self.browse_file)

# decrypting field

        self.decrypt_label = QLabel("Wybierz klucz", self)
        self.decrypt_label.setGeometry(20, 330, 100, 40)
        self.file_3_path = QLineEdit(self)
        self.file_3_path.setGeometry(20, 370, 250, 20)
        self.browse_4_button = QPushButton("Przeglądaj", self)
        self.browse_4_button.setGeometry(300, 365, 80, 25)
        self.browse_4_button.clicked.connect(self.browse_file)

# select signature

        self.file_4_label = QLabel("Wybierz podpis", self)
        self.file_4_label.setGeometry(20, 400, 220, 40)
        self.file_4_path = QLineEdit(self)
        self.file_4_path.setGeometry(20, 440, 250, 20)
        self.browse_5_button = QPushButton("Przeglądaj", self)
        self.browse_5_button.setGeometry(300, 435, 80, 25)
        self.browse_5_button.clicked.connect(self.browse_file)

# decrypting button

        self.decrypt_button = QPushButton("Sprawdź", self)
        self.decrypt_button.setGeometry(165, 500, 95, 30)
        self.decrypt_button.clicked.connect(self.decrypt_file)





# result field

        #self.result_label = QLabel("Wynik:", self)
        #self.result_label.setGeometry(20, 220, 100, 20)
        #self.result_text = QLineEdit(self)
        #self.result_text.setGeometry(120, 220, 270, 20)
               


    def create_key(self):
        rsa = RSA()
        rsa.gen_keys()
        # print(rsa.public_key.get_key())
        # print(rsa.private_key.get_key())

        path = QFileDialog.getExistingDirectory(self, "Wybierz folder", os.path.expanduser('~/'))
        rsa.save_keys(path)
        

# browse file to encrypt

    def browse_file(self):
        file_dialog = QFileDialog()
        button = self.sender()
        file_path, _ = file_dialog.getOpenFileName(self, "Wybierz plik")
        
        if button == self.browse_button:
            self.file_path.setText(file_path)

        elif button == self.browse_2_button:
            self.private_key_path.setText(file_path)

        elif button == self.browse_3_button:
            self.file_2_path.setText(file_path)
        
        elif button == self.browse_4_button:
            self.file_3_path.setText(file_path)

        elif button == self.browse_5_button:
            self.file_4_path.setText(file_path)

# browse file to decrypt


    def encrypt_file(self):
        file_path = self.file_path.text()
        key_path = self.private_key_path.text()


        # Calculate MD4 hash 
        md4 = MD4(open(file_path, "rb").read())
        md4_hash = md4.get_hash()
        print("MD4 Hash:", md4_hash)

        key: Key = pickle.load(open(key_path, "rb"))
        
        # Encrypt MD4 hash using RSA
       
        encrypted_hash = RSA.encrypt(md4_hash, key.get_key())
        open(file_path + ".enc", "w").write(str(encrypted_hash))
        
            
        
    def decrypt_file(self):
        file_path = self.file_2_path.text()
        key_path = self.file_3_path.text()
        sign_path = self.file_4_path.text()

        # Calculate MD4 hash
        md4 = MD4(open(file_path, "rb").read())
        md4_hash = md4.get_hash()

        print(md4_hash)
    
        key = pickle.load(open(key_path, "rb"))
        decrypted_hash = RSA.decrypt(int(open(sign_path , "r").read()), key.get_key())
        print(decrypted_hash)
        if decrypted_hash == md4_hash:
            print("Podpis prawidłowy")
        else:
            print("Podpis nieprawidłowy")
        
app = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec_())