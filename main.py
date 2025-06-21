from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label

import smtplib
from email.mime.text import MIMEText

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


class CryptoEngine:
    def __init__(self):
        self.key_pair = RSA.generate(2048)
        self.public_key = self.key_pair.publickey()
        self.encryptor = PKCS1_OAEP.new(self.public_key)
        self.decryptor = PKCS1_OAEP.new(self.key_pair)

    def encrypt(self, message):
        encrypted = self.encryptor.encrypt(message.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, encrypted_message):
        decoded = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = self.decryptor.decrypt(decoded)
        return decrypted.decode('utf-8')


crypto = CryptoEngine()


class SenderWindow(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        layout.add_widget(Label(text="Sender - Encrypt & Send Message", font_size=24))

        self.sender_email = TextInput(hint_text="Your Email", multiline=False)
        layout.add_widget(self.sender_email)

        self.sender_password = TextInput(hint_text="Your Email Password / App Password", password=True, multiline=False)
        layout.add_widget(self.sender_password)

        self.recipient_email = TextInput(hint_text="Recipient Email", multiline=False)
        layout.add_widget(self.recipient_email)

        self.message_input = TextInput(hint_text="Enter message to encrypt & send", multiline=True)
        layout.add_widget(self.message_input)

        encrypt_btn = Button(text="Encrypt & Send Email")
        encrypt_btn.bind(on_press=self.encrypt_and_send)
        layout.add_widget(encrypt_btn)

        self.status = Label(text="")
        layout.add_widget(self.status)

        switch_btn = Button(text="Go to Receiver")
        switch_btn.bind(on_press=self.go_to_receiver)
        layout.add_widget(switch_btn)

        self.add_widget(layout)

    def encrypt_and_send(self, instance):
        email = self.sender_email.text.strip()
        password = self.sender_password.text.strip()
        recipient = self.recipient_email.text.strip()
        message = self.message_input.text.strip()

        if not (email and password and recipient and message):
            self.status.text = "Please fill all fields"
            return

        try:
            encrypted_msg = crypto.encrypt(message)
        except Exception as e:
            self.status.text = f"Encryption error: {str(e)}"
            return

        try:
            # Prepare email
            msg = MIMEText(encrypted_msg)
            msg['Subject'] = "Encrypted Message"
            msg['From'] = email
            msg['To'] = recipient

            # Send email using Gmail SMTP server
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(email, password)
            server.send_message(msg)
            server.quit()

            self.status.text = "Email sent successfully!"
        except Exception as e:
            self.status.text = f"Email send error: {str(e)}"

    def go_to_receiver(self, instance):
        self.manager.current = 'receiver'


class ReceiverWindow(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        layout.add_widget(Label(text="Receiver - Decrypt Message", font_size=24))

        self.input_enc = TextInput(hint_text="Paste encrypted message here", multiline=True)
        layout.add_widget(self.input_enc)

        decrypt_btn = Button(text="Decrypt")
        decrypt_btn.bind(on_press=self.decrypt_and_show)
        layout.add_widget(decrypt_btn)

        self.output_dec = TextInput(hint_text="Decrypted message", readonly=True, multiline=True)
        layout.add_widget(self.output_dec)

        switch_btn = Button(text="Go to Sender")
        switch_btn.bind(on_press=self.go_to_sender)
        layout.add_widget(switch_btn)

        self.add_widget(layout)

    def decrypt_and_show(self, instance):
        enc = self.input_enc.text.strip()
        if enc:
            try:
                decrypted = crypto.decrypt(enc)
                self.output_dec.text = decrypted
            except Exception as e:
                self.output_dec.text = f"Decryption error: {str(e)}"
        else:
            self.output_dec.text = "Enter an encrypted message"

    def go_to_sender(self, instance):
        self.manager.current = 'sender'


class WindowManager(ScreenManager):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_widget(SenderWindow(name='sender'))
        self.add_widget(ReceiverWindow(name='receiver'))


class EncryptedSMSApp(App):
    def build(self):
        return WindowManager()


if __name__ == '__main__':
    EncryptedSMSApp().run()
