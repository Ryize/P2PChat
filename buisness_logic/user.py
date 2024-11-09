from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


class User:
    """
    Класс User представляет пользователя с функциями для создания пары RSA-ключей,
    шифрования и расшифровки сообщений с использованием асимметричного шифрования.

    Используется в системе P2P для обеспечения сквозного шифрования сообщений.
    Каждый экземпляр класса User имеет собственные приватный и публичный ключи,
    а также может сохранять публичный ключ собеседника (peer_public_key).
    """

    def __init__(self, login: str):
        """
        Инициализирует нового пользователя с заданным логином и генерирует пару RSA-ключей.

        Args:
            login (str): Логин пользователя.

        Attributes:
            private_key: Приватный ключ RSA, сгенерированный для пользователя.
            public_key: Публичный ключ RSA, соответствующий приватному ключу.
            peer_public_key: Публичный ключ собеседника, используется для шифрования сообщений.
        """
        self.login = login
        self.private_key, self.public_key = self.generate_keys()
        self.peer_public_key = None

    def generate_keys(self):
        """
        Генерирует пару RSA-ключей (приватный и публичный) для пользователя.

        Returns:
            tuple: Пара (private_key, public_key), где:
                   - private_key: Приватный ключ RSA.
                   - public_key: Публичный ключ RSA.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_message(self, message: str, receiver_public_key):
        """
        Шифрует сообщение для заданного получателя, используя его публичный ключ.

        Args:
            message (str): Текст сообщения для шифрования.
            receiver_public_key: Публичный ключ получателя, с помощью которого выполняется шифрование.

        Returns:
            bytes: Зашифрованное сообщение в виде байтов.
        """
        encrypted = receiver_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_message(self, encrypted_message: bytes):
        """
        Расшифровывает зашифрованное сообщение, используя приватный ключ пользователя.

        Args:
            encrypted_message (bytes): Зашифрованное сообщение в виде байтов, полученное от собеседника.

        Returns:
            str: Расшифрованное сообщение в виде строки.
        """
        decrypted = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
