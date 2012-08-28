from Crypto.Cipher import AES
import base64
import hashlib
import json
import os
from pbkdf2 import PBKDF2

class KeychainEntry:
    def __init__(self, keychain, store, header):
        self.keychain = keychain
        self.store = store

        self.uuid = header[0]
        self.type = header[1]
        self.name = header[2]
        self.url = header[3]
        self.date = header[4]
        self.folder = header[5]
        self.strength = int(header[6])
        self.trashed = header[7] == 'Y'

        self._data_cache = None
        self._decrypted_cache = None

    # Cache file contents
    @property
    def _data(self):
        if self._data_cache is None:
            self._data_cache = self.keychain._read_entry(self)
        return self._data_cache

    # Cleartext key-file data values
    @property
    def encrypted(self):
        return self._data['encrypted']

    @property
    def key_id(self):
        return self._data['keyID']

    @property
    def location(self):
        return self._data['location']

    # Encrypted key-file data values
    @property
    def _decrypted(self):
        if self._decrypted_cache is None:
            edata = self.keychain._decrypt_by_key_id(self.encrypted,
                                                     self.store,
                                                     self.key_id)
            self._decrypted_cache = json.loads(edata.decode())
        return self._decrypted_cache

    # Pretty-print something helpful
    def __str__(self):
        return "<{0} named '{1}'>".format(self.__class__.__name__, self.name)
    
class IdentityEntry(KeychainEntry):
    pass

class PasswordEntry(KeychainEntry):
    @property
    def password(self):
        return self._decrypted['password']

class WalletEntry(KeychainEntry):
    pass

class WebFormEntry(KeychainEntry):
    pass

def make_keychain_entry(keychain, store, header):
    classes = {
        'identities': IdentityEntry,
        'passwords': PasswordEntry,
        'wallet': WalletEntry,
        'webforms': WebFormEntry,
    }
    cls = header[1].partition('.')[0]
    return classes[cls](keychain, store, header)

class AgileKeychain:
    def __init__(self, path):
        self.config_path = os.path.join(path, 'config')
        self.data_path = os.path.join(path, 'data')
        self._keys = {}

    def _decrypt_by_key_id(self, blob, store, key_id):
        return self._decrypt_by_md5(blob, self._keys[(store, key_id)])

    def _decrypt_by_keyiv(self, blob, keyiv):
        (key, iv) = keyiv
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cleartext = cipher.decrypt(blob)
        pad = cleartext[-1]
        assert pad <= 16
        return cleartext[:-pad]

    def _decrypt_by_md5(self, blob, key):
        binary = base64.b64decode(blob.encode())
        if binary[0:8] != b'Salted__':
            raise Exception("Un-salted MD5 is not supported")
        keyiv = self._keygen_md5(key, binary[8:16])
        return self._decrypt_by_keyiv(binary[16:], keyiv)

    def _decrypt_by_password(self, blob, password, iterations):
        binary = base64.b64decode(blob.encode())
        if binary[0:8] != b'Salted__':
            raise Exception("Un-salted PBKDF2 is not supported")
        keyiv = self._keygen_pbkdf2(password, binary[8:16], iterations)
        return self._decrypt_by_keyiv(binary[16:], keyiv)

    def _keygen_md5(self, password, salt):
        rounds = 2
        data = password + salt
        md5 = []
        for i in range(0, rounds):
            h = hashlib.md5()
            h.update(data)
            md5.append(h.digest())
            data = md5[i] + password + salt
        return (md5[0], md5[1])

    def _keygen_pbkdf2(self, password, salt, iterations):
        keyiv = PBKDF2(password, salt, iterations = iterations).read(32)
        return (keyiv[0:16], keyiv[16:32])

    def _read_entry(self, entry):
        entry_path = os.path.join(self.data_path, entry.store, entry.uuid + '.1password')
        with open(entry_path, 'r') as entry_file:
            return json.load(entry_file)

    def list(self, store = 'default'):
        content_path = os.path.join(self.data_path, store, 'contents.js')
        with open(content_path, 'r') as content_file:
            contents = json.load(content_file)
            return [make_keychain_entry(self, store, i) for i in contents]

    def unlock(self, password, store = 'default'):
        keys_path = os.path.join(self.data_path, store, 'encryptionKeys.js')
        unlocked = False
        with open(keys_path, 'r') as keys_file:
            keys = json.load(keys_file)
            for l in keys['list']:
                result = self._decrypt_by_password(l['data'], password, l['iterations'])
                vresult = self._decrypt_by_md5(l['validation'], result)
                if result == vresult:
                    unlocked = True
                    self._keys[(store, l['identifier'])] = result
        if not unlocked:
            raise Exception("Password unlocked no keys")
