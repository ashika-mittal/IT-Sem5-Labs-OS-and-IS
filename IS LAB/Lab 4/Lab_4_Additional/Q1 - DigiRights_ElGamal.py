import time
import logging
from datetime import datetime, timedelta
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from math import ceil

logging.basicConfig(level=logging.INFO)

class DRMSystem:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.master_key = None  # (public_key, private_key)
        self.content_db = {}    # content_id -> encrypted content (integer)
        self.access_rights = {} # user_id -> {content_id: access_expiry}
        self.key_generation_time = None
        self.generate_master_keys()

    def generate_master_keys(self):
        start_time = time.time()
        self.master_key = ElGamal.generate(self.key_size, get_random_bytes)
        self.key_generation_time = time.time() - start_time
        logging.info(f"Master keys generated in {self.key_generation_time:.2f}s")

    def encrypt_content(self, content_id, data_bytes):
        pub_key = self.master_key.publickey()
        m = bytes_to_long(data_bytes)
        # Encrypt message (using ElGamal's encrypt method)
        k = get_random_bytes(ceil(self.key_size / 8))
        k = bytes_to_long(k) % (pub_key.p - 1)
        c1 = pow(pub_key.g, k, pub_key.p)
        c2 = (m * pow(pub_key.y, k, pub_key.p)) % pub_key.p
        self.content_db[content_id] = (c1, c2)
        logging.info(f"Content {content_id} encrypted and stored.")
    
    def distribute_private_key(self, user_id):
        # In real systems this would be secure key distribution
        # Here we simulate by returning the private key object
        return self.master_key

    def grant_access(self, user_id, content_id, days=30):
        expiry = datetime.now() + timedelta(days=days)
        self.access_rights.setdefault(user_id, {})[content_id] = expiry
        logging.info(f"Access granted to user '{user_id}' for content '{content_id}' until {expiry}")

    def revoke_access(self, user_id, content_id):
        rights = self.access_rights.get(user_id, {})
        if content_id in rights:
            del rights[content_id]
            logging.info(f"Access revoked for user '{user_id}' on content '{content_id}'")
    
    def check_access(self, user_id, content_id):
        rights = self.access_rights.get(user_id, {})
        expiry = rights.get(content_id)
        if expiry and expiry > datetime.now():
            return True
        return False

    def decrypt_content(self, user_id, content_id):
        if not self.check_access(user_id, content_id):
            logging.warning(f"User '{user_id}' has no access to content '{content_id}'")
            return None
        
        priv_key = self.master_key
        c1, c2 = self.content_db.get(content_id, (None, None))
        if c1 is None or c2 is None:
            logging.warning(f"Content '{content_id}' not found.")
            return None
        
        s = pow(c1, priv_key.x, priv_key.p)
        s_inv = pow(s, -1, priv_key.p)
        m = (c2 * s_inv) % priv_key.p
        data_bytes = long_to_bytes(m)
        logging.info(f"Content '{content_id}' decrypted for user '{user_id}'")
        return data_bytes

    def renew_keys(self):
        logging.info("Renewing master keys.")
        self.generate_master_keys()

    # Optional: Add auditing/logging for key/revocation/etc as desired

# Example usage
drm = DRMSystem()

# Creator uploads content
content_id = "ebook123"
drm.encrypt_content(content_id, b"My valuable e-book content")

# Manage access
user = "customerA"
drm.grant_access(user, content_id, days=10)
print("Access granted:", drm.check_access(user, content_id))

# Decrypt content for authorized user
decrypted = drm.decrypt_content(user, content_id)
print("Decrypted content:", decrypted.decode() if decrypted else "No Access")

# Revoke access and try decryption again
drm.revoke_access(user, content_id)
decrypted = drm.decrypt_content(user, content_id)
print("Decrypted after revocation:", decrypted.decode() if decrypted else "Access Denied")

# Renew keys periodically
drm.renew_keys()
