import sympy
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class RabinKey:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q

class KeyManagementService:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}  # Store keys as {entity_name: RabinKey}
        self.expiry_dates = {}

    def generate_prime(self):
        while True:
            prime = sympy.randprime(2**(self.key_size//2 - 1), 2**(self.key_size//2))
            if prime % 4 == 3:
                return prime

    def generate_keypair(self, entity_name):
        p = self.generate_prime()
        q = self.generate_prime()
        rabin_key = RabinKey(p, q)
        self.keys[entity_name] = rabin_key
        self.expiry_dates[entity_name] = datetime.now() + timedelta(days=365)
        logging.info(f'Keys generated for {entity_name}. Expiry set to {self.expiry_dates[entity_name]}')
        return rabin_key.n, (p, q)

    def distribute_keys(self, entity_name):
        if entity_name in self.keys:
            rabin_key = self.keys[entity_name]
            logging.info(f'Keys distributed for {entity_name}')
            return rabin_key.n, (rabin_key.p, rabin_key.q)
        else:
            logging.warning(f'No keys found for {entity_name}')
            return None

    def revoke_keys(self, entity_name):
        if entity_name in self.keys:
            del self.keys[entity_name]
            del self.expiry_dates[entity_name]
            logging.info(f'Keys revoked for {entity_name}')
        else:
            logging.warning(f'Attempt to revoke keys for {entity_name} failed - no such entity')

    def renew_keys(self):
        to_renew = []
        for entity, expiry in list(self.expiry_dates.items()):
            if expiry <= datetime.now():
                self.generate_keypair(entity)
                to_renew.append(entity)
        if to_renew:
            logging.info(f'Renewed keys for: {", ".join(to_renew)}')
        else:
            logging.info('No keys needed renewal at this time')

    def audit_log(self):
        logging.info('Audit report generated.')
        # In real implementation, this would generate detailed audit reports

# Example usage
kms = KeyManagementService(key_size=512)  # Smaller for quick generation

# Generate keys for hospitals/clinics
kms.generate_keypair('Hospital_1')
kms.generate_keypair('Clinic_1')

# Distribute keys
print(kms.distribute_keys('Hospital_1'))

# Revoke keys for a clinic
kms.revoke_keys('Clinic_1')

# Renew keys simulating expiry
kms.expiry_dates['Hospital_1'] = datetime.now() - timedelta(days=1)
kms.renew_keys()

# Audit log
kms.audit_log()
