from abc import ABC, abstractmethod
import os
import gi
import json

secureKeyring = False
try:
    gi.require_version("Secret", "1")
    from gi.repository import Secret
except (ValueError, ImportError) as e:
    secureKeyring = True


class TokenKeyring(ABC):
    def __init__(self, variant):
        self.variant = variant

    @property
    def available(self) -> bool:
        return True

    @abstractmethod
    def clear(self, attributes) -> bool:
        pass

    @abstractmethod
    def save(self, label, attributes, secret):
        pass

    @abstractmethod
    def load(self, attributes):
        pass

class DBusKeyring(TokenKeyring):
    """A keyring using libsecret with DBus"""
    def __init__(self, variant):
        super().__init__(variant)
        # None is the default collection
        self.collection = None

    @property
    def available(self):
        # TODO: Do a trial run
        return secureKeyring

    def create_schema(self, attributes):
        return Secret.Schema.new(self.variant.name, Secret.SchemaFlags.NONE, {
            k: Secret.SchemaAttributeType.STRING
            for k in attributes})

    def clear(self, attributes) -> bool:
        schema = self.create_schema(attributes)
        return Secret.password_clear_sync(schema, attributes, None)

    def save(self, label, attributes, secret):
        # Prefix the label with the client name
        label = f"{self.variant.name} - {label}"
        schema = self.create_schema(attributes)
        return Secret.password_store_sync(
            schema, attributes, self.collection, label,
            str(secret), None)

    def load(self, attributes):
        """Load a password in the secret service, return None when found nothing"""
        schema = self.create_schema(attributes)
        return Secret.password_lookup_sync(schema, attributes, None)

class InsecureFileKeyring(TokenKeyring):
    def __init__(self, variant):
        super().__init__(variant)

    @property
    def filename(self):
        return self.variant.config_prefix / "keys"

    def hash_key(self, attributes):
        return str(hash(tuple(sorted(attributes))))

    def load_previous(self):
        with open(self.filename, "r") as f:
            return json.load(f)

    def write(self, vals):
        with open(self.filename, "w+") as f:
            json.dump(vals, f)

    def clear(self, attributes) -> bool:
        # Get previous entries
        new = {}
        if os.path.exists(self.filename):
            new = self.load_previous()
        key = self.hash_key(attributes)
        new.pop(key, None)
        self.write(new)
        return True

    def save(self, label, attributes, secret):
        new = {}

        # Get previous entries
        if os.path.exists(self.filename):
            new = self.load_previous()

        # add/overwrite new entry
        key = self.hash_key(attributes)
        new[key] = secret

        # Write new values
        self.write(new)

    def load(self, attributes):
        if not os.path.exists(self.filename):
            return None
        previous = self.load_previous()
        key = self.hash_key(attributes)
        return previous.get(key, None)
