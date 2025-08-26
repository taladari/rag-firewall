import hashlib
class Hasher:
    @staticmethod
    def hash_text(text:str)->str:
        return hashlib.sha256((text or '').encode('utf-8')).hexdigest()
