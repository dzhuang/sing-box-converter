import random
import string
from abc import ABC, abstractmethod


class ParserBase(ABC):
    @property
    @abstractmethod
    def protocol_type(self):
        raise NotImplementedError()

    def parse(self, data):
        raise NotImplementedError()

    @property
    def random_name(self):
        prefix = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"{prefix}_{self.protocol_type}"
