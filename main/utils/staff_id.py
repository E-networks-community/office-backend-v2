import random

def create_staff_id(name: str):
    return f'{name}'.join(random.choices('0123456789', k=6))