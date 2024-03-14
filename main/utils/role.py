from flask_jwt_extended import get_jwt_identity
from flask import jsonify
from functools import wraps
from models import User


def require_role(role_names):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.filter_by(id=user_id).first()
            if not user or user.role.role_name not in role_names:
                return jsonify(message='Insufficient permissions'), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def has_role(user_id, roles):
    user = User.query.get(user_id)
    if user and user.role:
        return user.role.role_name in roles
    return False