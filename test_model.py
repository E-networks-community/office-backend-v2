from datetime import date, datetime, timedelta
import uuid
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# 
class Form(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    full_name = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False, default="0000-0000")
    phone_number = db.Column(db.String(20), index=True, unique=True)
    bvn = db.Column(db.String(20), index=True, unique=True)
    nin = db.Column(db.String(20), index=True, unique=True)
    agent_email = db.Column(db.String(100), index=True)
    agent_card_no = db.Column(db.String(100), index=True)
    address = db.Column(db.String(255), index=True)
    gender = db.Column(db.String(255), index=True, nullable=True)
    guarantor_name = db.Column(db.String(255), index=True, nullable=True)
    guarantor_phone_number = db.Column(
        db.String(255), index=True, nullable=True)
    guarantor_bvn = db.Column(db.String(255), index=True, nullable=True)
    guarantor_nin = db.Column(db.String(255), index=True, nullable=True)
    guarantor_address = db.Column(db.String(255), index=True, nullable=True)
    guarantor_passport = db.Column(db.TEXT, index=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.TEXT, default=None, index=True)
    signature = db.Column(db.TEXT, default=None, index=True)
    passport_photo = db.Column(db.TEXT, default=None, index=True)
    is_email_verified = db.Column(db.Boolean, default=False, index=True)
    office_status = db.Column(db.Boolean, default=False, index=True)
    date_of_birth = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone_number": self.phone_number,
            "address": self.address,
            "gender": self.gender,
            "created_at": str(self.created_at),
            "modified_at": str(self.modified_at),
            "passport_photo": self.passport_photo,
            "date_of_birth": str(self.date_of_birth) if self.date_of_birth else None,
            "signature": self.signature,
        }


class ReferralSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), unique=True, nullable=False)
    salary_per_referral = db.Column(db.Float, nullable=False)
    base_salary = db.Column(db.Integer, nullable=False, default=False)
    referral_target = db.Column(db.Integer, nullable=True)
    position = db.Column(db.String, nullable=True)
    total_referral_done = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "salary_per_referral": self.salary_per_referral,
            "base_salary": self.base_salary,
            "referral_target": self.referral_target,
            "position": self.position,
            "total_referral_done": self.total_referral_done,
        }


class User(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    staff_id = db.Column(db.String(50), nullable=True, unique=True)
    full_name = db.Column(db.String(50), nullable=True, unique=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False, default="0000-0000")
    phone_number = db.Column(db.String(20), index=True,
                             unique=True, nullable=True)
    bvn = db.Column(db.String(20), index=True, unique=True, nullable=True)
    nin = db.Column(db.String(20), index=True, unique=True, nullable=True)
    agent_email = db.Column(db.String(100), index=True, nullable=True)
    agent_card_no = db.Column(db.String(100), index=True, nullable=True)
    address = db.Column(db.String(255), index=True, nullable=True)
    gender = db.Column(db.String(255), index=True, nullable=True)
    date_of_birth = db.Column(db.DateTime, nullable=True)
    guarantor_name = db.Column(db.String(255), index=True, nullable=True)
    guarantor_phone_number = db.Column(
        db.String(255), index=True, nullable=True)
    guarantor_bvn = db.Column(db.String(255), index=True, nullable=True)
    guarantor_nin = db.Column(db.String(255), index=True, nullable=True)
    guarantor_address = db.Column(db.String(255), index=True, nullable=True)
    guarantor_passport = db.Column(db.TEXT, index=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.TEXT, default=None, index=True, nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False, index=True)
    filled_form = db.Column(db.Boolean, default=False, index=True)
    referrals_made = db.relationship(
        'SuccessfulReferral', backref='referrer', lazy='dynamic')
    referral_settings = db.relationship(
        'ReferralSettings', backref='user', uselist=False)
    office_status = db.Column(
        db.Boolean, default=False, index=True, nullable=True)
    referral = db.relationship('Referral', backref='user', uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "email": self.email,
            "phone_number": self.phone_number,
            "bvn": self.bvn,
            "nin": self.nin,
            "agent_email": self.agent_email,
            "agent_card_no": self.agent_card_no,
            "address": self.address,
            "gender": self.gender,
            "date_of_birth": str(self.date_of_birth) if self.date_of_birth else None,
            "guarantor_name": self.guarantor_name,
            "guarantor_phone_number": self.guarantor_phone_number,
            "guarantor_bvn": self.guarantor_bvn,
            "guarantor_nin": self.guarantor_nin,
            "guarantor_address": self.guarantor_address,
            "guarantor_passport": self.guarantor_passport,
            "created_at": str(self.created_at),
            "modified_at": str(self.modified_at),
            "profile_image": self.profile_image,
            "is_email_verified": self.is_email_verified,
            "office_status": self.office_status,
            "referral": self.referral.to_dict() if self.referral else None,
            "successful_referrals": [referral.to_dict() for referral in self.referrals_made]
        }

    def get_referral_settings(user_id):
        settings = ReferralSettings.query.filter_by(user_id=user_id).first()
        return settings.to_dict() if settings else None




class StaffSalary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(
        db.String(36), db.ForeignKey('user.id'), nullable=False)
    month = db.Column(db.String(7), nullable=False)  # Format: "YYYY-MM"
    base_salary = db.Column(db.Float, nullable=False)
    actual_salary = db.Column(db.Float, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "staff_id": self.staff_id,
            "month": self.month,
            "base_salary": self.base_salary,
            "actual_salary": self.actual_salary,
        }


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<Role {self.role_name}>"


class SuccessfulPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), nullable=False)
    transaction_reference = db.Column(db.String(36), nullable=False)
    slip_code = db.Column(db.String(36), nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "transaction_reference": self.transaction_reference,
            "slip_code": self.slip_code,
            "payment_amount": self.payment_amount,
            "timestamp": str(self.timestamp),
        }


class SuccessfulReferral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(
        db.String(36), db.ForeignKey('user.id'), nullable=False)
    referred_user_name = db.Column(db.String(50), nullable=False)
    referred_user_email = db.Column(db.String(255), nullable=False, index=True)
    referred_user_card_number = db.Column(
        db.String(100), nullable=False, index=True)
    validity = db.Column(db.Boolean, nullable=False, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    referral_id = db.Column(db.Integer, db.ForeignKey('referral.id'))

    def to_dict(self):
        return {
            "id": self.id,
            "referrer_id": self.referrer_id,
            "referred_user_name": self.referred_user_name,
            "referred_user_email": self.referred_user_email,
            "referred_user_card_number": self.referred_user_card_number,
            "validity": self.validity,
            "timestamp": str(self.timestamp),
            "referral_id": self.referral_id,
        }

    def get_successful_referrals(user_id, limit=10):
        # Get the successful referrals made by a user
        referrals = SuccessfulReferral.query.filter_by(
            referrer_id=user_id).limit(limit).all()
        return [referral.to_dict() for referral in referrals]

    @staticmethod
    def get_weekly_work_done(user_id):
        # Calculate the start and end dates for the current week
        start_date = datetime.utcnow().date() - timedelta(days=datetime.utcnow().weekday())
        end_date = start_date + timedelta(days=6)

        # Query successful referrals within the current week
        weekly_work_done = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == user_id,
            SuccessfulReferral.timestamp >= start_date,
            SuccessfulReferral.timestamp <= end_date
        ).all()

        return [referral.to_dict() for referral in weekly_work_done]

    @staticmethod
    def get_monthly_work_done(user_id):
        # Calculate the start and end dates for the current month
        today = datetime.utcnow().date()
        start_date = date(today.year, today.month, 1)
        end_date = date(today.year, today.month + 1, 1) - timedelta(days=1)

        # Query successful referrals within the current month
        monthly_work_done = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == user_id,
            SuccessfulReferral.timestamp >= start_date,
            SuccessfulReferral.timestamp <= end_date
        ).all()

        return [referral.to_dict() for referral in monthly_work_done]

    @staticmethod
    def get_total_referrals_count(user_id):
        # Get the total number of referrals for the user
        total_referrals = SuccessfulReferral.query.filter_by(
            referrer_id=user_id).count()
        return total_referrals


class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), unique=True, nullable=False)
    monthly_target = db.Column(db.Integer, nullable=True)
    salary_id = db.Column(db.Integer, db.ForeignKey(
        'staff_salary.id'), nullable=True)
    total_referrals = db.Column(db.Integer, default=0, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "monthly_target": self.monthly_target,
            "salary_id": self.salary_id,
            "total_referrals": self.total_referrals,
            # ... (other fields as needed)
        }
