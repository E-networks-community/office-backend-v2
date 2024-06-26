from datetime import date, datetime, timedelta
import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

db = SQLAlchemy()


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


class FieldApplication(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    full_name = db.Column(db.String(255), nullable=False, unique=True)
    agent_email = db.Column(db.String(255), nullable=False, unique=True)
    agent_card_number = db.Column(db.String(255), nullable=False, unique=True)
    address = db.Column(db.String(255), nullable=False)
    state = db.Column(db.String(255), nullable=False)
    lga = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    ward = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False, unique=True)
    next_of_kin_name = db.Column(db.String(255), nullable=False, unique=True)
    next_of_kin_phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    next_of_kin_relationship = db.Column(
        db.String(255), nullable=False, unique=True)
    next_of_kin_email_address = db.Column(
        db.String(255), nullable=False, unique=True)
    guarantor_name = db.Column(db.String(255), nullable=False, unique=True)
    guarantor_phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    language = db.Column(db.String(255), nullable=False, unique=True)
    position = db.Column(db.String(255), nullable=False, unique=True)
    position_state = db.Column(db.String(255), nullable=False, unique=True)
    passport_photo = db.Column(db.TEXT, nullable=False, unique=True)

    # time and date
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Boolean
    is_email_verified = db.Column(db.Boolean, default=False, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.full_name,
            "address": self.address,
            "gender": self.gender,
            "created_at": str(self.created_at),
            "modified_at": str(self.modified_at),
            "passport_photo": self.passport_photo,
            "date_of_birth": str(self.date_of_birth) if self.date_of_birth else None,
            "signature": self.signature,
        }

############################################################
############################################################
############################################################
########################  USER #############################


class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), unique=True, nullable=False)
    monthly_target = db.Column(db.Integer, nullable=True)
    total_referrals = db.Column(db.Integer, default=0, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "monthly_target": self.monthly_target,
            "total_referrals_completed": self.total_referrals,
        }

    def calculate_completion_percentage(self):
        if self.monthly_target == 0:
            return 100  # If monthly target is 0, completion is 100%
        return (self.total_referrals / self.monthly_target) * 100

    def get_monthly_users(self):
        # Calculate the start and end dates for the current month
        today = datetime.utcnow().date()
        start_date = date(today.year, today.month, 1)
        end_date = date(today.year, today.month + 1, 1) - timedelta(days=1)

        # Query successful referrals within the current month
        monthly_users = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == self.user_id,
            SuccessfulReferral.timestamp >= start_date,
            SuccessfulReferral.timestamp <= end_date
        ).distinct(SuccessfulReferral.referred_user_email).count()

        return monthly_users


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

    @staticmethod
    def get_successful_referrals(user_id, limit=10):
        # Get the successful referrals made by a user
        referrals = SuccessfulReferral.query.filter_by(
            referrer_id=user_id).limit(limit).all()
        return [referral.to_dict() for referral in referrals]


class User(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    full_name = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    agent_email = db.Column(db.String(255), nullable=False, unique=True)
    agent_card_number = db.Column(db.String(255), nullable=False, unique=True)
    address = db.Column(db.String(255), nullable=False)
    state = db.Column(db.String(255), nullable=False)
    lga = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    ward = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False, unique=True)
    next_of_kin_name = db.Column(db.String(255), nullable=False, unique=True)
    next_of_kin_phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    next_of_kin_relationship = db.Column(
        db.String(255), nullable=False, unique=True)
    next_of_kin_email_address = db.Column(
        db.String(255), nullable=False, unique=True)
    guarantor_name = db.Column(db.String(255), nullable=False, unique=True)
    guarantor_phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    language = db.Column(db.String(255), nullable=False, unique=True)
    position = db.Column(db.String(255), nullable=False, unique=True)
    position_state = db.Column(db.String(255), nullable=False, unique=True)
    passport_photo = db.Column(db.TEXT, nullable=False, unique=True)
    referrals_made = db.relationship(
        'SuccessfulReferral', backref='referrer', lazy='dynamic')
    office_status = db.Column(
        db.Boolean, default=False, index=True, nullable=True)
    referral = db.relationship('Referral', backref='user', uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "agent_email": self.agent_email,
            "office_status": self.office_status,
            "referral": self.referral.to_dict() if self.referral else None,
            "successful_referrals": [referral.to_dict() for referral in self.referrals_made]
        }

############################################################
############################################################
############################################################
#######################   Field   ##########################


class FieldOfficer(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    full_name = db.Column(db.String(50), nullable=True, unique=True)
    agent_email = db.Column(db.String(255), unique=True,
                            nullable=False, index=True)
    agent_card_no = db.Column(db.String(100), index=True, nullable=True)
    bvn = db.Column(db.String(100), index=True, nullable=True)
    nin = db.Column(db.String(100), index=True, nullable=True)
    gender = db.Column(db.String(255), index=True, nullable=True)
    password = db.Column(db.String(255), nullable=False, default="0000-0000")
    address = db.Column(db.String(255), index=True, nullable=True)
    guarantor_name = db.Column(db.String(255), nullable=False, unique=True)
    guarantor_phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    guarantor_bvn = db.Column(db.String(25), nullable=False, unique=True)
    guarantor_nin = db.Column(
        db.String(25), nullable=False, unique=True)
    guarantor_address = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(255), index=True,
                             unique=True, nullable=True)
    date_of_birth = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)
    unique_referral_link = db.Column(db.String(100), index=True, nullable=True)
    signature = db.Column(db.TEXT, default=None, index=True, nullable=True)
    passport_photo = db.Column(
        db.TEXT, default=None, index=True, nullable=True)
    guarantor_photo = db.Column(
        db.TEXT, default=None, index=True, nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False, index=True)
    referrals_made = db.relationship(
        'FieldOfficerSuccessfulReferral', back_populates='referrer', lazy='dynamic')
    office_status = db.Column(
        db.Boolean, default=False, index=True, nullable=True)
    referral = db.relationship(
        'FieldOfficerReferral', back_populates='user', uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "agent_email": self.agent_email,
            "office_status": self.office_status,
            "referral": self.referral.to_dict() if self.referral else None,
            "successful_referrals": [referral.to_dict() for referral in self.referrals_made]
        }


class FieldOfficerReferral(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'field_officer.id'), unique=True, nullable=False)
    monthly_target = db.Column(db.Integer, nullable=True)
    total_referrals = db.Column(db.Integer, default=0, nullable=False)
    user = db.relationship(
        'FieldOfficer', back_populates='referral', uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "monthly_target": self.monthly_target,
            "total_referrals_completed": self.total_referrals,
        }

    def calculate_completion_percentage(self):
        if self.monthly_target == 0:
            return 100  # If monthly target is 0, completion is 100%
        return (self.total_referrals / self.monthly_target) * 100

    def get_monthly_users(self):
        try:
            # Calculate the start and end dates for the current month
            today = datetime.utcnow().date()
            start_date = date(today.year, today.month, 1)
            end_date = date(today.year, today.month + 1, 1) - timedelta(days=1)

            # Query successful referrals within the current month
            monthly_users_count = FieldOfficerSuccessfulReferral.query.filter(
                FieldOfficerSuccessfulReferral.referrer_id == self.user_id,
                FieldOfficerSuccessfulReferral.timestamp >= start_date,
                FieldOfficerSuccessfulReferral.timestamp <= end_date
            ).distinct(FieldOfficerSuccessfulReferral.referred_user_email).count()

            return monthly_users_count
        except Exception as e:
            print("Error in get_monthly_users:", e)
            return None


class FieldOfficerSuccessfulReferral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(
        db.String(36), db.ForeignKey('field_officer.id'), nullable=False)
    referred_user_name = db.Column(db.String(50), nullable=False)
    referred_user_email = db.Column(db.String(255), nullable=False, index=True)
    referred_user_card_number = db.Column(
        db.String(100), nullable=False, index=True)
    validity = db.Column(db.Boolean, nullable=False, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    referral_id = db.Column(
        db.Integer, db.ForeignKey('field_officer_referral.id'))
    referrer = db.relationship('FieldOfficer', back_populates='referrals_made')

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

    @staticmethod
    def get_successful_referrals(user_id, limit=10):
        # Get the successful referrals made by a user
        referrals = FieldOfficerSuccessfulReferral.query.filter_by(
            referrer_id=user_id).limit(limit).all()
        return [referral.to_dict() for referral in referrals]

    @staticmethod
    def get_weekly_work_done(user_id):
        # Calculate the start and end dates for the current week
        start_of_week = datetime.now().date() - timedelta(days=datetime.now().date().weekday())
        end_of_week = start_of_week + timedelta(days=6)

        # Query to get the successful referrals for the current week
        weekly_work_done = FieldOfficerSuccessfulReferral.query.filter(
            FieldOfficerSuccessfulReferral.referrer_id == user_id,
            FieldOfficerSuccessfulReferral.timestamp >= start_of_week,
            FieldOfficerSuccessfulReferral.timestamp <= end_of_week
        ).all()

        return [referral.to_dict() for referral in weekly_work_done]

    @staticmethod
    def get_monthly_work_done(user_id):
        # Calculate the start and end dates for the current month
        start_of_month = datetime.now().replace(day=1).date()
        end_of_month = start_of_month + timedelta(days=31)

        # Query to get the successful referrals for the current month
        monthly_work_done = FieldOfficerSuccessfulReferral.query.filter(
            FieldOfficerSuccessfulReferral.referrer_id == user_id,
            FieldOfficerSuccessfulReferral.timestamp >= start_of_month,
            FieldOfficerSuccessfulReferral.timestamp <= end_of_month
        ).all()

        return [referral.to_dict() for referral in monthly_work_done]

    @staticmethod
    def get_total_referrals(user_id):
        # Query to get all successful referrals for the user
        total_referrals = FieldOfficerSuccessfulReferral.query.filter(
            FieldOfficerSuccessfulReferral.referrer_id == user_id
        ).all()

        return [referral.to_dict() for referral in total_referrals]


############################################################
############################################################
############################################################
#################  Nominated Field  ########################
class NominatedFieldOfficer(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    full_name = db.Column(db.String(50), nullable=True, unique=True)
    agent_email = db.Column(db.String(255), unique=True,
                            nullable=False, index=True)
    agent_card_no = db.Column(db.String(100), index=True, nullable=True)
    bvn = db.Column(db.String(100), index=True, nullable=True)
    nin = db.Column(db.String(100), index=True, nullable=True)
    gender = db.Column(db.String(255), index=True, nullable=True)
    password = db.Column(db.String(255), nullable=False, default="0000-0000")
    address = db.Column(db.String(255), index=True, nullable=True)
    guarantor_name = db.Column(db.String(255), nullable=False, unique=True)
    guarantor_phone_number = db.Column(
        db.String(255), nullable=False, unique=True)
    guarantor_bvn = db.Column(db.String(25), nullable=False, unique=True)
    guarantor_nin = db.Column(
        db.String(25), nullable=False, unique=True)
    guarantor_address = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(255), index=True,
                             unique=True, nullable=True)
    date_of_birth = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)
    nominated_me = db.Column(db.String(100), index=True, nullable=True)
    unique_referral_link = db.Column(db.String(100), index=True, nullable=True)
    signature = db.Column(db.TEXT, default=None, index=True, nullable=True)
    passport_photo = db.Column(
        db.TEXT, default=None, index=True, nullable=True)
    guarantor_photo = db.Column(
        db.TEXT, default=None, index=True, nullable=True)
    is_email_verified = db.Column(db.Boolean, default=False, index=True)
    referrals_made = db.relationship(
        'NominatedFieldOfficerSuccessfulReferral', back_populates='referrer', lazy='dynamic')
    office_status = db.Column(
        db.Boolean, default=False, index=True, nullable=True)
    referral = db.relationship(
        'NominatedFieldOfficerReferral', back_populates='user', uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "full_name": self.full_name,
            "agent_email": self.agent_email,
            "agent_card_no": self.agent_card_no,
            "bvn": self.bvn,
            "nin": self.nin,
            "gender": self.gender,
            "password": self.password,
            "address": self.address,
            "guarantor_name": self.guarantor_name,
            "guarantor_phone_number": self.guarantor_phone_number,
            "guarantor_bvn": self.guarantor_bvn,
            "guarantor_nin": self.guarantor_nin,
            "guarantor_address": self.guarantor_address,
            "phone_number": self.phone_number,
            "date_of_birth": str(self.date_of_birth) if self.date_of_birth else None,
            "created_at": str(self.created_at),
            "modified_at": str(self.modified_at),
            "nominated_me": self.nominated_me,
            "unique_referral_link": self.unique_referral_link,
            "signature": self.signature,
            "passport_photo": self.passport_photo,
            "guarantor_photo": self.guarantor_photo,
            "is_email_verified": self.is_email_verified,
            "office_status": self.office_status,
            "referral": self.referral.to_dict() if self.referral else None,
            "successful_referrals": [referral.to_dict() for referral in self.referrals_made]
        }


class NominatedFieldOfficerReferral(db.Model):
    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'nominated_field_officer.id'), unique=True, nullable=False)
    monthly_target = db.Column(db.Integer, nullable=True)
    total_referrals = db.Column(db.Integer, default=0, nullable=False)
    user = db.relationship(
        'NominatedFieldOfficer', back_populates='referral', uselist=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "monthly_target": self.monthly_target,
            "total_referrals_completed": self.total_referrals,
        }

    def calculate_completion_percentage(self):
        if self.monthly_target == 0:
            return 100  # If monthly target is 0, completion is 100%
        return (self.total_referrals / self.monthly_target) * 100

    def get_monthly_users(self):
        try:
            # Calculate the start and end dates for the current month
            today = datetime.utcnow().date()
            start_date = date(today.year, today.month, 1)
            end_date = date(today.year, today.month + 1, 1) - timedelta(days=1)

            # Query successful referrals within the current month
            monthly_users_count = NominatedFieldOfficerSuccessfulReferral.query.filter(
                NominatedFieldOfficerSuccessfulReferral.referrer_id == self.user_id,
                NominatedFieldOfficerSuccessfulReferral.timestamp >= start_date,
                NominatedFieldOfficerSuccessfulReferral.timestamp <= end_date
            ).distinct(NominatedFieldOfficerSuccessfulReferral.referred_user_email).count()

            return monthly_users_count
        except Exception as e:
            print("Error in get_monthly_users:", e)
            return None


class NominatedFieldOfficerSuccessfulReferral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(
        db.String(36), db.ForeignKey('nominated_field_officer.id'), nullable=False)
    referred_user_name = db.Column(db.String(50), nullable=False)
    referred_user_email = db.Column(db.String(255), nullable=False, index=True)
    referred_user_card_number = db.Column(
        db.String(100), nullable=False, index=True)
    validity = db.Column(db.Boolean, nullable=False, default=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    referral_id = db.Column(
        db.Integer, db.ForeignKey('nominated_field_officer_referral.id'))
    referrer = db.relationship(
        'NominatedFieldOfficer', back_populates='referrals_made')

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

    @staticmethod
    def get_successful_referrals(user_id, limit=10):
        # Get the successful referrals made by a user
        referrals = NominatedFieldOfficerSuccessfulReferral.query.filter_by(
            referrer_id=user_id).limit(limit).all()
        return [referral.to_dict() for referral in referrals]

    @staticmethod
    def get_weekly_work_done(user_id):
        # Calculate the start and end dates for the current week
        start_of_week = datetime.now().date() - timedelta(days=datetime.now().date().weekday())
        end_of_week = start_of_week + timedelta(days=6)

        # Query to get the successful referrals for the current week
        weekly_work_done = NominatedFieldOfficerSuccessfulReferral.query.filter(
            NominatedFieldOfficerSuccessfulReferral.referrer_id == user_id,
            NominatedFieldOfficerSuccessfulReferral.timestamp >= start_of_week,
            NominatedFieldOfficerSuccessfulReferral.timestamp <= end_of_week
        ).all()

        return [referral.to_dict() for referral in weekly_work_done]

    @staticmethod
    def get_monthly_work_done(user_id):
        # Calculate the start and end dates for the current month
        start_of_month = datetime.now().replace(day=1).date()
        end_of_month = start_of_month + timedelta(days=31)

        # Query to get the successful referrals for the current month
        monthly_work_done = NominatedFieldOfficerSuccessfulReferral.query.filter(
            NominatedFieldOfficerSuccessfulReferral.referrer_id == user_id,
            NominatedFieldOfficerSuccessfulReferral.timestamp >= start_of_month,
            NominatedFieldOfficerSuccessfulReferral.timestamp <= end_of_month
        ).all()

        return [referral.to_dict() for referral in monthly_work_done]

    @staticmethod
    def get_total_referrals(user_id):
        # Query to get all successful referrals for the user
        total_referrals = NominatedFieldOfficerSuccessfulReferral.query.filter(
            NominatedFieldOfficerSuccessfulReferral.referrer_id == user_id
        ).all()

        return [referral.to_dict() for referral in total_referrals]
