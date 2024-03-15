from io import StringIO, BytesIO
import pandas as pd
import zipfile
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from functools import wraps
import json
from datetime import datetime
import uuid
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, session, send_file
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_session import Session
from models import db, User, AccecptanceForm, SuccessfulReferral, Referral, FieldOfficer, FieldOfficerReferral
from config import ApplicationConfig
import os
import requests
import string
from flask_mail import Mail, Message
import base64
import cloudinary
import cloudinary.uploader
import cloudinary.api
from passlib.hash import bcrypt_sha256
cloudinary.config(
    cloud_name="dagw7pro6",
    api_key="761564937985964",
    api_secret="4GsZPO7aW5TvNNrkIAD4AgC_TTI"
)
# 
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######### Initializing the app with the necessary packages #########
app = Flask(__name__)
# app_asgi = WsgiToAsgi(app)
app.config.from_object(ApplicationConfig)
CORS(app, allow_headers=True, supports_credentials=True)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
migrate = Migrate(app, db)
server_session = Session(app)
db.init_app(app)
# with app.app_context():
#     db.drop_all()
#     db.create_all()



####################################################################
######## Setting a concurent function to be run per request #######
@app.after_request
def add_cors_headers(response):
    frontend_domains = [
        'http://localhost:3000',
        'http://enetworksoffice.com.ng',
        'http://www.enetworksoffice.com.ng',
        'https://enetworksoffice.com.ng',
        'https://www.enetworksoffice.com.ng'
    ]

    origin = request.headers.get('Origin')
    if origin in frontend_domains:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
####################################################################
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
####################################################################
################## Function to save profile Image ##################
def upload_image_to_cloudinary(image):
    # Upload the image to Cloudinary
    result = cloudinary.uploader.upload(
        image,
        quality='auto:low',  # Set compression quality
    )
    # Get the public URL of the uploaded image from the Cloudinary response
    image_url = result['url']

    return image_url
####################################################################
####################################################################


@app.route('/')
def hello_world():
    return 'Hello from Koyeb'

@app.route('/create_users_batch', methods=['POST'])
def create_users_batch():
    """
    This creates users in Batches. It recieves an array of lists which it then iterates over to
    create the user, then hash the password and set the referral target based of position
    """
    try:
        data = request.get_json()

        if not isinstance(data, list):
            return jsonify({"error": "Invalid input format. Expected a list of emails and positions."}), 400

        created_users = []

        for entry in data:
            if not isinstance(entry, dict) or 'email' not in entry or 'position' not in entry:
                created_users.append(
                    {"message": "Invalid entry format. Skipping."})
                continue

            email = entry['email']
            position = entry['position']

            try:
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    created_users.append(
                        {"email": email, "message": "User already exists. Skipping."})
                    continue

                password = "0000-0000"
                hashed_password = bcrypt_sha256.hash(password)

                # Create a new user
                new_user = User(email=email, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()

                # Create a referral for the new user
                monthly_target = 50 if position.upper() == 'LG' else 30
                referral_data = Referral(
                    user_id=new_user.id, monthly_target=monthly_target, total_referrals=0)
                db.session.add(referral_data)
                db.session.commit()

                created_users.append(
                    {"email": email, "message": "User and referral created successfully."})
            except Exception as user_creation_error:
                # Print or log the specific error details for debugging
                print(
                    f"Error creating user for email {email}: {str(user_creation_error)}")
                created_users.append(
                    {"email": email, "message": "Error creating user."})

        return jsonify({"created_users": created_users}), 201

    except Exception as e:
        # Print or log the specific error details for debugging
        print(f"An error occurred while processing the request: {str(e)}")
        return jsonify({"error": "An error occurred while processing the request."}), 500

@app.route('/login', methods=["POST"])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if user is None or not bcrypt_sha256.verify(password, user.password):
        return jsonify({"message": "Wrong email or password"}), 401

    # Create the access token with the user ID as the identity
    access_token = create_access_token(identity=str(user.id))

    # Return the access token and user role as JSON response
    return jsonify(message="Logged in successfully", access_token=access_token), 200

@app.route('/dashboard', methods=["GET"])
@jwt_required()
def dashboard():

    current_user_id = get_jwt_identity()

    # Query the user information from the database
    user = User.query.filter_by(id=current_user_id).first()

    if user is None:
        return jsonify({"message": "User not found"}), 404

    # Get user data using the to_dict method
    dashboard_data = user.to_dict()

    return jsonify(dashboard_data), 200

@app.route('/submit_referral', methods=['POST'])
@jwt_required()
def submit_referral():
    try:
        current_user_id = get_jwt_identity()

        # Ensure the current user exists
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({"message": "User not found"}), 404

        # Parse details from the request
        referred_user_name = request.json.get('referred_user_name')
        referred_user_email = request.json.get('referred_user_email')
        referred_user_card_number = request.json.get('referred_user_card_number')

        # Make API request to fetch user data
        api_url_fetch_user_data = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
        api_payload_fetch_user_data = {'email': referred_user_email}
        api_response_fetch_user_data = requests.post(
            api_url_fetch_user_data, data=api_payload_fetch_user_data)

        if api_response_fetch_user_data.status_code == 200:
            api_data_fetch_user_data = api_response_fetch_user_data.json()

            if api_data_fetch_user_data['status']:
                user_data = api_data_fetch_user_data['agent_details']

                # Check if the email in the referred_me matches the email of the logged-in user
                if user_data.get('referred_by') != current_user.email:
                    return jsonify({"message": "The nominated user does not match the referred user"}), 400

                # Check account status and error reasons
                if user_data['account_status'] is False or user_data.get('error_reason'):
                    error_reasons = user_data.get('error_reason', [])
                    return jsonify({"message": "Applicant does not have a valid account or card", "error_reasons": error_reasons}), 400

                # Check user balance
                if "Applicant must have a minimum wallet balance of #10,000." in user_data.get('error_reason', []):
                    error_reasons = user_data.get('error_reason', [])
                    return jsonify({"message": "Applicant must have a minimum wallet balance of #10,000.", "error_reasons": error_reasons}), 400

                # Create a new SuccessfulReferral instance
                new_referral = SuccessfulReferral(
                    referrer_id=current_user.id,
                    referred_user_name=referred_user_name,
                    referred_user_email=referred_user_email,
                    referred_user_card_number=referred_user_card_number,
                    validity=True,
                    timestamp=datetime.utcnow()
                )

                # Add the new referral to the database
                db.session.add(new_referral)
                db.session.commit()

                # Update the Referral table
                referral = Referral.query.filter_by(
                    user_id=current_user.id).first()
                if referral:
                    referral.total_referrals = referral.total_referrals + 1
                    db.session.commit()

                return jsonify({"message": "Referral submitted successfully"}), 201

            else:
                error_reasons = api_data_fetch_user_data.get(
                    "error_reason", [])
                return jsonify({"message": "Failed to fetch user data", "error_reasons": error_reasons}), 500

        else:
            return jsonify({"message": "Failed to fetch user data", "error_reasons": []}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/submit_form', methods=['POST'])
@jwt_required()
def submit_form():
    try:
        current_user_id = get_jwt_identity()

        # Check if the current user is logged in
        if not current_user_id:
            return jsonify({"message": "User not logged in"}), 401

        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        form_data = request.form
        signature_image = request.files.get('signature')
        profile_image = request.files.get('profile_image')
        passport_photo = request.files.get('passport_photo')
        guarantor_photo = request.files.get('guarantor_passport')

        if not signature_image or not profile_image or not passport_photo or not guarantor_photo:
            return jsonify(message="One or more required files not provided in the request"), 400

        required_fields = ['name', 'address', 'bvn', 'nin', 'agent_email', 'agent_card_number',
                           'gender', 'guarantor_name', 'guarantor_phone_number', 'guarantor_bvn', 'guarantor_nin',
                           'guarantor_address', 'date_of_birth', 'phone_number']

        for field in required_fields:
            if field not in form_data:
                return jsonify({"message": f"Missing required field: {field}"}), 400

        # Create a new instance of AccecptanceForm
        acceptance_form = AccecptanceForm(
            full_name=form_data.get('name'),
            bvn=form_data.get('bvn'),
            nin=form_data.get('nin'),
            agent_email=form_data.get('agent_email'),
            agent_card_number=form_data.get('agent_card_number'),
            address=form_data.get('address'),
            gender=form_data.get('gender'),
            guarantor_name=form_data.get('guarantor_name'),
            guarantor_phone_number=form_data.get('guarantor_phone_number'),
            guarantor_bvn=form_data.get('guarantor_bvn'),
            guarantor_nin=form_data.get('guarantor_nin'),
            guarantor_address=form_data.get('guarantor_address'),
            guarantor_pasport=cloudinary.uploader.upload(guarantor_photo)['url'],
            profile_image=cloudinary.uploader.upload(profile_image)['url'],
            signature=cloudinary.uploader.upload(signature_image)['url'],
            passport=cloudinary.uploader.upload(passport_photo)['url'],
            created_at=datetime.utcnow(),
            modified_at=datetime.utcnow(),
            date_of_birth=datetime.strptime(form_data.get('date_of_birth'), '%Y-%m-%d').date(),
            is_email_verified=False
        )

        # Add the acceptance form to the database
        db.session.add(acceptance_form)
        db.session.commit()

        # Update user filled_form attribute
        user.filled_form = True

        # Update remaining fields of the user model
	user.full_name = form_data.get('name')
        user.address = form_data.get('address')
        user.bvn = form_data.get('bvn')
        user.nin = form_data.get('nin')
        user.agent_email = form_data.get('agent_email')
        user.agent_card_no = form_data.get('agent_card_number')
        user.gender = form_data.get('gender')
        user.guarantor_name = form_data.get('guarantor_name')
        user.guarantor_phone_number = form_data.get('guarantor_phone_number')
        user.guarantor_bvn = form_data.get('guarantor_bvn')
        user.guarantor_nin = form_data.get('guarantor_nin')
        user.guarantor_address = form_data.get('guarantor_address')
        user.date_of_birth = datetime.strptime(
            form_data.get('date_of_birth'), '%Y-%m-%d').date()
        user.phone_number = form_data.get('phone_number')
	user.profile_image = profile_image

        db.session.commit()

        return jsonify(message="Form submitted successfully"), 200

    except Exception as e:
        return jsonify(message=str(e)), 500

@app.route('/user/referral', methods=['GET'])
@jwt_required()
def get_user_referral():
    try:
        # Get the current user's identity from the JWT token
        current_user_id = get_jwt_identity()

        # Ensure the current user exists
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({"message": "User not found"}), 404

        # Fetch the referral data for the user
        referral_data = Referral.query.filter_by(
            user_id=current_user.id).first()

        # Check if the referral data exists
        if not referral_data:
            return jsonify({"message": "Referral data not found for the user"}), 404

        # Convert referral data to dictionary
        referral_dict = referral_data.to_dict()

        return jsonify({"referral_data": referral_dict}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/monthly_users', methods=['GET'])
@jwt_required()
def get_monthly_users():
    try:
        # Get the current user's identity from the JWT token
        current_user_id = get_jwt_identity()

        # Ensure the current user exists
        current_user_referral = Referral.query.filter_by(user_id=current_user_id).first()
        if not current_user_referral:
            return jsonify({"message": "User referral data not found"}), 404

        # Get the monthly users for the current user
        monthly_users = current_user_referral.get_monthly_users()

        return jsonify({"monthly_users": monthly_users}), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/successful_referrals', methods=['GET'])
@jwt_required()
def get_successful_referrals_route():
    try:
        user_id = get_jwt_identity()
        # Check if the user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Get successful referrals for the user using the class method
        referrals_data = SuccessfulReferral.get_successful_referrals(user.id)

        return jsonify({"successful_referrals": referrals_data})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/weekly_work_done', methods=['GET'])
@jwt_required()
def get_weekly_work_done_route():
    try:
        # Get user ID from the JWT identity
        current_user_id = get_jwt_identity()

        # Get weekly work done for the user
        weekly_work_done = SuccessfulReferral.get_weekly_work_done(
            current_user_id)
        return jsonify({"weekly_work_done": weekly_work_done})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/monthly_work_done', methods=['GET'])
@jwt_required()
def get_monthly_work_done_route():
    try:
        # Get user ID from the JWT identity
        current_user_id = get_jwt_identity()

        # Get monthly work done for the user
        monthly_work_done = SuccessfulReferral.get_monthly_work_done(
            current_user_id)
        return jsonify({"monthly_work_done": monthly_work_done})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/total_referrals_count', methods=['GET'])
@jwt_required()
def get_total_referrals_count_route():
    try:
        # Get user ID from the JWT identity
        current_user_id = get_jwt_identity()

        # Get total referrals count for the user
        total_referrals_count = SuccessfulReferral.get_total_referrals_count(
            current_user_id)
        return jsonify({"total_referrals_count": total_referrals_count})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create_field_officer', methods=['POST'])
def create_field_officer():
    try:
        data = request.form  # Assuming the data is sent as form data

        # Extracting data from the form
        email = data.get('email')
        full_name = data.get('full_name')
        password = data.get('password')
        phone_number = data.get('phone_number')
        agent_email = data.get('agent_email')
        agent_card_no = data.get('agent_card_no')
        address = data.get('address')
        gender = data.get('gender')
        date_of_birth = datetime.strptime(data.get('date_of_birth'), '%Y-%m-%d').date()
        nominated_me = data.get('nominated_me')
        profile_image = request.files.get('profile_image')

        # Make API call to fetch user data
        api_url = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
        api_payload_fetch_user_data = {'email': email}

        # Make API call to fetch user data
        user_data_response = requests.post(api_url, data=api_payload_fetch_user_data).json()

        # Check if the nominated user matches the referred user in the response
        referred_by_email = user_data_response.get('agent_details', {}).get('referred_by', '')
        if referred_by_email != nominated_me:
            return jsonify({"error": "The nominated user does not match the referred user"}), 400

        # Create a unique referral link
        unique_referral_link = f"https://enetworkspay.com/register.php?ref={nominated_me}&id={email}"

        # Create a new field officer instance
        new_field_officer = FieldOfficer(
            email=email,
            full_name=full_name,
            password=password,
            phone_number=phone_number,
            agent_email=agent_email,
            agent_card_no=agent_card_no,
            address=address,
            gender=gender,
            date_of_birth=date_of_birth,
            nominated_me=nominated_me,
            unique_referral_link=unique_referral_link,
            created_at=datetime.utcnow(),
            modified_at=datetime.utcnow(),
            profile_image=cloudinary.uploader.upload(profile_image)['url'] if profile_image else None,
            is_email_verified=False,
            filled_form=True,  # Assuming the form is being filled during creation
            office_status=False  # Assuming the default office status
        )

        # Add the new field officer to the database
        db.session.add(new_field_officer)
        db.session.commit()  # Commit the changes

        # Retrieve the newly created field officer to get the user_id
        new_field_officer = FieldOfficer.query.filter_by(email=email).first()

        # Check if the field officer was retrieved successfully
        if new_field_officer:
            # Create a referral for the new field officer
            monthly_target = 100
            referral_data = Referral(
                user_id=new_field_officer.id,
                monthly_target=monthly_target,
                total_referrals=0
            )
            db.session.add(referral_data)

            # Commit the changes
            db.session.commit()

            return jsonify({"message": "Field officer created successfully"}), 201
        else:
            return jsonify({"error": "Error retrieving the newly created field officer"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
