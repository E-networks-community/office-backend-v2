from datetime import date, datetime, timedelta
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError
from flask_migrate import Migrate
from sqlalchemy import and_, func
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, SuccessfulReferral, Referral, FieldOfficer, FieldOfficerReferral, FieldOfficerSuccessfulReferral, NominatedFieldOfficer, NominatedFieldOfficerReferral
from config import ApplicationConfig
import requests
from flask_mail import Mail
import cloudinary
import cloudinary.uploader
import logging
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
logging.basicConfig(level=logging.INFO)
CORS(app, allow_headers=True, supports_credentials=True)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
migrate = Migrate(app, db)
# server_session = Session(app)
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
        'https://enetworksjobs.com.ng',
        'https://www.enetworksjobs.com.ng'
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
    return jsonify(message="Hello from Aldorax!")


@app.route("/api/submit", methods=["POST"])
def submit_test():
    form_data = request.form.to_dict()
    files = request.files

    # Print form data in the terminal
    print("Received form data:")
    for key, value in form_data.items():
        print(f"{key}: {value}")

    # Print file data in the terminal
    print("Received files:")
    for key in files:
        file = files[key]
        print(f"{key}: {file.filename}")

    # Combine form data and file data for response
    response_data = form_data.copy()
    for key in files:
        response_data[key] = files[key].filename

    return jsonify(response_data), 200


@app.route('/staff/apply', methods=['POST'])
def create_user():
    try:
        data = request.form

        # Handle image upload to Cloudinary
        if 'passport_photo' not in request.files:
            return jsonify({"error": "No passport photo provided"}), 400

        passport_photo = request.files['passport_photo']
        if passport_photo.filename == '':
            return jsonify({"error": "Empty passport photo file"}), 400

        upload_result = cloudinary.uploader.upload(passport_photo)
        passport_photo_url = upload_result['url']

        password = bcrypt_sha256.hash("0000-0000")
        if 'password' in request.form:
            req_password = data.get('password')
            hashed_password = bcrypt_sha256.hash(req_password)
            password = hashed_password

        # Create new user
        new_user = User(
            full_name=data.get('full_name'),
            phone_number=data.get('phone_number'),
            agent_email=data.get('agent_email'),
            agent_card_number=data.get('agent_card_number'),
            password=password,
            address=data.get('address'),
            state=data.get('state'),
            lga=data.get('lga'),
            ward=data.get('ward'),
            gender=data.get('gender'),
            next_of_kin_name=data.get('next_of_kin_name'),
            next_of_kin_phone_number=data.get('next_of_kin_phone_number'),
            next_of_kin_relationship=data.get('next_of_kin_relationship'),
            next_of_kin_email_address=data.get('next_of_kin_email_address'),
            guarantor_name=data.get('guarantor_name'),
            guarantor_phone_number=data.get('guarantor_phone_number'),
            language=data.get('language'),
            position=data.get('position'),
            position_state=data.get('position_state'),
            passport_photo=passport_photo_url
        )

        db.session.add(new_user)
        db.session.commit()

        base_referral = Referral(user_id=new_user.id, monthly_target=50)
        db.session.add(base_referral)
        db.session.commit()

        return jsonify(new_user.to_dict()), 201

    except Exception as e:
        print(str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/field/apply', methods=['POST'])
def create_field_officer():
    data = request.form

    try:
        # Upload images to Cloudinary
        passport_photo_url = None
        guarantor_photo_url = None
        signature_url = None
        password = "0000-0000"

        if 'passport_photo' not in request.files:
            return jsonify(message="Please upload a valid passport photograph"), 400

        if 'guarantor_photo' not in request.files:
            return jsonify(message="Please upload a valid guarantor photo"), 400

        if 'signature' not in request.files:
            return jsonify(message="Please upload a valid signature"), 400

        if 'passport_photo' in request.files:
            uploaded_passport_photo = cloudinary.uploader.upload(
                request.files['passport_photo'])
            passport_photo_url = uploaded_passport_photo['url']

        if 'guarantor_photo' in request.files:
            uploaded_guarantor_photo = cloudinary.uploader.upload(
                request.files['guarantor_photo'])
            guarantor_photo_url = uploaded_guarantor_photo['url']

        if 'signature' in request.files:
            uploaded_signature = cloudinary.uploader.upload(
                request.files['signature'])
            signature_url = uploaded_signature['url']

        if 'password' in request.form:
            req_password = data.get('password')
            hashed_password = bcrypt_sha256.hash(req_password)
            password = hashed_password

        date_of_birth = None
        if 'date_of_birth' in request.form:
            date_of = data.get('date_of_birth')
            date_of_birth = datetime.strptime(date_of, '%Y-%m-%d')

        # Create new FieldOfficer object
        new_field_officer = FieldOfficer(
            full_name=data.get('full_name'),
            agent_email=data.get('agent_email'),
            agent_card_no=data.get('agent_card_number'),
            password=password,
            bvn=data.get('bvn'),
            nin=data.get('nin'),
            gender=data.get('gender'),
            address=data.get('address'),
            guarantor_name=data.get('guarantor_name'),
            guarantor_phone_number=data.get('guarantor_phone_number'),
            guarantor_bvn=data.get('guarantor_bvn'),
            guarantor_nin=data.get('guarantor_nin'),
            guarantor_address=data.get('guarantor_address'),
            phone_number=data.get('phone_number'),
            date_of_birth=date_of_birth,
            created_at=datetime.utcnow(),
            modified_at=datetime.utcnow(),
            signature=signature_url,
            passport_photo=passport_photo_url,
            guarantor_photo=guarantor_photo_url,
        )

        # Add and commit the new FieldOfficer to the database
        db.session.add(new_field_officer)
        db.session.commit()

        base_referral = FieldOfficerReferral(
            user_id=new_field_officer.id, monthly_target=50)
        db.session.add(base_referral)
        db.session.commit()

        return jsonify(new_field_officer.to_dict()), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "message": str(e)}), 500
    except cloudinary.exceptions.Error as e:
        return jsonify({"error": "Image upload error", "message": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


@app.route('/nominated-field/apply', methods=['POST'])
def create_nominated_field_officer():
    data = request.form

    try:
        # Required fields check
        if 'passport_photo' not in request.files:
            return jsonify(message="Please upload a valid passport photograph"), 400
        if 'guarantor_photo' not in request.files:
            return jsonify(message="Please upload a valid guarantor photo"), 400
        if 'signature' not in request.files:
            return jsonify(message="Please upload a valid signature"), 400

        # Upload images to Cloudinary
        passport_photo_url = cloudinary.uploader.upload(
            request.files['passport_photo'])['url']
        guarantor_photo_url = cloudinary.uploader.upload(
            request.files['guarantor_photo'])['url']
        signature_url = cloudinary.uploader.upload(
            request.files['signature'])['url']

        # Hash password if provided
        password = bcrypt_sha256.hash("0000-0000")
        if 'password' in request.form:
            req_password = data.get('password')
            hashed_password = bcrypt_sha256.hash(req_password)
            password = hashed_password

        # Parse date of birth if provided
        date_of_birth = None
        if 'date_of_birth' in request.form:
            date_of = data.get('date_of_birth')
            date_of_birth = datetime.strptime(date_of, '%Y-%m-%d')

        # Fetch user data from external API
        api_url = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
        api_payload_fetch_user_data = {'email': data.get('agent_email')}
        user_data_response = requests.post(
            api_url, data=api_payload_fetch_user_data)
        user_data = user_data_response.json()

        # Check API response status
        if not user_data.get('status'):
            return jsonify({"error": "API returned False status"}), 400

        # Ensure the person who referred the user matches nominated_me
        referred_by_email = user_data.get(
            'agent_details', {}).get('referred_by', '')
        if referred_by_email != data.get('nominated_me'):
            return jsonify({"error": "The person who referred you does not match the nominated_me"}), 400

        # Create a unique referral link
        unique_referral_link = f"https://enetworkspay.com/register.php?ref={
            data.get('nominated_me')}&id={data.get('agent_email')}"

        # Create new NominatedFieldOfficer object
        new_field_officer = NominatedFieldOfficer(
            full_name=data.get('full_name'),
            agent_email=data.get('agent_email'),
            agent_card_no=data.get('agent_card_number'),
            bvn=data.get('bvn'),
            nin=data.get('nin'),
            gender=data.get('gender'),
            password=password,
            address=data.get('address'),
            guarantor_name=data.get('guarantor_name'),
            guarantor_phone_number=data.get('guarantor_phone_number'),
            guarantor_bvn=data.get('guarantor_bvn'),
            guarantor_nin=data.get('guarantor_nin'),
            guarantor_address=data.get('guarantor_address'),
            phone_number=data.get('phone_number'),
            date_of_birth=date_of_birth,
            created_at=datetime.utcnow(),
            modified_at=datetime.utcnow(),
            nominated_me=data.get('nominated_me'),
            unique_referral_link=unique_referral_link,
            signature=signature_url,
            passport_photo=passport_photo_url,
            guarantor_photo=guarantor_photo_url,
            is_email_verified=data.get('is_email_verified', False),
            office_status=data.get('office_status', False)
        )

        # Add and commit the new NominatedFieldOfficer to the database
        db.session.add(new_field_officer)
        db.session.commit()

        base_referral = NominatedFieldOfficerReferral(
            user_id=new_field_officer.id, monthly_target=50)
        db.session.add(base_referral)
        db.session.commit()

        return jsonify(new_field_officer.to_dict()), 201

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({"error": "Database error", "message": str(e)}), 500
    except cloudinary.exceptions.Error as e:
        return jsonify({"error": "Image upload error", "message": str(e)}), 500
    except requests.RequestException as e:
        return jsonify({"error": "External API request error", "message": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500

# Staff login route


@app.route('/login/staff', methods=['POST'])
def staff_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Find staff by email
    staff = User.query.filter_by(agent_email=email).first()
    if not staff:
        return jsonify({"error": "Invalid email or password"}), 401

    # Verify password
    if not bcrypt_sha256.verify(password, staff.password):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = create_access_token(identity=str(staff.id))

    # Return staff details
    return jsonify({"message": "Staff logged in successfully", "access_token": access_token}), 200


@app.route('/staff/dashboard', methods=['GET'])
@jwt_required()
def staff_dashboard():
    current_user_id = get_jwt_identity()

    # Query the user information from the database
    staff = User.query.filter_by(id=current_user_id).first()

    if staff is None:
        return jsonify({"message": "User not found"}), 404

    # Get user data using the to_dict method
    dashboard_data = staff.to_dict()

    return jsonify(dashboard_data), 200

# Field Officer login route


@app.route('/add_successful_referral', methods=['POST'])
@jwt_required()
def add_successful_referral():
    data = request.json
    current_user_id = get_jwt_identity()

    try:
        # Create a new successful referral associated with the current user
        new_successful_referral = SuccessfulReferral(
            referrer_id=current_user_id,
            referred_user_name=data.get('referred_user_name'),
            referred_user_email=data.get('referred_user_email'),
            referred_user_card_number=data.get('referred_user_card_number'),
            validity=True,  # Assuming referral is initially valid
            timestamp=datetime.utcnow()
        )

        # Add the new successful referral to the database
        db.session.add(new_successful_referral)
        db.session.commit()

        return jsonify({"message": "Successful referral added successfully"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


@app.route('/staff/referral', methods=['GET'])
@jwt_required()
def get_user_referral():
    user_id = get_jwt_identity()
    try:
        # Fetch the user's referral details
        user_referral = Referral.query.filter_by(user_id=user_id).first()
        if not user_referral:
            return jsonify({"error": "User referral not found"}), 404

        # Get referral counts for today
        today = datetime.utcnow().date()
        referrals_today = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == user_id,
            func.DATE(SuccessfulReferral.timestamp) == today
        ).count()

        # Get referral counts for this week
        start_of_week = today - timedelta(days=today.weekday())
        end_of_week = start_of_week + timedelta(days=6)
        referrals_this_week = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == user_id,
            and_(
                func.DATE(SuccessfulReferral.timestamp) >= start_of_week,
                func.DATE(SuccessfulReferral.timestamp) <= end_of_week
            )
        ).count()

        # Get referral counts for this month
        start_of_month = date(today.year, today.month, 1)
        end_of_month = date(today.year, today.month + 1, 1) - timedelta(days=1)
        referrals_this_month = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == user_id,
            and_(
                func.DATE(SuccessfulReferral.timestamp) >= start_of_month,
                func.DATE(SuccessfulReferral.timestamp) <= end_of_month
            )
        ).count()

        # Calculate total referrals dynamically
        total_referrals = SuccessfulReferral.query.filter(
            SuccessfulReferral.referrer_id == user_id
        ).count()

        # Prepare response
        response = {
            "user_id": user_id,
            "monthly_target": user_referral.monthly_target,
            "total_referrals": total_referrals,  # Use dynamically calculated value
            "referrals_today": referrals_today,
            "referrals_this_week": referrals_this_week,
            "referrals_this_month": referrals_this_month
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500



@app.route('/login/field_officer', methods=['POST'])
def field_officer_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Find field officer by email
    field_officer = FieldOfficer.query.filter_by(email=email).first()
    if not field_officer:
        return jsonify({"error": "Invalid email or password"}), 401

    # Verify password
    if not bcrypt_sha256.verify(password, field_officer.password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Return field officer details
    return jsonify({"message": "Field officer logged in successfully", "field_officer": field_officer.to_dict()}), 200

# Nominated Field Officer login route


@app.route('/field/dashboard', methods=['GET'])
@jwt_required()
def field_dashboard():
    current_user_id = get_jwt_identity()

    # Query the user information from the database
    staff = FieldOfficer.query.filter_by(id=current_user_id).first()

    if staff is None:
        return jsonify({"message": "User not found"}), 404

    # Get user data using the to_dict method
    dashboard_data = staff.to_dict()

    return jsonify(dashboard_data), 200


@app.route('/staff/successful_referrals', methods=['GET'])
@jwt_required()
def get_successful_referrals():
    try:
        # Get the user ID from the JWT token
        user_id = get_jwt_identity()

        # Query successful referrals for the user
        successful_referrals = SuccessfulReferral.query.filter_by(referrer_id=user_id).all()

        # Convert successful referrals to a list of dictionaries
        successful_referrals_data = [referral.to_dict() for referral in successful_referrals]

        # Return the successful referrals data
        return jsonify(successful_referrals_data), 200
    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
        

@app.route('/field/referral', methods=['GET'])
@jwt_required()
def get_field_referral():
    user_id = get_jwt_identity()
    try:
        # Fetch the user's referral details
        user_referral = FieldOfficerReferral.query.filter_by(
            user_id=user_id).first()
        if not user_referral:
            return jsonify({"error": "User referral not found"}), 404

        # Get referral counts for today
        today = datetime.utcnow().date()
        referrals_today = FieldOfficerReferral.query.filter(
            FieldOfficerReferral.referrer_id == user_id,
            func.DATE(FieldOfficerReferral.timestamp) == today
        ).count()

        # Get referral counts for this week
        start_of_week = today - timedelta(days=today.weekday())
        end_of_week = start_of_week + timedelta(days=6)
        referrals_this_week = FieldOfficerReferral.query.filter(
            FieldOfficerReferral.referrer_id == user_id,
            and_(
                func.DATE(FieldOfficerReferral.timestamp) >= start_of_week,
                func.DATE(FieldOfficerReferral.timestamp) <= end_of_week
            )
        ).count()

        # Get referral counts for this month
        start_of_month = date(today.year, today.month, 1)
        end_of_month = date(today.year, today.month + 1, 1) - timedelta(days=1)
        referrals_this_month = FieldOfficerReferral.query.filter(
            FieldOfficerReferral.referrer_id == user_id,
            and_(
                func.DATE(FieldOfficerReferral.timestamp) >= start_of_month,
                func.DATE(FieldOfficerReferral.timestamp) <= end_of_month
            )
        ).count()

        # Get overall referral count
        overall_referrals = user_referral.total_referrals

        # Prepare response
        response = {
            "user_id": user_id,
            "monthly_target": user_referral.monthly_target,
            "total_referrals": overall_referrals,
            "referrals_today": referrals_today,
            "referrals_this_week": referrals_this_week,
            "referrals_this_month": referrals_this_month
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


@app.route('/field/successful_referrals', methods=['GET'])
@jwt_required()
def get_field_successful_referrals():
    try:
        # Get the user ID from the JWT token
        user_id = get_jwt_identity()

        # Query successful referrals for the user
        successful_referrals = FieldOfficerSuccessfulReferral.query.filter_by(referrer_id=user_id).all()

        # Convert successful referrals to a list of dictionaries
        successful_referrals_data = [referral.to_dict() for referral in successful_referrals]

        # Return the successful referrals data
        return jsonify(successful_referrals_data), 200
    except Exception as e:
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


@app.route('/login/nominated_field_officer', methods=['POST'])
def nominated_field_officer_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Find nominated field officer by email
    nominated_field_officer = NominatedFieldOfficer.query.filter_by(
        email=email).first()
    if not nominated_field_officer:
        return jsonify({"error": "Invalid email or password"}), 401

    # Verify password
    if not bcrypt_sha256.verify(password, nominated_field_officer.password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Return nominated field officer details
    return jsonify({"message": "Nominated field officer logged in successfully", "nominated_field_officer": nominated_field_officer.to_dict()}), 200


@app.route('/nominated-field/dashboard', methods=['GET'])
@jwt_required()
def nominated_field_dashboard():
    current_user_id = get_jwt_identity()

    # Query the user information from the database
    staff = NominatedFieldOfficer.query.filter_by(id=current_user_id).first()

    if staff is None:
        return jsonify({"message": "User not found"}), 404

    # Get user data using the to_dict method
    dashboard_data = staff.to_dict()

    return jsonify(dashboard_data), 200



@app.route("/change-password", methods=["POST"])
@jwt_required()
def change_password():
    data = request.json
    old_password = data.get('oldPassword')
    new_password = data.get('newPassword')

    if not old_password or not new_password:
        return jsonify({"success": False, "message": "Old and new passwords are required"}), 400
    
    current_user_id = get_jwt_identity()
    if not current_user_id:
        return jsonify(message="User not authenticated")
    
    staff = User.query.get(user_id)
    if not staff:
        return jsonify(message="Staff not found")

    if not bcrypt_sha256.verify(staff.password, old_password):
        return jsonify({"error": "Incorrect old password"}), 401

    hashed_password = bcrypt_sha256.encrypt(new_password)

    staff.password = hashed_password
    db.session.commit()

    return jsonify({"success": True, "message": "Password changed successfully"}), 200
    


# @app.route('/create_users_batch', methods=['POST'])
# def create_users_batch():
#     """
#     This creates users in Batches. It recieves an array of lists which it then iterates over to
#     create the user, then hash the password and set the referral target based of position
#     """
#     try:
#         data = request.get_json()

#         if not isinstance(data, list):
#             return jsonify({"error": "Invalid input format. Expected a list of emails and positions."}), 400

#         created_users = []

#         for entry in data:
#             if not isinstance(entry, dict) or 'email' not in entry or 'position' not in entry:
#                 created_users.append(
#                     {"message": "Invalid entry format. Skipping."})
#                 continue

#             email = entry['email']
#             position = entry['position']

#             try:
#                 existing_user = User.query.filter_by(email=email).first()
#                 if existing_user:
#                     created_users.append(
#                         {"email": email, "message": "User already exists. Skipping."})
#                     continue

#                 password = "0000-0000"
#                 hashed_password = bcrypt_sha256.hash(password)

#                 # Create a new user
#                 new_user = User(email=email, password=hashed_password)
#                 db.session.add(new_user)
#                 db.session.commit()

#                 # Create a referral for the new user
#                 monthly_target = 50 if position.upper() == 'LG' else 30
#                 referral_data = Referral(
#                     user_id=new_user.id, monthly_target=monthly_target, total_referrals=0)
#                 db.session.add(referral_data)
#                 db.session.commit()

#                 created_users.append(
#                     {"email": email, "message": "User and referral created successfully."})
#             except Exception as user_creation_error:
#                 # Print or log the specific error details for debugging
#                 print(
#                     f"Error creating user for email {email}: {str(user_creation_error)}")
#                 created_users.append(
#                     {"email": email, "message": "Error creating user."})

#         return jsonify({"created_users": created_users}), 201

#     except Exception as e:
#         # Print or log the specific error details for debugging
#         print(f"An error occurred while processing the request: {str(e)}")
#         return jsonify({"error": "An error occurred while processing the request."}), 500


# @app.route('/login', methods=["POST"])
# def login():
#     email = request.json.get('email')
#     password = request.json.get('password')

#     user = User.query.filter_by(email=email).first()

#     if user is None or not bcrypt_sha256.verify(password, user.password):
#         return jsonify({"message": "Wrong email or password"}), 401

#     # Create the access token with the user ID as the identity
#     access_token = create_access_token(identity=str(user.id))

#     # Return the access token and user role as JSON response
#     return jsonify(message="Logged in successfully", access_token=access_token), 200


# @app.route('/dashboard', methods=["GET"])
# @jwt_required()
# def dashboard():

#     current_user_id = get_jwt_identity()

#     # Query the user information from the database
#     user = User.query.filter_by(id=current_user_id).first()

#     if user is None:
#         return jsonify({"message": "User not found"}), 404

#     # Get user data using the to_dict method
#     dashboard_data = user.to_dict()

#     return jsonify(dashboard_data), 200


# @app.route('/submit_referral', methods=['POST'])
# @jwt_required()
# def submit_referral():
#     try:
#         current_user_id = get_jwt_identity()

#         # Ensure the current user exists
#         current_user = User.query.get(current_user_id)
#         if not current_user:
#             return jsonify({"message": "User not found"}), 404

#         # Parse details from the request
#         referred_user_name = request.json.get('referred_user_name')
#         referred_user_email = request.json.get('referred_user_email')
#         referred_user_card_number = request.json.get(
#             'referred_user_card_number')

#         # Make API request to fetch user data
#         api_url_fetch_user_data = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
#         api_payload_fetch_user_data = {'email': referred_user_email}
#         api_response_fetch_user_data = requests.post(
#             api_url_fetch_user_data, data=api_payload_fetch_user_data)

#         if api_response_fetch_user_data.status_code == 200:
#             api_data_fetch_user_data = api_response_fetch_user_data.json()

#             if api_data_fetch_user_data['status']:
#                 user_data = api_data_fetch_user_data['agent_details']

#                 # Check if the email in the referred_me matches the email of the logged-in user
#                 if user_data.get('referred_by') != current_user.email:
#                     return jsonify({"message": "The nominated user does not match the referred user"}), 400

#                 # Check account status and error reasons
#                 if user_data['account_status'] is False or user_data.get('error_reason'):
#                     error_reasons = user_data.get('error_reason', [])
#                     return jsonify({"message": "Applicant does not have a valid account or card", "error_reasons": error_reasons}), 400

#                 # Check user balance
#                 if "Applicant must have a minimum wallet balance of #10,000." in user_data.get('error_reason', []):
#                     error_reasons = user_data.get('error_reason', [])
#                     return jsonify({"message": "Applicant must have a minimum wallet balance of #10,000.", "error_reasons": error_reasons}), 400

#                 # Create a new SuccessfulReferral instance
#                 new_referral = SuccessfulReferral(
#                     referrer_id=current_user.id,
#                     referred_user_name=referred_user_name,
#                     referred_user_email=referred_user_email,
#                     referred_user_card_number=referred_user_card_number,
#                     validity=True,
#                     timestamp=datetime.utcnow()
#                 )

#                 # Add the new referral to the database
#                 db.session.add(new_referral)
#                 db.session.commit()

#                 # Update the Referral table
#                 referral = Referral.query.filter_by(
#                     user_id=current_user.id).first()
#                 if referral:
#                     referral.total_referrals = referral.total_referrals + 1
#                     db.session.commit()

#                 return jsonify({"message": "Referral submitted successfully"}), 201

#             else:
#                 error_reasons = api_data_fetch_user_data.get(
#                     "error_reason", [])
#                 return jsonify({"message": "Failed to fetch user data", "error_reasons": error_reasons}), 500

#         else:
#             return jsonify({"message": "Failed to fetch user data", "error_reasons": []}), 500

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/submit_form', methods=['POST'])
# @jwt_required()
# def submit_form():
#     try:
#         current_user_id = get_jwt_identity()

#         # Check if the current user is logged in
#         if not current_user_id:
#             return jsonify({"message": "User not logged in"}), 401

#         user = User.query.get(current_user_id)
#         if not user:
#             return jsonify({"message": "User not found"}), 404

#         form_data = request.form
#         signature_image = request.files.get('signature')
#         profile_image = request.files.get('profile_image')
#         passport_photo = request.files.get('passport_photo')
#         guarantor_photo = request.files.get('guarantor_passport')

#         if not signature_image or not profile_image or not passport_photo or not guarantor_photo:
#             return jsonify(message="One or more required files not provided in the request"), 400

#         required_fields = ['name', 'address', 'bvn', 'nin', 'agent_email', 'agent_card_number',
#                            'gender', 'guarantor_name', 'guarantor_phone_number', 'guarantor_bvn', 'guarantor_nin',
#                            'guarantor_address', 'date_of_birth', 'phone_number']

#         for field in required_fields:
#             if field not in form_data:
#                 return jsonify({"message": f"Missing required field: {field}"}), 400

#         # Create a new instance of AccecptanceForm
#         acceptance_form = AccecptanceForm(
#             full_name=form_data.get('name'),
#             bvn=form_data.get('bvn'),
#             nin=form_data.get('nin'),
#             agent_email=form_data.get('agent_email'),
#             agent_card_number=form_data.get('agent_card_number'),
#             address=form_data.get('address'),
#             gender=form_data.get('gender'),
#             guarantor_name=form_data.get('guarantor_name'),
#             guarantor_phone_number=form_data.get('guarantor_phone_number'),
#             guarantor_bvn=form_data.get('guarantor_bvn'),
#             guarantor_nin=form_data.get('guarantor_nin'),
#             guarantor_address=form_data.get('guarantor_address'),
#             guarantor_pasport=cloudinary.uploader.upload(guarantor_photo)[
#                 'url'],
#             profile_image=cloudinary.uploader.upload(profile_image)['url'],
#             signature=cloudinary.uploader.upload(signature_image)['url'],
#             passport=cloudinary.uploader.upload(passport_photo)['url'],
#             created_at=datetime.utcnow(),
#             modified_at=datetime.utcnow(),
#             date_of_birth=datetime.strptime(
#                 form_data.get('date_of_birth'), '%Y-%m-%d').date(),
#             is_email_verified=False
#         )

#         # Add the acceptance form to the database
#         db.session.add(acceptance_form)
#         db.session.commit()

#         # Update user filled_form attribute
#         user.filled_form = True

#         # Update remaining fields of the user model

#         user.full_name = form_data.get('name')
#         user.address = form_data.get('address')
#         user.bvn = form_data.get('bvn')
#         user.nin = form_data.get('nin')
#         user.agent_email = form_data.get('agent_email')
#         user.agent_card_no = form_data.get('agent_card_number')
#         user.gender = form_data.get('gender')
#         user.guarantor_name = form_data.get('guarantor_name')
#         user.guarantor_phone_number = form_data.get('guarantor_phone_number')
#         user.guarantor_bvn = form_data.get('guarantor_bvn')
#         user.guarantor_nin = form_data.get('guarantor_nin')
#         user.guarantor_address = form_data.get('guarantor_address')
#         user.date_of_birth = datetime.strptime(
#             form_data.get('date_of_birth'), '%Y-%m-%d').date()
#         user.phone_number = form_data.get('phone_number')
#         user.profile_image = cloudinary.uploader.upload(profile_image)['url']

#         db.session.commit()

#         return jsonify(message="Form submitted successfully"), 200

#     except Exception as e:
#         return jsonify(message=str(e)), 500


# @app.route('/user/referral', methods=['GET'])
# @jwt_required()
# def get_user_referral():
#     try:
#         # Get the current user's identity from the JWT token
#         current_user_id = get_jwt_identity()

#         # Ensure the current user exists
#         current_user = User.query.get(current_user_id)
#         if not current_user:
#             return jsonify({"message": "User not found"}), 404

#         # Fetch the referral data for the user
#         referral_data = Referral.query.filter_by(
#             user_id=current_user.id).first()

#         # Check if the referral data exists
#         if not referral_data:
#             return jsonify({"message": "Referral data not found for the user"}), 404

#         # Convert referral data to dictionary
#         referral_dict = referral_data.to_dict()

#         return jsonify({"referral_data": referral_dict}), 200

#     except Exception as e:
#         return jsonify({"message": str(e)}), 500


# @app.route('/monthly_users', methods=['GET'])
# @jwt_required()
# def get_monthly_users():
#     try:
#         # Get the current user's identity from the JWT token
#         current_user_id = get_jwt_identity()

#         # Ensure the current user exists
#         current_user_referral = Referral.query.filter_by(
#             user_id=current_user_id).first()
#         if not current_user_referral:
#             return jsonify({"message": "User referral data not found"}), 404

#         # Get the monthly users for the current user
#         monthly_users = current_user_referral.get_monthly_users()

#         return jsonify({"monthly_users": monthly_users}), 200

#     except Exception as e:
#         return jsonify({"message": str(e)}), 500


# @app.route('/successful_referrals', methods=['GET'])
# @jwt_required()
# def get_successful_referrals_route():
#     try:
#         user_id = get_jwt_identity()
#         # Check if the user exists
#         user = User.query.get(user_id)
#         if not user:
#             return jsonify({"error": "User not found"}), 404

#         # Get successful referrals for the user using the class method
#         referrals_data = SuccessfulReferral.get_successful_referrals(user.id)

#         return jsonify({"successful_referrals": referrals_data})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/weekly_work_done', methods=['GET'])
# @jwt_required()
# def get_weekly_work_done_route():
#     try:
#         # Get user ID from the JWT identity
#         current_user_id = get_jwt_identity()

#         # Get weekly work done for the user
#         weekly_work_done = SuccessfulReferral.get_weekly_work_done(
#             current_user_id)
#         return jsonify({"weekly_work_done": weekly_work_done})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/monthly_work_done', methods=['GET'])
# @jwt_required()
# def get_monthly_work_done_route():
#     try:
#         # Get user ID from the JWT identity
#         current_user_id = get_jwt_identity()

#         # Get monthly work done for the user
#         monthly_work_done = SuccessfulReferral.get_monthly_work_done(
#             current_user_id)
#         return jsonify({"monthly_work_done": monthly_work_done})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/total_referrals_count', methods=['GET'])
# @jwt_required()
# def get_total_referrals_count_route():
#     try:
#         # Get user ID from the JWT identity
#         current_user_id = get_jwt_identity()

#         # Get total referrals count for the user
#         total_referrals_count = SuccessfulReferral.get_total_referrals_count(
#             current_user_id)
#         return jsonify({"total_referrals_count": total_referrals_count})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/register', methods=['POST'])
# def create_field_officer():
#     try:
#         # Extracting data from the request JSON
#         email = request.json.get('email')
#         full_name = request.json.get('name')
#         password = request.json.get('password')
#         nominated_me = request.json.get('nominated_me')
#         hashed_password = bcrypt_sha256.hash(password)

#         # Make API call to fetch user data
#         api_url = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
#         api_payload_fetch_user_data = {'email': email}

#         # Make API call to fetch user data
#         user_data_response = requests.post(
#             api_url, data=api_payload_fetch_user_data)

#         # Print the API response content in the terminal
#         print("API Response:", user_data_response.text)

#         # Check if the status is True in the API response
#         user_data = user_data_response.json()
#         status = user_data.get('status')
#         if not status:
#             return jsonify({"error": "API returned False status"}), 400

#         # Ensure that the person who referred the user is equal to nominated_me
#         referred_by_email = user_data.get(
#             'agent_details', {}).get('referred_by', '')
#         if referred_by_email != nominated_me:
#             return jsonify({"error": "The person who referred you does not match the nominated_me"}), 400

#         # Continue with the rest of your code for creating the field officer...
#         # Create a unique referral link
#         unique_referral_link = f"https://enetworkspay.com/register.php?ref={
#             nominated_me}&id={email}"

#         # Create a new field officer instance
#         new_field_officer = FieldOfficer(
#             email=email,
#             full_name=full_name,
#             password=hashed_password,
#             nominated_me=nominated_me,
#             unique_referral_link=unique_referral_link,
#             created_at=datetime.utcnow(),
#             modified_at=datetime.utcnow(),
#             is_email_verified=False,
#             filled_form=False,
#             office_status=False
#         )

#         # Add the new field officer to the database
#         db.session.add(new_field_officer)
#         db.session.commit()  # Commit the changes

#         # Retrieve the newly created field officer to get the user_id
#         new_field_officer = FieldOfficer.query.filter_by(email=email).first()

#         # Check if the field officer was retrieved successfully
#         if new_field_officer:
#             # Create a referral for the new field officer
#             monthly_target = 150
#             referral_data = FieldOfficerReferral(
#                 user_id=new_field_officer.id,
#                 monthly_target=monthly_target,
#                 total_referrals=0
#             )
#             db.session.add(referral_data)

#             # Commit the changes
#             db.session.commit()

#             return jsonify({"message": "Field officer created successfully"}), 201
#         else:
#             return jsonify({"error": "Error retrieving the newly created field officer"}), 500

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/login', methods=["POST"])
# def field_login():
#     email = request.json.get('email')
#     password = request.json.get('password')

#     user = FieldOfficer.query.filter_by(email=email).first()

#     if user is None or not bcrypt_sha256.verify(password, user.password):
#         return jsonify({"message": "Wrong email or password"}), 401

#     # Create the access token with the user ID as the identity
#     access_token = create_access_token(identity=str(user.id))

#     # Return the access token and user role as JSON response
#     return jsonify(message="Logged in successfully", access_token=access_token), 200


# @app.route('/field/dashboard', methods=["GET"])
# @jwt_required()
# def field_dashboard():

#     current_user_id = get_jwt_identity()

#     # Query the user information from the database
#     user = FieldOfficer.query.filter_by(id=current_user_id).first()

#     if user is None:
#         return jsonify({"message": "User not found"}), 404

#     # Get user data using the to_dict method
#     dashboard_data = user.to_dict()

#     return jsonify(dashboard_data), 200


# @app.route('/field/submit_referral', methods=['POST'])
# @jwt_required()
# def field_submit_referral():
#     try:
#         current_user_id = get_jwt_identity()

#         # Query the user information from the database
#         current_user = FieldOfficer.query.filter_by(id=current_user_id).first()
#         if not current_user:
#             return jsonify({"message": "User not found"}), 404

#         # Parse details from the request
#         referred_user_name = request.json.get('referred_user_name')
#         referred_user_email = request.json.get('referred_user_email')
#         referred_user_card_number = request.json.get(
#             'referred_user_card_number')

#         # Make API request to fetch user data
#         api_url_fetch_user_data = 'https://enetworkspay.com/backend_data/api/fetch_user_data.php'
#         api_payload_fetch_user_data = {'email': referred_user_email}
#         api_response_fetch_user_data = requests.post(
#             api_url_fetch_user_data, data=api_payload_fetch_user_data)

#         if api_response_fetch_user_data.status_code == 200:
#             api_data_fetch_user_data = api_response_fetch_user_data.json()

#             if api_data_fetch_user_data['status']:
#                 user_data = api_data_fetch_user_data['agent_details']

#                 # Check if the email in the referred_me matches the email of the logged-in user
#                 if user_data.get('referred_by') != current_user.email:
#                     return jsonify({"message": "The nominated user does not match the referred user"}), 400

#                 # Check account status and error reasons
#                 if user_data['account_status'] is False or user_data.get('error_reason'):
#                     error_reasons = user_data.get('error_reason', [])
#                     return jsonify({"message": "Applicant does not have a valid account or card", "error_reasons": error_reasons}), 400

#                 # Check user balance
#                 if "Applicant must have a minimum wallet balance of #10,000." in user_data.get('error_reason', []):
#                     error_reasons = user_data.get('error_reason', [])
#                     return jsonify({"message": "Applicant must have a minimum wallet balance of #10,000.", "error_reasons": error_reasons}), 400

#                 # Create a new SuccessfulReferral instance
#                 new_referral = SuccessfulReferral(
#                     referrer_id=current_user.id,
#                     referred_user_name=referred_user_name,
#                     referred_user_email=referred_user_email,
#                     referred_user_card_number=referred_user_card_number,
#                     validity=True,
#                     timestamp=datetime.utcnow()
#                 )

#                 # Add the new referral to the database
#                 db.session.add(new_referral)
#                 db.session.commit()

#                 # Update the Referral table
#                 referral = Referral.query.filter_by(
#                     user_id=current_user.id).first()
#                 if referral:
#                     referral.total_referrals = referral.total_referrals + 1
#                     db.session.commit()

#                 return jsonify({"message": "Referral submitted successfully"}), 201

#             else:
#                 error_reasons = api_data_fetch_user_data.get(
#                     "error_reason", [])
#                 return jsonify({"message": "Failed to fetch user data", "error_reasons": error_reasons}), 500

#         else:
#             return jsonify({"message": "Failed to fetch user data", "error_reasons": []}), 500

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/submit_form', methods=['POST'])
# @jwt_required()
# def field_submit_form():
#     try:
#         current_user_id = get_jwt_identity()

#         # Check if the current user is logged in
#         if not current_user_id:
#             return jsonify({"message": "User not logged in"}), 401

#         user = FieldOfficer.query.filter_by(id=current_user_id).first()
#         if not user:
#             return jsonify({"message": "User not found"}), 404

#         form_data = request.form
#         signature_image = request.files.get('signature')
#         profile_image = request.files.get('profile_image')
#         passport_photo = request.files.get('passport_photo')

#         if not signature_image or not profile_image or not passport_photo:
#             return jsonify(message="One or more required files not provided in the request"), 400

#         required_fields = ['name', 'address', 'bvn', 'nin', 'agent_email', 'agent_card_number',
#                            'gender', 'date_of_birth', 'phone_number']

#         for field in required_fields:
#             if field not in form_data:
#                 return jsonify({"message": f"Missing required field: {field}"}), 400

#         signature_image1 = cloudinary.uploader.upload(signature_image)['url']
#         profile_image1 = cloudinary.uploader.upload(profile_image)['url']
#         passport_photo1 = cloudinary.uploader.upload(passport_photo)['url']

#         # Create a new instance of AccecptanceForm
#         acceptance_form = FieldOfficerAccecptanceForm(
#             full_name=form_data.get('name'),
#             address=form_data.get('address'),
#             bvn=form_data.get('bvn'),
#             nin=form_data.get('nin'),
#             agent_email=form_data.get('agent_email'),
#             agent_card_number=form_data.get('agent_card_number'),
#             gender=form_data.get('gender'),
#             date_of_birth=datetime.strptime(
#                 form_data.get('date_of_birth'), '%Y-%m-%d').date(),
#             signature=signature_image1,
#             profile_image=profile_image1,
#             passport=passport_photo1,
#             created_at=datetime.utcnow(),
#             modified_at=datetime.utcnow(),
#             is_email_verified=False
#         )

#         # Add the acceptance form to the database
#         db.session.add(acceptance_form)
#         db.session.commit()

#         # Update user filled_form attribute
#         user.filled_form = True

#         # Update remaining fields of the user model

#         user.address = form_data.get('address')
#         user.bvn = form_data.get('bvn')
#         user.nin = form_data.get('nin')
#         user.agent_email = form_data.get('agent_email')
#         user.agent_card_no = form_data.get('agent_card_number')
#         user.gender = form_data.get('gender')
#         user.date_of_birth = datetime.strptime(
#             form_data.get('date_of_birth'), '%Y-%m-%d').date()
#         user.phone_number = form_data.get('phone_number')
#         user.profile_image = profile_image1

#         db.session.commit()

#         return jsonify(message="Form submitted successfully"), 200

#     except Exception as e:
#         return jsonify(message=str(e)), 500


# @app.route('/field/monthly_users', methods=['GET'])
# @jwt_required()
# def field_get_monthly_users():
#     try:
#         # Get the current user's identity from the JWT token
#         current_user_id = get_jwt_identity()

#         # Ensure the current user exists
#         current_user_referral = FieldOfficerReferral.query.filter_by(
#             user_id=current_user_id).first()
#         if not current_user_referral:
#             return jsonify({"message": "User referral data not found"}), 404

#         # Get the monthly users for the current user
#         monthly_users = current_user_referral.get_monthly_users()

#         return jsonify({"monthly_users": monthly_users}), 200

#     except Exception as e:
#         return jsonify({"message": str(e)}), 500


# @app.route('/field/successful_referrals', methods=['GET'])
# @jwt_required()
# def field_get_successful_referrals_route():
#     try:
#         user_id = get_jwt_identity()
#         # Check if the user exists
#         user = FieldOfficer.query.get(user_id)
#         if not user:
#             return jsonify({"error": "User not found"}), 404

#         # Get successful referrals for the user using the class method
#         referrals_data = FieldOfficerSuccessfulReferral.get_successful_referrals(
#             user.id)

#         return jsonify({"successful_referrals": referrals_data})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/weekly_work_done', methods=['GET'])
# @jwt_required()
# def field_get_weekly_work_done_route():
#     try:
#         # Get user ID from the JWT identity
#         current_user_id = get_jwt_identity()

#         # Get weekly work done for the user
#         weekly_work_done = FieldOfficerSuccessfulReferral.get_weekly_work_done(
#             current_user_id)
#         return jsonify({"weekly_work_done": weekly_work_done})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/monthly_work_done', methods=['GET'])
# @jwt_required()
# def field_get_monthly_work_done_route():
#     try:
#         # Get user ID from the JWT identity
#         current_user_id = get_jwt_identity()

#         # Get monthly work done for the user
#         monthly_work_done = FieldOfficerSuccessfulReferral.get_monthly_work_done(
#             current_user_id)
#         return jsonify({"monthly_work_done": monthly_work_done})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/total_referrals_count', methods=['GET'])
# @jwt_required()
# def field_get_total_referrals_count_route():
#     try:
#         # Get user ID from the JWT identity
#         current_user_id = get_jwt_identity()

#         # Get total referrals count for the user
#         total_referrals_count = FieldOfficerSuccessfulReferral.get_total_referrals_count(
#             current_user_id)
#         return jsonify({"total_referrals_count": total_referrals_count})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route('/field/referral', methods=['GET'])
# @jwt_required()
# def field_get_user_referral():
#     try:
#         # Get the current user's identity from the JWT token
#         current_user_id = get_jwt_identity()

#         # Ensure the current user exists
#         current_user = FieldOfficer.query.get(current_user_id)
#         if not current_user:
#             return jsonify({"message": "User not found"}), 404

#         # Fetch the referral data for the user
#         referral_data = FieldOfficerReferral.query.filter_by(
#             user_id=current_user.id).first()

#         # Check if the referral data exists
#         if not referral_data:
#             return jsonify({"message": "Referral data not found for the user"}), 404

#         # Convert referral data to dictionary
#         referral_dict = referral_data.to_dict()

#         return jsonify({"referral_data": referral_dict}), 200

#     except Exception as e:
#         return jsonify({"message": str(e)}), 500


if __name__ == "__main__":
    app.run(port=8000, debug=True)
