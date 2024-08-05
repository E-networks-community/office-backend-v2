from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from models import db, User, Staff, Team, TeamMember, Project, ProjectUser, Client, File, Invoice, Transaction, Invitation
from flask_migrate import Migrate
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object('config.ApplicationConfig')
db.init_app(app)
# with app.app_context():
#     db.drop_all()
#     db.create_all()

CORS(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

def hash_password(password):
    return generate_password_hash(password)

def verify_password(stored_password, provided_password):
    return check_password_hash(stored_password, provided_password)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = hash_password(data['password'])
    user = User(
        email=data['email'],
        username=data['username'],
        password=hashed_password
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    
    if not data or 'username_or_email' not in data or 'password' not in data:
        return jsonify({"msg": "Missing 'username_or_email' or 'password'"}), 400
    
    username_or_email = data['username_or_email']
    password = data['password']
    
 
    user = User.query.filter(
        (User.username == username_or_email) |
        (User.email == username_or_email)
    ).first()

    # Verify the user and password
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity={'id': user.id})
        return jsonify(access_token=access_token)
    
    return jsonify({"msg": "Invalid credentials"}), 401

# Route to update user profile
@app.route('/update_profile', methods=['POST'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()['id']
    data = request.json
    user = User.query.get(user_id)
    if user:
        user.full_name = data.get('full_name', user.full_name)
        user.address = data.get('address', user.address)
        user.phone_number = data.get('phone_number', user.phone_number)
        user.state = data.get('state', user.state)
        user.nationality = data.get('nationality', user.nationality)
        db.session.commit()
        return jsonify({"msg": "Profile updated successfully"})
    return jsonify({"msg": "User not found"}), 404

# Route to handle KYC (Note: BVN is not stored; KYC type and status are managed)
@app.route('/submit_kyc', methods=['POST'])
@jwt_required()
def submit_kyc():
    user_id = get_jwt_identity()['id']
    data = request.json
    user = User.query.get(user_id)
    if user:
        user.kyc_type = data.get('kyc_type')
        user.kyc_status = data.get('kyc_status')
        db.session.commit()
        return jsonify({"msg": "KYC details submitted"})
    return jsonify({"msg": "User not found"}), 404

# Route to send invitations
@app.route('/invite', methods=['POST'])
@jwt_required()
def invite():
    data = request.json
    user_id = get_jwt_identity()['id']
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    token = jwt.encode({'email': data['email'], 'team_id': data.get('team_id'), 'project_id': data.get('project_id')}, 'your_secret_key', algorithm='HS256')
    invitation_link = f'http://example.com/accept_invitation/{token}'

    # Send the email with the invitation link (pseudo-code)
    # send_invitation_email(data['email'], invitation_link)

    invitation = Invitation(
        email=data['email'],
        team_id=data.get('team_id'),
        project_id=data.get('project_id'),
        token=token
    )
    db.session.add(invitation)
    db.session.commit()
    return jsonify({"msg": "Invitation sent"}), 200

# Route to accept invitation
@app.route('/accept_invitation/<token>', methods=['GET'])
def accept_invitation(token):
    try:
        data = jwt.decode(token, 'your_secret_key', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"msg": "Token expired"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"msg": "Invalid token"}), 400

    email = data.get('email')
    team_id = data.get('team_id')
    project_id = data.get('project_id')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if team_id:
        team_member = TeamMember(team_id=team_id, user_id=user.id)
        db.session.add(team_member)
    if project_id:
        project_user = ProjectUser(project_id=project_id, user_id=user.id)
        db.session.add(project_user)

    invitation = Invitation.query.filter_by(token=token).first()
    if invitation:
        invitation.accepted = True
        db.session.commit()

    return jsonify({"msg": "Invitation accepted"}), 200

# Route to list projects for authenticated user
@app.route('/projects', methods=['GET'])
@jwt_required()
def get_projects():
    user_id = get_jwt_identity()['id']
    user = User.query.get(user_id)
    if user:
        projects = Project.query.filter(
            (Project.user_id == user_id) |
            (Project.id.in_([pu.project_id for pu in ProjectUser.query.filter_by(user_id=user_id)]))
        ).all()
        return jsonify([{'id': project.id, 'name': project.name, 'description': project.description} for project in projects])
    return jsonify({"msg": "User not found"}), 404

# Route to list teams for authenticated user
@app.route('/teams', methods=['GET'])
@jwt_required()
def get_teams():
    user_id = get_jwt_identity()['id']
    user = User.query.get(user_id)
    if user:
        teams = Team.query.filter(
            Team.creator_id == user_id  # Teams created by user
        ).union(
            Team.query.join(TeamMember).filter(TeamMember.user_id == user_id)  # Teams user is a member of
        ).all()
        return jsonify([{'id': team.id, 'name': team.name} for team in teams])
    return jsonify({"msg": "User not found"}), 404


# Route to upload a file
@app.route('/upload_file', methods=['POST'])
@jwt_required()
def upload_file():
    user_id = get_jwt_identity()['id']
    file = request.files.get('file')
    if not file:
        return jsonify({"msg": "No file provided"}), 400

    filename = file.filename
    file_url = f'files/{filename}'  # Implement actual file storage
    file.save(file_url)

    new_file = File(filename=filename, file_url=file_url, user_id=user_id)
    db.session.add(new_file)
    db.session.commit()

    return jsonify({"msg": "File uploaded successfully"}), 201

# Route to list files for authenticated user
@app.route('/files', methods=['GET'])
@jwt_required()
def get_files():
    user_id = get_jwt_identity()['id']
    user = User.query.get(user_id)
    if user:
        files = File.query.filter_by(user_id=user_id).all()
        return jsonify([{'filename': f.filename, 'file_url': f.file_url} for f in files])
    return jsonify({"msg": "User not found"}), 404

# Route to update user settings (e.g., notifications, 2FA)
@app.route('/update_settings', methods=['POST'])
@jwt_required()
def update_settings():
    user_id = get_jwt_identity()['id']
    data = request.json
    user = User.query.get(user_id)
    if user:
        # Update settings as needed (pseudo-code)
        # user.settings.update(data)
        db.session.commit()
        return jsonify({"msg": "Settings updated successfully"})
    return jsonify({"msg": "User not found"}), 404

@app.route('/teams', methods=['POST'])
@jwt_required()
def create_team():
    data = request.json
    name = data.get('name')
    description = data.get('description')

    if not name:
        return jsonify({"msg": "Team name is required"}), 400

    user_id = get_jwt_identity()['id']
    user_exist = User.query.filter_by(id=user_id).first()
    if not user_exist:
        return jsonify(message="User does not exists")
    
    team_exist = Team.query.filter_by(name=name, creator_id=user_id).all()
    print(team_exist)
    if team_exist:
        return jsonify(message="This team already exists")
    
    team = Team(name=name, description=description, creator_id=user_id)
    db.session.add(team)
    db.session.commit()
    
    return jsonify({"msg": "Team created successfully", "team_id": team.id}), 201

@app.route('/projects', methods=['POST'])
@jwt_required()
def create_project():
    data = request.json
    name = data.get('name')
    description = data.get('description')

    if not name:
        return jsonify({"msg": "Project name is required"}), 400

    user_id = get_jwt_identity()['id']
    project = Project(name=name, description=description, user_id=user_id)
    db.session.add(project)
    db.session.commit()
    
    return jsonify({"msg": "Project created successfully", "project_id": project.id}), 201
    
@app.route('/invite_team', methods=['POST'])
@jwt_required()
def invite_team():
    data = request.json
    email = data.get('email')
    team_id = data.get('team_id')

    if not email or not team_id:
        return jsonify({"msg": "Email and team_id are required"}), 400

    # Generate an invitation token
    token = jwt.encode({
        'email': email,
        'team_id': team_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, 'your_secret_key', algorithm='HS256')

    invitation = Invitation(email=email, team_id=team_id, token=token)
    db.session.add(invitation)
    db.session.commit()

    # Send email with the invitation link (pseudo-code)
    # send_invitation_email(email, f'http://yourdomain.com/accept_invitation/{token}')

    return jsonify({"msg": "Invitation sent", "token": f"{token}"}), 200

@app.route('/invite_team_to_project', methods=['POST'])
@jwt_required()
def invite_team_to_project():
    data = request.json
    team_id = data.get('team_id')
    project_id = data.get('project_id')

    if not team_id or not project_id:
        return jsonify({"msg": "team_id and project_id are required"}), 400

    team = Team.query.get(team_id)
    if not team:
        return jsonify({"msg": "Team not found"}), 404

    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404

    # Fetch team members
    team_members = TeamMember.query.filter_by(team_id=team_id).all()
    for member in team_members:
        user = User.query.get(member.user_id)
        if user:
            project_user = ProjectUser(project_id=project_id, user_id=user.id)
            db.session.add(project_user)
    db.session.commit()

    return jsonify({"msg": "Team invited to project"}), 200

@app.route('/teams/<int:team_id>', methods=['GET'])
@jwt_required()
def get_team(team_id):
    # Fetch the team
    team = Team.query.get(team_id)
    if team:
        # Fetch team members
        members = []
        team_members = TeamMember.query.filter_by(team_id=team_id).all()
        for member in team_members:
            user = User.query.get(member.user_id)
            if user:
                members.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                })

        # Construct response
        team_info = {
            'id': team.id,
            'name': team.name,
            'description': team.description,
            'creator': {
                'id': team.creator.id,
                'username': team.creator.username
            },
            'members': members
        }
        return jsonify(team_info)
    return jsonify({"msg": "Team not found"}), 404

@app.route('/projects/<int:project_id>', methods=['GET'])
@jwt_required()
def get_project(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"msg": "Project not found"}), 404
    
    # Fetch team information
    team = Team.query.get(project.team_id)
    team_info = {
        'id': team.id,
        'name': team.name,
        'description': team.description
    } if team else None

    # Fetch project members
    members = []
    project_users = ProjectUser.query.filter_by(project_id=project_id).all()
    for pu in project_users:
        user = User.query.get(pu.user_id)
        if user:
            members.append({
                'id': user.id,
                'username': user.username,
                'email': user.email
            })

    # Construct project info
    project_info = {
        'id': project.id,
        'name': project.name,
        'description': project.description,
        'creator': {
            'id': project.creator.id,
            'username': project.creator.username
        },
        'team': team_info,
        'members': members
    }
    return jsonify(project_info), 200

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()['id']
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    # Fetch projects created by the user or the user is a part of
    project_ids = [pu.project_id for pu in ProjectUser.query.filter_by(user_id=user_id).all()]
    projects = Project.query.filter(
        (Project.user_id == user_id) |
        (Project.id.in_(project_ids))
    ).all()

    # Fetch teams created by the user or the user is a part of
    teams = Team.query.filter(
        Team.creator_id == user_id
    ).union(
        Team.query.join(TeamMember).filter(TeamMember.user_id == user_id)
    ).all()

    # Fetch staff members
    staff_members = Staff.query.filter_by(user_id=user_id).all()

    # Fetch files uploaded by the user
    files = File.query.filter_by(user_id=user_id).all()

    # Fetch invitations sent by the user
    invitations_sent = Invitation.query.filter_by(email=user.email).all()

    # Fetch invitations received by the user
    received_team_ids = [team.id for team in Team.query.filter_by(creator_id=user_id).all()]
    received_project_ids = [project.id for project in Project.query.filter_by(user_id=user_id).all()]
    
    invitations_received = Invitation.query.filter(
        (Invitation.team_id.in_(received_team_ids)) |
        (Invitation.project_id.in_(received_project_ids))
    ).all()

    # Construct the dashboard information
    dashboard_info = {
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name,
            'address': user.address,
            'phone_number': user.phone_number,
            'state': user.state,
            'nationality': user.nationality,
            'kyc_status': user.kyc_status,
        },
        'projects': [{'id': project.id, 'name': project.name, 'description': project.description} for project in projects],
        'teams': [{'id': team.id, 'name': team.name, 'description': team.description} for team in teams],
        'staff': [{'id': staff.id, 'email': staff.email, 'date_joined': staff.date_joined} for staff in staff_members],
        'files': [{'id': file.id, 'filename': file.filename, 'file_url': file.file_url} for file in files],
        'invitations_sent': [{'email': inv.email, 'team_id': inv.team_id, 'project_id': inv.project_id, 'token': inv.token} for inv in invitations_sent],
        'invitations_received': [{'email': inv.email, 'team_id': inv.team_id, 'project_id': inv.project_id, 'token': inv.token} for inv in invitations_received]
    }

    return jsonify(dashboard_info), 200





if __name__ == '__main__':
    app.run(debug=True)