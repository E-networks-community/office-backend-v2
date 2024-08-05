from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150))
    address = db.Column(db.String(250))
    phone_number = db.Column(db.String(20))
    state = db.Column(db.String(100))
    nationality = db.Column(db.String(100))
    kyc_type = db.Column(db.String(50))  # 'bvn' or other types
    kyc_status = db.Column(db.String(50))  # 'pending', 'success', 'failed'

    # Relationships
    staff = db.relationship('Staff', backref='user', lazy=True)
    teams = db.relationship('Team', backref='creator', lazy=True)
    project_users = db.relationship('ProjectUser', backref='user', lazy=True)
    clients = db.relationship('Client', backref='user', lazy=True)
    files = db.relationship('File', backref='user', lazy=True)
    invoices = db.relationship('Invoice', backref='user', lazy=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    tasks = db.relationship('Task', backref='creator', lazy=True)

class Staff(db.Model):
    __tablename__ = 'staff'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(100))  # Define roles as needed
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

class TeamMember(db.Model):
    __tablename__ = 'team_member'
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

class Project(db.Model):
    __tablename__ = 'project'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_project_user'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id', name='fk_project_team'))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    creator = db.relationship('User', backref='created_projects')
    team = db.relationship('Team', backref='projects', lazy=True)
    project_users = db.relationship('ProjectUser', backref='project_association', lazy=True)
    tasks = db.relationship('Task', backref='project', lazy=True)

class ProjectUser(db.Model):
    __tablename__ = 'project_user'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_assigned = db.Column(db.DateTime, default=datetime.utcnow)

class Team(db.Model):
    __tablename__ = 'team'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_team_creator'), nullable=False)

    team_members = db.relationship('TeamMember', backref='team', lazy=True)

class Client(db.Model):
    __tablename__ = 'client'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    file_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)

class Invoice(db.Model):
    __tablename__ = 'invoice'
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(250))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # 'credit' or 'debit'
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Invitation(db.Model):
    __tablename__ = 'invitation'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    token = db.Column(db.String(100), nullable=False, unique=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    accepted = db.Column(db.Boolean, default=False)
    team = db.relationship('Team', backref='invitations', lazy=True)
    project = db.relationship('Project', backref='invitations', lazy=True)

class Task(db.Model):
    __tablename__ = 'task'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    task_assignments = db.relationship('TaskAssignment', backref='task', lazy=True)

class TaskAssignment(db.Model):
    __tablename__ = 'task_assignment'
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignee_type = db.Column(db.String(50), nullable=False)  # 'team_member' or 'staff'
    date_assigned = db.Column(db.DateTime, default=datetime.utcnow)

class ClientInvitation(db.Model):
    __tablename__ = 'client_invitation'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token = db.Column(db.String(100), nullable=False, unique=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    accepted = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='client_invitations', lazy=True)
