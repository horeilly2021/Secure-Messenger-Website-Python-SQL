from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime
import os
import secrets
from argon2 import PasswordHasher

app = Flask(__name__)
# Update database path to be relative to the current file
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'messages.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = secrets.token_hex(16)  # Required for session management

db = SQLAlchemy(app)
socketio = SocketIO(app)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    receiver = db.Column(db.String(80), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'sender': self.sender,
            'receiver': self.receiver,
            'message': self.message,
            'timestamp': self.timestamp.isoformat()
        }

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'sender': self.sender,
            'message': self.message,
            'timestamp': self.timestamp.isoformat()
        }

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reported_user = db.Column(db.String(80), nullable=False)
    reported_by = db.Column(db.String(80), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, reviewed, dismissed

    def to_dict(self):
        return {
            'id': self.id,
            'reported_user': self.reported_user,
            'reported_by': self.reported_by,
            'reason': self.reason,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status
        }

class User(db.Model):
    username = db.Column(db.String(80), primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.Text, nullable=True)  # Allow null initially for existing users

    def to_dict(self):
        return {
            'username': self.username,
            'public_key': self.public_key
        }

with app.app_context():
    db.create_all()

def input_sanitizer(input):
    for c in input:
        if 32 <= ord(c) <= 126:
            continue
        else:
            return False, "Only Numbers, Letters and Symbols on the Keyboard are Allowed"
    return True, input

@app.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/api/messages/<user1>/<user2>')
def get_messages(user1, user2):
    # Get messages between two users (in either direction)
    messages = Message.query.filter(
        ((Message.sender == user1) & (Message.receiver == user2)) |
        ((Message.sender == user2) & (Message.receiver == user1))
    ).order_by(Message.timestamp).all()
    
    return jsonify([msg.to_dict() for msg in messages])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        if not input_sanitizer(username)[0]:
            return render_template('login.html', error=input_sanitizer(username)[1])

        if not input_sanitizer(password)[0]:
            return render_template('login.html', error=input_sanitizer(password)[1])
        
        try:
            # Using raw SQL with parameterized query
            query = text('SELECT username, password FROM user WHERE username = :username')

            result = db.session.execute(
                # 'SELECT username, password FROM user WHERE username = :username',
                query, 
                {'username': username}
            ).first()
            
            if result is None:
                return render_template('login.html', error='User not found')
                
            try:
                if PasswordHasher().verify(result.password, password):
                    session['user'] = username
                    return redirect(url_for('index'))
            except:
                pass
            
            return render_template('login.html', error='Invalid password')

        except Exception as e:
            print(f"Database error: {e}")  # Log the error
            return render_template('login.html', error='Database error occurred')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        password2 = request.form.get('password2').strip()
        
        if password != password2:
            return render_template('register.html', error='Passwords do not match')

        if not input_sanitizer(username)[0]:
            return render_template('register.html', error=input_sanitizer(username)[1])
        
        if not input_sanitizer(password)[0]:
            return render_template('register.html', error=input_sanitizer(password)[1])
        
        try:
            # Using raw SQL with parameterized query
            query = text('SELECT username FROM user WHERE username = :username')
            result = db.session.execute(
                # 'SELECT username FROM user WHERE username = :username',
                query, 
                {'username': username}
            ).first()
            
            if result is not None:
                return render_template('register.html', error='Username already exists')
                
            password = PasswordHasher().hash(password)
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            
            session['user'] = username
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Database error: {e}")  # Log the error
            return render_template('register.html', error='Database error occurred')
    
    return render_template('register.html')

@socketio.on('private_message')
def handle_private_message(data):
    sender = data.get('sender')
    recipient = data.get('recipient')
    message = data.get('message')
    encrypted = data.get('encrypted', False)
    
    if not all([sender, recipient, message]):
        return
    
    # Save message to database
    msg = Message(
        sender=sender,
        receiver=recipient,
        message=message
    )
    db.session.add(msg)
    db.session.commit()
    
    # Emit the message to the recipient
    socketio.emit('private_message', {
        'sender': sender,
        'message': message,
        'encrypted': encrypted,
        'timestamp': msg.timestamp.isoformat()
    }, room=recipient)

@socketio.on('video_chat_message')
def handle_video_chat_message(data):
    # Broadcast the video chat message to all connected clients
    socketio.emit('video_chat_message', data)

@app.route('/api/group_members')
def get_group_members():
    # Get all users except the current user
    current_user = session.get('user', '')
    users = User.query.filter(User.username != current_user).all()
    
    # Prepare the list of users
    group_members = [
        {
            'username': user.username,
            'is_current_user': False
        } for user in users
    ]
    
    # Add current user at the end with a special flag
    if current_user:
        group_members.append({
            'username': current_user,
            'is_current_user': True
        })
    
    return jsonify(group_members)

@app.route('/api/group_messages', methods=['GET'])
def get_group_messages():
    # Retrieve last 50 group messages
    messages = GroupMessage.query.order_by(GroupMessage.timestamp.desc()).limit(50).all()
    return jsonify([msg.to_dict() for msg in reversed(messages)])

@socketio.on('group_message')
def handle_group_message(data):
    # Validate message
    if not data or 'message' not in data or 'sender' not in data:
        return
    
    # Create and save message to database
    new_message = GroupMessage(
        sender=data['sender'], 
        message=data['message']
    )
    db.session.add(new_message)
    db.session.commit()
    
    # Broadcast message to all clients
    socketio.emit('group_message', {
        'sender': new_message.sender,
        'message': new_message.message,
        'timestamp': new_message.timestamp.isoformat()
    })

@socketio.on('connect')
def handle_connect():
    if 'user' in session:
        socketio.server.enter_room(request.sid, session['user'])

@socketio.on('submit_report')
def handle_report(data):
    report = Report(
        reported_user=data['reportedUser'],
        reported_by=data['reportedBy'],
        reason=data['reason']
    )
    db.session.add(report)
    db.session.commit()
    
    # You could add admin notification here
    print(f"New report submitted: {report.to_dict()}")

@app.route('/api/keys/register', methods=['POST'])
def register_public_key():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    if not data or 'publicKey' not in data:
        return jsonify({'error': 'No public key provided'}), 400
    
    try:
        user = User.query.get(session['user'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.public_key = data['publicKey']
        db.session.commit()
        return jsonify({'message': 'Public key registered successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/<username>', methods=['GET'])
def get_public_key(username):
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        user = User.query.get(username)
        if not user or not user.public_key:
            return jsonify({'error': 'Public key not found'}), 404
        
        return jsonify({
            'username': user.username,
            'public_key': user.public_key
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    socketio.run(app, port=4443, debug=True, ssl_context=("localhost+2.pem", "localhost+2-key.pem"))
