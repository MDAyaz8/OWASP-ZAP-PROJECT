# target_app.py
# ఇది intentionally vulnerable app — scan practice కోసం మాత్రమే!
# Add this at top of target_app.py
import json
USERS = {
    'admin': 'admin123',
    'user': 'password123',
    'test': 'test123'
}
try:
    # type: ignore[import]
    from flask import Flask, request, render_template_string
except ImportError as exc:
    raise ImportError(
        "Flask is required to run this app. Install it with `pip install flask`."
    ) from exc

target = Flask(__name__)

# Home page


@target.route('/')
def home():
    return '''
    <h1>Vulnerable Test App</h1>
    <a href="/login">Login Page</a><br>
    <a href="/search">Search Page</a><br>
    <a href="/comment">Comment Page</a>
    '''

# Login page — SQL Injection vulnerable


@target.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    status = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and USERS[username] == password:
            message = f'Login SUCCESS! Welcome {username}'
            status = 'success'
        else:
            message = 'Login FAILED! Invalid credentials'
            status = 'failed'

    return render_template_string('''
        <h2>Login Page</h2>
        <form method="POST">
            Username: <input name="username"><br><br>
            Password: <input name="password"
                       type="password"><br><br>
            <input type="submit" value="Login">
        </form>
        <p style="color:
            {{'green' if status == 'success' else 'red'}}">
            {{ message }}
        </p>
        <a href="/">Back</a>
    ''', message=message, status=status)
# Search page — XSS vulnerable


@target.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string('''
        <h2>Search Page</h2>
        <form>
            <input name="q" value="{{ query }}">
            <input type="submit" value="Search">
        </form>
        <p>Results for: {{ query }}</p>
        <a href="/">Back</a>
    ''', query=query)

# Comment page


@target.route('/comment', methods=['GET', 'POST'])
def comment():
    comment_text = ''
    if request.method == 'POST':
        comment_text = request.form.get('comment', '')

    return render_template_string('''
        <h2>Comment Page</h2>
        <form method="POST">
            <textarea name="comment"></textarea><br>
            <input type="submit" value="Submit">
        </form>
        <p>Your comment: {{ comment_text }}</p>
        <a href="/">Back</a>
    ''', comment_text=comment_text)


# API endpoint - get all users


@target.route('/api/users')
def api_users():
    return json.dumps({
        'users': ['admin', 'user', 'test'],
        'total': 3
    })

# API endpoint - get user info


@target.route('/api/user/<username>')
def api_user(username):
    if username in USERS:
        return json.dumps({
            'username': username,
            'role': 'admin' if username == 'admin' else 'user',
            'status': 'active'
        })
    return json.dumps({'error': 'User not found'}), 404

# API endpoint - get scan status


@target.route('/api/status')
def api_status():
    return json.dumps({
        'app': 'Vulnerable Test App',
        'version': '1.0',
        'status': 'running',
        'endpoints': [
            '/login',
            '/search',
            '/comment',
            '/api/users',
            '/api/user/<username>',
            '/api/status'
        ]
    })


if __name__ == '__main__':
    target.run(debug=True, port=5001)
