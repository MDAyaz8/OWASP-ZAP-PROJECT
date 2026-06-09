# target_app.py
# ఇది intentionally vulnerable app — scan practice కోసం మాత్రమే!
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
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Intentionally vulnerable — no validation!
        message = f'Trying login: {username}'

    return render_template_string('''
        <h2>Login Page</h2>
        <form method="POST">
            Username: <input name="username"><br><br>
            Password: <input name="password" type="password"><br><br>
            <input type="submit" value="Login">
        </form>
        <p>{{ message }}</p>
        <a href="/">Back</a>
    ''', message=message)

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


if __name__ == '__main__':
    target.run(debug=True, port=5001)
