from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from hashlib import sha256

app = Flask(__name__)
app.secret_key = 'your_secret_key'


def get_db():
    conn = sqlite3.connect("blog.db")
    conn.row_factory = sqlite3.Row
    return conn


def setup():
    db = get_db()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    );

    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        title TEXT,
        content TEXT,
        is_private INTEGER,
        tags TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY,
        follower_id INTEGER,
        followed_id INTEGER
    );

    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        post_id INTEGER,
        content TEXT
    );

    CREATE TABLE IF NOT EXISTS access_requests (
        id INTEGER PRIMARY KEY,
        requester_id INTEGER,
        post_id INTEGER,
        status TEXT DEFAULT 'pending',
        UNIQUE(requester_id, post_id)
    );
    ''')
    db.commit()


def hash_pw(password):
    return sha256(password.encode()).hexdigest()


@app.route('/')
def index():
    tag = request.args.get('tag')
    db = get_db()
    if tag:
        posts = db.execute(
            "SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE tags LIKE ? ORDER BY posts.id DESC",
            (f"%{tag}%",)).fetchall()
    else:
        posts = db.execute(
            "SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.id DESC"
        ).fetchall()
    return render_template("index.html", posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (request.form['username'], hash_pw(request.form['password'])))
            db.commit()
            return redirect('/login')
        except:
            return "Пользователь уже существует"
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND password=?",
                          (request.form['username'], hash_pw(request.form['password']))).fetchone()
        if user:
            session['user_id'] = user['id']
            return redirect('/')
        return "Неверный логин или пароль"
    return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/create', methods=["GET", "POST"])
def create():
    if 'user_id' not in session:
        return redirect('/login')
    if request.method == "POST":
        db = get_db()
        db.execute("INSERT INTO posts (user_id, title, content, is_private, tags) VALUES (?, ?, ?, ?, ?)",
                   (session['user_id'], request.form['title'], request.form['content'],
                    int('private' in request.form), request.form['tags']))
        db.commit()
        return redirect('/')
    return render_template("create_post.html")


@app.route('/edit/<int:post_id>', methods=["GET", "POST"])
def edit(post_id):
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=? AND user_id=?", (post_id, session['user_id'])).fetchone()
    if not post:
        return "Нет доступа"
    if request.method == "POST":
        db.execute("UPDATE posts SET title=?, content=?, is_private=?, tags=? WHERE id=?",
                   (request.form['title'], request.form['content'],
                    int('private' in request.form), request.form['tags'], post_id))
        db.commit()
        return redirect(f"/post/{post_id}")
    return render_template("edit_post.html", post=post)


@app.route('/delete/<int:post_id>')
def delete(post_id):
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    db.execute("DELETE FROM posts WHERE id=? AND user_id=?", (post_id, session['user_id']))
    db.commit()
    return redirect('/')


@app.route('/post/<int:post_id>')
def view_post(post_id):
    db = get_db()
    post = db.execute("SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id=?", (post_id,)).fetchone()
    if not post:
        return "Пост не найден"

    user_id = session.get('user_id')

    if post['is_private']:
        if user_id == post['user_id']:
            pass  # Автор видит всегда
        else:
            access = db.execute(
                "SELECT * FROM access_requests WHERE requester_id=? AND post_id=? AND status='approved'",
                (user_id, post_id)
            ).fetchone() if user_id else None

            if not access:
                return render_template("private_post_request.html", post=post)

    comments = db.execute("SELECT comments.*, users.username FROM comments JOIN users ON comments.user_id = users.id WHERE post_id=?", (post_id,)).fetchall()
    return render_template("post.html", post=post, comments=comments)


@app.route('/comment/<int:post_id>', methods=["POST"])
def comment(post_id):
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    db.execute("INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)",
               (session['user_id'], post_id, request.form['content']))
    db.commit()
    return redirect(url_for('view_post', post_id=post_id))


@app.route('/follow/<int:user_id>')
def follow(user_id):
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    exists = db.execute("SELECT * FROM follows WHERE follower_id=? AND followed_id=?", (session['user_id'], user_id)).fetchone()
    if not exists and user_id != session['user_id']:
        db.execute("INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)",
                   (session['user_id'], user_id))
        db.commit()
    return redirect('/users')


@app.route('/users')
def users():
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    users = db.execute("SELECT id, username FROM users WHERE id != ?", (session['user_id'],)).fetchall()
    follows = db.execute("SELECT followed_id FROM follows WHERE follower_id = ?", (session['user_id'],)).fetchall()
    follows_ids = set(f['followed_id'] for f in follows)
    return render_template("users.html", users=users, follows=follows_ids)


@app.route('/feed')
def feed():
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    posts = db.execute('''
        SELECT posts.*, users.username FROM posts 
        JOIN users ON posts.user_id = users.id 
        WHERE posts.user_id IN (
            SELECT followed_id FROM follows WHERE follower_id = ?
        )
        ORDER BY posts.id DESC
    ''', (session['user_id'],)).fetchall()
    return render_template("index.html", posts=posts)


@app.route('/request_access/<int:post_id>')
def request_access(post_id):
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post or post['is_private'] == 0:
        return redirect(f'/post/{post_id}')
    existing = db.execute("SELECT * FROM access_requests WHERE requester_id=? AND post_id=?", (session['user_id'], post_id)).fetchone()
    if existing:
        return "Вы уже отправили запрос на доступ. Ждите подтверждения."
    db.execute("INSERT INTO access_requests (requester_id, post_id) VALUES (?, ?)", (session['user_id'], post_id))
    db.commit()
    return "Запрос на доступ отправлен владельцу поста."


@app.route('/access_requests')
def access_requests():
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    requests = db.execute('''
        SELECT ar.id, ar.requester_id, ar.post_id, u.username as requester_name, p.title as post_title
        FROM access_requests ar
        JOIN users u ON ar.requester_id = u.id
        JOIN posts p ON ar.post_id = p.id
        WHERE p.user_id = ? AND ar.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    return render_template("access_requests.html", requests=requests)


@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db()
    req = db.execute('''
        SELECT ar.*, p.user_id FROM access_requests ar
        JOIN posts p ON ar.post_id = p.id
        WHERE ar.id = ?
    ''', (request_id,)).fetchone()
    if not req or req['user_id'] != session['user_id']:
        return "Нет доступа"
    db.execute("UPDATE access_requests SET status='approved' WHERE id=?", (request_id,))
    db.commit()
    return redirect('/access_requests')


if __name__ == '__main__':
    setup()
    app.run(debug=True)
