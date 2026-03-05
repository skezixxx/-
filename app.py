from flask import Flask, render_template, request, redirect, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime
import os

# Пароли для начальной инициализации БД.
# Для продакшена задайте переменные окружения ADMIN_PASSWORD и USER1_PASSWORD.
DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
DEFAULT_USER1_PASSWORD = os.environ.get('USER1_PASSWORD', 'user123')

app = Flask(__name__)
app.secret_key = 'my_secret_key_123'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, 'tasks.db')

STATUSES = ['новая', 'в работе', 'готова']
STAGES   = ['планирование', 'выполнение', 'тестирование', 'готово']
ROLES    = ['admin', 'manager', 'employee']
ROLE_HIERARCHY = {'admin': 3, 'manager': 2, 'employee': 1}


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db()
    # executescript() выполняет неявный COMMIT перед запуском и сбрасывает PRAGMA,
    # поэтому схему создаём через него, а вставку начальных данных — отдельно,
    # уже после того как соединение снова получило PRAGMA foreign_keys = ON.
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'employee',
            name     TEXT
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            status      TEXT DEFAULT 'новая',
            stage       TEXT DEFAULT 'планирование',
            deadline    TEXT,
            created_at  TEXT,
            author_id   INTEGER,
            assignee_id INTEGER,
            FOREIGN KEY (author_id)   REFERENCES users(id),
            FOREIGN KEY (assignee_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS completed_tasks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            title        TEXT,
            description  TEXT,
            deadline     TEXT,
            completed_at TEXT,
            author_id    INTEGER,
            assignee_id  INTEGER
        );
        CREATE TABLE IF NOT EXISTS comments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id    INTEGER,
            author_id  INTEGER,
            text       TEXT,
            created_at TEXT,
            FOREIGN KEY (task_id)   REFERENCES tasks(id),
            FOREIGN KEY (author_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            text       TEXT,
            is_read    INTEGER DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS activity (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            action     TEXT,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.close()

    # Открываем новое соединение — теперь PRAGMA foreign_keys = ON активна корректно
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO users(username, password, role, name) VALUES (?,?,?,?)",
        ('admin', generate_password_hash(DEFAULT_ADMIN_PASSWORD), 'admin', 'Администратор')
    )
    conn.execute(
        "INSERT OR IGNORE INTO users(username, password, role, name) VALUES (?,?,?,?)",
        ('user1', generate_password_hash(DEFAULT_USER1_PASSWORD), 'employee', 'Иванов Иван')
    )
    conn.commit()
    conn.close()


init_db()


def now():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M')


def log(action):
    conn = get_db()
    conn.execute(
        "INSERT INTO activity(user_id, action, created_at) VALUES (?,?,?)",
        (session.get('user_id'), action, now())
    )
    conn.commit()
    conn.close()


def notify(user_id, text):
    conn = get_db()
    conn.execute(
        "INSERT INTO notifications(user_id, text, created_at) VALUES (?,?,?)",
        (user_id, text, now())
    )
    conn.commit()
    conn.close()


def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Только для администратора', 'danger')
            return redirect('/tasks')
        return f(*args, **kwargs)
    return wrapper


@app.before_request
def count_notifications():
    g.unread = 0
    if session.get('user_id'):
        conn = get_db()
        row = conn.execute(
            "SELECT COUNT(*) as c FROM notifications WHERE user_id=? AND is_read=0",
            (session['user_id'],)
        ).fetchone()
        conn.close()
        g.unread = row['c'] if row else 0


@app.context_processor
def inject_globals():
    return dict(
        statuses=STATUSES,
        stages=STAGES,
        unread=g.unread if hasattr(g, 'unread') else 0,
        session=session
    )


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/tasks')
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['name'] = user['name']
            log('Вход в систему')
            return redirect('/tasks')
        flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    log('Выход из системы')
    session.clear()
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        name     = request.form.get('name', '').strip()

        if not username or not password:
            flash('Заполните все поля', 'danger')
            return redirect('/register')

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users(username, password, role, name) VALUES (?,?,?,?)",
                (username, generate_password_hash(password), 'employee', name)
            )
            conn.commit()
            flash('Аккаунт создан, войдите в систему', 'success')
            return redirect('/login')
        except Exception:
            flash('Такой логин уже занят', 'danger')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/tasks')
@login_required
def tasks():
    conn = get_db()
    uid  = session['user_id']
    role = session['role']
    sort = request.args.get('sort', '')

    if sort == 'deadline':
        order = "ORDER BY CASE WHEN t.deadline IS NULL THEN 1 ELSE 0 END, t.deadline ASC"
    else:
        order = "ORDER BY t.id DESC"

    if role in ('admin', 'manager'):
        rows = conn.execute(f"""
            SELECT t.*, a.name as assignee_name, u.name as author_name
            FROM tasks t
            LEFT JOIN users a ON a.id = t.assignee_id
            LEFT JOIN users u ON u.id = t.author_id
            {order}
        """).fetchall()
    else:
        rows = conn.execute(f"""
            SELECT t.*, a.name as assignee_name, u.name as author_name
            FROM tasks t
            LEFT JOIN users a ON a.id = t.assignee_id
            LEFT JOIN users u ON u.id = t.author_id
            WHERE t.assignee_id=? OR t.author_id=?
            {order}
        """, (uid, uid)).fetchall()

    conn.close()
    return render_template('tasks.html', tasks=rows, sort=sort)


@app.route('/tasks/new', methods=['GET', 'POST'])
@login_required
def new_task():
    my_level = ROLE_HIERARCHY.get(session['role'], 1)

    def get_users_for_form():
        conn = get_db()
        all_users = conn.execute("SELECT * FROM users").fetchall()
        conn.close()
        return [u for u in all_users if ROLE_HIERARCHY.get(u['role'], 1) <= my_level]

    if request.method == 'POST':
        title       = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        deadline    = request.form.get('deadline') or None
        assignee_id = request.form.get('assignee_id') or None

        if not title:
            flash('Название обязательно', 'danger')
            return render_template('new_task.html', users=get_users_for_form())

        assignee_id_int = int(assignee_id) if assignee_id else None

        if assignee_id_int:
            conn = get_db()
            assignee = conn.execute(
                "SELECT role FROM users WHERE id=?", (assignee_id_int,)
            ).fetchone()
            conn.close()
            if assignee and ROLE_HIERARCHY.get(assignee['role'], 1) > my_level:
                flash('Нельзя назначить задачу пользователю с более высокой ролью', 'danger')
                return render_template('new_task.html', users=get_users_for_form())

        conn = get_db()
        conn.execute("""
            INSERT INTO tasks(title, description, status, stage, deadline, created_at, author_id, assignee_id)
            VALUES (?,?,?,?,?,?,?,?)
        """, (title, description, STATUSES[0], STAGES[0], deadline, now(),
              session['user_id'], assignee_id_int))
        conn.commit()
        conn.close()

        if assignee_id_int and assignee_id_int != session['user_id']:
            notify(assignee_id_int, f'Вам назначена задача: {title}')

        log(f'Создана задача: {title}')
        flash('Задача создана', 'success')
        return redirect('/tasks')

    return render_template('new_task.html', users=get_users_for_form())


@app.route('/tasks/<int:tid>')
@login_required
def task_detail(tid):
    conn = get_db()
    task = conn.execute("""
        SELECT t.*, a.name as assignee_name, u.name as author_name
        FROM tasks t
        LEFT JOIN users a ON a.id = t.assignee_id
        LEFT JOIN users u ON u.id = t.author_id
        WHERE t.id=?
    """, (tid,)).fetchone()

    if not task:
        conn.close()
        return 'Задача не найдена', 404

    comments = conn.execute("""
        SELECT c.*, u.name as author_name
        FROM comments c
        LEFT JOIN users u ON u.id = c.author_id
        WHERE c.task_id=?
        ORDER BY c.id ASC
    """, (tid,)).fetchall()

    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template('task_detail.html', task=task, comments=comments, users=users)


@app.route('/tasks/<int:tid>/status', methods=['POST'])
@login_required
def change_status(tid):
    new_status = request.form.get('status')
    if new_status not in STATUSES:
        flash('Неверный статус', 'danger')
        return redirect(f'/tasks/{tid}')

    conn = get_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
    if task:
        task_title = task['title']
        author_id  = task['author_id']

        conn.execute("UPDATE tasks SET status=? WHERE id=?", (new_status, tid))

        if new_status == 'готова':
            conn.execute("""
                INSERT INTO completed_tasks(title, description, deadline, completed_at, author_id, assignee_id)
                VALUES (?,?,?,?,?,?)
            """, (task['title'], task['description'], task['deadline'],
                  now(), task['author_id'], task['assignee_id']))
            conn.execute("DELETE FROM comments WHERE task_id=?", (tid,))
            conn.execute("DELETE FROM tasks WHERE id=?", (tid,))
            conn.commit()
            conn.close()
            if author_id and author_id != session['user_id']:
                notify(author_id, f'Статус задачи «{task_title}» → {new_status}')
            log(f'Задача завершена: {task_title}')
            flash('Задача завершена и перемещена в архив', 'success')
            return redirect('/tasks')

        conn.commit()
        conn.close()
        if author_id and author_id != session['user_id']:
            notify(author_id, f'Статус задачи «{task_title}» → {new_status}')
        log(f'Статус задачи «{task_title}» → {new_status}')
        flash('Статус обновлён', 'success')
        return redirect(f'/tasks/{tid}')

    conn.close()
    return redirect(f'/tasks/{tid}')


@app.route('/tasks/<int:tid>/stage', methods=['POST'])
@login_required
def change_stage(tid):
    new_stage = request.form.get('stage')
    if new_stage not in STAGES:
        flash('Неверный этап', 'danger')
        return redirect(f'/tasks/{tid}')

    conn = get_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
    if task:
        task_title = task['title']
        author_id  = task['author_id']
        conn.execute("UPDATE tasks SET stage=? WHERE id=?", (new_stage, tid))
        conn.commit()
        conn.close()
        if author_id and author_id != session['user_id']:
            notify(author_id, f'Этап задачи «{task_title}» → {new_stage}')
        log(f'Этап задачи «{task_title}» → {new_stage}')
        flash('Этап обновлён', 'success')
        return redirect(f'/tasks/{tid}')

    conn.close()
    return redirect(f'/tasks/{tid}')


@app.route('/tasks/<int:tid>/comment', methods=['POST'])
@login_required
def add_comment(tid):
    text = request.form.get('text', '').strip()
    if not text:
        flash('Комментарий не может быть пустым', 'danger')
        return redirect(f'/tasks/{tid}')

    conn = get_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()
    if not task:
        conn.close()
        flash('Задача не найдена', 'danger')
        return redirect('/tasks')
    conn.execute(
        "INSERT INTO comments(task_id, author_id, text, created_at) VALUES (?,?,?,?)",
        (tid, session['user_id'], text, now())
    )
    conn.commit()
    conn.close()
    if task['author_id'] != session['user_id']:
        notify(task['author_id'], f'Комментарий к задаче «{task["title"]}»: {text[:40]}')
    log(f'Комментарий к задаче #{tid}')
    return redirect(f'/tasks/{tid}')


@app.route('/tasks/<int:tid>/delete', methods=['POST'])
@login_required
def delete_task(tid):
    conn = get_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()

    if not task:
        conn.close()
        flash('Задача не найдена', 'danger')
        return redirect('/tasks')

    if task['author_id'] != session['user_id'] and session['role'] != 'admin':
        conn.close()
        flash('Нет прав для удаления', 'danger')
        return redirect(f'/tasks/{tid}')

    conn.execute("DELETE FROM comments WHERE task_id=?", (tid,))
    conn.execute("DELETE FROM tasks WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    log(f'Удалена задача: {task["title"]}')
    flash('Задача удалена', 'success')
    return redirect('/tasks')


@app.route('/archive')
@login_required
def archive():
    conn = get_db()
    uid  = session['user_id']
    role = session['role']

    if role in ('admin', 'manager'):
        tasks = conn.execute("""
            SELECT ct.*, a.name as assignee_name, u.name as author_name
            FROM completed_tasks ct
            LEFT JOIN users a ON a.id = ct.assignee_id
            LEFT JOIN users u ON u.id = ct.author_id
            ORDER BY ct.completed_at DESC
        """).fetchall()
    else:
        tasks = conn.execute("""
            SELECT ct.*, a.name as assignee_name, u.name as author_name
            FROM completed_tasks ct
            LEFT JOIN users a ON a.id = ct.assignee_id
            LEFT JOIN users u ON u.id = ct.author_id
            WHERE ct.assignee_id=? OR ct.author_id=?
            ORDER BY ct.completed_at DESC
        """, (uid, uid)).fetchall()

    conn.close()
    return render_template('archive.html', tasks=tasks)


@app.route('/activity')
@login_required
def activity():
    conn = get_db()
    uid  = session['user_id']
    role = session['role']

    if role in ('admin', 'manager'):
        logs = conn.execute("""
            SELECT a.*, u.name as user_name, u.username
            FROM activity a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.id DESC LIMIT 100
        """).fetchall()
    else:
        logs = conn.execute("""
            SELECT a.*, u.name as user_name, u.username
            FROM activity a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.user_id=?
            ORDER BY a.id DESC LIMIT 50
        """, (uid,)).fetchall()

    conn.close()
    return render_template('activity.html', logs=logs)


@app.route('/notifications')
@login_required
def notifications():
    conn = get_db()
    notes = conn.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",
        (session['user_id'],)
    ).fetchall()
    conn.execute(
        "UPDATE notifications SET is_read=1 WHERE user_id=?",
        (session['user_id'],)
    )
    conn.commit()
    conn.close()
    return render_template('notifications.html', notifications=notes)


@app.route('/users')
@login_required
@admin_required
def users():
    conn = get_db()
    all_users = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    conn.close()
    return render_template('users.html', users=all_users)


@app.route('/users/<int:uid>/role', methods=['POST'])
@login_required
@admin_required
def change_role(uid):
    if uid == session['user_id']:
        flash('Нельзя изменить собственную роль', 'danger')
        return redirect('/users')
    new_role = request.form.get('role')
    if new_role in ROLES:
        conn = get_db()
        conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
        conn.commit()
        conn.close()
        log(f'Изменена роль пользователя #{uid} на {new_role}')
        flash('Роль изменена', 'success')
    return redirect('/users')


if __name__ == '__main__':
    app.run(debug=True)
