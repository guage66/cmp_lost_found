import csv
import io
import os
import re
import secrets
import uuid

from flask import Flask, Response, abort, flash, get_flashed_messages, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from db import get_db_connection
from utils.email_sender import send_email_code


app = Flask(__name__)
app.secret_key = "lost_found_secret_key"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
USER_CARD_FOLDER = os.path.join(app.root_path, "static", "uploads", "user_cards")
AVATAR_FOLDER = os.path.join(app.root_path, "static", "uploads", "avatars")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_USER_CARD_EXTENSIONS = {"png", "jpg", "jpeg"}
ALLOWED_AVATAR_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
ALLOWED_IMAGE_MIMES = {"image/png", "image/jpeg", "image/gif"}
ALLOWED_USER_CARD_MIMES = {"image/png", "image/jpeg"}
ALLOWED_AVATAR_MIMES = {"image/png", "image/jpeg", "image/gif"}

ITEM_TYPES = {"lost", "found"}
ITEM_STATUSES = {"pending", "approved", "resolved"}
USER_STATUSES = {"pending", "approved", "rejected"}
CATEGORIES = {"校园卡", "手机数码", "钥匙", "钱包", "书籍资料", "衣物", "其他"}
REPORT_REASONS = {"虚假信息", "广告或垃圾信息", "联系方式异常", "图片或内容不清晰", "其他"}
CLAIM_STATUSES = {"pending", "approved", "rejected"}
NOT_DELETED_SQL = "(is_deleted = 0 OR is_deleted IS NULL)"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(USER_CARD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def allowed_user_card(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_USER_CARD_EXTENSIONS


def clean_text(value, max_len=255):
    if value is None:
        return ""
    return str(value).strip()[:max_len]


def clean_long_text(value, max_len=2000):
    if value is None:
        return ""
    return str(value).strip()[:max_len]


def validate_choice(value, allowed_values, default=None):
    value = clean_text(value)
    if value in allowed_values:
        return value
    return default


def validate_email(email):
    email = clean_text(email, 120)
    if not email:
        return ""
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        return ""
    return email


def validate_phone(phone):
    phone = clean_text(phone, 30)
    if not phone:
        return ""
    if re.fullmatch(r"[0-9+\-\s]{1,30}", phone):
        return phone
    return ""


def log_db_error(exc):
    print(f"Database error: {exc}")


def system_error_message():
    return "系统错误，请稍后再试"


def generate_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf_token():
    token = request.form.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
        abort(403)


def save_uploaded_file(file_storage, target_folder, allowed_extensions, allowed_mimes, relative_prefix):
    if not file_storage or not file_storage.filename:
        return ""

    original_filename = secure_filename(file_storage.filename)
    if "." not in original_filename:
        raise ValueError("文件类型不正确")

    extension = original_filename.rsplit(".", 1)[1].lower()
    if extension not in allowed_extensions:
        raise ValueError("文件类型不正确")

    if file_storage.mimetype not in allowed_mimes:
        raise ValueError("文件类型不正确")

    target_abs = os.path.abspath(target_folder)
    os.makedirs(target_abs, exist_ok=True)
    new_filename = f"{uuid.uuid4().hex}.{extension}"
    save_path = os.path.abspath(os.path.join(target_abs, new_filename))

    if not save_path.startswith(target_abs + os.sep):
        raise ValueError("文件路径不安全")

    file_storage.save(save_path)
    return f"{relative_prefix}/{new_filename}"


def login_required_check():
    if "user_id" not in session:
        flash("请先登录", "warning")
        return redirect(url_for("login"))
    return None


def admin_required_check():
    login_redirect = login_required_check()
    if login_redirect:
        return login_redirect
    if not is_admin():
        abort(403)
    return None


@app.before_request
def csrf_protect():
    if request.method == "POST":
        validate_csrf_token()


@app.after_request
def inject_csrf_token(response):
    if response.content_type and response.content_type.startswith("text/html"):
        body = response.get_data(as_text=True)
        token_input = f'<input type="hidden" name="csrf_token" value="{generate_csrf_token()}">'
        body = re.sub(
            r"(<form\b[^>]*\bmethod=[\"']post[\"'][^>]*>)",
            r"\1" + token_input,
            body,
            flags=re.IGNORECASE,
        )
        response.set_data(body)
        response.headers["Content-Length"] = str(len(response.get_data()))
    return response


def create_notification(user_id, title, content):
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO notification (user_id, title, content)
                VALUES (%s, %s, %s)
                """,
                (user_id, title, content),
            )
            connection.commit()
    except Exception:
        pass
    finally:
        if connection:
            connection.close()


def get_client_ip():
    try:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return clean_text(forwarded_for.split(",")[0], 64)
        return clean_text(request.remote_addr, 64)
    except Exception:
        return ""


def write_operation_log(action, detail="", user_id=None, username=None):
    connection = None
    try:
        if user_id is None:
            user_id = session.get("user_id")
        if username is None:
            username = session.get("username")

        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO operation_log
                    (user_id, username, action, detail, ip_address)
                VALUES
                    (%s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    clean_text(username, 80) if username else None,
                    clean_text(action, 100),
                    clean_long_text(detail, 1000),
                    get_client_ip(),
                ),
            )
            connection.commit()
    except Exception as exc:
        print(f"Operation log error: {exc}")
    finally:
        if connection:
            connection.close()


def write_login_log(username, status, message="", user_id=None):
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO login_log
                    (username, user_id, status, message, ip_address)
                VALUES
                    (%s, %s, %s, %s, %s)
                """,
                (
                    clean_text(username, 80) if username else None,
                    user_id,
                    clean_text(status, 40),
                    clean_text(message, 255),
                    get_client_ip(),
                ),
            )
            connection.commit()
    except Exception as exc:
        print(f"Login log error: {exc}")
    finally:
        if connection:
            connection.close()


def get_unread_notification_count(user_id):
    if not user_id:
        return 0

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS unread_count
                FROM notification
                WHERE user_id = %s AND is_read = 0
                """,
                (user_id,),
            )
            row = cursor.fetchone() or {}
            return row.get("unread_count") or 0
    except Exception:
        return 0
    finally:
        if connection:
            connection.close()


def get_current_user_avatar(user_id):
    if not user_id:
        return ""

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT avatar FROM `user` WHERE id = %s",
                (user_id,),
            )
            user = cursor.fetchone() or {}
            return user.get("avatar") or ""
    except Exception:
        return ""
    finally:
        if connection:
            connection.close()


def is_admin():
    return str(session.get("is_admin")) == "1"


def get_pending_user_count():
    if not is_admin():
        return 0

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM `user`
                WHERE status = %s
                """,
                ("pending",),
            )
            row = cursor.fetchone() or {}
            return row.get("count") or 0
    except Exception:
        return 0
    finally:
        if connection:
            connection.close()


def is_current_user_banned():
    user_id = session.get("user_id")
    if not user_id:
        return False, ""

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT is_banned, banned_reason
                FROM `user`
                WHERE id = %s
                """,
                (user_id,),
            )
            user = cursor.fetchone() or {}
            return int(user.get("is_banned") or 0) == 1, user.get("banned_reason") or ""
    except Exception:
        return False, ""
    finally:
        if connection:
            connection.close()


def check_publish_limit(user_id):
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM item
                WHERE
                    user_id = %s
                    AND created_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (user_id,),
            )
            minute_count = (cursor.fetchone() or {}).get("count") or 0
            if minute_count >= 1:
                return False, "发布太频繁，请 1 分钟后再试"

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM item
                WHERE
                    user_id = %s
                    AND DATE(created_at) = CURDATE()
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (user_id,),
            )
            today_count = (cursor.fetchone() or {}).get("count") or 0
            if today_count >= 10:
                return False, "今日发布数量已达上限"

            return True, ""
    except Exception as exc:
        log_db_error(exc)
        return False, system_error_message()
    finally:
        if connection:
            connection.close()


def get_active_pickup_locations():
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, address, description
                FROM pickup_location
                WHERE is_active = 1
                ORDER BY created_at DESC, id DESC
                """
            )
            return cursor.fetchall()
    except Exception:
        return []
    finally:
        if connection:
            connection.close()


def get_valid_pickup_location_id(cursor, value):
    try:
        location_id = int(value)
    except (TypeError, ValueError):
        return None

    if location_id <= 0:
        return None

    cursor.execute(
        """
        SELECT id
        FROM pickup_location
        WHERE id = %s AND is_active = 1
        """,
        (location_id,),
    )
    location = cursor.fetchone()
    return location["id"] if location else None


@app.context_processor
def inject_notification_count():
    is_admin_user = is_admin()
    return {
        "is_admin_user": is_admin_user,
        "pending_user_count": get_pending_user_count() if is_admin_user else 0,
        "unread_count": get_unread_notification_count(session.get("user_id")),
    }


def format_datetime_local(value):
    if not value:
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%dT%H:%M")
    return str(value).replace(" ", "T")[:16]


def get_page_info(page, per_page, total):
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1

    if page < 1:
        page = 1

    total_pages = max((total + per_page - 1) // per_page, 1)

    if page > total_pages:
        page = total_pages

    offset = (page - 1) * per_page
    return {
        "page": page,
        "per_page": per_page,
        "offset": offset,
        "total_pages": total_pages,
    }


def get_similar_items(item):
    if not item:
        return []

    opposite_type = "found" if item.get("item_type") == "lost" else "lost"
    category = item.get("category") or ""
    location = item.get("location") or ""
    title = item.get("title") or ""
    title_keyword = title[:2] if len(title) >= 2 else title
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id, title, category, item_type, location,
                    image, status, created_at,
                    (
                        CASE WHEN category = %s AND category <> '' THEN 3 ELSE 0 END
                        + CASE WHEN location LIKE %s AND location <> '' THEN 2 ELSE 0 END
                        + CASE WHEN title LIKE %s THEN 1 ELSE 0 END
                    ) AS score
                FROM item
                WHERE
                    item_type = %s
                    AND status IN ('approved', 'resolved')
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                    AND id <> %s
                ORDER BY score DESC, created_at DESC
                LIMIT 5
                """,
                (
                    category,
                    f"%{location}%" if location else "",
                    f"%{title_keyword}%" if title_keyword else "",
                    opposite_type,
                    item["id"],
                ),
            )
            return cursor.fetchall()
    except Exception:
        return []
    finally:
        if connection:
            connection.close()


def get_page_head(title):
    return """
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
    </head>
    """


def get_nav_html():
    return """
    <header class="site-header navbar">
        <div class="container nav-wrap">
            <a class="logo" href="{{ url_for('index') }}">校园失物招领平台</a>
            <nav class="nav nav-links">
                <a class="nav-link" href="{{ url_for('index') }}">首页</a>
                <a class="nav-link" href="{{ url_for('announcements') }}">公告</a>
                <a class="nav-link" href="{{ url_for('lost_items') }}">失物信息</a>
                <a class="nav-link" href="{{ url_for('found_items') }}">招领信息</a>
                {% if current_username %}
                <a class="nav-link" href="{{ url_for('publish') }}">发布信息</a>
                <a class="nav-link" href="{{ url_for('notifications') }}">通知{% if unread_count %}({{ unread_count }}){% endif %}</a>
                <div class="nav-dropdown">
                    <button class="dropdown-toggle nav-avatar-toggle" type="button">
                        {% if current_avatar %}
                        <img class="avatar-small" src="{{ url_for('static', filename=current_avatar) }}" alt="{{ current_username }}">
                        {% else %}
                        <span class="avatar-small avatar-placeholder">{{ current_username[:1] if current_username else "用" }}</span>
                        {% endif %}
                        <span>更多</span>
                    </button>
                    <div class="dropdown-menu">
                        <a href="{{ url_for('my_items') }}">我的发布</a>
                        <a href="{{ url_for('my_claims') }}">我的申请</a>
                        <a href="{{ url_for('received_claims') }}">收到的申请</a>
                        <a href="{{ url_for('my_favorites') }}">我的收藏</a>
                        <a href="{{ url_for('profile') }}">个人中心</a>
                        {% if is_admin_user %}
                        <a href="{{ url_for('admin') }}">后台管理</a>
                        {% endif %}
                    </div>
                </div>
                <a href="{{ url_for('logout') }}" class="logout-btn">退出登录</a>
                {% else %}
                <a class="nav-link" href="{{ url_for('login') }}">登录</a>
                <a href="{{ url_for('register') }}" class="logout-btn">注册</a>
                {% endif %}
            </nav>
        </div>
    </header>
    """


def get_flash_html():
    return """
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
        <div class="flash-container">
            {% for category, message in messages %}
            <div class="flash-message {{ category }}">
                <span class="flash-icon">
                    {% if category == "success" %}✓{% elif category == "error" %}!{% elif category == "warning" %}⚠{% else %}i{% endif %}
                </span>
                <span class="flash-text">{{ message }}</span>
            </div>
            {% endfor %}
        </div>
        {% endif %}
    {% endwith %}
    """


def get_admin_alert_html():
    return """
    {% if is_admin_user and pending_user_count > 0 %}
    <div class="admin-alert">
        <div>
            <strong>注册审核提醒：</strong>
            当前有 {{ pending_user_count }} 个注册用户待审核
        </div>
        <a href="{{ url_for('user_reviews') }}">去审核</a>
    </div>
    {% endif %}
    """


def get_back_button_html():
    if request.path == "/":
        return ""

    if request.path in {"/login", "/register"}:
        return """
        <div class="page-back-wrap">
            <a href="{{ url_for('index') }}" class="page-back-btn">← 返回首页</a>
        </div>
        """

    return """
    <div class="page-back-wrap">
        <a
            href="javascript:void(0)"
            onclick="if (document.referrer) { history.back(); } else { window.location.href='{{ url_for('index') }}'; }"
            class="page-back-btn"
        >← 返回上一页</a>
    </div>
    """


def render_page(title, body_html, **context):
    current_username = session.get("username")
    is_admin_user = is_admin()
    pending_user_count = get_pending_user_count() if is_admin_user else 0
    page_head = render_template_string(get_page_head(title), title=title)
    nav_html = render_template_string(
        get_nav_html(),
        current_username=current_username,
        current_avatar=get_current_user_avatar(session.get("user_id")),
        is_admin_user=is_admin_user,
        unread_count=get_unread_notification_count(session.get("user_id")),
    )
    admin_alert_html = render_template_string(
        get_admin_alert_html(),
        is_admin_user=is_admin_user,
        pending_user_count=pending_user_count,
    )
    flash_html = render_template_string(
        get_flash_html(),
        get_flashed_messages=get_flashed_messages,
    )
    back_button_html = render_template_string(get_back_button_html())
    rendered_body = render_template_string(body_html, **context)

    html = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    {{ page_head | safe }}
    <body>
        {{ nav_html | safe }}
        {{ admin_alert_html | safe }}
        {{ flash_html | safe }}
        {{ back_button_html | safe }}

        <main>
            {{ rendered_body | safe }}
        </main>

        <footer class="site-footer">
            <div class="container">
                <p>校园失物招领平台 - 让校园互助更简单</p>
            </div>
        </footer>
    </body>
    </html>
    """
    return render_template_string(
        html,
        admin_alert_html=admin_alert_html,
        back_button_html=back_button_html,
        flash_html=flash_html,
        nav_html=nav_html,
        page_head=page_head,
        rendered_body=rendered_body,
        title=title,
    )


def render_error_page(code, text):
    content = """
    <section class="error-section">
        <div class="container">
            <div class="error-box">
                <div class="error-code">{{ code }}</div>
                <h1 class="error-title">{{ code }}</h1>
                <p class="error-text">{{ text }}</p>
                <div class="error-actions">
                    <a class="btn btn-form error-home-btn" href="{{ url_for('index') }}">返回首页</a>
                </div>
            </div>
        </div>
    </section>
    """
    page_content = render_template_string(content, code=code, text=text)
    return render_page(f"{code} - 校园失物招领平台", page_content), code


@app.errorhandler(404)
def handle_404(error):
    return render_error_page(404, "页面不存在或已被删除")


@app.errorhandler(403)
def handle_403(error):
    return render_error_page(403, "你没有权限访问该页面")


@app.errorhandler(500)
def handle_500(error):
    return render_error_page(500, "服务器出现错误，请稍后再试")


@app.route("/")
def index():
    username = session.get("username")
    error = ""
    latest_announcements = []
    latest_lost_items = []
    latest_found_items = []
    connection = None
    login_text = (
        f"欢迎你，{username}"
        if username
        else "请登录后发布失物招领信息"
    )

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, created_at
                FROM announcement
                WHERE is_active = 1
                ORDER BY created_at DESC
                LIMIT 3
                """
            )
            latest_announcements = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id, title, category, location, image, status, created_at,
                    (
                        SELECT COUNT(*)
                        FROM favorite
                        WHERE favorite.item_id = item.id
                    ) AS favorite_count
                FROM item
                WHERE
                    item_type = %s
                    AND status IN ('approved', 'resolved')
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                ORDER BY created_at DESC
                LIMIT 6
                """,
                ("lost",),
            )
            latest_lost_items = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id, title, category, location, image, status, created_at,
                    (
                        SELECT COUNT(*)
                        FROM favorite
                        WHERE favorite.item_id = item.id
                    ) AS favorite_count
                FROM item
                WHERE
                    item_type = %s
                    AND status IN ('approved', 'resolved')
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                ORDER BY created_at DESC
                LIMIT 6
                """,
                ("found",),
            )
            latest_found_items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    status_map = {
        "approved": "已通过",
        "resolved": "已完成",
    }

    content = """
    <section class="hero">
        <div class="container hero-content">
            <p class="hero-label">Campus Lost & Found</p>
            <h1>校园失物招领平台</h1>
            <p class="hero-text">
                本平台用于发布校园失物信息和招领信息，帮助同学们更快找回遗失物品，也让捡到的物品及时回到主人身边。
            </p>
            <p class="login-state">{{ login_text }}</p>
            <div class="hero-actions">
                <a class="btn btn-primary" href="{{ url_for('publish') }}">发布失物</a>
                <a class="btn btn-secondary" href="{{ url_for('publish') }}">发布招领</a>
            </div>
        </div>
    </section>

    {% if error %}
    <div class="container">
        <p class="notice notice-error">{{ error }}</p>
    </div>
    {% endif %}

    <section class="home-section announcement-home-section">
        <div class="container">
            <div class="home-section-header">
                <div>
                    <p class="hero-label">Announcements</p>
                    <h2>公告栏</h2>
                </div>
                <a class="more-link" href="{{ url_for('announcements') }}">查看更多公告</a>
            </div>

            {% if not latest_announcements %}
            <div class="empty-state">暂无公告</div>
            {% else %}
            <div class="announcement-list announcement-home-list">
                {% for announcement in latest_announcements %}
                <article class="announcement-card">
                    <a class="announcement-card-link" href="{{ url_for('announcement_detail', announcement_id=announcement.id) }}" aria-label="查看公告{{ announcement.title }}"></a>
                    <h3 class="announcement-title">{{ announcement.title }}</h3>
                    <div class="notification-time">{{ announcement.created_at }}</div>
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>

    <section class="features">
        <div class="container feature-grid">
            <a class="feature-card" href="{{ url_for('publish') }}">
                <h2>发布失物</h2>
                <p>遗失物品后，可以在平台发布失物信息，方便其他同学查看和联系。</p>
            </a>
            <a class="feature-card" href="{{ url_for('found_items') }}">
                <h2>查看招领</h2>
                <p>浏览同学们发布的招领信息，看看是否有你正在寻找的物品。</p>
            </a>
            <a class="feature-card" href="{{ url_for('lost_items') }}">
                <h2>快速搜索</h2>
                <p>后续可通过关键词、地点和时间快速筛选相关失物与招领信息。</p>
            </a>
        </div>
    </section>

    <section class="home-section">
        <div class="container">
            <div class="home-section-header">
                <div>
                    <p class="hero-label">Latest Lost</p>
                    <h2>最新失物</h2>
                </div>
                <a class="more-link" href="{{ url_for('lost_items') }}">查看更多</a>
            </div>

            {% if not latest_lost_items %}
            <div class="empty-state">暂无失物信息</div>
            {% else %}
            <div class="home-item-grid">
                {% for item in latest_lost_items %}
                <article class="home-item-card">
                    <a class="home-card-link" href="{{ url_for('item_detail', item_id=item.id) }}" aria-label="查看{{ item.title }}"></a>
                    <div class="home-item-image">
                        {% if item.image %}
                        <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                        {% else %}
                        <span>暂无图片</span>
                        {% endif %}
                    </div>
                    <div class="home-item-body">
                        <div class="item-topline">
                            <span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span>
                        </div>
                        <h3><a class="item-title-link" href="{{ url_for('item_detail', item_id=item.id) }}">{{ item.title }}</a></h3>
                        <dl class="item-meta">
                            <div>
                                <dt>分类</dt>
                                <dd>{{ item.category or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>地点</dt>
                                <dd>{{ item.location or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>发布时间</dt>
                                <dd>{{ item.created_at }}</dd>
                            </div>
                            <div>
                                <dt>收藏</dt>
                                <dd><span class="favorite-count">收藏：{{ item.favorite_count or 0 }}</span></dd>
                            </div>
                        </dl>
                        <a class="detail-link" href="{{ url_for('item_detail', item_id=item.id) }}">查看详情</a>
                    </div>
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>

    <section class="home-section home-section-last">
        <div class="container">
            <div class="home-section-header">
                <div>
                    <p class="hero-label">Latest Found</p>
                    <h2>最新招领</h2>
                </div>
                <a class="more-link" href="{{ url_for('found_items') }}">查看更多</a>
            </div>

            {% if not latest_found_items %}
            <div class="empty-state">暂无招领信息</div>
            {% else %}
            <div class="home-item-grid">
                {% for item in latest_found_items %}
                <article class="home-item-card">
                    <a class="home-card-link" href="{{ url_for('item_detail', item_id=item.id) }}" aria-label="查看{{ item.title }}"></a>
                    <div class="home-item-image">
                        {% if item.image %}
                        <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                        {% else %}
                        <span>暂无图片</span>
                        {% endif %}
                    </div>
                    <div class="home-item-body">
                        <div class="item-topline">
                            <span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span>
                        </div>
                        <h3><a class="item-title-link" href="{{ url_for('item_detail', item_id=item.id) }}">{{ item.title }}</a></h3>
                        <dl class="item-meta">
                            <div>
                                <dt>分类</dt>
                                <dd>{{ item.category or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>地点</dt>
                                <dd>{{ item.location or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>发布时间</dt>
                                <dd>{{ item.created_at }}</dd>
                            </div>
                            <div>
                                <dt>收藏</dt>
                                <dd><span class="favorite-count">收藏：{{ item.favorite_count or 0 }}</span></dd>
                            </div>
                        </dl>
                        <a class="detail-link" href="{{ url_for('item_detail', item_id=item.id) }}">查看详情</a>
                    </div>
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        latest_announcements=latest_announcements,
        latest_found_items=latest_found_items,
        latest_lost_items=latest_lost_items,
        login_text=login_text,
        status_map=status_map,
    )
    return render_page("校园失物招领平台", page_content)


@app.route("/announcements")
def announcements():
    error = ""
    announcement_list = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, content, created_at
                FROM announcement
                WHERE is_active = 1
                ORDER BY created_at DESC
                """
            )
            announcement_list = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Announcements</p>
                <h1>公告栏</h1>
                <p>查看校园失物招领平台的最新公告和重要提醒。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not announcement_list %}
            <div class="empty-state">暂无公告</div>
            {% else %}
            <div class="announcement-list">
                {% for announcement in announcement_list %}
                <article class="announcement-card">
                    <a class="announcement-card-link" href="{{ url_for('announcement_detail', announcement_id=announcement.id) }}" aria-label="查看公告{{ announcement.title }}"></a>
                    <h2 class="announcement-title">
                        <a class="item-title-link" href="{{ url_for('announcement_detail', announcement_id=announcement.id) }}">{{ announcement.title }}</a>
                    </h2>
                    <p class="announcement-content text-content">{{ announcement.content }}</p>
                    <div class="notification-time">{{ announcement.created_at }}</div>
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        announcement_list=announcement_list,
        error=error,
    )
    return render_page("公告栏 - 校园失物招领平台", page_content)


@app.route("/announcement/<int:announcement_id>")
def announcement_detail(announcement_id):
    error = ""
    announcement = None
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, content, created_at
                FROM announcement
                WHERE id = %s AND is_active = 1
                """,
                (announcement_id,),
            )
            announcement = cursor.fetchone()

            if not announcement:
                abort(404)
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <a class="back-link" href="{{ url_for('announcements') }}">返回公告栏</a>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif announcement %}
            <article class="announcement-card announcement-detail-card">
                <h1 class="announcement-title">{{ announcement.title }}</h1>
                <div class="notification-time">{{ announcement.created_at }}</div>
                <p class="announcement-content text-content">{{ announcement.content }}</p>
            </article>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        announcement=announcement,
        error=error,
    )
    return render_page("公告详情 - 校园失物招领平台", page_content)


def render_public_items_page(
    item_type,
    page_title,
    empty_text,
    filtered_empty_text,
    time_label,
    intro_text,
    reset_endpoint,
):
    error = ""
    items = []
    connection = None
    keyword = clean_text(request.args.get("keyword", ""), 100)
    category = validate_choice(request.args.get("category", ""), CATEGORIES, "")
    location = clean_text(request.args.get("location", ""), 100)
    page = request.args.get("page", 1)
    has_filters = bool(keyword or category or location)
    display_empty_text = filtered_empty_text if has_filters else empty_text
    page_info = get_page_info(page, 6, 0)

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            conditions = [
                "item.item_type = %s",
                "item.status IN ('approved', 'resolved')",
                "(item.is_deleted = 0 OR item.is_deleted IS NULL)",
            ]
            params = [item_type]

            if keyword:
                conditions.append("(item.title LIKE %s OR item.description LIKE %s OR item.location LIKE %s)")
                keyword_value = f"%{keyword}%"
                params.extend([keyword_value, keyword_value, keyword_value])

            if category:
                conditions.append("item.category = %s")
                params.append(category)

            if location:
                conditions.append("item.location LIKE %s")
                params.append(f"%{location}%")

            where_clause = " AND ".join(conditions)
            count_sql = """
                SELECT COUNT(*) AS total
                FROM item
                WHERE """ + where_clause
            cursor.execute(count_sql, params)
            total = (cursor.fetchone() or {}).get("total") or 0
            page_info = get_page_info(page, 6, total)

            sql = """
                SELECT
                    item.id, item.title, item.category, item.location, item.event_time,
                    item.image, item.contact, item.status, item.created_at,
                    pickup_location.name AS pickup_location_name,
                    (
                        SELECT COUNT(*)
                        FROM favorite
                        WHERE favorite.item_id = item.id
                    ) AS favorite_count
                FROM item
                LEFT JOIN pickup_location ON item.pickup_location_id = pickup_location.id
                WHERE """ + where_clause + """
                ORDER BY item.created_at DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(sql, params + [page_info["per_page"], page_info["offset"]])
            items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Public List</p>
                <h1>{{ page_title }}</h1>
                <p>{{ intro_text }}</p>
            </div>

            <form class="search-form" method="get" action="{{ url_for(reset_endpoint) }}">
                <input type="text" name="keyword" value="{{ keyword }}" placeholder="搜索物品名称、描述或地点">
                <input type="text" name="location" value="{{ location }}" placeholder="输入地点">
                <select name="category">
                    <option value="">全部分类</option>
                    <option value="校园卡" {% if category == '校园卡' %}selected{% endif %}>校园卡</option>
                    <option value="手机数码" {% if category == '手机数码' %}selected{% endif %}>手机数码</option>
                    <option value="钥匙" {% if category == '钥匙' %}selected{% endif %}>钥匙</option>
                    <option value="钱包" {% if category == '钱包' %}selected{% endif %}>钱包</option>
                    <option value="书籍资料" {% if category == '书籍资料' %}selected{% endif %}>书籍资料</option>
                    <option value="衣物" {% if category == '衣物' %}selected{% endif %}>衣物</option>
                    <option value="其他" {% if category == '其他' %}selected{% endif %}>其他</option>
                </select>
                <button class="search-btn" type="submit">搜索</button>
                <a class="reset-btn" href="{{ url_for(reset_endpoint) }}">重置</a>
            </form>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not items %}
            <div class="empty-state">{{ display_empty_text }}</div>
            {% else %}
            <div class="item-grid">
                {% for item in items %}
                <article class="item-card public-item-card">
                    <div class="item-image">
                        {% if item.image %}
                        <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                        {% else %}
                        <span>暂无图片</span>
                        {% endif %}
                    </div>

                    <div class="item-body">
                        <div class="item-topline">
                            <span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span>
                        </div>
                        <h2>
                            <a class="item-title-link" href="{{ url_for('item_detail', item_id=item.id) }}">{{ item.title }}</a>
                        </h2>
                        <dl class="item-meta">
                            <div>
                                <dt>分类</dt>
                                <dd>{{ item.category or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>地点</dt>
                                <dd>{{ item.location or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>{{ time_label }}</dt>
                                <dd>{{ item.event_time or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>联系方式</dt>
                                <dd>{{ item.contact or "未填写" }}</dd>
                            </div>
                            {% if reset_endpoint == "found_items" %}
                            <div>
                                <dt>领取地点</dt>
                                <dd>{{ item.pickup_location_name or "未填写" }}</dd>
                            </div>
                            {% endif %}
                            <div>
                                <dt>发布时间</dt>
                                <dd>{{ item.created_at }}</dd>
                            </div>
                            <div>
                                <dt>收藏</dt>
                                <dd><span class="favorite-count">收藏：{{ item.favorite_count or 0 }}</span></dd>
                            </div>
                        </dl>
                        <a class="detail-link" href="{{ url_for('item_detail', item_id=item.id) }}">查看详情</a>
                    </div>
                </article>
                {% endfor %}
            </div>
            {% endif %}

            {% if page_info.total_pages > 1 %}
            <nav class="pagination">
                {% if page_info.page > 1 %}
                <a href="{{ page_url(page_info.page - 1) }}">上一页</a>
                {% else %}
                <span class="disabled">上一页</span>
                {% endif %}

                {% for page_number in page_numbers %}
                    {% if page_number == page_info.page %}
                    <span class="active">{{ page_number }}</span>
                    {% else %}
                    <a href="{{ page_url(page_number) }}">{{ page_number }}</a>
                    {% endif %}
                {% endfor %}

                {% if page_info.page < page_info.total_pages %}
                <a href="{{ page_url(page_info.page + 1) }}">下一页</a>
                {% else %}
                <span class="disabled">下一页</span>
                {% endif %}
            </nav>
            {% endif %}
        </div>
    </section>
    """
    query_args = {}
    if keyword:
        query_args["keyword"] = keyword
    if category:
        query_args["category"] = category
    if location:
        query_args["location"] = location

    def page_url(page_number):
        return url_for(reset_endpoint, page=page_number, **query_args)

    page_content = render_template_string(
        content,
        category=category,
        display_empty_text=display_empty_text,
        error=error,
        intro_text=intro_text,
        items=items,
        keyword=keyword,
        location=location,
        page_info=page_info,
        page_numbers=range(1, page_info["total_pages"] + 1),
        page_url=page_url,
        page_title=page_title,
        reset_endpoint=reset_endpoint,
        status_map={
            "approved": "已通过",
            "resolved": "已完成",
        },
        time_label=time_label,
    )
    return render_page(f"{page_title} - 校园失物招领平台", page_content)


@app.route("/lost")
def lost_items():
    return render_public_items_page(
        item_type="lost",
        page_title="失物信息",
        empty_text="暂无失物信息",
        filtered_empty_text="暂无符合条件的失物信息",
        time_label="丢失时间",
        intro_text="这里展示已经审核通过的失物信息，方便同学们帮助寻找。",
        reset_endpoint="lost_items",
    )


@app.route("/found")
def found_items():
    return render_public_items_page(
        item_type="found",
        page_title="招领信息",
        empty_text="暂无招领信息",
        filtered_empty_text="暂无符合条件的招领信息",
        time_label="拾到时间",
        intro_text="这里展示已经审核通过的招领信息，方便失主及时认领。",
        reset_endpoint="found_items",
    )


@app.route("/item/<int:item_id>")
def item_detail(item_id):
    error = ""
    item = None
    is_favorited = False
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    item.id, item.title, item.description, item.category,
                    item.item_type, item.location, item.event_time, item.image,
                    item.contact, item.status, item.created_at, item.views,
                    item.user_id, `user`.username,
                    pickup_location.name AS pickup_location_name,
                    pickup_location.address AS pickup_location_address,
                    pickup_location.description AS pickup_location_description
                FROM item
                JOIN `user` ON item.user_id = `user`.id
                LEFT JOIN pickup_location ON item.pickup_location_id = pickup_location.id
                WHERE
                    item.id = %s
                    AND item.status IN ('approved', 'resolved')
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item:
                abort(404)

            cursor.execute(
                """
                UPDATE item
                SET views = views + 1
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            connection.commit()
            item["views"] = (item.get("views") or 0) + 1

            if session.get("user_id"):
                cursor.execute(
                    """
                    SELECT id
                    FROM favorite
                    WHERE user_id = %s AND item_id = %s
                    """,
                    (session["user_id"], item_id),
                )
                is_favorited = cursor.fetchone() is not None
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "approved": "已通过",
        "resolved": "已完成",
    }
    time_label = "丢失时间" if item and item.get("item_type") == "lost" else "拾到时间"
    similar_items = get_similar_items(item)
    similar_title = "可能相关的招领信息" if item and item.get("item_type") == "lost" else "可能相关的失物信息"

    content = """
    <section class="detail-section">
        <div class="container">
            <a class="back-link" href="{{ url_for('lost_items') if item and item.item_type == 'lost' else url_for('found_items') }}">返回列表</a>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif item %}
            <article class="detail-card">
                <div class="detail-image">
                    {% if item.image %}
                    <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                    {% else %}
                    <span>暂无图片</span>
                    {% endif %}
                </div>

                <div class="detail-content">
                    <div class="item-topline">
                        <span class="type-tag">{{ type_map.get(item.item_type, item.item_type) }}</span>
                        <span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span>
                    </div>

                    <h1>{{ item.title }}</h1>
                    <p class="detail-description">{{ item.description }}</p>

                    <dl class="detail-meta">
                        <div>
                            <dt>分类</dt>
                            <dd>{{ item.category or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>地点</dt>
                            <dd>{{ item.location or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>{{ time_label }}</dt>
                            <dd>{{ item.event_time or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>联系方式</dt>
                            <dd>{{ item.contact or "未填写" }}</dd>
                        </div>
                        {% if item.item_type == "found" and item.pickup_location_name %}
                        <div>
                            <dt>领取地点</dt>
                            <dd>{{ item.pickup_location_name }}</dd>
                        </div>
                        <div>
                            <dt>地点地址</dt>
                            <dd>{{ item.pickup_location_address or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>地点说明</dt>
                            <dd class="text-content">{{ item.pickup_location_description or "未填写" }}</dd>
                        </div>
                        {% endif %}
                        <div>
                            <dt>发布人</dt>
                            <dd>{{ item.username }}</dd>
                        </div>
                        <div>
                            <dt>发布时间</dt>
                            <dd>{{ item.created_at }}</dd>
                        </div>
                        <div>
                            <dt>浏览量</dt>
                            <dd>{{ item.views }}</dd>
                        </div>
                    </dl>

                    <div class="claim-panel">
                        <div class="favorite-action">
                            {% if not session.get("user_id") %}
                            <p class="claim-hint">登录后可收藏</p>
                            {% elif is_favorited %}
                            <form class="inline-form" method="post" action="{{ url_for('unfavorite_item', item_id=item.id) }}">
                                <button class="favorite-btn unfavorite-btn" type="submit">取消收藏</button>
                            </form>
                            {% else %}
                            <form class="inline-form" method="post" action="{{ url_for('favorite_item', item_id=item.id) }}">
                                <button class="favorite-btn" type="submit">收藏</button>
                            </form>
                            {% endif %}
                        </div>

                        {% if not session.get("user_id") %}
                        <p class="claim-hint">登录后可提交申请</p>
                        <a class="detail-link" href="{{ url_for('login') }}">去登录</a>
                        {% elif session.get("user_id") == item.user_id %}
                        <p class="claim-hint owner-claim-hint">这是你发布的信息</p>
                        {% else %}
                        <a class="btn btn-form claim-submit-link" href="{{ url_for('submit_claim', item_id=item.id) }}">提交申请</a>
                        {% endif %}

                        <div class="report-action">
                            {% if not session.get("user_id") %}
                            <p class="claim-hint">登录后可举报</p>
                            {% elif session.get("user_id") != item.user_id %}
                            <a class="detail-link report-link" href="{{ url_for('submit_report', item_id=item.id) }}">举报信息</a>
                            {% endif %}
                            {% if is_admin_user %}
                            <form class="inline-form" method="post" action="{{ url_for('delete_item', item_id=item.id) }}">
                                <button class="detail-link report-link admin-detail-delete-btn" type="submit" onclick="return confirm('确定要删除这条信息吗？')">删除</button>
                            </form>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </article>

            <section class="similar-section">
                <h2 class="similar-title">{{ similar_title }}</h2>
                {% if similar_items %}
                <div class="similar-grid">
                    {% for similar in similar_items %}
                    <article class="item-card public-item-card">
                        <div class="item-image">
                            {% if similar.image %}
                            <img src="{{ url_for('static', filename=similar.image) }}" alt="{{ similar.title }}">
                            {% else %}
                            <span>暂无图片</span>
                            {% endif %}
                        </div>

                        <div class="item-body">
                            <div class="item-topline">
                                <span class="type-tag">{{ type_map.get(similar.item_type, similar.item_type) }}</span>
                                <span class="status-tag status-{{ similar.status }}">{{ status_map.get(similar.status, similar.status) }}</span>
                            </div>
                            <h2>
                                <a class="item-title-link" href="{{ url_for('item_detail', item_id=similar.id) }}">{{ similar.title }}</a>
                            </h2>
                            <dl class="item-meta">
                                <div>
                                    <dt>分类</dt>
                                    <dd>{{ similar.category or "未填写" }}</dd>
                                </div>
                                <div>
                                    <dt>地点</dt>
                                    <dd>{{ similar.location or "未填写" }}</dd>
                                </div>
                                <div>
                                    <dt>发布时间</dt>
                                    <dd>{{ similar.created_at }}</dd>
                                </div>
                            </dl>
                            <a class="detail-link" href="{{ url_for('item_detail', item_id=similar.id) }}">查看详情</a>
                        </div>
                    </article>
                    {% endfor %}
                </div>
                {% else %}
                <div class="empty-state">暂无相似信息</div>
                {% endif %}
            </section>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        is_admin_user=is_admin(),
        is_favorited=is_favorited,
        item=item,
        similar_items=similar_items,
        similar_title=similar_title,
        status_map=status_map,
        time_label=time_label,
        type_map=type_map,
    )
    return render_page("物品详情 - 校园失物招领平台", page_content)


@app.route("/favorite/<int:item_id>", methods=["POST"])
def favorite_item(item_id):
    if "user_id" not in session:
        flash("请先登录后收藏", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id
                FROM item
                WHERE
                    id = %s
                    AND status IN ('approved', 'resolved')
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item:
                abort(404)

            cursor.execute(
                """
                SELECT id
                FROM favorite
                WHERE user_id = %s AND item_id = %s
                """,
                (session["user_id"], item_id),
            )
            favorite = cursor.fetchone()

            if not favorite:
                cursor.execute(
                    """
                    INSERT INTO favorite (user_id, item_id)
                    VALUES (%s, %s)
                    """,
                    (session["user_id"], item_id),
                )
                connection.commit()
        flash("收藏成功", "success")
        write_operation_log("收藏信息", f"收藏信息 ID：{item_id}")
        return redirect(url_for("item_detail", item_id=item_id))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("item_detail", item_id=item_id))
    finally:
        if connection:
            connection.close()


@app.route("/unfavorite/<int:item_id>", methods=["POST"])
def unfavorite_item(item_id):
    if "user_id" not in session:
        flash("请先登录后取消收藏", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM favorite
                WHERE user_id = %s AND item_id = %s
                """,
                (session["user_id"], item_id),
            )
            connection.commit()
        flash("已取消收藏", "success")
        write_operation_log("取消收藏", f"取消收藏信息 ID：{item_id}")
        if request.args.get("next") == "my_favorites":
            return redirect(url_for("my_favorites"))
        return redirect(url_for("item_detail", item_id=item_id))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("item_detail", item_id=item_id))
    finally:
        if connection:
            connection.close()


@app.route("/my_favorites")
def my_favorites():
    if "user_id" not in session:
        flash("请先登录后查看我的收藏", "warning")
        return redirect(url_for("login"))

    error = ""
    items = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    item.id, item.title, item.category, item.item_type,
                    item.location, item.image, item.status,
                    favorite.created_at AS favorite_created_at
                FROM favorite
                JOIN item ON favorite.item_id = item.id
                WHERE favorite.user_id = %s
                    AND item.status IN ('approved', 'resolved')
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                ORDER BY favorite.created_at DESC
                """,
                (session["user_id"],),
            )
            items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "approved": "已通过",
        "resolved": "已完成",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">My Favorites</p>
                <h1>我的收藏</h1>
                <p>这里展示你收藏过的失物和招领信息。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not items %}
            <div class="empty-state">暂无收藏</div>
            {% else %}
            <div class="item-grid">
                {% for item in items %}
                <article class="item-card public-item-card">
                    <div class="item-image">
                        {% if item.image %}
                        <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                        {% else %}
                        <span>暂无图片</span>
                        {% endif %}
                    </div>

                    <div class="item-body">
                        <div class="item-topline">
                            <span class="type-tag">{{ type_map.get(item.item_type, item.item_type) }}</span>
                            <span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span>
                        </div>
                        <h2>
                            <a class="item-title-link" href="{{ url_for('item_detail', item_id=item.id) }}">{{ item.title }}</a>
                        </h2>
                        <dl class="item-meta">
                            <div>
                                <dt>分类</dt>
                                <dd>{{ item.category or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>地点</dt>
                                <dd>{{ item.location or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>收藏时间</dt>
                                <dd>{{ item.favorite_created_at }}</dd>
                            </div>
                        </dl>
                        <div class="item-actions">
                            <a class="detail-link" href="{{ url_for('item_detail', item_id=item.id) }}">查看详情</a>
                            <form class="inline-form" method="post" action="{{ url_for('unfavorite_item', item_id=item.id, next='my_favorites') }}">
                                <button class="favorite-btn unfavorite-btn" type="submit">取消收藏</button>
                            </form>
                        </div>
                    </div>
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        items=items,
        status_map=status_map,
        type_map=type_map,
    )
    return render_page("我的收藏 - 校园失物招领平台", page_content)


@app.route("/send_email_code", methods=["POST"])
def send_email_code_route():
    raw_email = clean_text(request.form.get("email"), 120)
    email = validate_email(raw_email)

    if not raw_email:
        return jsonify(success=False, message="邮箱不能为空")

    if not email:
        return jsonify(success=False, message="邮箱格式不正确")

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM `user` WHERE email = %s",
                (email,),
            )
            if cursor.fetchone():
                return jsonify(success=False, message="邮箱已被注册，请更换邮箱")

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM email_code
                WHERE email = %s
                    AND created_at >= DATE_SUB(NOW(), INTERVAL 60 SECOND)
                """,
                (email,),
            )
            recent_count = (cursor.fetchone() or {}).get("count") or 0
            if recent_count > 0:
                return jsonify(success=False, message="验证码发送太频繁，请 60 秒后再试")

            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM email_code
                WHERE email = %s
                    AND DATE(created_at) = CURDATE()
                """,
                (email,),
            )
            daily_count = (cursor.fetchone() or {}).get("count") or 0
            if daily_count >= 5:
                return jsonify(success=False, message="该邮箱今日验证码发送次数已达上限")

            code = f"{secrets.randbelow(1000000):06d}"
            cursor.execute(
                """
                INSERT INTO email_code (email, code, used, created_at, expire_at)
                VALUES (%s, %s, 0, NOW(), DATE_ADD(NOW(), INTERVAL 5 MINUTE))
                """,
                (email, code),
            )
            connection.commit()

        send_success, send_message = send_email_code(email, code)
        if not send_success:
            print("Email send error:", send_message)
            return jsonify(success=False, message=send_message)

        return jsonify(success=True, message="验证码已发送，请查收邮箱")
    except Exception as exc:
        log_db_error(exc)
        return jsonify(success=False, message=system_error_message())
    finally:
        if connection:
            connection.close()


@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    pickup_locations = get_active_pickup_locations()

    if request.method == "POST":
        username = clean_text(request.form.get("username"), 80)
        password = clean_text(request.form.get("password"), 128)
        confirm_password = clean_text(request.form.get("confirm_password"), 128)
        real_name = clean_text(request.form.get("real_name"), 80)
        student_id = clean_text(request.form.get("student_id"), 50)
        raw_phone = clean_text(request.form.get("phone"), 30)
        raw_email = clean_text(request.form.get("email"), 120)
        email_code_input = clean_text(request.form.get("email_code"), 6)
        phone = validate_phone(raw_phone)
        email = validate_email(raw_email)
        student_card_file = request.files.get("student_card")
        student_card_path = ""

        if not username:
            error = "用户名不能为空"
        elif not password:
            error = "密码不能为空"
        elif not confirm_password:
            error = "确认密码不能为空"
        elif password != confirm_password:
            error = "两次输入的密码不一致"
        elif not real_name:
            error = "姓名不能为空"
        elif not student_id:
            error = "学号不能为空"
        elif not raw_email:
            error = "邮箱不能为空"
        elif not email:
            error = "邮箱格式不正确"
        elif not email_code_input:
            error = "邮箱验证码不能为空"
        elif not re.fullmatch(r"\d{6}", email_code_input):
            error = "邮箱验证码格式不正确"
        elif not raw_phone:
            error = "手机号不能为空"
        elif not phone:
            error = "手机号格式不正确"
        elif not student_card_file or not student_card_file.filename:
            error = "请上传学生证照片"
        else:
            connection = None
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT id FROM `user` WHERE username = %s",
                        (username,),
                    )
                    existing_user = cursor.fetchone()

                    if existing_user:
                        error = "用户名已存在，请更换用户名"
                    else:
                        cursor.execute(
                            "SELECT id FROM `user` WHERE email = %s",
                            (email,),
                        )
                        existing_email = cursor.fetchone()

                        if existing_email:
                            error = "邮箱已被注册，请更换邮箱"
                        else:
                            cursor.execute(
                                "SELECT id FROM `user` WHERE student_id = %s",
                                (student_id,),
                            )
                            existing_student = cursor.fetchone()

                            if existing_student:
                                error = "学号已被注册，请检查信息"
                            else:
                                cursor.execute(
                                    """
                                    SELECT id
                                    FROM email_code
                                    WHERE
                                        email = %s
                                        AND code = %s
                                        AND used = 0
                                        AND expire_at >= NOW()
                                    ORDER BY created_at DESC
                                    LIMIT 1
                                    """,
                                    (email, email_code_input),
                                )
                                valid_code = cursor.fetchone()

                                if not valid_code:
                                    error = "邮箱验证码错误或已过期"
                                else:
                                    student_card_path = save_uploaded_file(
                                        student_card_file,
                                        USER_CARD_FOLDER,
                                        ALLOWED_USER_CARD_EXTENSIONS,
                                        ALLOWED_USER_CARD_MIMES,
                                        "uploads/user_cards",
                                    )

                                    password_hash = generate_password_hash(password)
                                    cursor.execute(
                                        """
                                        INSERT INTO `user`
                                            (username, password_hash, real_name, student_id, phone, email, student_card, status)
                                        VALUES
                                            (%s, %s, %s, %s, %s, %s, %s, %s)
                                        """,
                                        (
                                            username,
                                            password_hash,
                                            real_name,
                                            student_id,
                                            phone,
                                            email,
                                            student_card_path,
                                            "pending",
                                        ),
                                    )
                                    cursor.execute(
                                        "UPDATE email_code SET used = 1 WHERE id = %s",
                                        (valid_code["id"],),
                                    )
                                    connection.commit()
                                    write_operation_log(
                                        "用户注册",
                                        f"用户 {username} 提交注册申请",
                                        username=username,
                                    )
                                    flash("注册成功，请等待管理员审核", "success")
                                    return redirect(url_for("login"))
            except Exception as exc:
                log_db_error(exc)
                error = system_error_message()
                flash(error, "error")
            finally:
                if connection:
                    connection.close()

        if error:
            flash(error, "error")

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Join Campus Lost & Found</p>
                <h1>注册账号</h1>
                <p>账号提交后需要管理员审核，通过后才能登录并发布失物招领信息。</p>
            </div>

            <form class="register-form" method="post" action="{{ url_for('register') }}" enctype="multipart/form-data">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                <label>
                    用户名
                    <input type="text" name="username" value="{{ request.form.get('username', '') }}" placeholder="用户名" required>
                </label>

                <label>
                    密码
                    <input type="password" name="password" placeholder="密码" required>
                </label>

                <label>
                    确认密码
                    <input type="password" name="confirm_password" placeholder="确认密码" required>
                </label>

                <label>
                    姓名
                    <input type="text" name="real_name" value="{{ request.form.get('real_name', '') }}" placeholder="姓名" required>
                </label>

                <label>
                    学号
                    <input type="text" name="student_id" value="{{ request.form.get('student_id', '') }}" placeholder="学号" required>
                </label>

                <label>
                    手机号
                    <input type="text" name="phone" value="{{ request.form.get('phone', '') }}" placeholder="手机号" required>
                </label>

                <label>
                    邮箱
                    <input type="email" name="email" value="{{ request.form.get('email', '') }}" placeholder="邮箱" required>
                </label>

                <label>
                    邮箱验证码
                    <div class="email-code-row">
                        <input type="text" name="email_code" value="{{ request.form.get('email_code', '') }}" placeholder="请输入 6 位邮箱验证码" maxlength="6" required>
                        <button class="email-code-btn" id="sendEmailCodeBtn" type="button">发送验证码</button>
                    </div>
                </label>

                <label>
                    学生证照片
                    <input type="file" name="student_card" accept="image/png,image/jpeg" required>
                </label>

                <button class="btn btn-form" type="submit">注册</button>
            </form>
        </div>
    </section>

    <script>
        const sendCodeButton = document.getElementById("sendEmailCodeBtn");
        const registerForm = document.querySelector("form.register-form");
        let emailCodeCountdown = 0;
        let emailCodeTimer = null;

        function updateEmailCodeButton() {
            if (emailCodeCountdown > 0) {
                sendCodeButton.disabled = true;
                sendCodeButton.textContent = emailCodeCountdown + " 秒后重发";
                emailCodeCountdown -= 1;
            } else {
                sendCodeButton.disabled = false;
                sendCodeButton.textContent = "发送验证码";
                if (emailCodeTimer) {
                    clearInterval(emailCodeTimer);
                    emailCodeTimer = null;
                }
            }
        }

        sendCodeButton.addEventListener("click", function () {
            const emailInput = registerForm.querySelector('input[name="email"]');
            const csrfInput = registerForm.querySelector('input[name="csrf_token"]');
            const email = emailInput.value.trim();

            if (!email) {
                alert("请先填写邮箱");
                return;
            }

            const formData = new FormData();
            formData.append("email", email);
            if (csrfInput) {
                formData.append("csrf_token", csrfInput.value);
            }

            sendCodeButton.disabled = true;

            fetch("{{ url_for('send_email_code_route') }}", {
                method: "POST",
                body: formData
            })
                .then(response => response.json())
                .then(data => {
                    alert(data.message);
                    if (data.success) {
                        emailCodeCountdown = 60;
                        updateEmailCodeButton();
                        emailCodeTimer = setInterval(updateEmailCodeButton, 1000);
                    } else {
                        sendCodeButton.disabled = false;
                    }
                })
                .catch(() => {
                    alert("验证码发送失败，请稍后再试");
                    sendCodeButton.disabled = false;
                });
        });
    </script>
    """
    form_content = render_template_string(content, error=error)
    return render_page("注册 - 校园失物招领平台", form_content)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""

    if request.method == "POST":
        account = clean_text(request.form.get("account"), 100)
        password = clean_text(request.form.get("password"), 128)

        if not account:
            error = "账号不能为空"
        elif not password:
            error = "密码不能为空"
        else:
            connection = None
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT
                            id, username, password_hash, is_admin, status,
                            review_note, is_banned, banned_reason
                        FROM `user`
                        WHERE username = %s OR email = %s
                        """,
                        (account, account),
                    )
                    user = cursor.fetchone()

                if user and check_password_hash(user["password_hash"], password):
                    if user["status"] == "pending":
                        error = "账号正在审核中，请等待管理员通过"
                        write_login_log(account, "pending", "账号正在审核中", user["id"])
                    elif user["status"] == "rejected":
                        write_login_log(account, "rejected", "账号审核未通过", user["id"])
                        flash("账号审核未通过，请重新提交资料", "warning")
                        return redirect(url_for("resubmit_register", username=user["username"]))
                    elif user["status"] == "approved":
                        if int(user.get("is_banned") or 0) == 1:
                            write_login_log(account, "banned", "账号已被封禁", user["id"])
                            flash("账号已被封禁，无法登录", "error")
                            if user.get("banned_reason"):
                                flash(f"封禁原因：{user['banned_reason']}", "warning")
                            return redirect(url_for("login"))

                        session["user_id"] = user["id"]
                        session["username"] = user["username"]
                        session["is_admin"] = int(user["is_admin"])
                        write_login_log(user["username"], "success", "登录成功", user["id"])
                        flash("登录成功", "success")
                        return redirect(url_for("index"))
                    else:
                        error = "账号状态异常，请联系管理员"
                        write_login_log(account, "abnormal", "账号状态异常", user["id"])
                else:
                    error = "账号或密码错误"
                    write_login_log(account, "failed", "账号或密码错误", user["id"] if user else None)

                if error:
                    flash(error, "error")
            except Exception as exc:
                log_db_error(exc)
                error = system_error_message()
                flash(error, "error")
            finally:
                if connection:
                    connection.close()

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Welcome Back</p>
                <h1>登录账号</h1>
                <p>使用用户名或邮箱登录后，即可发布和管理自己的失物招领信息。</p>
            </div>

            <form class="register-form" method="post" action="{{ url_for('login') }}">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                <label>
                    账号
                    <input type="text" name="account" value="{{ request.form.get('account', '') }}" placeholder="请输入用户名或邮箱">
                </label>

                <label>
                    密码
                    <input type="password" name="password" placeholder="请输入密码">
                </label>

                <div class="form-extra-link">
                    <a href="{{ url_for('forgot_password') }}">忘记密码？</a>
                </div>

                <button class="btn btn-form" type="submit">登录</button>
            </form>
        </div>
    </section>
    """
    form_content = render_template_string(content, error=error)
    return render_page(
        "登录 - 校园失物招领平台",
        form_content,
    )


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    error = ""

    if request.method == "POST":
        username = clean_text(request.form.get("username"), 80)
        email = validate_email(request.form.get("email"))
        new_password = clean_text(request.form.get("new_password"), 128)
        confirm_password = clean_text(request.form.get("confirm_password"), 128)

        if not username or not email:
            error = "用户名或邮箱不正确"
        elif not new_password:
            error = "新密码不能为空"
        elif new_password != confirm_password:
            error = "两次输入的新密码不一致"
        else:
            connection = None
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT id, username, status
                        FROM `user`
                        WHERE username = %s AND email = %s
                        """,
                        (username, email),
                    )
                    user = cursor.fetchone()

                    if not user:
                        error = "用户名或邮箱不正确"
                    elif user["status"] != "approved":
                        error = "账号未通过审核，暂不能找回密码"
                    else:
                        cursor.execute(
                            """
                            UPDATE `user`
                            SET password_hash = %s
                            WHERE id = %s
                            """,
                            (generate_password_hash(new_password), user["id"]),
                        )
                        connection.commit()
                        write_operation_log(
                            "找回密码",
                            f"用户 {user['username']} 重置密码",
                            user_id=user["id"],
                            username=user["username"],
                        )
                        flash("密码重置成功，请登录", "success")
                        return redirect(url_for("login"))
            except Exception as exc:
                log_db_error(exc)
                error = system_error_message()
                flash(error, "error")
            finally:
                if connection:
                    connection.close()

        if error:
            flash(error, "error")

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Password Recovery</p>
                <h1>找回密码</h1>
                <p>请输入注册时使用的用户名和邮箱，通过校验后即可重置密码。</p>
            </div>

            <form class="register-form change-password-form" method="post" action="{{ url_for('forgot_password') }}">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                <label>
                    用户名
                    <input type="text" name="username" value="{{ request.form.get('username', '') }}" placeholder="请输入用户名">
                </label>

                <label>
                    邮箱
                    <input type="email" name="email" value="{{ request.form.get('email', '') }}" placeholder="请输入注册邮箱">
                </label>

                <label>
                    新密码
                    <input type="password" name="new_password" placeholder="请输入新密码">
                </label>

                <label>
                    确认新密码
                    <input type="password" name="confirm_password" placeholder="请再次输入新密码">
                </label>

                <button class="btn btn-form" type="submit">重置密码</button>
                <a class="reset-btn" href="{{ url_for('login') }}">返回登录</a>
            </form>
        </div>
    </section>
    """
    form_content = render_template_string(content, error=error)
    return render_page("找回密码 - 校园失物招领平台", form_content)


@app.route("/resubmit_register", methods=["GET", "POST"])
def resubmit_register():
    username = clean_text(request.args.get("username"), 80) or clean_text(request.form.get("username"), 80)
    error = ""
    user = None
    connection = None

    if not username:
        error = "用户不存在"
    else:
        try:
            connection = get_db_connection()
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, username, real_name, student_id, phone, email, status, review_note
                    FROM `user`
                    WHERE username = %s
                    """,
                    (username,),
                )
                user = cursor.fetchone()

                if not user:
                    error = "用户不存在"
                elif user["status"] != "rejected":
                    error = "当前账号不需要重新提交"
                elif request.method == "POST":
                    real_name = clean_text(request.form.get("real_name"), 80)
                    student_id = clean_text(request.form.get("student_id"), 50)
                    phone = validate_phone(request.form.get("phone"))
                    email = validate_email(request.form.get("email"))
                    student_card_file = request.files.get("student_card")

                    if not student_card_file or not student_card_file.filename:
                        error = "请上传学生证照片"
                    else:
                        student_card_path = save_uploaded_file(
                            student_card_file,
                            USER_CARD_FOLDER,
                            ALLOWED_USER_CARD_EXTENSIONS,
                            ALLOWED_USER_CARD_MIMES,
                            "uploads/user_cards",
                        )

                        cursor.execute(
                            """
                            UPDATE `user`
                            SET
                                real_name = %s,
                                student_id = %s,
                                phone = %s,
                                email = %s,
                                student_card = %s,
                                status = %s,
                                review_note = NULL
                            WHERE id = %s AND status = %s
                            """,
                            (
                                real_name,
                                student_id,
                                phone,
                                email,
                                student_card_path,
                                "pending",
                                user["id"],
                                "rejected",
                            ),
                        )
                        connection.commit()
                        write_operation_log(
                            "重新提交注册资料",
                            f"用户 {username} 重新提交注册审核资料",
                            user_id=user["id"],
                            username=username,
                        )
                        flash("资料已重新提交，请等待管理员审核", "success")
                        return redirect(url_for("login"))
        except Exception as exc:
            log_db_error(exc)
            error = system_error_message()
            flash(error, "error")
        finally:
            if connection:
                connection.close()

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Resubmit Application</p>
                <h1>重新提交资料</h1>
                <p>请根据管理员反馈补充或修改资料，重新提交后账号会回到待审核状态。</p>
                {% if user and user.review_note %}
                <div class="rejected-note">
                    <strong>拒绝原因</strong>
                    <span>{{ user.review_note }}</span>
                </div>
                {% endif %}
            </div>

            <form class="register-form" method="post" action="{{ url_for('resubmit_register') }}" enctype="multipart/form-data">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                {% if user and user.status == "rejected" %}
                <label>
                    用户名
                    <input type="text" name="username" value="{{ user.username }}" readonly>
                </label>

                <label>
                    真实姓名
                    <input type="text" name="real_name" value="{{ request.form.get('real_name', user.real_name or '') }}" placeholder="请输入真实姓名">
                </label>

                <label>
                    学号
                    <input type="text" name="student_id" value="{{ request.form.get('student_id', user.student_id or '') }}" placeholder="请输入学号">
                </label>

                <label>
                    手机号
                    <input type="text" name="phone" value="{{ request.form.get('phone', user.phone or '') }}" placeholder="请输入手机号">
                </label>

                <label>
                    邮箱
                    <input type="email" name="email" value="{{ request.form.get('email', user.email or '') }}" placeholder="请输入邮箱">
                </label>

                <label>
                    学生证照片
                    <input type="file" name="student_card" accept=".png,.jpg,.jpeg">
                </label>

                <button class="btn btn-form" type="submit">重新提交</button>
                {% endif %}
            </form>
        </div>
    </section>
    """
    form_content = render_template_string(content, error=error, user=user)
    return render_page("重新提交资料 - 校园失物招领平台", form_content)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("请先登录后访问个人中心", "warning")
        return redirect(url_for("login"))

    error = ""
    message = ""
    user = None
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            if request.method == "POST":
                phone = validate_phone(request.form.get("phone"))
                email = validate_email(request.form.get("email"))
                cursor.execute(
                    """
                    UPDATE `user`
                    SET phone = %s, email = %s
                    WHERE id = %s
                    """,
                    (phone, email, session["user_id"]),
                )
                connection.commit()
                write_operation_log("修改个人资料", "用户修改手机号或邮箱")
                flash("个人资料修改成功", "success")

            cursor.execute(
                """
                SELECT
                    id, username, real_name, student_id,
                    phone, email, avatar, is_admin, status, created_at
                FROM `user`
                WHERE id = %s
                """,
                (session["user_id"],),
            )
            user = cursor.fetchone()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="profile-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Profile</p>
                <h1>个人中心</h1>
                <p>查看账号资料，并维护你的联系方式。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            {% if user %}
            <div class="profile-card">
                <div class="profile-info">
                    <div class="avatar-profile-block">
                        {% if user.avatar %}
                        <img class="avatar-large" src="{{ url_for('static', filename=user.avatar) }}" alt="{{ user.username }}">
                        {% else %}
                        <span class="avatar-large avatar-placeholder">{{ user.username[:1] if user.username else "用" }}</span>
                        {% endif %}
                        <form class="avatar-upload-form" method="post" action="{{ url_for('upload_avatar') }}" enctype="multipart/form-data">
                            <label>
                                上传头像
                                <input type="file" name="avatar" accept=".png,.jpg,.jpeg,.gif">
                            </label>
                            <button class="btn btn-form" type="submit">更新头像</button>
                        </form>
                    </div>
                    <div>
                        <span>用户名</span>
                        <strong>{{ user.username }}</strong>
                    </div>
                    <div>
                        <span>真实姓名</span>
                        <strong>{{ user.real_name or "未填写" }}</strong>
                    </div>
                    <div>
                        <span>学号</span>
                        <strong>{{ user.student_id or "未填写" }}</strong>
                    </div>
                    <div>
                        <span>手机号</span>
                        <strong>{{ user.phone or "未填写" }}</strong>
                    </div>
                    <div>
                        <span>邮箱</span>
                        <strong>{{ user.email or "未填写" }}</strong>
                    </div>
                    <div>
                        <span>账号审核状态</span>
                        <strong>{{ status_map.get(user.status, user.status or "未填写") }}</strong>
                    </div>
                    <div>
                        <span>是否管理员</span>
                        <strong>{{ "是" if user.is_admin == 1 else "否" }}</strong>
                    </div>
                    <div>
                        <span>注册时间</span>
                        <strong>{{ user.created_at }}</strong>
                    </div>
                </div>

                <form class="profile-form" method="post" action="{{ url_for('profile') }}">
                    <label>
                        手机号
                        <input type="text" name="phone" value="{{ request.form.get('phone', user.phone or '') }}" placeholder="请输入手机号">
                    </label>
                    <label>
                        邮箱
                        <input type="email" name="email" value="{{ request.form.get('email', user.email or '') }}" placeholder="请输入邮箱">
                    </label>
                    <div class="profile-actions">
                        <button class="btn btn-form profile-submit" type="submit">保存资料</button>
                        <a class="reset-btn" href="{{ url_for('change_password') }}">修改密码</a>
                    </div>
                </form>
            </div>
            {% endif %}
        </div>
    </section>
    """
    status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "rejected": "已拒绝",
    }
    page_content = render_template_string(
        content,
        error=error,
        status_map=status_map,
        user=user,
    )
    return render_page(
        "个人中心 - 校园失物招领平台",
        page_content,
    )


@app.route("/upload_avatar", methods=["POST"])
def upload_avatar():
    if "user_id" not in session:
        flash("请先登录后上传头像", "warning")
        return redirect(url_for("login"))

    avatar_file = request.files.get("avatar")
    if not avatar_file or not avatar_file.filename:
        flash("请选择头像图片", "warning")
        return redirect(url_for("profile"))

    connection = None
    try:
        avatar_path = save_uploaded_file(
            avatar_file,
            AVATAR_FOLDER,
            ALLOWED_AVATAR_EXTENSIONS,
            ALLOWED_AVATAR_MIMES,
            "uploads/avatars",
        )

        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE `user`
                SET avatar = %s
                WHERE id = %s
                """,
                (avatar_path, session["user_id"]),
            )
            connection.commit()

        write_operation_log("更新头像", "用户更新个人头像")
        flash("头像更新成功", "success")
    except ValueError:
        flash("头像格式不支持", "error")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("profile"))


@app.route("/notifications")
def notifications():
    if "user_id" not in session:
        flash("请先登录后查看通知", "warning")
        return redirect(url_for("login"))

    error = ""
    notifications_list = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, content, is_read, created_at
                FROM notification
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (session["user_id"],),
            )
            notifications_list = cursor.fetchall()
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Notifications</p>
                <h1>通知</h1>
                <p>查看系统发送给你的审核和管理通知。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            <div class="notification-actions">
                <form class="inline-form" method="post" action="{{ url_for('read_all_notifications') }}">
                    <button class="admin-btn make-admin-btn mark-read" type="submit">一键全部已读</button>
                </form>
            </div>

            {% if notifications_list %}
            <div class="notification-list">
                {% for notification in notifications_list %}
                <article class="notification-card {{ 'read' if notification.is_read else 'unread' }}">
                    <div class="notification-main">
                        <div class="notification-title">
                            {{ notification.title }}
                            {% if not notification.is_read %}
                            <span class="status-tag status-pending">未读</span>
                            {% else %}
                            <span class="status-tag status-resolved">已读</span>
                            {% endif %}
                        </div>
                        <p>{{ notification.content }}</p>
                        <div class="notification-time">{{ notification.created_at }}</div>
                    </div>
                    {% if not notification.is_read %}
                    <form class="inline-form" method="post" action="{{ url_for('read_notification', notification_id=notification.id) }}">
                        <button class="admin-btn approve-btn mark-read" type="submit">标记已读</button>
                    </form>
                    {% endif %}
                </article>
                {% endfor %}
            </div>
            {% elif not error %}
            <div class="empty-state">暂无通知</div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        notifications_list=notifications_list,
    )
    return render_page("通知 - 校园失物招领平台", page_content)


@app.route("/notification/<int:notification_id>/read", methods=["POST"])
def read_notification(notification_id):
    if "user_id" not in session:
        flash("请先登录后查看通知", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE notification
                SET is_read = 1
                WHERE id = %s AND user_id = %s
                """,
                (notification_id, session["user_id"]),
            )
            connection.commit()
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("notifications"))


@app.route("/notifications/read_all", methods=["POST"])
def read_all_notifications():
    if "user_id" not in session:
        flash("请先登录后查看通知", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE notification
                SET is_read = 1
                WHERE user_id = %s
                """,
                (session["user_id"],),
            )
            connection.commit()
        flash("已全部标记为已读", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("notifications"))


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        flash("请先登录后修改密码", "warning")
        return redirect(url_for("login"))

    error = ""

    if request.method == "POST":
        old_password = clean_text(request.form.get("old_password"), 128)
        new_password = clean_text(request.form.get("new_password"), 128)
        confirm_password = clean_text(request.form.get("confirm_password"), 128)

        if not old_password:
            error = "原密码不能为空"
        elif not new_password:
            error = "新密码不能为空"
        elif new_password != confirm_password:
            error = "两次输入的新密码不一致"
        else:
            connection = None
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT password_hash FROM `user` WHERE id = %s",
                        (session["user_id"],),
                    )
                    user = cursor.fetchone()

                    if not user or not check_password_hash(user["password_hash"], old_password):
                        error = "原密码错误"
                    else:
                        new_password_hash = generate_password_hash(new_password)
                        cursor.execute(
                            "UPDATE `user` SET password_hash = %s WHERE id = %s",
                            (new_password_hash, session["user_id"]),
                        )
                        connection.commit()
                        write_operation_log("修改密码", "用户修改密码")
                        session.clear()
                        flash("密码修改成功，请重新登录", "success")
                        return redirect(url_for("login"))
            except Exception as exc:
                log_db_error(exc)
                error = system_error_message()
                flash(error, "error")
            finally:
                if connection:
                    connection.close()

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Account Security</p>
                <h1>修改密码</h1>
                <p>请先输入原密码，再设置新的登录密码。</p>
            </div>

            <form class="register-form change-password-form" method="post" action="{{ url_for('change_password') }}">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                <label>
                    原密码
                    <input type="password" name="old_password" placeholder="请输入原密码">
                </label>

                <label>
                    新密码
                    <input type="password" name="new_password" placeholder="请输入新密码">
                </label>

                <label>
                    确认新密码
                    <input type="password" name="confirm_password" placeholder="请再次输入新密码">
                </label>

                <button class="btn btn-form" type="submit">确认修改</button>
            </form>
        </div>
    </section>
    """
    form_content = render_template_string(content, error=error)
    return render_page("修改密码 - 校园失物招领平台", form_content)


@app.route("/publish", methods=["GET", "POST"])
def publish():
    if "user_id" not in session:
        flash("请先登录后发布信息", "warning")
        return redirect(url_for("login"))

    error = ""
    pickup_locations = get_active_pickup_locations()

    if request.method == "POST":
        banned, banned_reason = is_current_user_banned()
        if banned:
            flash("账号已被封禁，不能发布信息", "error")
            if banned_reason:
                flash(f"封禁原因：{banned_reason}", "warning")
            session.clear()
            return redirect(url_for("login"))

        limit_ok, limit_message = check_publish_limit(session["user_id"])
        if not limit_ok:
            if limit_message != system_error_message():
                write_operation_log("发布频率限制", "用户发布过于频繁")
            flash(limit_message, "warning" if limit_message != system_error_message() else "error")
            return redirect(url_for("publish"))

        title = clean_text(request.form.get("title"), 120)
        description = clean_long_text(request.form.get("description"), 2000)
        category = validate_choice(request.form.get("category"), CATEGORIES, "")
        item_type = validate_choice(request.form.get("item_type"), ITEM_TYPES, "")
        location = clean_text(request.form.get("location"), 120)
        event_time = clean_text(request.form.get("event_time"), 40).replace("T", " ") or None
        contact = clean_text(request.form.get("contact"), 120)
        pickup_location_id = None
        image_file = request.files.get("image")
        image_path = ""

        if not title:
            error = "标题不能为空"
        elif not description:
            error = "描述不能为空"
        elif not item_type:
            error = "类型不能为空"
        elif item_type not in ITEM_TYPES:
            error = "类型选择不正确"
        else:
            connection = None
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    if item_type == "found":
                        pickup_location_id = get_valid_pickup_location_id(
                            cursor,
                            request.form.get("pickup_location_id"),
                        )

                    if image_file and image_file.filename:
                        image_path = save_uploaded_file(
                            image_file,
                            UPLOAD_FOLDER,
                            ALLOWED_IMAGE_EXTENSIONS,
                            ALLOWED_IMAGE_MIMES,
                            "uploads",
                        )

                    if not error:
                        cursor.execute(
                            """
                            INSERT INTO item
                                (
                                    title, description, category, item_type,
                                    location, event_time, image, contact,
                                    pickup_location_id, user_id
                                )
                            VALUES
                                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                title,
                                description,
                                category,
                                item_type,
                                location,
                                event_time,
                                image_path,
                                contact,
                                pickup_location_id,
                                session["user_id"],
                            ),
                        )
                        connection.commit()
                    write_operation_log("发布信息", f"发布标题：{title}")
                    flash("发布成功，等待管理员审核", "success")
                    return redirect(url_for("index"))
            except Exception as exc:
                log_db_error(exc)
                error = system_error_message()
                flash(error, "error")
            finally:
                if connection:
                    connection.close()

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Publish Information</p>
                <h1>发布信息</h1>
                <p>请选择失物或招领类型，填写清楚物品特征、地点和联系方式，提交后将等待管理员审核。</p>
            </div>

            <form class="register-form" method="post" action="{{ url_for('publish') }}" enctype="multipart/form-data">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                <label>
                    标题
                    <input type="text" name="title" value="{{ request.form.get('title', '') }}" placeholder="例如：丢失黑色钱包">
                </label>

                <label>
                    类型
                    <select name="item_type">
                        <option value="">请选择类型</option>
                        <option value="lost" {% if request.form.get('item_type') == 'lost' %}selected{% endif %}>我丢失了物品</option>
                        <option value="found" {% if request.form.get('item_type') == 'found' %}selected{% endif %}>我捡到了物品</option>
                    </select>
                </label>

                <label>
                    分类
                    <select name="category">
                        {% set selected_category = request.form.get('category', '') %}
                        <option value="">请选择分类</option>
                        <option value="校园卡" {% if selected_category == '校园卡' %}selected{% endif %}>校园卡</option>
                        <option value="手机数码" {% if selected_category == '手机数码' %}selected{% endif %}>手机数码</option>
                        <option value="钥匙" {% if selected_category == '钥匙' %}selected{% endif %}>钥匙</option>
                        <option value="钱包" {% if selected_category == '钱包' %}selected{% endif %}>钱包</option>
                        <option value="书籍资料" {% if selected_category == '书籍资料' %}selected{% endif %}>书籍资料</option>
                        <option value="衣物" {% if selected_category == '衣物' %}selected{% endif %}>衣物</option>
                        <option value="其他" {% if selected_category == '其他' %}selected{% endif %}>其他</option>
                    </select>
                </label>

                <label>
                    描述
                    <textarea name="description" rows="5" placeholder="请描述物品外观、特征、丢失或拾到经过">{{ request.form.get('description', '') }}</textarea>
                </label>

                <label>
                    地点
                    <input type="text" name="location" value="{{ request.form.get('location', '') }}" placeholder="例如：图书馆二楼">
                </label>

                <label>
                    丢失或拾到时间
                    <input type="datetime-local" name="event_time" value="{{ request.form.get('event_time', '') }}">
                </label>

                <label>
                    联系方式
                    <input type="text" name="contact" value="{{ request.form.get('contact', '') }}" placeholder="手机号、邮箱或其他联系方式">
                </label>

                <label>
                    领取地点（招领信息可选）
                    <select name="pickup_location_id">
                        <option value="">不选择领取地点</option>
                        {% for pickup_location in pickup_locations %}
                        <option value="{{ pickup_location.id }}" {% if request.form.get('pickup_location_id') == pickup_location.id|string %}selected{% endif %}>
                            {{ pickup_location.name }}{% if pickup_location.address %} - {{ pickup_location.address }}{% endif %}
                        </option>
                        {% endfor %}
                    </select>
                </label>

                <label>
                    图片
                    <input type="file" name="image" accept=".png,.jpg,.jpeg,.gif">
                </label>

                <button class="btn btn-form" type="submit">提交发布</button>
            </form>
        </div>
    </section>
    """
    form_content = render_template_string(
        content,
        error=error,
        pickup_locations=pickup_locations,
    )
    return render_page("发布信息 - 校园失物招领平台", form_content)


@app.route("/my_items")
def my_items():
    if "user_id" not in session:
        flash("请先登录后查看我的发布", "warning")
        return redirect(url_for("login"))

    error = ""
    message = ""
    page = request.args.get("page", 1)
    items = []
    page_info = get_page_info(page, 6, 0)
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM item
                WHERE user_id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (session["user_id"],),
            )
            total = (cursor.fetchone() or {}).get("total") or 0
            page_info = get_page_info(page, 6, total)

            cursor.execute(
                """
                SELECT
                    id, title, description, category, item_type,
                    location, event_time, image, contact, status, created_at
                FROM item
                WHERE user_id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                (session["user_id"], page_info["per_page"], page_info["offset"]),
            )
            items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "resolved": "已完成",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">My Publications</p>
                <h1>我的发布</h1>
                <p>这里仅展示你自己发布过的失物和招领信息，最新发布的内容会排在最前面。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not items %}
            <div class="empty-state">暂无发布记录</div>
            {% else %}
            <div class="item-grid">
                {% for item in items %}
                <article class="item-card">
                    <div class="item-image">
                        {% if item.image %}
                        <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                        {% else %}
                        <span>暂无图片</span>
                        {% endif %}
                    </div>

                    <div class="item-body">
                        <div class="item-topline">
                            <span class="type-tag">{{ type_map.get(item.item_type, item.item_type) }}</span>
                            <span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span>
                        </div>

                        <h2>{{ item.title }}</h2>
                        <dl class="item-meta">
                            <div>
                                <dt>分类</dt>
                                <dd>{{ item.category or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>地点</dt>
                                <dd>{{ item.location or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>时间</dt>
                                <dd>{{ item.event_time or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>联系方式</dt>
                                <dd>{{ item.contact or "未填写" }}</dd>
                            </div>
                            <div>
                                <dt>发布时间</dt>
                                <dd>{{ item.created_at }}</dd>
                            </div>
                        </dl>
                        <div class="owner-actions">
                            <a class="owner-btn edit-owner-btn" href="{{ url_for('edit_item', item_id=item.id) }}">修改</a>
                            <form class="inline-form" method="post" action="{{ url_for('user_delete_item', item_id=item.id) }}">
                                <button class="owner-btn delete-owner-btn" type="submit" onclick="return confirm('确定要删除这条信息吗？')">删除</button>
                            </form>
                            {% if item.status != "resolved" %}
                            <form class="inline-form" method="post" action="{{ url_for('resolve_item', item_id=item.id) }}">
                                <button class="owner-btn resolve-owner-btn" type="submit">标记已完成</button>
                            </form>
                            {% endif %}
                        </div>
                    </div>
                </article>
                {% endfor %}
            </div>
            {% endif %}

            {% if page_info.total_pages > 1 %}
            <nav class="pagination">
                {% if page_info.page > 1 %}
                <a href="{{ url_for('my_items', page=page_info.page - 1) }}">上一页</a>
                {% else %}
                <span class="disabled">上一页</span>
                {% endif %}

                {% for page_number in page_numbers %}
                    {% if page_number == page_info.page %}
                    <span class="active">{{ page_number }}</span>
                    {% else %}
                    <a href="{{ url_for('my_items', page=page_number) }}">{{ page_number }}</a>
                    {% endif %}
                {% endfor %}

                {% if page_info.page < page_info.total_pages %}
                <a href="{{ url_for('my_items', page=page_info.page + 1) }}">下一页</a>
                {% else %}
                <span class="disabled">下一页</span>
                {% endif %}
            </nav>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        items=items,
        page_info=page_info,
        page_numbers=range(1, page_info["total_pages"] + 1),
        status_map=status_map,
        type_map=type_map,
    )
    return render_page("我的发布 - 校园失物招领平台", page_content)


@app.route("/edit_item/<int:item_id>", methods=["GET", "POST"])
def edit_item(item_id):
    if "user_id" not in session:
        flash("请先登录后修改信息", "warning")
        return redirect(url_for("login"))

    error = ""
    item = None
    pickup_locations = get_active_pickup_locations()
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id, title, description, category, item_type,
                    location, event_time, image, contact,
                    pickup_location_id, user_id
                FROM item
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item or item["user_id"] != session["user_id"]:
                abort(403)

            if request.method == "POST":
                title = clean_text(request.form.get("title"), 120)
                description = clean_long_text(request.form.get("description"), 2000)
                category = validate_choice(request.form.get("category"), CATEGORIES, "")
                item_type = validate_choice(request.form.get("item_type"), ITEM_TYPES, "")
                location = clean_text(request.form.get("location"), 120)
                event_time = clean_text(request.form.get("event_time"), 40).replace("T", " ") or None
                contact = clean_text(request.form.get("contact"), 120)
                image_file = request.files.get("image")
                image_path = item.get("image") or ""
                pickup_location_id = None

                if not title:
                    error = "标题不能为空"
                elif not description:
                    error = "描述不能为空"
                elif not item_type:
                    error = "类型不能为空"
                elif item_type not in ITEM_TYPES:
                    error = "类型选择不正确"
                else:
                    if item_type == "found":
                        pickup_location_id = get_valid_pickup_location_id(
                            cursor,
                            request.form.get("pickup_location_id"),
                        )

                    if image_file and image_file.filename:
                        image_path = save_uploaded_file(
                            image_file,
                            UPLOAD_FOLDER,
                            ALLOWED_IMAGE_EXTENSIONS,
                            ALLOWED_IMAGE_MIMES,
                            "uploads",
                        )

                    if not error:
                        cursor.execute(
                            """
                            UPDATE item
                            SET
                                title = %s,
                                description = %s,
                                category = %s,
                                item_type = %s,
                                location = %s,
                                event_time = %s,
                                image = %s,
                                contact = %s,
                                pickup_location_id = %s,
                                status = 'pending'
                            WHERE
                                id = %s
                                AND user_id = %s
                                AND (is_deleted = 0 OR is_deleted IS NULL)
                            """,
                            (
                                title,
                                description,
                                category,
                                item_type,
                                location,
                                event_time,
                                image_path,
                                contact,
                                pickup_location_id,
                                item_id,
                                session["user_id"],
                            ),
                        )
                        connection.commit()
                        write_operation_log("修改信息", f"修改信息 ID：{item_id}，标题：{title}")
                        flash("修改成功，等待管理员重新审核", "success")
                        return redirect(url_for("my_items"))
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    if error and not item:
        return render_page(
            "修改失败 - 校园失物招领平台",
            f'<section class="items-section"><div class="container"><p class="notice notice-error">{error}</p></div></section>',
        )

    selected_item_type = validate_choice(request.form.get("item_type", item.get("item_type", "") if item else ""), ITEM_TYPES, "")
    selected_category = validate_choice(request.form.get("category", item.get("category", "") if item else ""), CATEGORIES, "")
    event_time_value = request.form.get("event_time", format_datetime_local(item.get("event_time")) if item else "")

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Edit Publication</p>
                <h1>修改信息</h1>
                <p>修改后信息会重新变为待审核状态，需要管理员再次审核通过后才会公开显示。</p>
            </div>

            <form class="register-form" method="post" action="{{ url_for('edit_item', item_id=item.id) }}" enctype="multipart/form-data">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                <label>
                    标题
                    <input type="text" name="title" value="{{ request.form.get('title', item.title) }}" placeholder="请输入标题">
                </label>

                <label>
                    类型
                    <select name="item_type">
                        <option value="">请选择类型</option>
                        <option value="lost" {% if selected_item_type == 'lost' %}selected{% endif %}>我丢失了物品</option>
                        <option value="found" {% if selected_item_type == 'found' %}selected{% endif %}>我捡到了物品</option>
                    </select>
                </label>

                <label>
                    分类
                    <select name="category">
                        <option value="">请选择分类</option>
                        <option value="校园卡" {% if selected_category == '校园卡' %}selected{% endif %}>校园卡</option>
                        <option value="手机数码" {% if selected_category == '手机数码' %}selected{% endif %}>手机数码</option>
                        <option value="钥匙" {% if selected_category == '钥匙' %}selected{% endif %}>钥匙</option>
                        <option value="钱包" {% if selected_category == '钱包' %}selected{% endif %}>钱包</option>
                        <option value="书籍资料" {% if selected_category == '书籍资料' %}selected{% endif %}>书籍资料</option>
                        <option value="衣物" {% if selected_category == '衣物' %}selected{% endif %}>衣物</option>
                        <option value="其他" {% if selected_category == '其他' %}selected{% endif %}>其他</option>
                    </select>
                </label>

                <label>
                    描述
                    <textarea name="description" rows="5" placeholder="请输入描述">{{ request.form.get('description', item.description) }}</textarea>
                </label>

                <label>
                    地点
                    <input type="text" name="location" value="{{ request.form.get('location', item.location or '') }}" placeholder="请输入地点">
                </label>

                <label>
                    丢失或拾到时间
                    <input type="datetime-local" name="event_time" value="{{ event_time_value }}">
                </label>

                <label>
                    联系方式
                    <input type="text" name="contact" value="{{ request.form.get('contact', item.contact or '') }}" placeholder="请输入联系方式">
                </label>

                <label>
                    领取地点（招领信息可选）
                    <select name="pickup_location_id">
                        <option value="">不选择领取地点</option>
                        {% set selected_location = request.form.get('pickup_location_id', item.pickup_location_id|string if item.pickup_location_id else '') %}
                        {% for pickup_location in pickup_locations %}
                        <option value="{{ pickup_location.id }}" {% if selected_location == pickup_location.id|string %}selected{% endif %}>
                            {{ pickup_location.name }}{% if pickup_location.address %} - {{ pickup_location.address }}{% endif %}
                        </option>
                        {% endfor %}
                    </select>
                </label>

                <label>
                    图片
                    <input type="file" name="image" accept=".png,.jpg,.jpeg,.gif">
                </label>

                <button class="btn btn-form" type="submit">保存修改</button>
            </form>
        </div>
    </section>
    """
    form_content = render_template_string(
        content,
        error=error,
        event_time_value=event_time_value,
        item=item,
        pickup_locations=pickup_locations,
        selected_category=selected_category,
        selected_item_type=selected_item_type,
    )
    return render_page("修改信息 - 校园失物招领平台", form_content)


@app.route("/delete_item/<int:item_id>", methods=["POST"])
def user_delete_item(item_id):
    if "user_id" not in session:
        flash("请先登录后删除信息", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id
                FROM item
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item or item["user_id"] != session["user_id"]:
                abort(403)

            cursor.execute(
                """
                UPDATE item
                SET is_deleted = 1, deleted_at = NOW(), deleted_by = %s
                WHERE
                    id = %s
                    AND user_id = %s
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (session["user_id"], item_id, session["user_id"]),
            )
            connection.commit()
        write_operation_log("删除信息", f"删除自己的信息 ID：{item_id}")
        flash("删除成功", "success")
        return redirect(url_for("my_items"))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return render_page(
            "删除失败 - 校园失物招领平台",
            '<section class="items-section"><div class="container"><p class="notice notice-error">删除失败，请稍后再试</p></div></section>',
        )
    finally:
        if connection:
            connection.close()


@app.route("/resolve_item/<int:item_id>", methods=["POST"])
def resolve_item(item_id):
    if "user_id" not in session:
        flash("请先登录后操作信息", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id
                FROM item
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item or item["user_id"] != session["user_id"]:
                abort(403)

            cursor.execute(
                """
                UPDATE item
                SET status = 'resolved'
                WHERE
                    id = %s
                    AND user_id = %s
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id, session["user_id"]),
            )
            connection.commit()
        write_operation_log("标记完成", f"标记信息 ID：{item_id} 为已完成")
        flash("已标记为完成", "success")
        return redirect(url_for("my_items"))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return render_page(
            "操作失败 - 校园失物招领平台",
            '<section class="items-section"><div class="container"><p class="notice notice-error">操作失败，请稍后再试</p></div></section>',
        )
    finally:
        if connection:
            connection.close()


@app.route("/admin")
def admin():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    stats = {
        "user_total": 0,
        "admin_total": 0,
        "banned_user_total": 0,
        "pending_user_total": 0,
        "announcement_total": 0,
        "pickup_location_total": 0,
        "item_total": 0,
        "today_item_total": 0,
        "lost_total": 0,
        "found_total": 0,
        "pending_total": 0,
        "approved_total": 0,
        "resolved_total": 0,
        "deleted_item_total": 0,
        "pending_report_total": 0,
        "views_total": 0,
    }
    latest_items = []
    popular_items = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS user_total,
                    SUM(CASE WHEN is_admin = 1 THEN 1 ELSE 0 END) AS admin_total,
                    SUM(CASE WHEN is_banned = 1 THEN 1 ELSE 0 END) AS banned_user_total,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_user_total
                FROM `user`
                """
            )
            user_row = cursor.fetchone() or {}

            cursor.execute("SELECT COUNT(*) AS announcement_total FROM announcement")
            announcement_row = cursor.fetchone() or {}

            cursor.execute("SELECT COUNT(*) AS pickup_location_total FROM pickup_location")
            pickup_location_row = cursor.fetchone() or {}

            cursor.execute(
                """
                SELECT
                    COUNT(*) AS item_total,
                    SUM(CASE WHEN item_type = 'lost' THEN 1 ELSE 0 END) AS lost_total,
                    SUM(CASE WHEN item_type = 'found' THEN 1 ELSE 0 END) AS found_total,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_total,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_total,
                    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved_total,
                    SUM(views) AS views_total
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                """
            )
            item_row = cursor.fetchone() or {}

            cursor.execute(
                """
                SELECT COUNT(*) AS today_item_total
                FROM item
                WHERE
                    DATE(created_at) = CURDATE()
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """
            )
            today_item_row = cursor.fetchone() or {}

            cursor.execute(
                """
                SELECT COUNT(*) AS deleted_item_total
                FROM item
                WHERE is_deleted = 1
                """
            )
            deleted_row = cursor.fetchone() or {}

            cursor.execute(
                """
                SELECT COUNT(*) AS pending_report_total
                FROM report
                JOIN item ON report.item_id = item.id
                WHERE
                    report.status = 'pending'
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                """
            )
            report_row = cursor.fetchone() or {}

            stats = {
                "user_total": user_row.get("user_total") or 0,
                "admin_total": user_row.get("admin_total") or 0,
                "banned_user_total": user_row.get("banned_user_total") or 0,
                "pending_user_total": user_row.get("pending_user_total") or 0,
                "announcement_total": announcement_row.get("announcement_total") or 0,
                "pickup_location_total": pickup_location_row.get("pickup_location_total") or 0,
                "item_total": item_row.get("item_total") or 0,
                "today_item_total": today_item_row.get("today_item_total") or 0,
                "lost_total": item_row.get("lost_total") or 0,
                "found_total": item_row.get("found_total") or 0,
                "pending_total": item_row.get("pending_total") or 0,
                "approved_total": item_row.get("approved_total") or 0,
                "resolved_total": item_row.get("resolved_total") or 0,
                "deleted_item_total": deleted_row.get("deleted_item_total") or 0,
                "pending_report_total": report_row.get("pending_report_total") or 0,
                "views_total": item_row.get("views_total") or 0,
            }

            cursor.execute(
                """
                SELECT
                    item.id, item.title, item.item_type, item.status,
                    item.created_at, `user`.username
                FROM item
                JOIN `user` ON item.user_id = `user`.id
                WHERE item.is_deleted = 0 OR item.is_deleted IS NULL
                ORDER BY item.created_at DESC
                LIMIT 5
                """
            )
            latest_items = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    id, title, item_type, views, status, created_at
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                ORDER BY views DESC, created_at DESC
                LIMIT 5
                """
            )
            popular_items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "resolved": "已完成",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Admin Dashboard</p>
                <h1>后台管理</h1>
                <p>查看用户、发布信息、审核状态和浏览量概况。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            <div class="admin-stats">
                <div class="admin-stat-card stat-card">
                    <span>用户总数</span>
                    <strong>{{ stats.user_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>管理员数量</span>
                    <strong>{{ stats.admin_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>已封禁用户</span>
                    <strong>{{ stats.banned_user_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>待审核用户</span>
                    <strong>{{ stats.pending_user_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>公告数量</span>
                    <strong>{{ stats.announcement_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>领取地点数量</span>
                    <strong>{{ stats.pickup_location_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>信息总数</span>
                    <strong>{{ stats.item_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>今日发布数量</span>
                    <strong>{{ stats.today_item_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>失物数量</span>
                    <strong>{{ stats.lost_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>招领数量</span>
                    <strong>{{ stats.found_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>待审核数量</span>
                    <strong>{{ stats.pending_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>已通过数量</span>
                    <strong>{{ stats.approved_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>已完成数量</span>
                    <strong>{{ stats.resolved_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>已删除信息</span>
                    <strong>{{ stats.deleted_item_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>待处理举报</span>
                    <strong>{{ stats.pending_report_total }}</strong>
                </div>
                <div class="admin-stat-card stat-card">
                    <span>浏览量总数</span>
                    <strong>{{ stats.views_total }}</strong>
                </div>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry" href="{{ url_for('admin_items') }}">信息审核管理</a>
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin_users') }}">用户管理</a>
                <a class="btn btn-form admin-entry export-btn" href="{{ url_for('export_items') }}">导出失物招领数据</a>
                <a class="btn btn-form admin-entry statistics-btn" href="{{ url_for('admin_statistics') }}">分类统计</a>
                <a class="btn btn-form admin-entry review-btn" href="{{ url_for('user_reviews') }}">注册审核</a>
                <a class="btn btn-form admin-entry claim-admin-entry" href="{{ url_for('admin_claims') }}">认领申请管理</a>
                <a class="btn btn-form admin-entry report-admin-entry" href="{{ url_for('admin_reports') }}">举报管理</a>
                <a class="btn btn-form admin-entry restore-btn" href="{{ url_for('admin_deleted_items') }}">已删除信息</a>
                <a class="btn btn-form admin-entry log-entry" href="{{ url_for('admin_logs') }}">系统日志</a>
                <a class="btn btn-form admin-entry announcement-admin-entry" href="{{ url_for('admin_announcements') }}">公告管理</a>
                <a class="btn btn-form admin-entry pickup-admin-entry" href="{{ url_for('admin_pickup_locations') }}">领取地点管理</a>
            </div>

            <div class="admin-panels">
                <section class="admin-section">
                    <div class="section-heading compact-heading">
                        <h2>最新发布记录</h2>
                    </div>
                    {% if latest_items %}
                    <div class="admin-table-wrap">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>标题</th>
                                    <th>类型</th>
                                    <th>状态</th>
                                    <th>发布人</th>
                                    <th>发布时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for item in latest_items %}
                                <tr>
                                    <td>{{ item.title }}</td>
                                    <td>{{ type_map.get(item.item_type, item.item_type) }}</td>
                                    <td><span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span></td>
                                    <td>{{ item.username }}</td>
                                    <td>{{ item.created_at }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="empty-state">暂无发布记录</div>
                    {% endif %}
                </section>

                <section class="admin-section">
                    <div class="section-heading compact-heading">
                        <h2>热门物品排行</h2>
                    </div>
                    {% if popular_items %}
                    <div class="admin-table-wrap">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>标题</th>
                                    <th>类型</th>
                                    <th>浏览量</th>
                                    <th>状态</th>
                                    <th>发布时间</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for item in popular_items %}
                                <tr>
                                    <td>{{ item.title }}</td>
                                    <td>{{ type_map.get(item.item_type, item.item_type) }}</td>
                                    <td>{{ item.views or 0 }}</td>
                                    <td><span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span></td>
                                    <td>{{ item.created_at }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div class="empty-state">暂无热门物品</div>
                    {% endif %}
                </section>
            </div>
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        latest_items=latest_items,
        popular_items=popular_items,
        stats=stats,
        status_map=status_map,
        type_map=type_map,
    )
    return render_page("后台管理 - 校园失物招领平台", page_content)


@app.route("/admin/items")
def admin_items():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    message = ""
    page = request.args.get("page", 1)
    items = []
    page_info = get_page_info(page, 10, 0)
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                """
            )
            total = (cursor.fetchone() or {}).get("total") or 0
            page_info = get_page_info(page, 10, total)

            cursor.execute(
                """
                SELECT
                    item.id, item.title, item.category, item.item_type,
                    item.location, item.image, item.contact, item.status,
                    item.created_at, `user`.username
                FROM item
                JOIN `user` ON item.user_id = `user`.id
                WHERE item.is_deleted = 0 OR item.is_deleted IS NULL
                ORDER BY item.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (page_info["per_page"], page_info["offset"]),
            )
            items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "resolved": "已完成",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Review Items</p>
                <h1>信息审核</h1>
                <p>审核待处理的失物和招领信息，也可以删除不合适的信息。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            {% if not error and not items %}
            <div class="empty-state">暂无发布信息</div>
            {% elif items %}
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>图片</th>
                            <th>标题</th>
                            <th>类型</th>
                            <th>分类</th>
                            <th>地点</th>
                            <th>联系方式</th>
                            <th>状态</th>
                            <th>发布人</th>
                            <th>发布时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in items %}
                        <tr>
                            <td>
                                <div class="admin-thumb">
                                    {% if item.image %}
                                    <img src="{{ url_for('static', filename=item.image) }}" alt="{{ item.title }}">
                                    {% else %}
                                    <span>暂无图片</span>
                                    {% endif %}
                                </div>
                            </td>
                            <td>{{ item.title }}</td>
                            <td>{{ type_map.get(item.item_type, item.item_type) }}</td>
                            <td>{{ item.category or "未填写" }}</td>
                            <td>{{ item.location or "未填写" }}</td>
                            <td>{{ item.contact or "未填写" }}</td>
                            <td><span class="status-tag status-{{ item.status }}">{{ status_map.get(item.status, item.status) }}</span></td>
                            <td>{{ item.username }}</td>
                            <td>{{ item.created_at }}</td>
                            <td>
                                <div class="admin-row-actions">
                                    {% if item.status == "pending" %}
                                    <form class="inline-form" method="post" action="{{ url_for('approve_item', item_id=item.id) }}">
                                        <button class="admin-btn approve-btn" type="submit">审核通过</button>
                                    </form>
                                    {% endif %}
                                    <form class="inline-form" method="post" action="{{ url_for('delete_item', item_id=item.id) }}">
                                        <button class="admin-btn delete-btn" type="submit" onclick="return confirm('确定要删除这条信息吗？')">删除</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if page_info.total_pages > 1 %}
            <nav class="pagination">
                {% if page_info.page > 1 %}
                <a href="{{ url_for('admin_items', page=page_info.page - 1) }}">上一页</a>
                {% else %}
                <span class="disabled">上一页</span>
                {% endif %}

                {% for page_number in page_numbers %}
                    {% if page_number == page_info.page %}
                    <span class="active">{{ page_number }}</span>
                    {% else %}
                    <a href="{{ url_for('admin_items', page=page_number) }}">{{ page_number }}</a>
                    {% endif %}
                {% endfor %}

                {% if page_info.page < page_info.total_pages %}
                <a href="{{ url_for('admin_items', page=page_info.page + 1) }}">下一页</a>
                {% else %}
                <span class="disabled">下一页</span>
                {% endif %}
            </nav>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        items=items,
        page_info=page_info,
        page_numbers=range(1, page_info["total_pages"] + 1),
        status_map=status_map,
        type_map=type_map,
    )
    return render_page(
        "信息审核 - 校园失物招领平台",
        page_content,
    )


@app.route("/admin/deleted_items")
def admin_deleted_items():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    items = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    item.id,
                    item.title,
                    item.item_type,
                    item.category,
                    item.location,
                    item.created_at,
                    item.deleted_at,
                    owner.username AS owner_username,
                    deleter.username AS deleter_username
                FROM item
                JOIN `user` AS owner ON item.user_id = owner.id
                LEFT JOIN `user` AS deleter ON item.deleted_by = deleter.id
                WHERE item.is_deleted = 1
                ORDER BY item.deleted_at DESC, item.id DESC
                """
            )
            items = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Deleted Items</p>
                <h1>已删除信息</h1>
                <p>这里展示被软删除的失物招领信息，管理员可以恢复或永久删除。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            {% if not error and not items %}
            <div class="empty-state">暂无已删除信息</div>
            {% elif items %}
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>标题</th>
                            <th>类型</th>
                            <th>分类</th>
                            <th>地点</th>
                            <th>发布人</th>
                            <th>删除人</th>
                            <th>删除时间</th>
                            <th>原发布时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in items %}
                        <tr>
                            <td>{{ item.id }}</td>
                            <td>{{ item.title }}</td>
                            <td>{{ type_map.get(item.item_type, item.item_type) }}</td>
                            <td>{{ item.category or "未填写" }}</td>
                            <td>{{ item.location or "未填写" }}</td>
                            <td>{{ item.owner_username }}</td>
                            <td>{{ item.deleter_username or "未知" }}</td>
                            <td>{{ item.deleted_at or "未知" }}</td>
                            <td>{{ item.created_at }}</td>
                            <td>
                                <div class="admin-row-actions">
                                    <form class="inline-form" method="post" action="{{ url_for('restore_deleted_item', item_id=item.id) }}">
                                        <button class="admin-btn approve-btn restore-btn" type="submit">恢复</button>
                                    </form>
                                    <form class="inline-form" method="post" action="{{ url_for('permanent_delete_item', item_id=item.id) }}">
                                        <button class="admin-btn delete-btn permanent-delete-btn" type="submit" onclick="return confirm('永久删除后无法恢复，确定继续吗？')">永久删除</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        items=items,
        type_map=type_map,
    )
    return render_page("已删除信息 - 校园失物招领平台", page_content)


@app.route("/admin/deleted_item/<int:item_id>/restore", methods=["POST"])
def restore_deleted_item(item_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE item
                SET is_deleted = 0, deleted_at = NULL, deleted_by = NULL
                WHERE id = %s AND is_deleted = 1
                """,
                (item_id,),
            )
            connection.commit()
        write_operation_log("恢复已删除信息", f"恢复信息 ID：{item_id}")
        flash("信息已恢复", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_deleted_items"))


@app.route("/admin/deleted_item/<int:item_id>/permanent_delete", methods=["POST"])
def permanent_delete_item(item_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM item WHERE id = %s AND is_deleted = 1",
                (item_id,),
            )
            item = cursor.fetchone()
            if not item:
                flash("已删除信息不存在", "error")
                return redirect(url_for("admin_deleted_items"))

            cursor.execute("DELETE FROM favorite WHERE item_id = %s", (item_id,))
            cursor.execute("DELETE FROM report WHERE item_id = %s", (item_id,))
            cursor.execute("DELETE FROM claim_request WHERE item_id = %s", (item_id,))
            cursor.execute("DELETE FROM item WHERE id = %s", (item_id,))
            connection.commit()
        write_operation_log("永久删除信息", f"永久删除信息 ID：{item_id}")
        flash("信息已永久删除", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_deleted_items"))


@app.route("/admin/announcements")
def admin_announcements():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    announcements_list = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, content, is_active, created_at
                FROM announcement
                ORDER BY created_at DESC
                """
            )
            announcements_list = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Announcement Management</p>
                <h1>公告管理</h1>
                <p>发布、编辑和管理平台公告。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry" href="{{ url_for('add_announcement') }}">新增公告</a>
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not announcements_list %}
            <div class="empty-state">暂无公告</div>
            {% else %}
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>标题</th>
                            <th>内容摘要</th>
                            <th>状态</th>
                            <th>发布时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for announcement in announcements_list %}
                        <tr>
                            <td>{{ announcement.id }}</td>
                            <td>{{ announcement.title }}</td>
                            <td>{{ announcement.content[:80] }}{% if announcement.content|length > 80 %}...{% endif %}</td>
                            <td>
                                {% if announcement.is_active == 1 %}
                                <span class="status-tag status-approved">显示中</span>
                                {% else %}
                                <span class="status-tag status-rejected">已隐藏</span>
                                {% endif %}
                            </td>
                            <td>{{ announcement.created_at }}</td>
                            <td>
                                <div class="admin-row-actions">
                                    <a class="admin-btn make-admin-btn small-btn" href="{{ url_for('edit_announcement', announcement_id=announcement.id) }}">编辑</a>
                                    {% if announcement.is_active == 1 %}
                                    <form class="inline-form" method="post" action="{{ url_for('hide_announcement', announcement_id=announcement.id) }}">
                                        <button class="admin-btn delete-btn small-btn" type="submit">隐藏</button>
                                    </form>
                                    {% else %}
                                    <form class="inline-form" method="post" action="{{ url_for('show_announcement', announcement_id=announcement.id) }}">
                                        <button class="admin-btn approve-btn small-btn" type="submit">显示</button>
                                    </form>
                                    {% endif %}
                                    <form class="inline-form" method="post" action="{{ url_for('delete_announcement', announcement_id=announcement.id) }}">
                                        <button class="admin-btn delete-btn small-btn" type="submit" onclick="return confirm('确定要删除这条公告吗？')">删除</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        announcements_list=announcements_list,
        error=error,
    )
    return render_page("公告管理 - 校园失物招领平台", page_content)


@app.route("/admin/announcement/add", methods=["GET", "POST"])
def add_announcement():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    if request.method == "POST":
        title = clean_text(request.form.get("title"), 100)
        content_text = clean_long_text(request.form.get("content"), 2000)

        if not title:
            error = "公告标题不能为空"
        elif not content_text:
            error = "公告内容不能为空"
        else:
            connection = None
            try:
                connection = get_db_connection()
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO announcement (title, content, is_active, created_by)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (title, content_text, 1, session["user_id"]),
                    )
                    connection.commit()
                write_operation_log("发布公告", f"发布公告：{title}")
                flash("公告发布成功", "success")
                return redirect(url_for("admin_announcements"))
            except Exception as exc:
                log_db_error(exc)
                error = system_error_message()
                flash(error, "error")
            finally:
                if connection:
                    connection.close()

        if error:
            flash(error, "error")

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Announcement</p>
                <h1>新增公告</h1>
                <p>发布平台公告，公告将展示在首页和公告栏。</p>
            </div>

            <form class="register-form admin-form" method="post" action="{{ url_for('add_announcement') }}">
                {% if error %}<p class="notice notice-error">{{ error }}</p>{% endif %}
                <label>
                    标题
                    <input type="text" name="title" value="{{ request.form.get('title', '') }}" maxlength="100" placeholder="请输入公告标题">
                </label>
                <label>
                    内容
                    <textarea name="content" rows="8" maxlength="2000" placeholder="请输入公告内容">{{ request.form.get('content', '') }}</textarea>
                </label>
                <button class="btn btn-form" type="submit">发布公告</button>
                <a class="reset-btn" href="{{ url_for('admin_announcements') }}">返回公告管理</a>
            </form>
        </div>
    </section>
    """
    page_content = render_template_string(content, error=error)
    return render_page("新增公告 - 校园失物招领平台", page_content)


@app.route("/admin/announcement/<int:announcement_id>/edit", methods=["GET", "POST"])
def edit_announcement(announcement_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    announcement = None
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, title, content FROM announcement WHERE id = %s",
                (announcement_id,),
            )
            announcement = cursor.fetchone()
            if not announcement:
                abort(404)

            if request.method == "POST":
                title = clean_text(request.form.get("title"), 100)
                content_text = clean_long_text(request.form.get("content"), 2000)

                if not title:
                    error = "公告标题不能为空"
                elif not content_text:
                    error = "公告内容不能为空"
                else:
                    cursor.execute(
                        """
                        UPDATE announcement
                        SET title = %s, content = %s
                        WHERE id = %s
                        """,
                        (title, content_text, announcement_id),
                    )
                    connection.commit()
                    write_operation_log("编辑公告", f"编辑公告 ID：{announcement_id}")
                    flash("公告修改成功", "success")
                    return redirect(url_for("admin_announcements"))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Announcement</p>
                <h1>编辑公告</h1>
                <p>修改公告标题和内容。</p>
            </div>

            {% if announcement %}
            <form class="register-form admin-form" method="post" action="{{ url_for('edit_announcement', announcement_id=announcement.id) }}">
                {% if error %}<p class="notice notice-error">{{ error }}</p>{% endif %}
                <label>
                    标题
                    <input type="text" name="title" value="{{ request.form.get('title', announcement.title) }}" maxlength="100">
                </label>
                <label>
                    内容
                    <textarea name="content" rows="8" maxlength="2000">{{ request.form.get('content', announcement.content) }}</textarea>
                </label>
                <button class="btn btn-form" type="submit">保存修改</button>
                <a class="reset-btn" href="{{ url_for('admin_announcements') }}">返回公告管理</a>
            </form>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(content, announcement=announcement, error=error)
    return render_page("编辑公告 - 校园失物招领平台", page_content)


@app.route("/admin/announcement/<int:announcement_id>/hide", methods=["POST"])
def hide_announcement(announcement_id):
    return update_announcement_status(announcement_id, 0, "隐藏公告", "公告已隐藏")


@app.route("/admin/announcement/<int:announcement_id>/show", methods=["POST"])
def show_announcement(announcement_id):
    return update_announcement_status(announcement_id, 1, "显示公告", "公告已显示")


def update_announcement_status(announcement_id, is_active_value, action, flash_message):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE announcement SET is_active = %s WHERE id = %s",
                (is_active_value, announcement_id),
            )
            connection.commit()
        write_operation_log(action, f"{action} ID：{announcement_id}")
        flash(flash_message, "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_announcements"))


@app.route("/admin/announcement/<int:announcement_id>/delete", methods=["POST"])
def delete_announcement(announcement_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM announcement WHERE id = %s", (announcement_id,))
            connection.commit()
        write_operation_log("删除公告", f"删除公告 ID：{announcement_id}")
        flash("公告已删除", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_announcements"))


@app.route("/admin/pickup_locations")
def admin_pickup_locations():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    locations = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, address, description, is_active, created_at
                FROM pickup_location
                ORDER BY created_at DESC
                """
            )
            locations = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Pickup Locations</p>
                <h1>领取地点管理</h1>
                <p>维护招领信息可选择的线下领取地点。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry" href="{{ url_for('add_pickup_location') }}">新增地点</a>
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not locations %}
            <div class="empty-state">暂无领取地点</div>
            {% else %}
            <div class="admin-table-wrap">
                <table class="admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>名称</th>
                            <th>地址</th>
                            <th>说明</th>
                            <th>状态</th>
                            <th>创建时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for location in locations %}
                        <tr>
                            <td>{{ location.id }}</td>
                            <td>{{ location.name }}</td>
                            <td>{{ location.address or "未填写" }}</td>
                            <td class="text-content">{{ location.description or "未填写" }}</td>
                            <td>
                                {% if location.is_active == 1 %}
                                <span class="status-tag status-approved">启用</span>
                                {% else %}
                                <span class="status-tag status-rejected">停用</span>
                                {% endif %}
                            </td>
                            <td>{{ location.created_at }}</td>
                            <td>
                                <div class="admin-row-actions">
                                    <a class="admin-btn make-admin-btn small-btn" href="{{ url_for('edit_pickup_location', location_id=location.id) }}">编辑</a>
                                    {% if location.is_active == 1 %}
                                    <form class="inline-form" method="post" action="{{ url_for('disable_pickup_location', location_id=location.id) }}">
                                        <button class="admin-btn delete-btn small-btn" type="submit">停用</button>
                                    </form>
                                    {% else %}
                                    <form class="inline-form" method="post" action="{{ url_for('enable_pickup_location', location_id=location.id) }}">
                                        <button class="admin-btn approve-btn small-btn" type="submit">启用</button>
                                    </form>
                                    {% endif %}
                                    <form class="inline-form" method="post" action="{{ url_for('delete_pickup_location', location_id=location.id) }}">
                                        <button class="admin-btn delete-btn small-btn" type="submit" onclick="return confirm('确定要删除该领取地点吗？')">删除</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(content, error=error, locations=locations)
    return render_page("领取地点管理 - 校园失物招领平台", page_content)


@app.route("/admin/pickup_location/add", methods=["GET", "POST"])
def add_pickup_location():
    return render_pickup_location_form()


@app.route("/admin/pickup_location/<int:location_id>/edit", methods=["GET", "POST"])
def edit_pickup_location(location_id):
    return render_pickup_location_form(location_id)


def render_pickup_location_form(location_id=None):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    location = None
    connection = None
    is_edit = location_id is not None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            if is_edit:
                cursor.execute(
                    "SELECT id, name, address, description FROM pickup_location WHERE id = %s",
                    (location_id,),
                )
                location = cursor.fetchone()
                if not location:
                    abort(404)

            if request.method == "POST":
                name = clean_text(request.form.get("name"), 100)
                address = clean_text(request.form.get("address"), 255)
                description = clean_long_text(request.form.get("description"), 1000)

                if not name:
                    error = "领取地点名称不能为空"
                elif is_edit:
                    cursor.execute(
                        """
                        UPDATE pickup_location
                        SET name = %s, address = %s, description = %s
                        WHERE id = %s
                        """,
                        (name, address, description, location_id),
                    )
                    connection.commit()
                    write_operation_log("编辑领取地点", f"编辑领取地点 ID：{location_id}")
                    flash("领取地点修改成功", "success")
                    return redirect(url_for("admin_pickup_locations"))
                else:
                    cursor.execute(
                        """
                        INSERT INTO pickup_location (name, address, description, is_active)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (name, address, description, 1),
                    )
                    connection.commit()
                    write_operation_log("新增领取地点", f"新增领取地点：{name}")
                    flash("领取地点添加成功", "success")
                    return redirect(url_for("admin_pickup_locations"))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Pickup Location</p>
                <h1>{{ "编辑领取地点" if is_edit else "新增领取地点" }}</h1>
                <p>维护招领物品的线下领取位置。</p>
            </div>

            <form class="register-form admin-form" method="post" action="{{ url_for('edit_pickup_location', location_id=location.id) if is_edit else url_for('add_pickup_location') }}">
                {% if error %}<p class="notice notice-error">{{ error }}</p>{% endif %}
                <label>
                    名称
                    <input type="text" name="name" value="{{ request.form.get('name', location.name if location else '') }}" maxlength="100" placeholder="例如：学生事务中心">
                </label>
                <label>
                    地址
                    <input type="text" name="address" value="{{ request.form.get('address', location.address if location else '') }}" maxlength="255" placeholder="例如：行政楼一楼">
                </label>
                <label>
                    说明
                    <textarea name="description" rows="6" maxlength="1000" placeholder="例如：工作日 9:00-17:00 可领取">{{ request.form.get('description', location.description if location else '') }}</textarea>
                </label>
                <button class="btn btn-form" type="submit">{{ "保存修改" if is_edit else "添加地点" }}</button>
                <a class="reset-btn" href="{{ url_for('admin_pickup_locations') }}">返回地点管理</a>
            </form>
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        is_edit=is_edit,
        location=location,
    )
    return render_page(("编辑领取地点" if is_edit else "新增领取地点") + " - 校园失物招领平台", page_content)


@app.route("/admin/pickup_location/<int:location_id>/enable", methods=["POST"])
def enable_pickup_location(location_id):
    return update_pickup_location_status(location_id, 1, "启用领取地点", "领取地点已启用")


@app.route("/admin/pickup_location/<int:location_id>/disable", methods=["POST"])
def disable_pickup_location(location_id):
    return update_pickup_location_status(location_id, 0, "停用领取地点", "领取地点已停用")


def update_pickup_location_status(location_id, is_active_value, action, flash_message):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE pickup_location SET is_active = %s WHERE id = %s",
                (is_active_value, location_id),
            )
            connection.commit()
        write_operation_log(action, f"{action} ID：{location_id}")
        flash(flash_message, "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_pickup_locations"))


@app.route("/admin/pickup_location/<int:location_id>/delete", methods=["POST"])
def delete_pickup_location(location_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS count FROM item WHERE pickup_location_id = %s",
                (location_id,),
            )
            used_count = (cursor.fetchone() or {}).get("count") or 0
            if used_count > 0:
                flash("该地点已有信息使用，不能删除，可选择停用", "warning")
                return redirect(url_for("admin_pickup_locations"))

            cursor.execute("DELETE FROM pickup_location WHERE id = %s", (location_id,))
            connection.commit()
        write_operation_log("删除领取地点", f"删除领取地点 ID：{location_id}")
        flash("领取地点已删除", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_pickup_locations"))


@app.route("/admin/users")
def admin_users():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    message = ""
    users = []
    keyword = clean_text(request.args.get("keyword"), 100)
    status_filter = validate_choice(
        request.args.get("status_filter"),
        {"all", "pending", "approved", "rejected"},
        "all",
    )
    role_filter = validate_choice(
        request.args.get("role_filter"),
        {"all", "admin", "normal"},
        "all",
    )
    ban_filter = validate_choice(
        request.args.get("ban_filter"),
        {"all", "banned", "normal"},
        "all",
    )
    avatar_filter = validate_choice(
        request.args.get("avatar_filter"),
        {"all", "has_avatar", "no_avatar"},
        "all",
    )
    has_filters = any(
        [
            keyword,
            status_filter != "all",
            role_filter != "all",
            ban_filter != "all",
            avatar_filter != "all",
        ]
    )
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            params = []
            where_clauses = []

            if keyword:
                keyword_like = "%" + keyword + "%"
                where_clauses.append(
                    """
                    (
                        `user`.username LIKE %s
                        OR `user`.real_name LIKE %s
                        OR `user`.student_id LIKE %s
                        OR `user`.email LIKE %s
                        OR `user`.phone LIKE %s
                    )
                    """
                )
                params.extend(
                    [
                        keyword_like,
                        keyword_like,
                        keyword_like,
                        keyword_like,
                        keyword_like,
                    ]
                )

            if status_filter != "all":
                where_clauses.append("`user`.status = %s")
                params.append(status_filter)

            if role_filter == "admin":
                where_clauses.append("`user`.is_admin = %s")
                params.append(1)
            elif role_filter == "normal":
                where_clauses.append("`user`.is_admin = %s")
                params.append(0)

            if ban_filter == "banned":
                where_clauses.append("`user`.is_banned = %s")
                params.append(1)
            elif ban_filter == "normal":
                where_clauses.append("(`user`.is_banned = 0 OR `user`.is_banned IS NULL)")

            if avatar_filter == "has_avatar":
                where_clauses.append("(`user`.avatar IS NOT NULL AND `user`.avatar != '')")
            elif avatar_filter == "no_avatar":
                where_clauses.append("(`user`.avatar IS NULL OR `user`.avatar = '')")

            where_clause = ""
            if where_clauses:
                where_clause = "WHERE " + " AND ".join(where_clauses)

            sql = """
                SELECT
                    `user`.id,
                    `user`.username,
                    `user`.real_name,
                    `user`.student_id,
                    `user`.phone,
                    `user`.email,
                    `user`.avatar,
                    `user`.student_card,
                    `user`.is_admin,
                    `user`.is_banned,
                    `user`.banned_reason,
                    `user`.banned_at,
                    `user`.status,
                    `user`.review_note,
                    `user`.created_at,
                    COUNT(
                        CASE
                            WHEN item.is_deleted = 0 OR item.is_deleted IS NULL
                            THEN item.id
                        END
                    ) AS item_count
                FROM `user`
                LEFT JOIN item ON item.user_id = `user`.id
                """ + where_clause + """
                GROUP BY
                    `user`.id,
                    `user`.username,
                    `user`.real_name,
                    `user`.student_id,
                    `user`.phone,
                    `user`.email,
                    `user`.avatar,
                    `user`.student_card,
                    `user`.is_admin,
                    `user`.is_banned,
                    `user`.banned_reason,
                    `user`.banned_at,
                    `user`.status,
                    `user`.review_note,
                    `user`.created_at
                ORDER BY `user`.created_at DESC
                """
            cursor.execute(sql, params)
            users = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    user_status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "rejected": "已拒绝",
    }
    status_filter_map = {
        "all": "全部审核状态",
        "pending": "待审核",
        "approved": "已通过",
        "rejected": "已拒绝",
    }
    role_filter_map = {
        "all": "全部角色",
        "admin": "管理员",
        "normal": "普通用户",
    }
    ban_filter_map = {
        "all": "全部封禁状态",
        "banned": "已封禁",
        "normal": "正常",
    }
    avatar_filter_map = {
        "all": "全部头像状态",
        "has_avatar": "有头像",
        "no_avatar": "无头像",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">User Management</p>
                <h1>用户管理</h1>
                <p>查看所有用户信息，并管理管理员权限。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            <form method="get" action="{{ url_for('admin_users') }}" class="admin-filter-box">
                <input type="text" name="keyword" value="{{ keyword }}" placeholder="搜索用户名、姓名、学号、邮箱或手机号">
                <select name="status_filter">
                    <option value="all" {% if status_filter == "all" %}selected{% endif %}>全部审核状态</option>
                    <option value="pending" {% if status_filter == "pending" %}selected{% endif %}>待审核</option>
                    <option value="approved" {% if status_filter == "approved" %}selected{% endif %}>已通过</option>
                    <option value="rejected" {% if status_filter == "rejected" %}selected{% endif %}>已拒绝</option>
                </select>
                <select name="role_filter">
                    <option value="all" {% if role_filter == "all" %}selected{% endif %}>全部角色</option>
                    <option value="admin" {% if role_filter == "admin" %}selected{% endif %}>管理员</option>
                    <option value="normal" {% if role_filter == "normal" %}selected{% endif %}>普通用户</option>
                </select>
                <select name="ban_filter">
                    <option value="all" {% if ban_filter == "all" %}selected{% endif %}>全部封禁状态</option>
                    <option value="banned" {% if ban_filter == "banned" %}selected{% endif %}>已封禁</option>
                    <option value="normal" {% if ban_filter == "normal" %}selected{% endif %}>正常</option>
                </select>
                <select name="avatar_filter">
                    <option value="all" {% if avatar_filter == "all" %}selected{% endif %}>全部头像状态</option>
                    <option value="has_avatar" {% if avatar_filter == "has_avatar" %}selected{% endif %}>有头像</option>
                    <option value="no_avatar" {% if avatar_filter == "no_avatar" %}selected{% endif %}>无头像</option>
                </select>
                <button type="submit" class="search-btn">搜索 / 筛选</button>
                <a href="{{ url_for('admin_users') }}" class="reset-btn">重置</a>
            </form>

            {% if has_filters %}
            <div class="filter-result-tip">
                <strong>当前筛选：</strong>
                <span>关键词：{{ keyword or "无" }}</span>
                <span>审核状态：{{ status_filter_map.get(status_filter, "全部审核状态") }}</span>
                <span>角色：{{ role_filter_map.get(role_filter, "全部角色") }}</span>
                <span>封禁状态：{{ ban_filter_map.get(ban_filter, "全部封禁状态") }}</span>
                <span>头像状态：{{ avatar_filter_map.get(avatar_filter, "全部头像状态") }}</span>
                <span>
                    {% if users %}
                    共找到 {{ users|length }} 个用户
                    {% else %}
                    没有找到符合条件的用户
                    {% endif %}
                </span>
            </div>
            {% endif %}

            {% if users %}
            <div class="admin-table-wrap user-table-wrap">
                <table class="admin-table user-admin-table">
                    <colgroup>
                        <col class="col-id">
                        <col class="col-username">
                        <col class="col-real-name">
                        <col class="col-student-id">
                        <col class="col-phone">
                        <col class="col-email">
                        <col class="col-avatar">
                        <col class="col-card">
                        <col class="col-admin">
                        <col class="col-ban-status">
                        <col class="col-reason">
                        <col class="col-status">
                        <col class="col-reason">
                        <col class="col-created">
                        <col class="col-count">
                        <col class="col-actions">
                    </colgroup>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>用户名</th>
                            <th>真实姓名</th>
                            <th>学号</th>
                            <th>手机号</th>
                            <th>邮箱</th>
                            <th>头像</th>
                            <th>学生证照片</th>
                            <th>是否管理员</th>
                            <th>封禁状态</th>
                            <th>封禁原因</th>
                            <th>审核状态</th>
                            <th>拒绝原因</th>
                            <th>注册时间</th>
                            <th>发布数量</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td>{{ user.real_name or "未填写" }}</td>
                            <td>{{ user.student_id or "未填写" }}</td>
                            <td>{{ user.phone or "未填写" }}</td>
                            <td class="cell-email">{{ user.email or "未填写" }}</td>
                            <td>
                                {% if user.avatar %}
                                <img class="avatar-thumb" src="{{ url_for('static', filename=user.avatar) }}" alt="{{ user.username }}">
                                {% else %}
                                <span class="avatar-thumb avatar-placeholder">{{ user.username[:1] if user.username else "用" }}</span>
                                {% endif %}
                            </td>
                            <td>{{ "已上传" if user.student_card else "未上传" }}</td>
                            <td>
                                {% if user.is_admin == 1 %}
                                <span class="status-tag status-approved">是</span>
                                {% else %}
                                <span class="status-tag status-resolved">否</span>
                                {% endif %}
                            </td>
                            <td>
                                {% if user.is_banned == 1 %}
                                <span class="status-tag status-rejected">已封禁</span>
                                {% else %}
                                <span class="status-tag status-resolved">正常</span>
                                {% endif %}
                            </td>
                            <td class="cell-reason">{{ user.banned_reason if user.is_banned == 1 and user.banned_reason else "无" }}</td>
                            <td>{{ user_status_map.get(user.status, user.status or "未知") }}</td>
                            <td class="cell-reason">{{ user.review_note if user.status == "rejected" and user.review_note else "无" }}</td>
                            <td>{{ user.created_at }}</td>
                            <td>{{ user.item_count }}</td>
                            <td>
                                <div class="admin-row-actions table-actions">
                                    {% if user.is_admin == 1 %}
                                    <form class="inline-form" method="post" action="{{ url_for('remove_admin', user_id=user.id) }}">
                                        <button class="admin-btn remove-admin-btn" type="submit" onclick="return confirm('确定要取消该用户的管理员权限吗？')">取消管理员</button>
                                    </form>
                                    {% else %}
                                    <form class="inline-form" method="post" action="{{ url_for('make_admin', user_id=user.id) }}">
                                        <button class="admin-btn make-admin-btn" type="submit">设为管理员</button>
                                    </form>
                                    {% endif %}
                                    {% if user.id != session.get("user_id") %}
                                        {% if user.is_banned == 1 %}
                                        <form class="inline-form" method="post" action="{{ url_for('unban_user', user_id=user.id) }}">
                                            <button class="admin-btn approve-btn small-btn" type="submit">解封</button>
                                        </form>
                                        {% else %}
                                        <form class="inline-form ban-user-form" method="post" action="{{ url_for('ban_user', user_id=user.id) }}">
                                            <input class="review-note-input" type="text" name="banned_reason" placeholder="封禁原因">
                                            <button class="admin-btn delete-btn small-btn" type="submit" onclick="return confirm('确定要封禁该用户吗？')">封禁</button>
                                        </form>
                                        {% endif %}
                                    {% endif %}
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% elif not error %}
            <div class="empty-state">{{ "没有找到符合条件的用户" if has_filters else "暂无用户" }}</div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        avatar_filter=avatar_filter,
        avatar_filter_map=avatar_filter_map,
        ban_filter=ban_filter,
        ban_filter_map=ban_filter_map,
        error=error,
        has_filters=has_filters,
        keyword=keyword,
        role_filter=role_filter,
        role_filter_map=role_filter_map,
        status_filter=status_filter,
        status_filter_map=status_filter_map,
        user_status_map=user_status_map,
        users=users,
    )
    return render_page(
        "用户管理 - 校园失物招领平台",
        page_content,
    )


@app.route("/admin/user/<int:user_id>/ban", methods=["POST"])
def ban_user(user_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    if user_id == session.get("user_id"):
        flash("不能封禁自己的账号", "error")
        return redirect(url_for("admin_users"))

    banned_reason = clean_text(request.form.get("banned_reason"), 255) or "违反平台规则"
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, username FROM `user` WHERE id = %s",
                (user_id,),
            )
            user = cursor.fetchone()
            if not user:
                flash("用户不存在", "error")
                return redirect(url_for("admin_users"))

            cursor.execute(
                """
                UPDATE `user`
                SET is_banned = 1, banned_reason = %s, banned_at = NOW()
                WHERE id = %s
                """,
                (banned_reason, user_id),
            )
            connection.commit()

        write_operation_log("封禁用户", f"封禁用户 {user['username']}，原因：{banned_reason}")
        flash("用户已封禁", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/unban", methods=["POST"])
def unban_user(user_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT id, username FROM `user` WHERE id = %s",
                (user_id,),
            )
            user = cursor.fetchone()
            if not user:
                flash("用户不存在", "error")
                return redirect(url_for("admin_users"))

            cursor.execute(
                """
                UPDATE `user`
                SET is_banned = 0, banned_reason = NULL, banned_at = NULL
                WHERE id = %s
                """,
                (user_id,),
            )
            connection.commit()

        write_operation_log("解封用户", f"解封用户 {user['username']}")
        flash("用户已解封", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/user_reviews")
def user_reviews():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    users = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, real_name, student_id, phone, email, student_card, created_at
                FROM `user`
                WHERE status = %s
                ORDER BY created_at ASC
                """,
                ("pending",),
            )
            users = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Registration Review</p>
                <h1>注册审核</h1>
                <p>审核新注册用户，通过后用户才能登录系统。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            {% if users %}
            <div class="admin-table-wrap">
                <table class="admin-table user-admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>用户名</th>
                            <th>真实姓名</th>
                            <th>学号</th>
                            <th>手机号</th>
                            <th>邮箱</th>
                            <th>学生证照片</th>
                            <th>注册时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td>{{ user.real_name or "未填写" }}</td>
                            <td>{{ user.student_id or "未填写" }}</td>
                            <td>{{ user.phone or "未填写" }}</td>
                            <td>{{ user.email or "未填写" }}</td>
                            <td>
                                {% if user.student_card %}
                                <a href="{{ url_for('static', filename=user.student_card) }}" target="_blank">
                                    <img class="card-thumb" src="{{ url_for('static', filename=user.student_card) }}" alt="学生证照片">
                                </a>
                                {% else %}
                                未上传
                                {% endif %}
                            </td>
                            <td>{{ user.created_at }}</td>
                            <td>
                                <div class="admin-row-actions review-actions">
                                    <form class="inline-form" method="post" action="{{ url_for('approve_register', user_id=user.id) }}">
                                        <button class="admin-btn approve-btn small-btn" type="submit">审核通过</button>
                                    </form>
                                    <form class="inline-form reject-form" method="post" action="{{ url_for('reject_register', user_id=user.id) }}">
                                        <input class="review-note-input" type="text" name="review_note" placeholder="拒绝原因">
                                        <button class="admin-btn delete-btn small-btn" type="submit" onclick="return confirm('确定要拒绝该用户的注册申请吗？')">拒绝申请</button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% elif not error %}
            <div class="empty-state">暂无待审核用户</div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(content, error=error, users=users)
    return render_page("注册审核 - 校园失物招领平台", page_content)


@app.route("/admin/user/<int:user_id>/approve_register", methods=["POST"])
def approve_register(user_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, username FROM `user` WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                flash("用户不存在", "error")
                return redirect(url_for("user_reviews"))

            cursor.execute(
                """
                UPDATE `user`
                SET status = %s, review_note = NULL
                WHERE id = %s
                """,
                ("approved", user_id),
            )
            connection.commit()
        write_operation_log("审核通过用户注册", f"审核通过用户：{user['username']}")
        create_notification(
            user_id,
            "注册审核通过",
            "你的账号已通过管理员审核，现在可以正常登录系统。",
        )
        flash("用户审核通过", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("user_reviews"))


@app.route("/admin/user/<int:user_id>/reject_register", methods=["POST"])
def reject_register(user_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    review_note = clean_text(request.form.get("review_note"), 255)
    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, username FROM `user` WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                flash("用户不存在", "error")
                return redirect(url_for("user_reviews"))

            cursor.execute(
                """
                UPDATE `user`
                SET status = %s, review_note = %s
                WHERE id = %s
                """,
                ("rejected", review_note, user_id),
            )
            connection.commit()
        write_operation_log("拒绝用户注册", f"拒绝用户：{user['username']}，原因：{review_note or '未填写'}")
        if review_note:
            content = f"你的注册申请未通过。原因：{review_note}"
        else:
            content = "你的注册申请未通过，请修改资料后重新提交。"
        create_notification(user_id, "注册审核未通过", content)
        flash("用户审核已拒绝", "success")
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
    finally:
        if connection:
            connection.close()

    return redirect(url_for("user_reviews"))


@app.route("/admin/export_items")
def export_items():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "resolved": "已完成",
    }
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    item.id, item.title, item.item_type, item.category,
                    item.location, item.event_time, item.description,
                    item.contact, item.status, item.views,
                    `user`.username, item.created_at
                FROM item
                JOIN `user` ON item.user_id = `user`.id
                WHERE item.is_deleted = 0 OR item.is_deleted IS NULL
                ORDER BY item.created_at DESC
                """
            )
            items = cursor.fetchall()

        output = io.StringIO()
        output.write("\ufeff")
        writer = csv.writer(output)
        writer.writerow([
            "ID",
            "标题",
            "类型",
            "分类",
            "地点",
            "事件时间",
            "描述",
            "联系方式",
            "状态",
            "浏览量",
            "发布人",
            "发布时间",
        ])

        for item in items:
            writer.writerow([
                item["id"],
                item["title"],
                type_map.get(item["item_type"], item["item_type"]),
                item["category"] or "",
                item["location"] or "",
                item["event_time"] or "",
                item["description"] or "",
                item["contact"] or "",
                status_map.get(item["status"], item["status"]),
                item["views"] or 0,
                item["username"],
                item["created_at"],
            ])

        csv_content = output.getvalue()
        write_operation_log("导出数据", "导出失物招领 CSV 数据")
        return Response(
            csv_content,
            mimetype="text/csv; charset=utf-8-sig",
            headers={
                "Content-Disposition": "attachment; filename=lost_found_items.csv"
            },
        )
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return render_page(
            "导出失败 - 校园失物招领平台",
            '<section class="items-section"><div class="container"><p class="notice notice-error">导出失败，请稍后再试</p></div></section>',
        )
    finally:
        if connection:
            connection.close()


@app.route("/admin/statistics")
def admin_statistics():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    type_stats = []
    status_stats = []
    category_stats = []
    popular_categories = []
    connection = None

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    status_map = {
        "pending": "待审核",
        "approved": "已通过",
        "resolved": "已完成",
    }

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT item_type, COUNT(*) AS count
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                GROUP BY item_type
                ORDER BY item_type
                """
            )
            type_stats = cursor.fetchall()

            cursor.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                GROUP BY status
                ORDER BY status
                """
            )
            status_stats = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    COALESCE(NULLIF(category, ''), '未分类') AS category_name,
                    COUNT(*) AS count,
                    SUM(views) AS views_sum
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                GROUP BY COALESCE(NULLIF(category, ''), '未分类')
                ORDER BY count DESC, views_sum DESC
                """
            )
            category_stats = cursor.fetchall()

            cursor.execute(
                """
                SELECT
                    COALESCE(NULLIF(category, ''), '未分类') AS category_name,
                    COUNT(*) AS count,
                    SUM(views) AS views_sum
                FROM item
                WHERE is_deleted = 0 OR is_deleted IS NULL
                GROUP BY COALESCE(NULLIF(category, ''), '未分类')
                ORDER BY views_sum DESC, count DESC
                LIMIT 5
                """
            )
            popular_categories = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Statistics</p>
                <h1>分类统计</h1>
                <p>按类型、状态和分类查看失物招领数据分布。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            <div class="admin-panels">
                <section class="admin-section stats-section">
                    <div class="section-heading compact-heading">
                        <h2>类型统计</h2>
                    </div>
                    <div class="admin-table-wrap">
                        <table class="admin-table statistics-table">
                            <thead>
                                <tr>
                                    <th>类型</th>
                                    <th>数量</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for row in type_stats %}
                                <tr>
                                    <td>{{ type_map.get(row.item_type, row.item_type) }}</td>
                                    <td>{{ row.count }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="admin-section stats-section">
                    <div class="section-heading compact-heading">
                        <h2>状态统计</h2>
                    </div>
                    <div class="admin-table-wrap">
                        <table class="admin-table statistics-table">
                            <thead>
                                <tr>
                                    <th>状态</th>
                                    <th>数量</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for row in status_stats %}
                                <tr>
                                    <td>{{ status_map.get(row.status, row.status) }}</td>
                                    <td>{{ row.count }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="admin-section stats-section">
                    <div class="section-heading compact-heading">
                        <h2>分类统计</h2>
                    </div>
                    <div class="admin-table-wrap">
                        <table class="admin-table statistics-table">
                            <thead>
                                <tr>
                                    <th>分类</th>
                                    <th>数量</th>
                                    <th>总浏览量</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for row in category_stats %}
                                <tr>
                                    <td>{{ row.category_name }}</td>
                                    <td>{{ row.count }}</td>
                                    <td>{{ row.views_sum or 0 }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </section>

                <section class="admin-section stats-section">
                    <div class="section-heading compact-heading">
                        <h2>热门分类</h2>
                    </div>
                    <div class="admin-table-wrap">
                        <table class="admin-table statistics-table">
                            <thead>
                                <tr>
                                    <th>排名</th>
                                    <th>分类</th>
                                    <th>数量</th>
                                    <th>总浏览量</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for row in popular_categories %}
                                <tr>
                                    <td>{{ loop.index }}</td>
                                    <td>{{ row.category_name }}</td>
                                    <td>{{ row.count }}</td>
                                    <td>{{ row.views_sum or 0 }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        category_stats=category_stats,
        error=error,
        popular_categories=popular_categories,
        status_map=status_map,
        status_stats=status_stats,
        type_map=type_map,
        type_stats=type_stats,
    )
    return render_page("分类统计 - 校园失物招领平台", page_content)


@app.route("/admin/user/<int:user_id>/make_admin", methods=["POST"])
def make_admin(user_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, username FROM `user` WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                flash("用户不存在", "error")
                return redirect(url_for("admin_users"))

            cursor.execute(
                "UPDATE `user` SET is_admin = 1 WHERE id = %s",
                (user_id,),
            )
            connection.commit()
        write_operation_log("设为管理员", f"将用户 {user['username']} 设为管理员")
        flash("已设为管理员", "success")
        return redirect(url_for("admin_users"))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("admin_users"))
    finally:
        if connection:
            connection.close()


@app.route("/admin/user/<int:user_id>/remove_admin", methods=["POST"])
def remove_admin(user_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    if user_id == session.get("user_id"):
        flash("不能取消自己的管理员权限", "error")
        return redirect(url_for("admin_users"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, username FROM `user` WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                flash("用户不存在", "error")
                return redirect(url_for("admin_users"))

            cursor.execute(
                "UPDATE `user` SET is_admin = 0 WHERE id = %s",
                (user_id,),
            )
            connection.commit()
        write_operation_log("取消管理员", f"取消用户 {user['username']} 的管理员权限")
        flash("已取消管理员权限", "success")
        return redirect(url_for("admin_users"))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("admin_users"))
    finally:
        if connection:
            connection.close()


@app.route("/admin/item/<int:item_id>/approve", methods=["POST"])
def approve_item(item_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, title
                FROM item
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()
            cursor.execute(
                """
                UPDATE item
                SET status = 'approved'
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            connection.commit()
        if item:
            write_operation_log("审核通过信息", f"审核通过信息 ID：{item_id}，标题：{item['title']}")
            create_notification(
                item["user_id"],
                "信息审核通过",
                f"你发布的“{item['title']}”已通过审核并公开展示。",
            )
        flash("审核通过", "success")
        return redirect(url_for("admin_items"))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("admin_items"))
    finally:
        if connection:
            connection.close()


@app.route("/admin/item/<int:item_id>/delete", methods=["POST"])
def delete_item(item_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, title
                FROM item
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()
            cursor.execute(
                """
                UPDATE item
                SET is_deleted = 1, deleted_at = NOW(), deleted_by = %s
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (session["user_id"], item_id),
            )
            connection.commit()
        if item:
            write_operation_log("管理员删除信息", f"管理员删除信息 ID：{item_id}，标题：{item['title']}")
            create_notification(
                item["user_id"],
                "信息被删除",
                f"你发布的“{item['title']}”已被管理员删除。如有疑问请联系管理员。",
            )
        flash("删除成功", "success")
        return redirect(url_for("admin_items"))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("admin_items"))
    finally:
        if connection:
            connection.close()


@app.route("/report/<int:item_id>", methods=["GET", "POST"])
def submit_report(item_id):
    if "user_id" not in session:
        flash("请先登录后举报信息", "warning")
        return redirect(url_for("login"))

    error = ""
    item = None
    reasons = [
        "虚假信息",
        "广告或垃圾信息",
        "联系方式异常",
        "图片或内容不清晰",
        "其他",
    ]
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, item_type, category, location, status, user_id
                FROM item
                WHERE
                    id = %s
                    AND status IN ('approved', 'resolved')
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item:
                abort(404)

            if item["user_id"] == session["user_id"]:
                flash("不能举报自己发布的信息", "error")
                return redirect(url_for("item_detail", item_id=item_id))

            if request.method == "POST":
                reason = validate_choice(request.form.get("reason"), REPORT_REASONS, "")
                description = clean_long_text(request.form.get("description"), 1000)

                if not reason:
                    error = "请选择举报原因"
                elif reason not in REPORT_REASONS:
                    error = "举报原因不正确"
                else:
                    cursor.execute(
                        """
                        SELECT id
                        FROM report
                        WHERE item_id = %s AND reporter_id = %s AND status = 'pending'
                        """,
                        (item_id, session["user_id"]),
                    )
                    existing_report = cursor.fetchone()

                    if existing_report:
                        error = "你已经提交过待处理举报，请等待管理员处理"
                    else:
                        cursor.execute(
                            """
                            INSERT INTO report (item_id, reporter_id, reason, description)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (item_id, session["user_id"], reason, description),
                        )
                        connection.commit()
                        write_operation_log("提交举报", f"举报信息 ID：{item_id}，原因：{reason}")
                        flash("举报已提交，等待管理员处理", "success")
                        return redirect(url_for("item_detail", item_id=item_id))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Report Item</p>
                <h1>举报违规信息</h1>
                <p>如果你发现信息存在虚假、广告或联系方式异常等问题，可以提交举报给管理员处理。</p>
            </div>

            <div class="form-box report-form">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                {% if item %}
                <div class="claim-target">
                    <span class="type-tag">{{ type_map.get(item.item_type, item.item_type) }}</span>
                    <strong>{{ item.title }}</strong>
                    <p>{{ item.category or "未填写分类" }} · {{ item.location or "未填写地点" }}</p>
                </div>

                <form class="register-form" method="post" action="{{ url_for('submit_report', item_id=item.id) }}">
                    <label>
                        举报原因
                        <select name="reason" required>
                            <option value="">请选择举报原因</option>
                            {% for reason in reasons %}
                            <option value="{{ reason }}" {% if request.form.get('reason') == reason %}selected{% endif %}>{{ reason }}</option>
                            {% endfor %}
                        </select>
                    </label>

                    <label>
                        补充说明
                        <textarea name="description" rows="6" placeholder="可以补充说明具体问题">{{ request.form.get("description", "") }}</textarea>
                    </label>

                    <button class="btn btn-form" type="submit">提交举报</button>
                    <a class="back-link form-back-link" href="{{ url_for('item_detail', item_id=item.id) }}">返回详情</a>
                </form>
                {% endif %}
            </div>
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        item=item,
        reasons=reasons,
        request=request,
        type_map=type_map,
    )
    return render_page("举报违规信息 - 校园失物招领平台", page_content)


@app.route("/claim/<int:item_id>", methods=["GET", "POST"])
def submit_claim(item_id):
    if "user_id" not in session:
        flash("请先登录后提交申请", "warning")
        return redirect(url_for("login"))

    error = ""
    item = None
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, title, item_type, category, location, status, user_id
                FROM item
                WHERE
                    id = %s
                    AND status IN ('approved', 'resolved')
                    AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (item_id,),
            )
            item = cursor.fetchone()

            if not item:
                abort(404)

            if item["user_id"] == session["user_id"]:
                flash("不能申请自己发布的信息", "error")
                return redirect(url_for("item_detail", item_id=item_id))

            if request.method == "POST":
                message = clean_long_text(request.form.get("message"), 1000)
                contact = clean_text(request.form.get("contact"), 120)

                if not message:
                    error = "申请说明不能为空"
                elif not contact:
                    error = "联系方式不能为空"
                else:
                    cursor.execute(
                        """
                        SELECT id
                        FROM claim_request
                        WHERE item_id = %s AND applicant_id = %s AND status = 'pending'
                        """,
                        (item_id, session["user_id"]),
                    )
                    existing_claim = cursor.fetchone()

                    if existing_claim:
                        error = "你已经提交过待处理申请，请等待发布者处理"
                    else:
                        cursor.execute(
                            """
                            INSERT INTO claim_request
                                (item_id, applicant_id, owner_id, message, contact)
                            VALUES (%s, %s, %s, %s, %s)
                            """,
                            (
                                item_id,
                                session["user_id"],
                                item["user_id"],
                                message,
                                contact,
                            ),
                        )
                        connection.commit()
                        write_operation_log("提交认领申请", f"对信息 ID：{item_id} 提交认领申请")
                        create_notification(
                            item["user_id"],
                            "收到新的认领申请",
                            f"你发布的“{item['title']}”收到一条新的认领申请，请及时处理。",
                        )
                        flash("申请已提交，请等待发布者处理", "success")
                        return redirect(url_for("item_detail", item_id=item_id))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }

    content = """
    <section class="form-section">
        <div class="container form-layout">
            <div class="form-intro">
                <p class="hero-label">Claim Request</p>
                <h1>提交申请</h1>
                <p>请填写申请说明和可联系到你的方式，发布者会在收到申请后进行处理。</p>
            </div>

            <div class="form-box claim-form">
                {% if error %}
                <p class="notice notice-error">{{ error }}</p>
                {% endif %}

                {% if item %}
                <div class="claim-target">
                    <span class="type-tag">{{ type_map.get(item.item_type, item.item_type) }}</span>
                    <strong>{{ item.title }}</strong>
                    <p>{{ item.category or "未填写分类" }} · {{ item.location or "未填写地点" }}</p>
                </div>
                {% endif %}

                {% if item %}
                <form class="register-form" method="post" action="{{ url_for('submit_claim', item_id=item.id) }}">
                    <label>
                        申请说明
                        <textarea name="message" rows="6" placeholder="请说明你认领或联系的理由" required>{{ request.form.get("message", "") }}</textarea>
                    </label>

                    <label>
                        联系方式
                        <input type="text" name="contact" value="{{ request.form.get('contact', '') }}" placeholder="手机号、邮箱或其他联系方式" required>
                    </label>

                    <button class="btn btn-form" type="submit">提交申请</button>
                    <a class="back-link form-back-link" href="{{ url_for('item_detail', item_id=item.id) }}">返回详情</a>
                </form>
                {% endif %}
            </div>
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        item=item,
        request=request,
        type_map=type_map,
    )
    return render_page("提交申请 - 校园失物招领平台", page_content)


@app.route("/my_claims")
def my_claims():
    if "user_id" not in session:
        flash("请先登录后查看我的申请", "warning")
        return redirect(url_for("login"))

    error = ""
    claims = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    claim_request.id, claim_request.message, claim_request.contact,
                    claim_request.status, claim_request.created_at,
                    item.id AS item_id, item.title, item.item_type,
                    item.category, item.location
                FROM claim_request
                JOIN item ON claim_request.item_id = item.id
                WHERE
                    claim_request.applicant_id = %s
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                ORDER BY claim_request.created_at DESC
                """,
                (session["user_id"],),
            )
            claims = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    type_map = {
        "lost": "失物",
        "found": "招领",
    }
    claim_status_map = {
        "pending": "待处理",
        "approved": "已同意",
        "rejected": "已拒绝",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">My Claims</p>
                <h1>我的申请</h1>
                <p>这里展示你提交过的认领或联系申请。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not claims %}
            <div class="empty-state">暂无申请记录</div>
            {% else %}
            <div class="claim-list">
                {% for claim in claims %}
                <article class="claim-card">
                    <div class="claim-card-head">
                        <div>
                            <span class="type-tag">{{ type_map.get(claim.item_type, claim.item_type) }}</span>
                            <h2><a class="item-title-link" href="{{ url_for('item_detail', item_id=claim.item_id) }}">{{ claim.title }}</a></h2>
                        </div>
                        <span class="status-tag status-{{ claim.status }}">{{ claim_status_map.get(claim.status, claim.status) }}</span>
                    </div>
                    <dl class="item-meta claim-meta">
                        <div>
                            <dt>分类</dt>
                            <dd>{{ claim.category or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>地点</dt>
                            <dd>{{ claim.location or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>申请说明</dt>
                            <dd>{{ claim.message }}</dd>
                        </div>
                        <div>
                            <dt>联系方式</dt>
                            <dd>{{ claim.contact }}</dd>
                        </div>
                        <div>
                            <dt>申请时间</dt>
                            <dd>{{ claim.created_at }}</dd>
                        </div>
                    </dl>
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        claim_status_map=claim_status_map,
        claims=claims,
        error=error,
        type_map=type_map,
    )
    return render_page("我的申请 - 校园失物招领平台", page_content)


@app.route("/received_claims")
def received_claims():
    if "user_id" not in session:
        flash("请先登录后查看收到的申请", "warning")
        return redirect(url_for("login"))

    error = ""
    claims = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    claim_request.id, claim_request.message, claim_request.contact,
                    claim_request.status, claim_request.created_at,
                    item.id AS item_id, item.title,
                    applicant.username, applicant.real_name, applicant.student_id
                FROM claim_request
                JOIN item ON claim_request.item_id = item.id
                JOIN `user` AS applicant ON claim_request.applicant_id = applicant.id
                WHERE
                    claim_request.owner_id = %s
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                ORDER BY claim_request.created_at DESC
                """,
                (session["user_id"],),
            )
            claims = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    claim_status_map = {
        "pending": "待处理",
        "approved": "已同意",
        "rejected": "已拒绝",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Received Claims</p>
                <h1>收到的申请</h1>
                <p>这里展示其他同学对你发布信息提交的申请。</p>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not claims %}
            <div class="empty-state">暂无收到的申请</div>
            {% else %}
            <div class="claim-list">
                {% for claim in claims %}
                <article class="claim-card">
                    <div class="claim-card-head">
                        <div>
                            <span class="hero-label">申请人：{{ claim.username }}</span>
                            <h2><a class="item-title-link" href="{{ url_for('item_detail', item_id=claim.item_id) }}">{{ claim.title }}</a></h2>
                        </div>
                        <span class="status-tag status-{{ claim.status }}">{{ claim_status_map.get(claim.status, claim.status) }}</span>
                    </div>
                    <dl class="item-meta claim-meta">
                        <div>
                            <dt>真实姓名</dt>
                            <dd>{{ claim.real_name or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>学号</dt>
                            <dd>{{ claim.student_id or "未填写" }}</dd>
                        </div>
                        <div>
                            <dt>申请说明</dt>
                            <dd>{{ claim.message }}</dd>
                        </div>
                        <div>
                            <dt>联系方式</dt>
                            <dd>{{ claim.contact }}</dd>
                        </div>
                        <div>
                            <dt>申请时间</dt>
                            <dd>{{ claim.created_at }}</dd>
                        </div>
                    </dl>

                    {% if claim.status == "pending" %}
                    <div class="claim-actions">
                        <form class="inline-form" method="post" action="{{ url_for('approve_claim', claim_id=claim.id) }}">
                            <button class="owner-btn resolve-owner-btn" type="submit">同意</button>
                        </form>
                        <form class="inline-form" method="post" action="{{ url_for('reject_claim', claim_id=claim.id) }}">
                            <button class="owner-btn delete-owner-btn" type="submit">拒绝</button>
                        </form>
                    </div>
                    {% endif %}
                </article>
                {% endfor %}
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        claim_status_map=claim_status_map,
        claims=claims,
        error=error,
    )
    return render_page("收到的申请 - 校园失物招领平台", page_content)


@app.route("/claim/<int:claim_id>/approve", methods=["POST"])
def approve_claim(claim_id):
    if "user_id" not in session:
        flash("请先登录后处理申请", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    claim_request.id, claim_request.applicant_id,
                    claim_request.owner_id, claim_request.status,
                    item.title
                FROM claim_request
                JOIN item ON claim_request.item_id = item.id
                WHERE
                    claim_request.id = %s
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                """,
                (claim_id,),
            )
            claim = cursor.fetchone()

            if not claim or claim["owner_id"] != session["user_id"]:
                abort(403)

            if claim["status"] != "pending":
                flash("该申请已经处理过", "warning")
                return redirect(url_for("received_claims"))

            cursor.execute(
                "UPDATE claim_request SET status = 'approved' WHERE id = %s",
                (claim_id,),
            )
            connection.commit()
        write_operation_log("同意认领申请", f"同意申请 ID：{claim_id}")
        create_notification(
            claim["applicant_id"],
            "认领申请已同意",
            f"你对“{claim['title']}”提交的申请已被发布者同意。",
        )
        flash("已同意申请", "success")
        return redirect(url_for("received_claims"))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("received_claims"))
    finally:
        if connection:
            connection.close()


@app.route("/claim/<int:claim_id>/reject", methods=["POST"])
def reject_claim(claim_id):
    if "user_id" not in session:
        flash("请先登录后处理申请", "warning")
        return redirect(url_for("login"))

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    claim_request.id, claim_request.applicant_id,
                    claim_request.owner_id, claim_request.status,
                    item.title
                FROM claim_request
                JOIN item ON claim_request.item_id = item.id
                WHERE
                    claim_request.id = %s
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                """,
                (claim_id,),
            )
            claim = cursor.fetchone()

            if not claim or claim["owner_id"] != session["user_id"]:
                abort(403)

            if claim["status"] != "pending":
                flash("该申请已经处理过", "warning")
                return redirect(url_for("received_claims"))

            cursor.execute(
                "UPDATE claim_request SET status = 'rejected' WHERE id = %s",
                (claim_id,),
            )
            connection.commit()
        write_operation_log("拒绝认领申请", f"拒绝申请 ID：{claim_id}")
        create_notification(
            claim["applicant_id"],
            "认领申请已拒绝",
            f"你对“{claim['title']}”提交的申请已被发布者拒绝。",
        )
        flash("已拒绝申请", "success")
        return redirect(url_for("received_claims"))
    except HTTPException:
        raise
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("received_claims"))
    finally:
        if connection:
            connection.close()


@app.route("/admin/claims")
def admin_claims():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    claims = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    claim_request.id, claim_request.contact,
                    claim_request.status, claim_request.created_at,
                    item.title,
                    applicant.username AS applicant_username,
                    owner.username AS owner_username
                FROM claim_request
                JOIN item ON claim_request.item_id = item.id
                JOIN `user` AS applicant ON claim_request.applicant_id = applicant.id
                JOIN `user` AS owner ON claim_request.owner_id = owner.id
                WHERE item.is_deleted = 0 OR item.is_deleted IS NULL
                ORDER BY claim_request.created_at DESC
                """
            )
            claims = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    claim_status_map = {
        "pending": "待处理",
        "approved": "已同意",
        "rejected": "已拒绝",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Claim Management</p>
                <h1>认领申请管理</h1>
                <p>查看所有认领和联系申请的处理状态。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not claims %}
            <div class="empty-state">暂无认领申请</div>
            {% else %}
            <div class="admin-table-wrap">
                <table class="admin-table claim-admin-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>物品标题</th>
                            <th>申请人</th>
                            <th>发布者</th>
                            <th>联系方式</th>
                            <th>状态</th>
                            <th>申请时间</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for claim in claims %}
                        <tr>
                            <td>{{ claim.id }}</td>
                            <td>{{ claim.title }}</td>
                            <td>{{ claim.applicant_username }}</td>
                            <td>{{ claim.owner_username }}</td>
                            <td>{{ claim.contact }}</td>
                            <td><span class="status-tag status-{{ claim.status }}">{{ claim_status_map.get(claim.status, claim.status) }}</span></td>
                            <td>{{ claim.created_at }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        claim_status_map=claim_status_map,
        claims=claims,
        error=error,
    )
    return render_page("认领申请管理 - 校园失物招领平台", page_content)


@app.route("/admin/reports")
def admin_reports():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    reports = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    report.id, report.reason, report.description,
                    report.status, report.created_at,
                    item.title AS item_title,
                    reporter.username AS reporter_username
                FROM report
                JOIN item ON report.item_id = item.id
                JOIN `user` AS reporter ON report.reporter_id = reporter.id
                WHERE item.is_deleted = 0 OR item.is_deleted IS NULL
                ORDER BY report.created_at DESC
                """
            )
            reports = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    report_status_map = {
        "pending": "待处理",
        "handled": "已处理",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">Report Management</p>
                <h1>举报管理</h1>
                <p>查看同学提交的违规信息举报，并进行处理。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% elif not reports %}
            <div class="empty-state">暂无举报记录</div>
            {% else %}
            <div class="admin-table-wrap">
                <table class="admin-table report-admin-table">
                    <thead>
                        <tr>
                            <th>举报 ID</th>
                            <th>物品标题</th>
                            <th>举报人</th>
                            <th>举报原因</th>
                            <th>补充说明</th>
                            <th>举报状态</th>
                            <th>举报时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for report in reports %}
                        <tr>
                            <td>{{ report.id }}</td>
                            <td>{{ report.item_title }}</td>
                            <td>{{ report.reporter_username }}</td>
                            <td>{{ report.reason }}</td>
                            <td>{{ report.description or "无" }}</td>
                            <td><span class="status-tag status-{{ report.status }}">{{ report_status_map.get(report.status, report.status) }}</span></td>
                            <td>{{ report.created_at }}</td>
                            <td>
                                {% if report.status == "pending" %}
                                <div class="admin-row-actions">
                                    <form class="inline-form" method="post" action="{{ url_for('handle_report', report_id=report.id) }}">
                                        <button class="admin-btn approve-btn small-btn" type="submit">标记已处理</button>
                                    </form>
                                    <form class="inline-form" method="post" action="{{ url_for('delete_reported_item', report_id=report.id) }}">
                                        <button class="admin-btn delete-btn small-btn" type="submit" onclick="return confirm('确定要删除这条被举报信息吗？')">删除被举报信息</button>
                                    </form>
                                </div>
                                {% else %}
                                <span>已处理</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        report_status_map=report_status_map,
        reports=reports,
    )
    return render_page("举报管理 - 校园失物招领平台", page_content)


@app.route("/admin/report/<int:report_id>/handle", methods=["POST"])
def handle_report(report_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM report WHERE id = %s", (report_id,))
            report = cursor.fetchone()
            if not report:
                flash("举报记录不存在", "error")
                return redirect(url_for("admin_reports"))

            cursor.execute(
                "UPDATE report SET status = 'handled' WHERE id = %s",
                (report_id,),
            )
            connection.commit()
        write_operation_log("处理举报", f"处理举报 ID：{report_id}")
        flash("举报已标记为处理", "success")
        return redirect(url_for("admin_reports"))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("admin_reports"))
    finally:
        if connection:
            connection.close()


@app.route("/admin/report/<int:report_id>/delete_item", methods=["POST"])
def delete_reported_item(report_id):
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    report.item_id,
                    item.user_id,
                    item.title
                FROM report
                JOIN item ON report.item_id = item.id
                WHERE
                    report.id = %s
                    AND (item.is_deleted = 0 OR item.is_deleted IS NULL)
                """,
                (report_id,),
            )
            item = cursor.fetchone()

            if not item:
                flash("举报或被举报信息不存在", "error")
                return redirect(url_for("admin_reports"))

            cursor.execute(
                "UPDATE report SET status = 'handled' WHERE item_id = %s",
                (item["item_id"],),
            )
            cursor.execute(
                """
                UPDATE item
                SET is_deleted = 1, deleted_at = NOW(), deleted_by = %s
                WHERE id = %s AND (is_deleted = 0 OR is_deleted IS NULL)
                """,
                (session["user_id"], item["item_id"]),
            )
            connection.commit()
        write_operation_log("删除被举报信息", f"删除被举报信息 ID：{item['item_id']}")
        create_notification(
            item["user_id"],
            "信息被举报并删除",
            f"你发布的“{item['title']}”因举报处理已被管理员删除。",
        )
        flash("被举报信息已删除", "success")
        return redirect(url_for("admin_reports"))
    except Exception as exc:
        log_db_error(exc)
        flash(system_error_message(), "error")
        return redirect(url_for("admin_reports"))
    finally:
        if connection:
            connection.close()


@app.route("/admin/logs")
def admin_logs():
    if "user_id" not in session:
        flash("请先登录后访问后台", "warning")
        return redirect(url_for("login"))

    if not is_admin():
        abort(403)

    error = ""
    operation_logs = []
    login_logs = []
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, action, detail, ip_address, created_at
                FROM operation_log
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (50,),
            )
            operation_logs = cursor.fetchall()

            cursor.execute(
                """
                SELECT id, username, status, message, ip_address, created_at
                FROM login_log
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (50,),
            )
            login_logs = cursor.fetchall()
    except Exception as exc:
        log_db_error(exc)
        error = system_error_message()
        flash(error, "error")
    finally:
        if connection:
            connection.close()

    login_status_map = {
        "success": "登录成功",
        "failed": "登录失败",
        "pending": "待审核",
        "rejected": "已拒绝",
        "banned": "已封禁",
        "abnormal": "状态异常",
    }

    content = """
    <section class="items-section">
        <div class="container">
            <div class="section-heading">
                <p class="hero-label">System Logs</p>
                <h1>系统日志</h1>
                <p>查看最新的系统操作记录和登录记录。</p>
            </div>

            <div class="admin-actions center-actions">
                <a class="btn btn-form admin-entry secondary-admin-entry" href="{{ url_for('admin') }}">返回后台首页</a>
            </div>

            {% if error %}
            <p class="notice notice-error">{{ error }}</p>
            {% endif %}

            <section class="admin-section log-section">
                <div class="section-heading compact-heading">
                    <h2>操作日志</h2>
                </div>
                {% if operation_logs %}
                <div class="admin-table-wrap">
                    <table class="admin-table log-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>用户名</th>
                                <th>操作类型</th>
                                <th>详情</th>
                                <th>IP 地址</th>
                                <th>时间</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in operation_logs %}
                            <tr>
                                <td>{{ log.id }}</td>
                                <td>{{ log.username or "未登录用户" }}</td>
                                <td><span class="log-badge">{{ log.action }}</span></td>
                                <td>{{ log.detail or "无" }}</td>
                                <td>{{ log.ip_address or "未知" }}</td>
                                <td>{{ log.created_at }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% elif not error %}
                <div class="empty-state">暂无日志</div>
                {% endif %}
            </section>

            <section class="admin-section log-section">
                <div class="section-heading compact-heading">
                    <h2>登录日志</h2>
                </div>
                {% if login_logs %}
                <div class="admin-table-wrap">
                    <table class="admin-table log-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>用户名</th>
                                <th>状态</th>
                                <th>说明</th>
                                <th>IP 地址</th>
                                <th>时间</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for log in login_logs %}
                            <tr>
                                <td>{{ log.id }}</td>
                                <td>{{ log.username or "未填写" }}</td>
                                <td>
                                    <span class="log-badge login-status-{{ log.status }}">
                                        {{ login_status_map.get(log.status, log.status) }}
                                    </span>
                                </td>
                                <td>{{ log.message or "无" }}</td>
                                <td>{{ log.ip_address or "未知" }}</td>
                                <td>{{ log.created_at }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% elif not error %}
                <div class="empty-state">暂无日志</div>
                {% endif %}
            </section>
        </div>
    </section>
    """
    page_content = render_template_string(
        content,
        error=error,
        login_logs=login_logs,
        login_status_map=login_status_map,
        operation_logs=operation_logs,
    )
    return render_page("系统日志 - 校园失物招领平台", page_content)


@app.route("/logout")
def logout():
    write_operation_log("退出登录", "用户退出登录")
    session.clear()
    flash("退出登录成功", "success")
    return redirect(url_for("index"))


if __name__ == "__main__":
    # 仅开发环境使用 debug=True，上线部署时必须关闭调试模式。
    app.run(debug=True)







