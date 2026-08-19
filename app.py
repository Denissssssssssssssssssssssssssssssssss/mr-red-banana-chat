from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    jsonify,
    url_for,
)

from flask_socketio import (
    SocketIO,
    emit,
    join_room,
    leave_room,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

from supabase import create_client
from supabase.client import ClientOptions

import os
import random
import hashlib
from datetime import datetime, timezone


# =========================================================
# Flask
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-key"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RENDER", "").lower() == "true"
)


# =========================================================
# Socket.IO
# =========================================================

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


# =========================================================
# Environment variables
# =========================================================

SUPABASE_URL = os.environ.get("SUPABASE_URL")

SUPABASE_PUBLISHABLE_KEY = os.environ.get(
    "SUPABASE_PUBLISHABLE_KEY"
)

SUPABASE_SECRET_KEY = os.environ.get(
    "SUPABASE_SECRET_KEY"
)


if not SUPABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL が設定されていません"
    )

if not SUPABASE_PUBLISHABLE_KEY:
    raise RuntimeError(
        "SUPABASE_PUBLISHABLE_KEY が設定されていません"
    )

if not SUPABASE_SECRET_KEY:
    raise RuntimeError(
        "SUPABASE_SECRET_KEY が設定されていません"
    )


# =========================================================
# Supabase DB client
#
# Secret Keyはサーバー側だけで使用。
# ブラウザには絶対に出さない。
# =========================================================

db = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# =========================================================
# Flask Session Storage
#
# Supabase OAuth / PKCE用
# =========================================================

class FlaskSessionStorage:

    def get_item(self, key):
        return session.get(key)

    def set_item(self, key, value):
        session[key] = value

    def remove_item(self, key):
        session.pop(key, None)


# =========================================================
# Supabase Auth client
# =========================================================

def get_auth_client():

    options = ClientOptions(
        storage=FlaskSessionStorage(),
        flow_type="pkce"
    )

    return create_client(
        SUPABASE_URL,
        SUPABASE_PUBLISHABLE_KEY,
        options=options
    )


# =========================================================
# 内部Auth用メールアドレス
#
# ユーザーが実際のメールを登録しなくても、
# Supabase Authのemail/password認証を利用できるようにする。
#
# 実際のプロフィールのemailには保存しない。
# =========================================================

def make_internal_auth_email(username):

    normalized = username.strip().lower()

    digest = hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()

    return (
        "user-"
        + digest
        + "@auth.mr-red-banana.invalid"
    )


# =========================================================
# 現在のSupabaseユーザー
# =========================================================

def get_current_user():

    access_token = session.get(
        "access_token"
    )

    refresh_token = session.get(
        "refresh_token"
    )

    if not access_token:
        return None

    try:

        auth_client = get_auth_client()

        if refresh_token:

            auth_client.auth.set_session(
                access_token,
                refresh_token
            )

        else:

            auth_client.auth.set_session(
                access_token,
                ""
            )

        current_session = (
            auth_client
            .auth
            .get_session()
        )

        if (
            current_session
            and current_session.session
        ):

            current = (
                current_session.session
            )

            session["access_token"] = (
                current.access_token
            )

            if current.refresh_token:

                session["refresh_token"] = (
                    current.refresh_token
                )

            access_token = (
                current.access_token
            )

        response = (
            auth_client
            .auth
            .get_user(
                access_token
            )
        )

        user = response.user

        if not user:
            return None

        return user

    except Exception as e:

        print(
            "get_current_user error:",
            repr(e)
        )

        return None


# =========================================================
# プロフィール取得
# =========================================================

def get_profile(user_id):

    result = (
        db
        .table("profiles")
        .select(
            "id,username,email,created_at,tutorial_completed"
        )
        .eq(
            "id",
            user_id
        )
        .execute()
    )

    if result.data:
        return result.data[0]

    return None


# =========================================================
# プロフィール作成 / 確認
# =========================================================

def ensure_profile(user):

    user_id = str(user.id)

    profile = get_profile(user_id)

    if profile:
        return profile, False

    metadata = (
        user.user_metadata
        or {}
    )

    username = (
        metadata.get("username")
        or metadata.get("user_name")
        or metadata.get("preferred_username")
        or metadata.get("name")
        or (
            user.email.split("@")[0]
            if user.email
            else "User"
        )
    )

    username = str(username).strip()[:100]

    if not username:
        username = "User"

    existing = (
        db
        .table("profiles")
        .select("id")
        .eq(
            "username",
            username
        )
        .execute()
    )

    if existing.data:

        username = (
            username
            + "_"
            + user_id[:8]
        )

    result = (
        db
        .table("profiles")
        .insert(
            {
                "id": user_id,
                "username": username,
                "email": None,
                "tutorial_completed": False
            }
        )
        .execute()
    )

    if result.data:
        return result.data[0], True

    profile = get_profile(user_id)

    return profile, True


# =========================================================
# ログイン必須
# =========================================================

def require_user():

    user = get_current_user()

    if not user:
        return None

    ensure_profile(user)

    return user


# =========================================================
# 初回ログイン後の移動先
# =========================================================

def redirect_after_auth(
    user,
    newly_created=False
):

    profile, created = ensure_profile(user)

    # -----------------------------------------------------
    # 新規登録直後
    #
    # まずセキュリティメール設定画面へ。
    # -----------------------------------------------------

    if newly_created or created:

        session["new_registration"] = True

        return redirect(
            url_for("security_email")
        )

    # -----------------------------------------------------
    # 新規登録途中ならメール設定へ
    # -----------------------------------------------------

    if session.get(
        "new_registration",
        False
    ):

        return redirect(
            url_for("security_email")
        )

    # -----------------------------------------------------
    # 契約済みだがチュートリアル未完了
    # -----------------------------------------------------

    if not profile.get(
        "tutorial_completed",
        False
    ):

        return redirect(
            url_for("tutorial")
        )

    return redirect("/")


# =========================================================
# トップページ
# =========================================================

@app.route("/")
def index():

    user = get_current_user()

    if not user:

        return render_template(
            "auth.html"
        )

    profile, _ = ensure_profile(user)

    if not profile.get(
        "tutorial_completed",
        False
    ):

        return redirect(
            url_for("tutorial")
        )

    username = profile["username"]

    user_id = str(user.id)

    # -----------------------------------------------------
    # ルーム履歴
    # -----------------------------------------------------

    member_result = (
        db
        .table("room_members")
        .select(
            "room_id,note,joined_at"
        )
        .eq(
            "user_id",
            user_id
        )
        .order(
            "joined_at",
            desc=True
        )
        .execute()
    )

    room_history = []

    for member in (
        member_result.data or []
    ):

        room_uuid = str(
            member["room_id"]
        )

        room_result = (
            db
            .table("rooms")
            .select(
                "id,room_code"
            )
            .eq(
                "id",
                room_uuid
            )
            .execute()
        )

        if not room_result.data:
            continue

        room = room_result.data[0]

        settings_result = (
            db
            .table("room_settings")
            .select(
                "password_enabled"
            )
            .eq(
                "room_id",
                room_uuid
            )
            .execute()
        )

        locked = False

        if settings_result.data:

            locked = bool(
                settings_result
                .data[0]
                .get(
                    "password_enabled",
                    False
                )
            )

        room_history.append(
            (
                room["room_code"],
                member.get(
                    "note",
                    ""
                ),
                locked
            )
        )

    # -----------------------------------------------------
    # CREATERログ
    # -----------------------------------------------------

    creator_result = (
        db
        .table("creator_logs")
        .select(
            "id,message,created_at"
        )
        .order(
            "id",
            desc=True
        )
        .execute()
    )

    creator_logs = []

    for row in (
        creator_result.data or []
    ):

        creator_logs.append(
            (
                row["id"],
                row["message"]
            )
        )

    return render_template(
        "index.html",
        username=username,
        room_history=room_history,
        creator_logs=creator_logs
    )


# =========================================================
# 新規登録
#
# ユーザー入力：
#   ユーザーネーム
#   パスワード
#
# メールはここでは要求しない。
# Supabase Auth内部では内部用メールアドレスを使用。
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
def register():

    username = str(
        request.form.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    if not username or not password:

        return (
            "ユーザーネームとパスワードを入力してください"
        ), 400

    if len(username) > 100:

        return (
            "ユーザーネームが長すぎます"
        ), 400

    if len(password) < 6:

        return (
            "パスワードは6文字以上にしてください"
        ), 400

    try:

        # -------------------------------------------------
        # profiles側でユーザーネーム重複確認
        # -------------------------------------------------

        existing_profile = (
            db
            .table("profiles")
            .select("id")
            .eq(
                "username",
                username
            )
            .execute()
        )

        if existing_profile.data:

            return (
                "そのユーザーネームはすでに使用されています"
            ), 400

        # -------------------------------------------------
        # Supabase Auth用の内部メール
        # -------------------------------------------------

        internal_email = (
            make_internal_auth_email(
                username
            )
        )

        # -------------------------------------------------
        # Supabase Admin APIでユーザー作成
        #
        # email_confirm=True
        # → 実メール確認は要求しない。
        # -------------------------------------------------

        response = (
            db
            .auth
            .admin
            .create_user(
                {
                    "email":
                        internal_email,

                    "password":
                        password,

                    "email_confirm":
                        True,

                    "user_metadata":
                        {
                            "username":
                                username
                        }
                }
            )
        )

        user = response.user

        if not user:

            return (
                "ユーザーを作成できませんでした"
            ), 400

        # -------------------------------------------------
        # profiles作成
        #
        # emailはNone。
        # 本物のメールはまだ登録されていない。
        # -------------------------------------------------

        profile_result = (
            db
            .table("profiles")
            .insert(
                {
                    "id":
                        str(user.id),

                    "username":
                        username,

                    "email":
                        None,

                    "tutorial_completed":
                        False
                }
            )
            .execute()
        )

        if not profile_result.data:

            # プロフィール作成失敗時はAuthユーザーも削除
            try:

                db.auth.admin.delete_user(
                    str(user.id)
                )

            except Exception as delete_error:

                print(
                    "rollback user error:",
                    repr(delete_error)
                )

            return (
                "プロフィールを作成できませんでした"
            ), 500

        # -------------------------------------------------
        # 作成したユーザーでログイン
        # -------------------------------------------------

        auth_client = get_auth_client()

        login_response = (
            auth_client
            .auth
            .sign_in_with_password(
                {
                    "email":
                        internal_email,

                    "password":
                        password
                }
            )
        )

        auth_session = (
            login_response.session
        )

        if not auth_session:

            return (
                "登録は完了しましたが、"
                "ログインセッションを作成できませんでした"
            ), 500

        session["access_token"] = (
            auth_session.access_token
        )

        session["refresh_token"] = (
            auth_session.refresh_token
        )

        session["new_registration"] = True

        session.modified = True

        print(
            "registration success:",
            username,
            str(user.id)
        )

        return redirect(
            url_for("security_email")
        )

    except Exception as e:

        print(
            "register error:",
            repr(e)
        )

        return (
            "新規登録に失敗しました: "
            + str(e)
        ), 400


# =========================================================
# ログイン
#
# 入力欄はユーザーネーム。
# profilesからユーザーIDを探し、
# Authユーザーの内部メールを取得してログイン。
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
def login():

    username = str(
        request.form.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    if not username or not password:

        return (
            "ユーザーネームとパスワードを入力してください"
        ), 400

    try:

        # -------------------------------------------------
        # profilesからユーザーを探す
        # -------------------------------------------------

        profile_result = (
            db
            .table("profiles")
            .select(
                "id,username,email,created_at,tutorial_completed"
            )
            .eq(
                "username",
                username
            )
            .execute()
        )

        if not profile_result.data:

            return (
                "ログインに失敗しました"
            ), 401

        profile = profile_result.data[0]

        user_id = str(
            profile["id"]
        )

        # -------------------------------------------------
        # Authユーザーを取得
        # -------------------------------------------------

        admin_user_response = (
            db
            .auth
            .admin
            .get_user_by_id(
                user_id
            )
        )

        auth_user = (
            admin_user_response.user
        )

        if not auth_user:

            return (
                "ログインに失敗しました"
            ), 401

        # -------------------------------------------------
        # Auth側に保存されているメール
        #
        # 新仕様では内部メール。
        # 旧ユーザーなど実メールの場合にも対応。
        # -------------------------------------------------

        auth_email = auth_user.email

        if not auth_email:

            return (
                "ログインに失敗しました"
            ), 401

        # -------------------------------------------------
        # Supabase Authログイン
        # -------------------------------------------------

        auth_client = get_auth_client()

        response = (
            auth_client
            .auth
            .sign_in_with_password(
                {
                    "email":
                        auth_email,

                    "password":
                        password
                }
            )
        )

        auth_session = response.session
        user = response.user

        if not auth_session or not user:

            return (
                "ログインに失敗しました"
            ), 401

        session["access_token"] = (
            auth_session.access_token
        )

        session["refresh_token"] = (
            auth_session.refresh_token
        )

        session.modified = True

        print(
            "login success:",
            username,
            str(user.id)
        )

        # -------------------------------------------------
        # 新規登録途中ならセキュリティ画面へ
        # -------------------------------------------------

        if session.get(
            "new_registration",
            False
        ):

            return redirect(
                url_for("security_email")
            )

        # -------------------------------------------------
        # チュートリアル未完了
        # -------------------------------------------------

        if not profile.get(
            "tutorial_completed",
            False
        ):

            return redirect(
                url_for("tutorial")
            )

        return redirect("/")

    except Exception as e:

        print(
            "login error:",
            repr(e)
        )

        return (
            "ログインに失敗しました"
        ), 401


# =========================================================
# セキュリティメール設定画面
# =========================================================

@app.route(
    "/security_email",
    methods=["GET", "POST"]
)
def security_email():

    user = require_user()

    if not user:

        return redirect("/")

    # -----------------------------------------------------
    # POST
    # -----------------------------------------------------

    if request.method == "POST":

        email = str(
            request.form.get(
                "email",
                ""
            )
        ).strip()

        # -------------------------------------------------
        # 空欄の場合
        # -------------------------------------------------

        if not email:

            return redirect(
                url_for("terms")
            )

        # -------------------------------------------------
        # 簡易メール形式確認
        # -------------------------------------------------

        if (
            "@" not in email
            or "." not in email.split("@")[-1]
        ):

            return (
                "有効なメールアドレスを入力してください"
            ), 400

        try:

            # -------------------------------------------------
            # profiles.email に保存
            # -------------------------------------------------

            (
                db
                .table("profiles")
                .update(
                    {
                        "email":
                            email
                    }
                )
                .eq(
                    "id",
                    str(user.id)
                )
                .execute()
            )

            print(
                "security email saved:",
                str(user.id)
            )

            # -------------------------------------------------
            # 契約へ
            # -------------------------------------------------

            return redirect(
                url_for("terms")
            )

        except Exception as e:

            print(
                "security email error:",
                repr(e)
            )

            return (
                "メールアドレスの保存に失敗しました"
            ), 500

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    profile, _ = ensure_profile(user)

    return render_template(
        "security_email.html",
        profile=profile
    )


# =========================================================
# セキュリティメールをスキップ
# =========================================================

@app.route(
    "/skip_security_email"
)
def skip_security_email():

    user = require_user()

    if not user:

        return redirect("/")

    # -----------------------------------------------------
    # emailはNULLのまま
    # -----------------------------------------------------

    return redirect(
        url_for("terms")
    )


# =========================================================
# OAuth開始
#
# security_email.htmlから呼び出される。
# =========================================================

@app.route(
    "/auth/<provider>"
)
def oauth_login(provider):

    allowed_providers = {
        "google",
        "github",
        "azure"
    }

    if provider not in allowed_providers:

        return (
            "対応していないログイン方法です"
        ), 400

    try:

        auth_client = get_auth_client()

        # -------------------------------------------------
        # 既にログイン中なら、
        # 「アカウントを追加する」意図として記録。
        # -------------------------------------------------

        current_user = get_current_user()

        if current_user:

            session["oauth_linking"] = True

        else:

            session["oauth_linking"] = False

        redirect_url = url_for(
            "oauth_callback",
            _external=True
        )

        response = (
            auth_client
            .auth
            .sign_in_with_oauth(
                {
                    "provider":
                        provider,

                    "options":
                        {
                            "redirect_to":
                                redirect_url
                        }
                }
            )
        )

        return redirect(
            response.url
        )

    except Exception as e:

        print(
            "OAuth start error:",
            repr(e)
        )

        return (
            "OAuthログインを開始できませんでした"
        ), 500


# =========================================================
# OAuth callback
# =========================================================

@app.route(
    "/auth/callback"
)
def oauth_callback():

    error = request.args.get(
        "error"
    )

    if error:

        description = request.args.get(
            "error_description",
            error
        )

        return (
            "ログインに失敗しました: "
            + description
        ), 400

    code = request.args.get(
        "code"
    )

    if not code:

        return (
            "認証コードがありません"
        ), 400

    try:

        auth_client = get_auth_client()

        # -------------------------------------------------
        # OAuth / PKCEコード交換
        # -------------------------------------------------

        response = (
            auth_client
            .auth
            .exchange_code_for_session(
                {
                    "auth_code":
                        code
                }
            )
        )

        auth_session = response.session
        user = response.user

        if not auth_session:

            return (
                "認証セッションを取得できませんでした"
            ), 500

        session["access_token"] = (
            auth_session.access_token
        )

        session["refresh_token"] = (
            auth_session.refresh_token
        )

        session.modified = True

        if not user:

            user_response = (
                auth_client
                .auth
                .get_user(
                    auth_session.access_token
                )
            )

            user = user_response.user

        if not user:

            return (
                "ユーザー情報を取得できませんでした"
            ), 500

        # -------------------------------------------------
        # OAuthで取得したメール
        # -------------------------------------------------

        oauth_email = (
            user.email
            if user.email
            else None
        )

        # -------------------------------------------------
        # 既存の新規登録ユーザーが
        # OAuthボタンを押した場合
        #
        # profiles.email にOAuthメールを保存する。
        #
        # ※OAuthアカウント自体の完全なID統合は、
        # SupabaseのManual Linking設定が必要。
        # -------------------------------------------------

        if session.get(
            "oauth_linking",
            False
        ):

            current_profile_id = session.get(
                "oauth_linking_user_id"
            )

            # 現在のログインユーザーIDを
            # OAuth開始前に保存していなかった場合は、
            # 新しく認証されたユーザーを使用する。

            if not current_profile_id:

                current_profile_id = str(
                    user.id
                )

            if oauth_email:

                try:

                    (
                        db
                        .table("profiles")
                        .update(
                            {
                                "email":
                                    oauth_email
                            }
                        )
                        .eq(
                            "id",
                            current_profile_id
                        )
                        .execute()
                    )

                except Exception as e:

                    print(
                        "OAuth email save error:",
                        repr(e)
                    )

            session["oauth_linking"] = False
            session.pop(
                "oauth_linking_user_id",
                None
            )

            # 新規登録途中なら契約へ
            if session.get(
                "new_registration",
                False
            ):

                return redirect(
                    url_for("terms")
                )

            return redirect("/")

        # -------------------------------------------------
        # 通常OAuthログイン
        # -------------------------------------------------

        profile, created = (
            ensure_profile(user)
        )

        if created:

            # OAuthユーザーの実メールを
            # profiles.email に保存
            if oauth_email:

                try:

                    (
                        db
                        .table("profiles")
                        .update(
                            {
                                "email":
                                    oauth_email
                            }
                        )
                        .eq(
                            "id",
                            str(user.id)
                        )
                        .execute()
                    )

                except Exception as e:

                    print(
                        "OAuth profile email error:",
                        repr(e)
                    )

            session["new_registration"] = True

            return redirect(
                url_for("terms")
            )

        return redirect_after_auth(
            user,
            newly_created=False
        )

    except Exception as e:

        print(
            "OAuth callback error:",
            repr(e)
        )

        return (
            "OAuthログイン処理でエラーが発生しました"
        ), 500


# =========================================================
# 契約画面
# =========================================================

@app.route(
    "/terms"
)
def terms():

    user = require_user()

    if not user:

        return redirect("/")

    profile, _ = ensure_profile(user)

    if profile.get(
        "tutorial_completed",
        False
    ):

        return redirect("/")

    return render_template(
        "terms.html"
    )


# =========================================================
# 契約同意
# =========================================================

@app.route(
    "/accept_terms",
    methods=["POST"]
)
def accept_terms():

    user = require_user()

    if not user:

        return redirect("/")

    session["terms_accepted"] = True

    return redirect(
        url_for("tutorial")
    )


# =========================================================
# チュートリアル
# =========================================================

@app.route(
    "/tutorial"
)
def tutorial():

    user = require_user()

    if not user:

        return redirect("/")

    profile, _ = ensure_profile(user)

    if profile.get(
        "tutorial_completed",
        False
    ):

        return redirect("/")

    # 新規登録ユーザーの場合、
    # 契約同意が必要。

    if (
        session.get(
            "new_registration",
            False
        )
        and not session.get(
            "terms_accepted",
            False
        )
    ):

        return redirect(
            url_for("terms")
        )

    return render_template(
        "tutorial.html"
    )


# =========================================================
# チュートリアル完了
# =========================================================

@app.route(
    "/complete_tutorial",
    methods=["POST"]
)
def complete_tutorial():

    user = require_user()

    if not user:

        return redirect("/")

    # -----------------------------------------------------
    # 新規登録ユーザーの場合は契約同意を確認
    # -----------------------------------------------------

    if (
        not session.get(
            "terms_accepted",
            False
        )
        and session.get(
            "new_registration",
            False
        )
    ):

        return redirect(
            url_for("terms")
        )

    (
        db
        .table("profiles")
        .update(
            {
                "tutorial_completed": True
            }
        )
        .eq(
            "id",
            str(user.id)
        )
        .execute()
    )

    session.pop(
        "new_registration",
        None
    )

    session.pop(
        "terms_accepted",
        None
    )

    return redirect("/")


# =========================================================
# ログアウト
# =========================================================

@app.route(
    "/logout"
)
def logout():

    try:

        auth_client = get_auth_client()

        auth_client.auth.sign_out()

    except Exception as e:

        print(
            "logout error:",
            repr(e)
        )

    session.clear()

    return redirect("/")


# =========================================================
# 通話ページ
# =========================================================

@app.route(
    "/call/<room_code>"
)
def call(room_code):

    user = require_user()

    if not user:

        return redirect("/")

    return render_template(
        "call.html",
        room_id=room_code
    )


# =========================================================
# room_code → UUID
# =========================================================

def get_room_by_code(room_code):

    result = (
        db
        .table("rooms")
        .select(
            "id,room_code,created_by,created_at"
        )
        .eq(
            "room_code",
            room_code
        )
        .execute()
    )

    if not result.data:

        return None

    return result.data[0]


# =========================================================
# ルームコード生成
# =========================================================

def generate_room_code():

    while True:

        room_code = str(
            random.randint(
                1000000000,
                9999999999
            )
        )

        result = (
            db
            .table("rooms")
            .select("id")
            .eq(
                "room_code",
                room_code
            )
            .execute()
        )

        if not result.data:

            return room_code


# =========================================================
# メモ保存
# =========================================================

@app.route(
    "/save_note",
    methods=["POST"]
)
def save_note():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    note = str(
        data.get("note", "")
    )

    room = get_room_by_code(room_code)

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    (
        db
        .table("room_members")
        .update(
            {
                "note": note
            }
        )
        .eq(
            "room_id",
            room["id"]
        )
        .eq(
            "user_id",
            str(user.id)
        )
        .execute()
    )

    return jsonify(
        {
            "status": "ok"
        }
    )


# =========================================================
# 履歴削除
# =========================================================

@app.route(
    "/delete_room",
    methods=["POST"]
)
def delete_room():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    room = get_room_by_code(room_code)

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    (
        db
        .table("room_members")
        .delete()
        .eq(
            "room_id",
            room["id"]
        )
        .eq(
            "user_id",
            str(user.id)
        )
        .execute()
    )

    return jsonify(
        {
            "status": "ok"
        }
    )


# =========================================================
# ルームパスワード設定
# =========================================================

@app.route(
    "/set_room_password",
    methods=["POST"]
)
def set_room_password():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ログインしてください"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    enabled = bool(
        data.get("enabled", False)
    )

    new_password = str(
        data.get("password", "")
    )

    room = get_room_by_code(room_code)

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    room_uuid = str(room["id"])

    settings_result = (
        db
        .table("room_settings")
        .select(
            "password_enabled,"
            "password_hash,"
            "password_changed_at"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    if settings_result.data:

        settings = settings_result.data[0]

    else:

        settings = {
            "password_enabled": False,
            "password_hash": None,
            "password_changed_at": None
        }

    old_password_hash = (
        settings.get("password_hash")
    )

    # -----------------------------------------------------
    # OFF
    # -----------------------------------------------------

    if not enabled:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled": False,
                    "updated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                }
            )
            .eq(
                "room_id",
                room_uuid
            )
            .execute()
        )

        return jsonify(
            {
                "status": "ok",
                "password_changed": False
            }
        )

    # -----------------------------------------------------
    # 既存パスワードを再利用
    # -----------------------------------------------------

    if old_password_hash:

        (
            db
            .table("room_settings")
            .update(
                {
                    "password_enabled": True,
                    "updated_at":
                        datetime.now(
                            timezone.utc
                        ).isoformat()
                }
            )
            .eq(
                "room_id",
                room_uuid
            )
            .execute()
        )

        return jsonify(
            {
                "status": "ok",
                "password_changed": False
            }
        )

    # -----------------------------------------------------
    # 初回設定
    # -----------------------------------------------------

    if not new_password:

        return jsonify(
            {
                "status": "error",
                "message":
                    "初回はパスワードを入力してください"
            }
        ), 400

    now = datetime.now(
        timezone.utc
    )

    (
        db
        .table("room_settings")
        .update(
            {
                "password_enabled": True,
                "password_hash":
                    generate_password_hash(
                        new_password
                    ),
                "password_changed_at":
                    now.isoformat(),
                "updated_at":
                    now.isoformat()
            }
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    return jsonify(
        {
            "status": "ok",
            "password_changed": True
        }
    )


# =========================================================
# パスワード変更
# =========================================================

@app.route(
    "/change_room_password",
    methods=["POST"]
)
def change_room_password():

    user = require_user()

    if not user:

        return jsonify(
            {
                "status": "error"
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    new_password = str(
        data.get("password", "")
    )

    if not new_password:

        return jsonify(
            {
                "status": "error",
                "message":
                    "パスワードを入力してください"
            }
        ), 400

    room = get_room_by_code(room_code)

    if not room:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルームが存在しません"
            }
        ), 404

    room_uuid = str(room["id"])

    result = (
        db
        .table("room_settings")
        .select(
            "password_changed_at"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    if not result.data:

        return jsonify(
            {
                "status": "error",
                "message":
                    "ルーム設定がありません"
            }
        ), 404

    changed_at = (
        result.data[0]
        .get("password_changed_at")
    )

    if changed_at:

        try:

            old_time = datetime.fromisoformat(
                changed_at.replace(
                    "Z",
                    "+00:00"
                )
            )

            now = datetime.now(
                timezone.utc
            )

            elapsed = (
                now - old_time
            ).total_seconds()

            if elapsed < 7200:

                remaining = int(
                    7200 - elapsed
                )

                minutes = (
                    remaining // 60
                )

                return jsonify(
                    {
                        "status": "error",
                        "message":
                            "パスワード変更は"
                            f"あと約{minutes}分後です"
                    }
                ), 429

        except Exception:
            pass

    now = datetime.now(
        timezone.utc
    )

    (
        db
        .table("room_settings")
        .update(
            {
                "password_hash":
                    generate_password_hash(
                        new_password
                    ),
                "password_changed_at":
                    now.isoformat(),
                "updated_at":
                    now.isoformat()
            }
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    return jsonify(
        {
            "status": "ok",
            "message":
                "パスワードを変更しました"
        }
    )


# =========================================================
# 参加前パスワード確認
# =========================================================

@app.route(
    "/check_room_password",
    methods=["POST"]
)
def check_room_password():

    user = require_user()

    if not user:

        return jsonify(
            {
                "ok": False
            }
        ), 401

    data = request.get_json() or {}

    room_code = str(
        data.get("room", "")
    )

    password = str(
        data.get("password", "")
    )

    room = get_room_by_code(room_code)

    if not room:

        return jsonify(
            {
                "ok": False
            }
        )

    room_uuid = str(room["id"])
    user_id = str(user.id)

    member_result = (
        db
        .table("room_members")
        .select("id")
        .eq(
            "room_id",
            room_uuid
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )

    if member_result.data:

        return jsonify(
            {
                "ok": True
            }
        )

    settings_result = (
        db
        .table("room_settings")
        .select(
            "password_enabled,"
            "password_hash"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .execute()
    )

    if not settings_result.data:

        return jsonify(
            {
                "ok": True
            }
        )

    settings = settings_result.data[0]

    enabled = bool(
        settings.get(
            "password_enabled",
            False
        )
    )

    password_hash = (
        settings.get("password_hash")
    )

    if not enabled:

        return jsonify(
            {
                "ok": True
            }
        )

    if not password_hash:

        return jsonify(
            {
                "ok": False
            }
        )

    if check_password_hash(
        password_hash,
        password
    ):

        return jsonify(
            {
                "ok": True
            }
        )

    return jsonify(
        {
            "ok": False
        }
    )


# =========================================================
# ルーム作成
# =========================================================

@socketio.on(
    "create_room"
)
def create_room():

    user = require_user()

    if not user:
        return

    user_id = str(user.id)

    room_code = generate_room_code()

    result = (
        db
        .table("rooms")
        .insert(
            {
                "room_code": room_code,
                "created_by": user_id
            }
        )
        .execute()
    )

    if not result.data:

        emit(
            "join_error",
            {
                "message":
                    "ルーム作成に失敗しました"
            }
        )

        return

    room = result.data[0]

    room_uuid = str(room["id"])

    db.table(
        "room_settings"
    ).insert(
        {
            "room_id": room_uuid,
            "password_enabled": False,
            "password_hash": None,
            "password_changed_at": None
        }
    ).execute()

    db.table(
        "room_members"
    ).insert(
        {
            "room_id": room_uuid,
            "user_id": user_id,
            "note": ""
        }
    ).execute()

    join_room(room_code)

    emit(
        "room_created",
        {
            "room": room_code
        }
    )


# =========================================================
# ルーム参加
# =========================================================

@socketio.on(
    "join_room_by_id"
)
def join_room_by_id(data):

    user = require_user()

    if not user:
        return

    room_code = str(
        data.get("room", "")
    )

    user_id = str(user.id)

    if (
        not room_code.isdigit()
        or len(room_code) != 10
    ):

        emit(
            "join_error",
            {
                "message":
                    "ルームIDは半角数字10桁です"
            }
        )

        return

    room = get_room_by_code(room_code)

    if not room:

        emit(
            "join_error",
            {
                "message":
                    "そのルームは存在しません"
            }
        )

        return

    room_uuid = str(room["id"])

    member_result = (
        db
        .table("room_members")
        .select("id")
        .eq(
            "room_id",
            room_uuid
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )

    if not member_result.data:

        db.table(
            "room_members"
        ).insert(
            {
                "room_id": room_uuid,
                "user_id": user_id,
                "note": ""
            }
        ).execute()

    join_room(room_code)

    emit(
        "joined",
        {
            "room": room_code
        }
    )

    message_result = (
        db
        .table("messages")
        .select(
            "user_id,message,created_at"
        )
        .eq(
            "room_id",
            room_uuid
        )
        .order("id")
        .execute()
    )

    for row in (
        message_result.data or []
    ):

        message_user_id = str(
            row["user_id"]
        )

        profile = get_profile(
            message_user_id
        )

        message_username = (
            profile["username"]
            if profile
            else "Unknown"
        )

        emit(
            "chat_message",
            {
                "username":
                    message_username,
                "message":
                    row["message"]
            }
        )


# =========================================================
# ルーム退出
# =========================================================

@socketio.on(
    "leave_room"
)
def leave(data):

    room_code = str(
        data.get("room", "")
    )

    leave_room(room_code)


# =========================================================
# メッセージ
# =========================================================

@socketio.on(
    "message"
)
def handle_message(data):

    user = require_user()

    if not user:
        return

    room_code = str(
        data.get("room", "")
    )

    message = str(
        data.get("message", "")
    ).strip()

    if not message:
        return

    room = get_room_by_code(room_code)

    if not room:
        return

    room_uuid = str(room["id"])
    user_id = str(user.id)

    member_result = (
        db
        .table("room_members")
        .select("id")
        .eq(
            "room_id",
            room_uuid
        )
        .eq(
            "user_id",
            user_id
        )
        .execute()
    )

    if not member_result.data:
        return

    db.table(
        "messages"
    ).insert(
        {
            "room_id": room_uuid,
            "user_id": user_id,
            "message": message
        }
    ).execute()

    profile, _ = ensure_profile(user)

    emit(
        "chat_message",
        {
            "username":
                profile["username"],
            "message":
                message
        },
        room=room_code
    )


# =========================================================
# 通話開始通知
# =========================================================

@socketio.on(
    "call_started"
)
def call_started(data):

    user = require_user()

    if not user:
        return

    room = str(
        data.get("room", "")
    )

    profile, _ = ensure_profile(user)

    socketio.emit(
        "call_notification",
        {
            "username":
                profile["username"],
            "room":
                room
        },
        room=room
    )


# =========================================================
# 通話終了通知
# =========================================================

@socketio.on(
    "call_ended"
)
def call_ended(data):

    user = require_user()

    if not user:
        return

    room = str(
        data.get("room", "")
    )

    profile, _ = ensure_profile(user)

    socketio.emit(
        "call_end_notification",
        {
            "username":
                profile["username"]
        },
        room=room
    )


# =========================================================
# CREATERログ投稿
# =========================================================

@socketio.on(
    "add_creator_log"
)
def add_creator_log(data):

    user = require_user()

    if not user:
        return

    profile, _ = ensure_profile(user)

    if profile["username"] != "開発者":
        return

    message = str(
        data.get("message", "")
    ).strip()

    if not message:
        return

    result = (
        db
        .table("creator_logs")
        .insert(
            {
                "user_id":
                    str(user.id),
                "message":
                    message
            }
        )
        .execute()
    )

    if not result.data:
        return

    log = result.data[0]

    socketio.emit(
        "new_creator_log",
        {
            "id":
                log["id"],
            "message":
                message
        }
    )


# =========================================================
# CREATERログ削除
# =========================================================

@socketio.on(
    "delete_creator_log"
)
def delete_creator_log(data):

    user = require_user()

    if not user:
        return

    profile, _ = ensure_profile(user)

    if profile["username"] != "開発者":
        return

    try:

        log_id = int(
            data.get("id")
        )

    except Exception:

        return

    (
        db
        .table("creator_logs")
        .delete()
        .eq(
            "id",
            log_id
        )
        .execute()
    )

    socketio.emit(
        "creator_log_deleted",
        {
            "id":
                log_id
        }
    )


# =========================================================
# Health Check
# =========================================================

@app.route(
    "/health"
)
def health():

    return jsonify(
        {
            "status": "ok"
        }
    )


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=port
    )
