from django.shortcuts import render, redirect
from django.db import connection
import hashlib
import hmac
import os


# Hashing is only used in the corrected versions!
def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"{salt.hex()}${digest.hex()}"

def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return hmac.compare_digest(test, bytes.fromhex(digest_hex))

# Create your views here.

def render_blogs(request):
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT b.title, b.body, u.username, b.id
            FROM core_blog AS b 
            JOIN core_user AS u on u.id = b.author_id_id
            ORDER BY b.id DESC""")
        rows = cursor.fetchall()
    blogs = [{
        "title": r[0], "body": r[1], "creator": r[2], "id": r[3]
    } for r in rows]
    return render(request, "core/render_blogs.html", {"blogs": blogs})


def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        # Purposefully allowing weak passwords
        if len(username) < 2 or len(password) < 2:
            return render(request, "core/error_state.html", {"error": "Username or password too short!"}, status=400)
        # Storing password as plaintext not hashed.
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO core_user (username, password) VALUES (%s, %s)",
                [username, password],
            )
            id = cursor.lastrowid
        if id != None:
            return redirect("/login")

    return render(request, "core/register.html")


# FIXED VERSION:
#def register_view(request):
#    if request.method == "POST":
#        username = request.POST.get("username", "")
#        password = request.POST.get("password", "")
#       if len(password) < 6 or not any(c.isdigit() for c in password):
#           return render(request, "core/error_state.html", {"error": "Password has to be +6 char and atleast 1 number!"}, status=400)
#        with connection.cursor() as cursor:
#            cursor.execute(
#               f"INSERT INTO core_user (username, password) VALUES (%s, %s)",
#                [username, hash_password(password)],
#            )
#           id = cursor.lastrowid
#       if id != None:
#            return redirect("/login")
#
#    return render(request, "core/register.html")

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        # Purposefully allowing weak passwords
        if len(username) < 2 or len(password) < 2:
            return render(request, "core/error_state.html", {"error": "Username or password too short!"})
        # Allowing injection by inserting the value directly into query.
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT id, password FROM core_user WHERE username = '{username}' LIMIT 1",
                [],
            )
            row = cursor.fetchone()
        # Here we have 2 distinct responses for wrong username or wrong password
        # This is already leaking information to an attacker
        if not row:
            return render(request, "core/login.html", {"error": "No account for that username."}, status=404)
        if row[1] != password:
            return render(request, "core/login.html", {"error": "Password doesn't match to account."}, status=403)

        response = redirect("/")
        response.set_cookie("user_id", str(row[0]))
        return response

    return render(request, "core/login.html")

#FIXED VERSION:
#def login_view(request):
#    if request.method == "POST":
#       username = request.POST.get("username", "")
#       password = request.POST.get("password", "")
#        if len(password) < 6 or not any(c.isdigit() for c in password):
#           return render(request, "core/error_state.html", {"error": "Password has to be +6 char and atleast 1 number!"})
#        with connection.cursor() as cursor:
#           cursor.execute(
#               "SELECT id, password FROM core_user WHERE username = %s LIMIT 1",
#               [username],
#           )
#           row = cursor.fetchone()
#        if not row:
#            # Hashing password still so query speed cant indicate if an account was found
#            hash_password(password)
#            return render(request, "core/login.html", {"error": "Not authorized."}, status=403)
#       if not verify_password(password, row[1]):
#            return render(request, "core/login.html", {"error": "Not authorized."}, status=403)
#        request.session.cycle_key()
#        request.session["user_id"] = row[0]
#        return redirect("/")

#    return render(request, "core/login.html")


# THIS IS FINE
# The problem with posts is that the render_blogs.html allows for scripts in the body
# Also uses the insecure COOKIE format
def create_post(request):
    user_id = request.COOKIES.get("user_id") or ""
    #FIXED:
    #user_id = request.session.get("user_id")
    if not user_id:
        return redirect("/login")
    
    if request.method == "POST":
        title = request.POST.get("title") or ""
        body_text = request.POST.get("body") or ""

        if len(title) < 5 or len(body_text) < 10:
                return render(request, "core/error_state.html", {"error": "Title or body too short!"}, status=400)

        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO core_blog (author_id_id, title, body) VALUES (%s, %s, %s) RETURNING title",
                [user_id, title, body_text],
            )
            return redirect("/")

    return render(request, "core/create_post.html")


def delete_post(request, post_id):
    user_id = request.COOKIES.get("user_id")
    if not user_id:
        return render(request, "core/error_state.html", {"error": "You need to be logged in for this!"}, status=403)
    with connection.cursor() as cursor:
        cursor.execute("SELECT author_id_id FROM core_blog WHERE id = %s", [post_id])
        row = cursor.fetchone()
    if row is None:
        return render(request, "core/error_state.html", {"error": "Couldn't find post!"}, status=404)

    if str(row[0]) != str(user_id):
        return render(request, "core/error_state.html", {"error": "User_id doesnt match post!"}, status=403)
    
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM core_blog WHERE id = %s", [post_id])

    return redirect("/")

# FIXED VERSION
#def delete_post(request, post_id):
#   if request.method != "POST":
#       return render(request, "core/error_state.html", {"error": "Only Post is allowed here!"}, status=405)
#   user_id = request.session.get("user_id")
#   if not user_id:
#        return render(request, "core/error_state.html", {"error": "You need to be logged in for this!"}, status=403)
#    with connection.cursor() as cursor:
#        cursor.execute("SELECT author_id_id FROM core_blog WHERE id = %s", [post_id])
#       row = cursor.fetchone()
#    if row == None:
#        return render(request, "core/error_state.html", {"error": "Couldn't find post!"}, status=404)
#
#    if str(row[0]) != str(user_id):
#        return render(request, "core/error_state.html", {"error": "User_id doesnt match post!"}, status=403)
#    
#    with connection.cursor() as cursor:
#        cursor.execute("DELETE FROM core_blog WHERE id = %s", [post_id])
#
#    return redirect("/")
