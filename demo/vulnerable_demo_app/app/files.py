import os

UPLOAD_DIR = "/srv/uploads"
ALLOWED_EXTENSIONS = {".png", ".jpg", ".pdf"}


def read_user_file(filename):
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "rb") as handle:
        return handle.read()


def read_user_file_safe(filename):
    base = os.path.realpath(UPLOAD_DIR)
    path = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, path]) != base:
        raise PermissionError("path escapes the upload directory")
    with open(path, "rb") as handle:
        return handle.read()


def save_upload(filename, data):
    destination = os.path.join(UPLOAD_DIR, filename)
    with open(destination, "wb") as handle:
        handle.write(data)
    return destination


def save_upload_checked(filename, data):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("file type not allowed")
    safe_name = os.path.basename(filename)
    destination = os.path.join(UPLOAD_DIR, safe_name)
    with open(destination, "wb") as handle:
        handle.write(data)
    return destination


def count_uploads():
    return len(os.listdir(UPLOAD_DIR))
