"""Upload validation. The client's filename, Content-Type and extension are all untrusted:
we check size, allow-list the extension, verify the content really is that type, sanitise
the name and choose the stored MIME type ourselves."""
import hashlib
import re
import zipfile
from io import BytesIO

CATEGORIES = ["Contract", "HR", "Finance", "Drawing", "Audit", "Other"]

ALLOWED = {  # ext -> (mime, kind)
    ".pdf": ("application/pdf", b"%PDF-"),
    ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
    ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    ".txt": ("text/plain", "text"),
    ".csv": ("text/csv", "text"),
    ".docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "ooxml:word/"),
    ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "ooxml:xl/"),
}
MAX_UNZIPPED = 100 * 1024 * 1024


class ValidationError(ValueError):
    pass


def clean_filename(raw: str) -> str:
    name = (raw or "").replace("\\", "/").split("/")[-1]           # drop any path
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = re.sub(r"[^\w.\-() ]", "_", name).strip(" .")
    name = re.sub(r"\.{2,}", ".", name)
    if not name:
        raise ValidationError("File name is empty after cleaning.")
    return name[:120]


def validate_upload(filename: str, data: bytes, max_bytes: int):
    name = clean_filename(filename)
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        raise ValidationError(f"File type '{ext or 'none'}' is not allowed. Allowed: {', '.join(sorted(ALLOWED))}.")
    if not data:
        raise ValidationError("File is empty.")
    if len(data) > max_bytes:
        raise ValidationError(f"File is larger than {max_bytes // (1024 * 1024)} MB.")
    mime, rule = ALLOWED[ext]
    if isinstance(rule, bytes):
        if not data.startswith(rule):
            raise ValidationError(f"Content is not a real {ext} file.")
    elif rule == "text":
        if b"\x00" in data:
            raise ValidationError("Content is not plain text.")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError("Text files must be UTF-8.") from None
    else:  # ooxml
        try:
            with zipfile.ZipFile(BytesIO(data)) as z:
                names = z.namelist()
                if sum(i.file_size for i in z.infolist()) > MAX_UNZIPPED:
                    raise ValidationError("Archive expands to an unsafe size.")
                if "[Content_Types].xml" not in names or not any(n.startswith(rule[6:]) for n in names):
                    raise ValidationError(f"Content is not a real {ext} file.")
        except zipfile.BadZipFile:
            raise ValidationError(f"Content is not a real {ext} file.") from None
    return {"filename": name, "ext": ext, "mime": mime, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}
