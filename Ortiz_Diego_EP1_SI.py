import os, sqlite3, hashlib, shutil, uuid
import jwt
from tkinter import messagebox, ttk
import customtkinter as ctk
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

ctk.set_appearance_mode("dark")

# ── RUTAS ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE  = os.path.join(BASE_DIR, "fernet.key")
DB        = os.path.join(BASE_DIR, "inventario.db")

MAX_INTENTOS = 5
BLOQUEO_MIN  = 5

# ── PALETA AZUL / NEGRO / GRIS ────────────────────────────────────────────────
C_BG     = "#0d1117"
C_CARD   = "#161b22"
C_ENTRY  = "#21262d"
C_BLUE   = "#1f6feb"
C_HOVER  = "#388bfd"
C_TEXT   = "#e6edf3"
C_TEXT2  = "#8b949e"
C_BORDER = "#30363d"

# ── WIDGETS HELPERS ───────────────────────────────────────────────────────────
def mk_btn(parent, text, command, width=120, **kw):
    return ctk.CTkButton(parent, text=text, command=command, width=width,
                         fg_color=C_BLUE, hover_color=C_HOVER,
                         text_color=C_TEXT, corner_radius=8,
                         font=("Arial", 10), **kw)

def mk_entry(parent, show=None, width=220):
    return ctk.CTkEntry(parent, show=show, width=width,
                        fg_color=C_ENTRY, text_color=C_TEXT,
                        border_color=C_BORDER, border_width=1,
                        corner_radius=8, font=("Arial", 10))

def mk_label(parent, text, font=("Arial", 10), fg=None, **kw):
    return ctk.CTkLabel(parent, text=text, font=font,
                        text_color=fg or C_TEXT2, fg_color="transparent", **kw)

# ── FERNET ────────────────────────────────────────────────────────────────────
def cargar_clave():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    clave = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(clave)
    return clave

_raw_key   = cargar_clave()
fernet     = Fernet(_raw_key)
JWT_SECRET = hashlib.sha256(_raw_key).hexdigest()

TOKEN_EXP_MIN   = 60
LOG_FILE        = os.path.join(BASE_DIR, "access_log.txt")
tokens_invalidos = set()

# ── HASH CONTRASEÑA ───────────────────────────────────────────────────────────
def derive_hash(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,
                 backend=default_backend())
    return kdf.derive(password.encode("utf-8"))

# ── HASH INTEGRIDAD ───────────────────────────────────────────────────────────
def calcular_row_hash(nombre, sku, cantidad, precio):
    contenido = f"{nombre}|{sku}|{int(cantidad)}|{float(precio)}"
    return hashlib.sha256(contenido.encode("utf-8")).hexdigest()

# ── VALIDACIONES ──────────────────────────────────────────────────────────────
def validar_usuario(u):
    if not u or len(u) < 3:
        return "El usuario debe tener al menos 3 caracteres"
    if len(u) > 30:
        return "El usuario no puede superar 30 caracteres"
    return None

def validar_password(p):
    if not p or len(p) < 6:
        return "La contrasena debe tener al menos 6 caracteres"
    if len(p) > 64:
        return "La contrasena no puede superar 64 caracteres"
    return None

def validar_email(e):
    import re
    if not e or len(e) > 100:
        return "El correo no puede estar vacio ni superar 100 caracteres"
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e):
        return "Formato de correo invalido. Use: usuario@dominio.com"
    return None

def validar_producto(nombre, sku, cantidad, precio):
    if not nombre or len(nombre) < 2:
        return "Nombre debe tener al menos 2 caracteres"
    if len(nombre) > 60:
        return "Nombre demasiado largo (max 60)"
    if not sku or len(sku) < 2:
        return "SKU invalido (min 2 caracteres)"
    if len(sku) > 20:
        return "SKU demasiado largo (max 20)"
    try:
        c = int(cantidad)
        if c < 0:
            return "Cantidad no puede ser negativa"
    except ValueError:
        return "Cantidad debe ser un numero entero"
    try:
        p = float(precio)
        if p < 0:
            return "Precio no puede ser negativo"
    except ValueError:
        return "Precio debe ser un numero"
    return None

# ── BASE DE DATOS ─────────────────────────────────────────────────────────────
def get_con():
    con = sqlite3.connect(DB)
    con.execute("PRAGMA foreign_keys = ON")
    return con

def init_db():
    try:
        with get_con() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT    UNIQUE NOT NULL
                                            CHECK(length(username) >= 3),
                    salt            BLOB    NOT NULL,
                    pwd_hash        BLOB    NOT NULL,
                    email_enc       BLOB    NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0
                                            CHECK(failed_attempts >= 0),
                    locked_until    TEXT
                )
            """)
            try:
                con.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'usuario'")
            except sqlite3.OperationalError:
                pass
            con.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    nombre    TEXT    NOT NULL CHECK(length(nombre) >= 2),
                    sku       TEXT    UNIQUE NOT NULL,
                    cantidad  INTEGER NOT NULL DEFAULT 0 CHECK(cantidad >= 0),
                    precio    REAL    NOT NULL DEFAULT 0 CHECK(precio >= 0),
                    row_hash  TEXT    NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha    TEXT NOT NULL,
                    usuario  TEXT NOT NULL,
                    accion   TEXT NOT NULL,
                    detalle  TEXT
                )
            """)
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", f"No se pudo inicializar la base de datos:\n{e}")

# ── BITACORA ──────────────────────────────────────────────────────────────────
def registrar_auditoria(usuario, accion, detalle=""):
    try:
        with get_con() as con:
            con.execute(
                "INSERT INTO audit_log(fecha, usuario, accion, detalle) VALUES(?,?,?,?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), usuario, accion, detalle)
            )
    except sqlite3.Error:
        pass

# ── TOKEN JWT ─────────────────────────────────────────────────────────────────
def generar_token(username, role):
    payload = {
        "sub":  username,
        "role": role,
        "jti":  str(uuid.uuid4()),
        "exp":  datetime.utcnow() + timedelta(minutes=TOKEN_EXP_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def validar_token(token):
    if not token or token in tokens_invalidos:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

def log_acceso(accion, usuario, token=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if token:
        detalle = "Token: " + token[:10] + "..." + token[-6:]
    else:
        detalle = "Token invalidado"
    linea = f"[{ts}] {accion} - Usuario: {usuario} - {detalle}"
    print(linea)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(linea + "\n")
    except OSError:
        pass

def sesion_ok():
    if validar_token(sesion_usuario.get("token")):
        return True
    messagebox.showerror("Sesion invalida", "Tu sesion ha expirado. Vuelve a iniciar sesion.")
    mostrar(inicio)
    return False

def es_admin():
    payload = validar_token(sesion_usuario.get("token"))
    return payload is not None and payload.get("role") == "admin"

# ── SESION ────────────────────────────────────────────────────────────────────
sesion_usuario = {"nombre": "", "token": None, "role": ""}

# ── VENTANA PRINCIPAL ─────────────────────────────────────────────────────────
v = ctk.CTk()
v.title("Sistema de Inventario")
v.geometry("520x580")
v.configure(fg_color=C_BG)

# ── ESTILO TTK (Treeview) ─────────────────────────────────────────────────────
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
    background=C_CARD, foreground=C_TEXT, fieldbackground=C_CARD,
    rowheight=26, font=("Arial", 9), borderwidth=0)
style.configure("Treeview.Heading",
    background="#1c2333", foreground=C_TEXT2,
    font=("Arial", 9, "bold"), relief="flat")
style.map("Treeview",
    background=[("selected", "#1f3a5f")],
    foreground=[("selected", C_TEXT)])
style.map("Treeview.Heading",
    background=[("active", "#243447")])

# ── FRAMES ────────────────────────────────────────────────────────────────────
def mk_frame(parent):
    return ctk.CTkFrame(parent, fg_color=C_CARD, corner_radius=0)

inicio      = mk_frame(v)
vlogin      = mk_frame(v)
vregister   = mk_frame(v)
vmenu       = mk_frame(v)
vproductos  = mk_frame(v)
vformulario = mk_frame(v)
vbitacora   = mk_frame(v)
vintegridad = mk_frame(v)

def mostrar(frame):
    for f in (inicio, vlogin, vregister, vmenu,
              vproductos, vformulario, vbitacora, vintegridad):
        f.pack_forget()
    frame.pack(fill="both", expand=True)

# ── PANTALLA INICIO ───────────────────────────────────────────────────────────
ctk.CTkLabel(inicio, text="Sistema de Inventario",
             font=("Arial", 20, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(80, 4))
ctk.CTkLabel(inicio, text="Gestion segura de productos",
             font=("Arial", 11), text_color=C_TEXT2,
             fg_color="transparent").pack(pady=(0, 50))
mk_btn(inicio, "Iniciar sesion", lambda: mostrar(vlogin),    width=200).pack(pady=8)
mk_btn(inicio, "Registrarse",    lambda: mostrar(vregister), width=200).pack(pady=8)

# ── LOGIN ─────────────────────────────────────────────────────────────────────
ctk.CTkLabel(vlogin, text="Iniciar sesion",
             font=("Arial", 17, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(50, 24))

_lf = ctk.CTkFrame(vlogin, fg_color="transparent")
_lf.pack()
mk_label(_lf, "Usuario").grid(row=0, column=0, sticky="w", pady=(0, 2))
login_username = mk_entry(_lf)
login_username.grid(row=1, column=0, pady=(0, 12))
mk_label(_lf, "Contrasena").grid(row=2, column=0, sticky="w", pady=(0, 2))
login_password = mk_entry(_lf, show="*")
login_password.grid(row=3, column=0, pady=(0, 20))

def guardar_login():
    user = login_username.get().strip()
    pwd  = login_password.get()
    if not user or not pwd:
        messagebox.showwarning("Aviso", "Completa todos los campos")
        return
    try:
        with get_con() as con:
            row = con.execute(
                "SELECT salt, pwd_hash, failed_attempts, locked_until, role FROM users WHERE username=?",
                (user,)
            ).fetchone()
    except sqlite3.Error as e:
        messagebox.showerror("Error BD",
            f"No se pudo consultar la base de datos:\n{e}\n"
            "Verifica que el archivo .db exista o restaura desde un backup.")
        return

    if not row:
        registrar_auditoria(user, "LOGIN_FAIL", "Usuario no encontrado")
        messagebox.showerror("Error", "Usuario no encontrado")
        return

    salt, stored_hash, intentos, locked_until, rol = row

    if locked_until:
        fin_bloqueo = datetime.fromisoformat(locked_until)
        if datetime.now() < fin_bloqueo:
            restante = int((fin_bloqueo - datetime.now()).total_seconds() / 60) + 1
            messagebox.showerror("Bloqueado",
                f"Usuario bloqueado. Intenta en {restante} minuto(s).")
            registrar_auditoria(user, "LOGIN_FAIL", "Cuenta bloqueada")
            return
        else:
            with get_con() as con:
                con.execute(
                    "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?",
                    (user,))
            intentos = 0

    try:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,
                     backend=default_backend())
        kdf.verify(pwd.encode("utf-8"), stored_hash)
    except Exception:
        intentos += 1
        try:
            if intentos >= MAX_INTENTOS:
                bloqueo = (datetime.now() + timedelta(minutes=BLOQUEO_MIN)).isoformat()
                with get_con() as con:
                    con.execute(
                        "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                        (intentos, bloqueo, user))
                registrar_auditoria(user, "LOGIN_FAIL", f"Cuenta bloqueada por {BLOQUEO_MIN} min")
                messagebox.showerror("Bloqueado",
                    f"Demasiados intentos. Usuario bloqueado {BLOQUEO_MIN} minutos.")
            else:
                with get_con() as con:
                    con.execute(
                        "UPDATE users SET failed_attempts=? WHERE username=?",
                        (intentos, user))
                registrar_auditoria(user, "LOGIN_FAIL",
                    f"Contrasena incorrecta (intento {intentos}/{MAX_INTENTOS})")
                messagebox.showerror("Error",
                    f"Contrasena incorrecta. Intentos: {intentos}/{MAX_INTENTOS}")
        except sqlite3.Error as e:
            messagebox.showerror("Error BD", str(e))
        return

    try:
        with get_con() as con:
            con.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?",
                (user,))
    except sqlite3.Error:
        pass
    token = generar_token(user, rol)
    sesion_usuario["nombre"] = user
    sesion_usuario["token"]  = token
    sesion_usuario["role"]   = rol
    registrar_auditoria(user, "LOGIN_OK", f"Acceso exitoso - Rol: {rol}")
    log_acceso("LOGIN", user, token)
    login_username.delete(0, "end")
    login_password.delete(0, "end")
    actualizar_label_email()
    mostrar(vmenu)

_lb = ctk.CTkFrame(vlogin, fg_color="transparent")
_lb.pack()
mk_btn(_lb, "Ingresar", guardar_login,          width=140).grid(row=0, column=0, padx=6)
mk_btn(_lb, "Volver",   lambda: mostrar(inicio), width=140).grid(row=0, column=1, padx=6)

# ── REGISTRO ──────────────────────────────────────────────────────────────────
ctk.CTkLabel(vregister, text="Registro de usuario",
             font=("Arial", 17, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(50, 24))

_rf = ctk.CTkFrame(vregister, fg_color="transparent")
_rf.pack()
mk_label(_rf, "Usuario (min 3 caracteres)").grid(row=0, column=0, sticky="w", pady=(0, 2))
reg_username = mk_entry(_rf)
reg_username.grid(row=1, column=0, pady=(0, 12))
mk_label(_rf, "Contrasena (min 6 caracteres)").grid(row=2, column=0, sticky="w", pady=(0, 2))
reg_password = mk_entry(_rf, show="*")
reg_password.grid(row=3, column=0, pady=(0, 12))
mk_label(_rf, "Correo electronico").grid(row=4, column=0, sticky="w", pady=(0, 2))
reg_email = mk_entry(_rf)
reg_email.grid(row=5, column=0, pady=(0, 20))
mk_label(_rf, "Rol").grid(row=6, column=0, sticky="w", pady=(0, 2))
reg_rol = ctk.CTkOptionMenu(_rf, values=["usuario", "admin"],
                             fg_color=C_ENTRY, button_color=C_BLUE,
                             button_hover_color=C_HOVER, text_color=C_TEXT,
                             dropdown_fg_color=C_CARD, dropdown_text_color=C_TEXT,
                             font=("Arial", 10), width=220)
reg_rol.grid(row=7, column=0, pady=(0, 20))
reg_rol.set("usuario")

def guardar_register():
    user  = reg_username.get().strip()
    pwd   = reg_password.get()
    email = reg_email.get().strip()
    rol   = reg_rol.get()

    err = validar_usuario(user) or validar_password(pwd) or validar_email(email)
    if err:
        messagebox.showerror("Error de validacion", err)
        return

    salt      = os.urandom(16)
    pwd_hash  = derive_hash(pwd, salt)
    email_enc = fernet.encrypt(email.encode("utf-8"))
    try:
        with get_con() as con:
            con.execute(
                "INSERT INTO users(username, salt, pwd_hash, email_enc, role) VALUES(?,?,?,?,?)",
                (user, salt, pwd_hash, email_enc, rol)
            )
        registrar_auditoria(user, "INSERT", "Nuevo usuario registrado")
        messagebox.showinfo("Exito", "Usuario registrado correctamente")
        for e in (reg_username, reg_password, reg_email):
            e.delete(0, "end")
        mostrar(inicio)
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "El usuario ya existe")
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))

_rb = ctk.CTkFrame(vregister, fg_color="transparent")
_rb.pack()
mk_btn(_rb, "Registrar", guardar_register,       width=140).grid(row=0, column=0, padx=6)
mk_btn(_rb, "Volver",    lambda: mostrar(inicio), width=140).grid(row=0, column=1, padx=6)

# ── MENU PRINCIPAL ────────────────────────────────────────────────────────────
ctk.CTkLabel(vmenu, text="Menu Principal",
             font=("Arial", 18, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(60, 6))
lbl_menu_email = ctk.CTkLabel(vmenu, text="", font=("Arial", 10),
                               text_color=C_TEXT2, fg_color="transparent")
lbl_menu_email.pack(pady=(0, 24))

def actualizar_label_email():
    try:
        with get_con() as con:
            row = con.execute(
                "SELECT email_enc FROM users WHERE username=?",
                (sesion_usuario["nombre"],)
            ).fetchone()
        if row:
            email = fernet.decrypt(row[0]).decode("utf-8")
            lbl_menu_email.configure(
                text=f"Sesion: {sesion_usuario['nombre']}  |  Rol: {sesion_usuario['role']}  |  Correo: {email}")
    except Exception:
        lbl_menu_email.configure(text=f"Sesion: {sesion_usuario['nombre']}")

def _abrir_bitacora():
    if not sesion_ok():
        return
    if not es_admin():
        messagebox.showerror("Acceso denegado",
            "Esta funcion es solo para administradores.")
        registrar_auditoria(sesion_usuario["nombre"], "ACCESO_DENEGADO",
                            "Intento acceder a Bitacora de Auditoria")
        return
    mostrar(vbitacora)
    cargar_bitacora()

def _abrir_integridad():
    if not sesion_ok():
        return
    if not es_admin():
        messagebox.showerror("Acceso denegado",
            "Esta funcion es solo para administradores.")
        registrar_auditoria(sesion_usuario["nombre"], "ACCESO_DENEGADO",
                            "Intento acceder a Verificar Integridad")
        return
    mostrar(vintegridad)
    verificar_integridad()

def cerrar_sesion():
    token = sesion_usuario.get("token")
    if token:
        log_acceso("LOGOUT", sesion_usuario["nombre"])
        tokens_invalidos.add(token)
        registrar_auditoria(sesion_usuario["nombre"], "LOGOUT", "Sesion cerrada")
    sesion_usuario["nombre"] = ""
    sesion_usuario["token"]  = None
    sesion_usuario["role"]   = ""
    mostrar(inicio)

for _txt, _cmd in [
    ("Productos",             lambda: sesion_ok() and [mostrar(vproductos), cargar_productos()]),
    ("Bitacora de Auditoria", lambda: _abrir_bitacora()),
    ("Verificar Integridad",  lambda: _abrir_integridad()),
    ("Generar Backup",        lambda: sesion_ok() and generar_backup()),
]:
    mk_btn(vmenu, _txt, _cmd, width=260).pack(pady=6)

ctk.CTkFrame(vmenu, fg_color=C_BORDER, height=2, corner_radius=0).pack(
    fill="x", padx=60, pady=20)
mk_btn(vmenu, "Cerrar sesion", cerrar_sesion, width=260).pack()

# ── BACKUP ────────────────────────────────────────────────────────────────────
def generar_backup():
    try:
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        destino = os.path.join(BASE_DIR, f"backup_{ts}.db")
        shutil.copy2(DB, destino)
        registrar_auditoria(sesion_usuario["nombre"], "BACKUP", f"Archivo: backup_{ts}.db")
        messagebox.showinfo("Backup generado", f"Respaldo guardado como:\nbackup_{ts}.db")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo generar el backup:\n{e}")

# ── PRODUCTOS — TABLA ─────────────────────────────────────────────────────────
ctk.CTkLabel(vproductos, text="Gestion de Productos",
             font=("Arial", 15, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(20, 10))

cols_p = ("ID", "Nombre", "SKU", "Cantidad", "Precio")
tree_p = ttk.Treeview(vproductos, columns=cols_p, show="headings", height=12)
tree_p.column("ID",       width=40,  anchor="center")
tree_p.column("Nombre",   width=140, anchor="w")
tree_p.column("SKU",      width=90,  anchor="center")
tree_p.column("Cantidad", width=75,  anchor="center")
tree_p.column("Precio",   width=80,  anchor="center")
for col in cols_p:
    tree_p.heading(col, text=col)
tree_p.pack(padx=16, pady=4)

_pp = ctk.CTkFrame(vproductos, fg_color="transparent")
_pp.pack(pady=8)
mk_btn(_pp, "Nuevo",    lambda: abrir_formulario("crear"),  width=100).grid(row=0, column=0, padx=4)
mk_btn(_pp, "Editar",   lambda: abrir_formulario("editar"), width=100).grid(row=0, column=1, padx=4)
mk_btn(_pp, "Eliminar", lambda: eliminar_producto(),        width=100).grid(row=0, column=2, padx=4)
ctk.CTkFrame(vproductos, fg_color=C_BORDER, height=2, corner_radius=0).pack(
    fill="x", padx=40, pady=8)
mk_btn(vproductos, "Volver al menu", lambda: mostrar(vmenu), width=200).pack(pady=4)

def cargar_productos():
    try:
        tree_p.delete(*tree_p.get_children())
        with get_con() as con:
            rows = con.execute(
                "SELECT id, nombre, sku, cantidad, precio FROM products").fetchall()
        for r in rows:
            tree_p.insert("", "end", values=(r[0], r[1], r[2], r[3], f"${r[4]:.2f}"))
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))

def eliminar_producto():
    sel = tree_p.selection()
    if not sel:
        messagebox.showwarning("Aviso", "Selecciona un producto de la tabla")
        return
    pid = tree_p.item(sel[0])["values"][0]
    sku = tree_p.item(sel[0])["values"][2]
    if not messagebox.askyesno("Confirmar", f"Eliminar el producto '{sku}'?"):
        return
    try:
        with get_con() as con:
            con.execute("DELETE FROM products WHERE id=?", (pid,))
        registrar_auditoria(sesion_usuario["nombre"], "DELETE", f"Producto ID {pid}: {sku}")
        cargar_productos()
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))

# ── PRODUCTOS — FORMULARIO ────────────────────────────────────────────────────
form_mode = {"accion": "crear", "pid": None}

lbl_form_titulo = ctk.CTkLabel(vformulario, text="",
                                font=("Arial", 15, "bold"),
                                text_color=C_TEXT, fg_color="transparent")
lbl_form_titulo.pack(pady=(40, 24))

_fpanel = ctk.CTkFrame(vformulario, fg_color="transparent")
_fpanel.pack()
labels_p = ["Nombre:", "SKU:", "Cantidad:", "Precio:"]
entries_p = {}
for i, lbl in enumerate(labels_p):
    mk_label(_fpanel, lbl).grid(row=i*2, column=0, sticky="w", pady=(4, 1))
    e = mk_entry(_fpanel, width=260)
    e.grid(row=i*2+1, column=0, pady=(0, 8))
    entries_p[lbl] = e

def limpiar_form_p():
    for e in entries_p.values():
        e.delete(0, "end")

def abrir_formulario(accion):
    if accion == "editar":
        sel = tree_p.selection()
        if not sel:
            messagebox.showwarning("Aviso", "Selecciona un producto de la tabla")
            return
        vals = tree_p.item(sel[0])["values"]
        limpiar_form_p()
        form_mode["pid"] = vals[0]
        entries_p["Nombre:"].insert(0, vals[1])
        entries_p["SKU:"].insert(0, vals[2])
        entries_p["Cantidad:"].insert(0, vals[3])
        entries_p["Precio:"].insert(0, str(vals[4]).replace("$", ""))
        lbl_form_titulo.configure(text="Editar Producto")
    else:
        limpiar_form_p()
        form_mode["pid"] = None
        lbl_form_titulo.configure(text="Nuevo Producto")
    form_mode["accion"] = accion
    mostrar(vformulario)

def guardar_formulario():
    nombre   = entries_p["Nombre:"].get().strip()
    sku      = entries_p["SKU:"].get().strip()
    cantidad = entries_p["Cantidad:"].get().strip()
    precio   = entries_p["Precio:"].get().strip()
    err = validar_producto(nombre, sku, cantidad, precio)
    if err:
        messagebox.showerror("Error de validacion", err)
        return
    rh = calcular_row_hash(nombre, sku, cantidad, precio)
    try:
        with get_con() as con:
            if form_mode["accion"] == "crear":
                con.execute(
                    "INSERT INTO products(nombre, sku, cantidad, precio, row_hash) VALUES(?,?,?,?,?)",
                    (nombre, sku, int(cantidad), float(precio), rh)
                )
                registrar_auditoria(sesion_usuario["nombre"], "INSERT", f"Producto: {sku}")
            else:
                con.execute(
                    "UPDATE products SET nombre=?, sku=?, cantidad=?, precio=?, row_hash=? WHERE id=?",
                    (nombre, sku, int(cantidad), float(precio), rh, form_mode["pid"])
                )
                registrar_auditoria(sesion_usuario["nombre"], "UPDATE",
                                    f"Producto ID {form_mode['pid']}: {sku}")
        cargar_productos()
        mostrar(vproductos)
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "El SKU ya existe")
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))

ctk.CTkFrame(vformulario, fg_color=C_BORDER, height=2, corner_radius=0).pack(
    fill="x", padx=40, pady=14)
_fb = ctk.CTkFrame(vformulario, fg_color="transparent")
_fb.pack()
mk_btn(_fb, "Guardar",  guardar_formulario,          width=140).grid(row=0, column=0, padx=6)
mk_btn(_fb, "Cancelar", lambda: mostrar(vproductos),  width=140).grid(row=0, column=1, padx=6)

# ── BITACORA ──────────────────────────────────────────────────────────────────
ctk.CTkLabel(vbitacora, text="Bitacora de Auditoria",
             font=("Arial", 15, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(20, 10))

cols_b = ("ID", "Fecha", "Usuario", "Accion", "Detalle")
tree_b = ttk.Treeview(vbitacora, columns=cols_b, show="headings", height=14)
tree_b.column("ID",      width=36,  anchor="center")
tree_b.column("Fecha",   width=130, anchor="center")
tree_b.column("Usuario", width=90,  anchor="center")
tree_b.column("Accion",  width=90,  anchor="center")
tree_b.column("Detalle", width=190, anchor="w")
for col in cols_b:
    tree_b.heading(col, text=col)
tree_b.pack(padx=10, pady=4, fill="both", expand=True)

ctk.CTkFrame(vbitacora, fg_color=C_BORDER, height=2, corner_radius=0).pack(
    fill="x", padx=40, pady=8)
mk_btn(vbitacora, "Volver al menu", lambda: mostrar(vmenu), width=200).pack(pady=4)

def cargar_bitacora():
    try:
        tree_b.delete(*tree_b.get_children())
        with get_con() as con:
            rows = con.execute(
                "SELECT id, fecha, usuario, accion, detalle FROM audit_log ORDER BY id DESC"
            ).fetchall()
        for r in rows:
            tree_b.insert("", "end", values=r)
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))

# ── INTEGRIDAD ────────────────────────────────────────────────────────────────
ctk.CTkLabel(vintegridad, text="Verificacion de Integridad",
             font=("Arial", 15, "bold"), text_color=C_TEXT,
             fg_color="transparent").pack(pady=(20, 10))

resultado_int = ctk.CTkTextbox(vintegridad, height=300, width=460, state="disabled",
                                fg_color=C_ENTRY, text_color=C_TEXT,
                                font=("Courier", 9), corner_radius=8,
                                border_color=C_BORDER, border_width=1)
resultado_int.pack(padx=16, pady=4)

ctk.CTkFrame(vintegridad, fg_color=C_BORDER, height=2, corner_radius=0).pack(
    fill="x", padx=40, pady=8)
mk_btn(vintegridad, "Volver al menu", lambda: mostrar(vmenu), width=200).pack(pady=4)

def verificar_integridad():
    try:
        with get_con() as con:
            rows = con.execute(
                "SELECT id, nombre, sku, cantidad, precio, row_hash FROM products"
            ).fetchall()
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))
        return

    resultado_int.configure(state="normal")
    resultado_int.delete("1.0", "end")

    if not rows:
        resultado_int.insert("end", "No hay productos registrados.\n")
        resultado_int.configure(state="disabled")
        return

    ok = 0
    fallos = 0
    for r in rows:
        pid, nombre, sku, cantidad, precio, hash_guardado = r
        hash_calculado = calcular_row_hash(nombre, sku, cantidad, precio)
        if hash_guardado == hash_calculado:
            resultado_int.insert("end", f"[OK]     ID {pid} - {sku}\n")
            ok += 1
        else:
            resultado_int.insert("end", f"[ALERTA] ID {pid} - {sku} — HASH NO COINCIDE\n")
            fallos += 1

    resultado_int.insert("end", f"\nResumen: {ok} correctos, {fallos} alterados.\n")
    resultado_int.configure(state="disabled")
    registrar_auditoria(sesion_usuario["nombre"], "INTEGRIDAD",
                        f"Verificados: {ok} OK, {fallos} alterados")

# ── ARRANQUE ──────────────────────────────────────────────────────────────────
try:
    init_db()
except Exception as e:
    messagebox.showerror("Error critico",
        f"No se pudo abrir la base de datos:\n{e}\n\n"
        "Verifica que el archivo .db no este corrupto\n"
        "o restaura desde un backup.")

print("DB :", os.path.abspath(DB))
print("Key:", os.path.abspath(KEY_FILE))
mostrar(inicio)
v.mainloop()
