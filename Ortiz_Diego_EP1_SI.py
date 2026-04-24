import os, sqlite3, tkinter as tk, hashlib, shutil
from tkinter import messagebox, ttk
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

#RUTAS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE  = os.path.join(BASE_DIR, "fernet.key")
DB        = os.path.join(BASE_DIR, "inventario.db")

MAX_INTENTOS  = 5
BLOQUEO_MIN   = 5

# PALETA
BG       = "#ececec"
BG2      = "#f8f8f8"
FG       = "#2e2e2e"
FG2      = "#8a8a8a"
BTN_BG   = "#5a5a5a"
BTN_ACT  = "#6e6e6e"
ENTRY_BG = "#ffffff"
SEL      = "#dcdcdc"
BORDER   = "#d0d0d0"

def mk_btn(parent, text, command, width=12, **kw):
    return tk.Button(parent, text=text, command=command, width=width,
                     bg=BTN_BG, fg=BG2, activebackground=BTN_ACT,
                     activeforeground=BG2, relief="flat", cursor="hand2",
                     font=("Arial", 9), padx=6, pady=4, **kw)

def mk_entry(parent, show=None, width=22):
    return tk.Entry(parent, show=show, width=width,
                    bg=ENTRY_BG, fg=FG, insertbackground=FG,
                    relief="flat", font=("Arial", 10),
                    highlightthickness=1, highlightbackground=BORDER,
                    highlightcolor="#111111")

def mk_label(parent, text, font=("Arial", 9), fg=FG2, **kw):
    return tk.Label(parent, text=text, font=font,
                    bg=BG2, fg=fg, **kw)

#  C — FERNET
def cargar_clave():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    clave = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(clave)
    return clave

fernet = Fernet(cargar_clave())

#  C — HASH CONTRASEÑA
def derive_hash(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1,
                 backend=default_backend())
    return kdf.derive(password.encode("utf-8"))

#  I
def calcular_row_hash(nombre, sku, cantidad, precio):
    contenido = f"{nombre}|{sku}|{int(cantidad)}|{float(precio)}"
    return hashlib.sha256(contenido.encode("utf-8")).hexdigest()

#  I — VALIDACIONES DE ENTRADA
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

def validar_dui(d):
    import re
    if not re.fullmatch(r"\d{8}-\d", d):
        return "Formato DUI invalido. Use: ########-#"
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

# BASE DE DATOS — INIT
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
                    dui_enc         BLOB    NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0
                                            CHECK(failed_attempts >= 0),
                    locked_until    TEXT
                )
            """)
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

#  I — BITACORA
def registrar_auditoria(usuario, accion, detalle=""):
    try:
        with get_con() as con:
            con.execute(
                "INSERT INTO audit_log(fecha, usuario, accion, detalle) VALUES(?,?,?,?)",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), usuario, accion, detalle)
            )
    except sqlite3.Error:
        pass

#  SESION ACTUAL
sesion_usuario = {"nombre": ""}

#  VENTANA PRINCIPAL
v = tk.Tk()
v.title("Sistema de Inventario")
v.geometry("520x560")
v.configure(bg=BG)

# ESTILO TTK
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
    background=BG2, foreground=FG, fieldbackground=BG2,
    rowheight=24, font=("Arial", 9), borderwidth=0)
style.configure("Treeview.Heading",
    background=BTN_BG, foreground=FG,
    font=("Arial", 9, "bold"), relief="flat")
style.map("Treeview",
    background=[("selected", SEL)],
    foreground=[("selected", FG)])
style.map("Treeview.Heading",
    background=[("active", BTN_ACT)])

#  FRAMES
def mk_frame(parent):
    return tk.Frame(parent, bg=BG2)

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

# ── PANTALLA INICIO ──────────────────────────────────────────────────────────
tk.Label(inicio, text="Sistema de Inventario",
         font=("Arial", 18, "bold"), bg=BG2, fg=FG).pack(pady=(60, 4))
tk.Label(inicio, text="Gestion segura de productos",
         font=("Arial", 10), bg=BG2, fg=FG2).pack(pady=(0, 40))
mk_btn(inicio, "Iniciar sesion", lambda: mostrar(vlogin), width=20).pack(pady=6)
mk_btn(inicio, "Registrarse",    lambda: mostrar(vregister), width=20).pack(pady=6)

# ── LOGIN ────────────────────────────────────────────────────────────────────
tk.Label(vlogin, text="Iniciar sesion",
         font=("Arial", 15, "bold"), bg=BG2, fg=FG).pack(pady=(40, 20))

_lf = tk.Frame(vlogin, bg=BG2)
_lf.pack()
mk_label(_lf, "Usuario").grid(row=0, column=0, sticky="w", pady=(0,2))
login_username = mk_entry(_lf)
login_username.grid(row=1, column=0, pady=(0, 10))
mk_label(_lf, "Contrasena").grid(row=2, column=0, sticky="w", pady=(0,2))
login_password = mk_entry(_lf, show="*")
login_password.grid(row=3, column=0, pady=(0, 16))

def guardar_login():
    user = login_username.get().strip()
    pwd  = login_password.get()
    if not user or not pwd:
        messagebox.showwarning("Aviso", "Completa todos los campos")
        return
    try:
        with get_con() as con:
            row = con.execute(
                "SELECT salt, pwd_hash, failed_attempts, locked_until FROM users WHERE username=?",
                (user,)
            ).fetchone()
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", f"No se pudo consultar la base de datos:\n{e}\nVerifica que el archivo .db exista o restaura desde un backup.")
        return

    if not row:
        registrar_auditoria(user, "LOGIN_FAIL", "Usuario no encontrado")
        messagebox.showerror("Error", "Usuario no encontrado")
        return

    salt, stored_hash, intentos, locked_until = row

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
                con.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (user,))
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
                        (intentos, bloqueo, user)
                    )
                registrar_auditoria(user, "LOGIN_FAIL", f"Cuenta bloqueada por {BLOQUEO_MIN} min")
                messagebox.showerror("Bloqueado",
                    f"Demasiados intentos. Usuario bloqueado {BLOQUEO_MIN} minutos.")
            else:
                with get_con() as con:
                    con.execute(
                        "UPDATE users SET failed_attempts=? WHERE username=?",
                        (intentos, user)
                    )
                registrar_auditoria(user, "LOGIN_FAIL",
                    f"Contrasena incorrecta (intento {intentos}/{MAX_INTENTOS})")
                messagebox.showerror("Error",
                    f"Contrasena incorrecta. Intentos: {intentos}/{MAX_INTENTOS}")
        except sqlite3.Error as e:
            messagebox.showerror("Error BD", str(e))
        return

    try:
        with get_con() as con:
            con.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (user,))
    except sqlite3.Error:
        pass
    registrar_auditoria(user, "LOGIN_OK", "Acceso exitoso")
    sesion_usuario["nombre"] = user
    login_username.delete(0, "end")
    login_password.delete(0, "end")
    mostrar(vmenu)

_lb = tk.Frame(vlogin, bg=BG2)
_lb.pack()
mk_btn(_lb, "Ingresar", guardar_login, width=14).grid(row=0, column=0, padx=4)
mk_btn(_lb, "Volver",   lambda: mostrar(inicio), width=14).grid(row=0, column=1, padx=4)

# ── REGISTRO ─────────────────────────────────────────────────────────────────
tk.Label(vregister, text="Registro de usuario",
         font=("Arial", 15, "bold"), bg=BG2, fg=FG).pack(pady=(40, 20))

_rf = tk.Frame(vregister, bg=BG2)
_rf.pack()
mk_label(_rf, "Usuario (min 3 caracteres)").grid(row=0, column=0, sticky="w", pady=(0,2))
reg_username = mk_entry(_rf)
reg_username.grid(row=1, column=0, pady=(0, 10))
mk_label(_rf, "Contrasena (min 6 caracteres)").grid(row=2, column=0, sticky="w", pady=(0,2))
reg_password = mk_entry(_rf, show="*")
reg_password.grid(row=3, column=0, pady=(0, 10))
mk_label(_rf, "DUI (########-#)").grid(row=4, column=0, sticky="w", pady=(0,2))
reg_dui = mk_entry(_rf)
reg_dui.grid(row=5, column=0, pady=(0, 16))

def guardar_register():
    user = reg_username.get().strip()
    pwd  = reg_password.get()
    dui  = reg_dui.get().strip()

    err = validar_usuario(user) or validar_password(pwd) or validar_dui(dui)
    if err:
        messagebox.showerror("Error de validacion", err)
        return

    salt     = os.urandom(16)
    pwd_hash = derive_hash(pwd, salt)
    dui_enc  = fernet.encrypt(dui.encode("utf-8"))
    try:
        with get_con() as con:
            con.execute(
                "INSERT INTO users(username, salt, pwd_hash, dui_enc) VALUES(?,?,?,?)",
                (user, salt, pwd_hash, dui_enc)
            )
        registrar_auditoria(user, "INSERT", "Nuevo usuario registrado")
        messagebox.showinfo("Exito", "Usuario registrado correctamente")
        for e in (reg_username, reg_password, reg_dui):
            e.delete(0, "end")
        mostrar(inicio)
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "El usuario ya existe")
    except sqlite3.Error as e:
        messagebox.showerror("Error BD", str(e))

_rb = tk.Frame(vregister, bg=BG2)
_rb.pack()
mk_btn(_rb, "Registrar", guardar_register, width=14).grid(row=0, column=0, padx=4)
mk_btn(_rb, "Volver",    lambda: mostrar(inicio), width=14).grid(row=0, column=1, padx=4)

# ── MENU PRINCIPAL ────────────────────────────────────────────────────────────
tk.Label(vmenu, text="Menu Principal",
         font=("Arial", 16, "bold"), bg=BG2, fg=FG).pack(pady=(50, 6))
tk.Label(vmenu, text="Selecciona una opcion",
         font=("Arial", 9), bg=BG2, fg=FG2).pack(pady=(0, 30))

for _txt, _cmd in [
    ("Productos",            lambda: [mostrar(vproductos), cargar_productos()]),
    ("Bitacora de Auditoria",lambda: [mostrar(vbitacora),  cargar_bitacora()]),
    ("Verificar Integridad", lambda: [mostrar(vintegridad), verificar_integridad()]),
    ("Generar Backup",       lambda: generar_backup()),
]:
    mk_btn(vmenu, _txt, _cmd, width=26).pack(pady=5)

tk.Frame(vmenu, bg=BORDER, height=1).pack(fill="x", padx=60, pady=18)
mk_btn(vmenu, "Cerrar sesion", lambda: mostrar(inicio), width=26).pack()

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
tk.Label(vproductos, text="Gestion de Productos",
         font=("Arial", 14, "bold"), bg=BG2, fg=FG).pack(pady=(20, 10))

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

_pp = tk.Frame(vproductos, bg=BG2)
_pp.pack(pady=8)
mk_btn(_pp, "Nuevo",    lambda: abrir_formulario("crear"),  width=10).grid(row=0, column=0, padx=4)
mk_btn(_pp, "Editar",   lambda: abrir_formulario("editar"), width=10).grid(row=0, column=1, padx=4)
mk_btn(_pp, "Eliminar", lambda: eliminar_producto(),        width=10).grid(row=0, column=2, padx=4)
tk.Frame(vproductos, bg=BORDER, height=1).pack(fill="x", padx=40, pady=8)
mk_btn(vproductos, "Volver al menu", lambda: mostrar(vmenu), width=20).pack(pady=4)

def cargar_productos():
    try:
        tree_p.delete(*tree_p.get_children())
        with get_con() as con:
            rows = con.execute("SELECT id, nombre, sku, cantidad, precio FROM products").fetchall()
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

lbl_form_titulo = tk.Label(vformulario, font=("Arial", 14, "bold"), bg=BG2, fg=FG)
lbl_form_titulo.pack(pady=(30, 20))

_fpanel = tk.Frame(vformulario, bg=BG2)
_fpanel.pack()
labels_p = ["Nombre:", "SKU:", "Cantidad:", "Precio:"]
entries_p = {}
for i, lbl in enumerate(labels_p):
    mk_label(_fpanel, lbl, fg=FG2).grid(row=i*2, column=0, sticky="w", pady=(4,1))
    e = mk_entry(_fpanel, width=26)
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
        lbl_form_titulo.config(text="Editar Producto")
    else:
        limpiar_form_p()
        form_mode["pid"] = None
        lbl_form_titulo.config(text="Nuevo Producto")
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

tk.Frame(vformulario, bg=BORDER, height=1).pack(fill="x", padx=40, pady=12)
_fb = tk.Frame(vformulario, bg=BG2)
_fb.pack()
mk_btn(_fb, "Guardar",  guardar_formulario,         width=14).grid(row=0, column=0, padx=6)
mk_btn(_fb, "Cancelar", lambda: mostrar(vproductos), width=14).grid(row=0, column=1, padx=6)

# ── BITACORA ──────────────────────────────────────────────────────────────────
tk.Label(vbitacora, text="Bitacora de Auditoria",
         font=("Arial", 14, "bold"), bg=BG2, fg=FG).pack(pady=(20, 10))

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

tk.Frame(vbitacora, bg=BORDER, height=1).pack(fill="x", padx=40, pady=8)
mk_btn(vbitacora, "Volver al menu", lambda: mostrar(vmenu), width=20).pack(pady=4)

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
tk.Label(vintegridad, text="Verificacion de Integridad",
         font=("Arial", 14, "bold"), bg=BG2, fg=FG).pack(pady=(20, 10))

resultado_int = tk.Text(vintegridad, height=16, width=58, state="disabled",
                        bg=ENTRY_BG, fg=FG, insertbackground=FG,
                        font=("Courier", 9), relief="flat",
                        highlightthickness=1, highlightbackground=BORDER)
resultado_int.pack(padx=16, pady=4)

tk.Frame(vintegridad, bg=BORDER, height=1).pack(fill="x", padx=40, pady=8)
mk_btn(vintegridad, "Volver al menu", lambda: mostrar(vmenu), width=20).pack(pady=4)

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

#  ARRANQUE
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
