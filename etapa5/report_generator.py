# region Imports
import copy
import json
import html
import pdfkit
import os
import re
import subprocess
from datetime import datetime
from http.cookies import SimpleCookie
from sys import argv, exit
from typing import Optional, Union
# endregion

# region Constants
BASH = "/bin/bash"
CMD_ENABLE_VENV = "source .venv/bin/activate"
REPORT_OUTPUT_FOLDER = f"{os.getcwd()}/reportes/".replace("etapa5", "")
REPORT_OUTPUT_FILE = f"{REPORT_OUTPUT_FOLDER}[DT]_reporte.pdf"
PORTS_FILE = f"{os.getcwd()}/services.json"
# Almacena los hallazgos
FINDINGS: list = []
ROW_FINDING: dict = {
        "title": "",
        "description": "",
        "severity": "",
        "impact": "",
        "tech_recommendation": []
    }
# Almacena las evidencias
EVIDENCES: list = []
ROW_EVIDENCE: dict = {
        "title": "",
        "description": "",
        "evidence": "",
        "url": ""
    }
# Recomendaciones técnicas
TECH_RECOMMENDATIONS: list = []
ROW_TR: dict = {
    "title": "",
    "recommendation": "",
    "responsible": "",
    "priority": ""
}
# Hallazgo por nivel de criticidad detectados
SL_CRITICAL = 0
SL_HIGH = 0
SL_MEDIUM = 0
SL_LOW = 0
SL_INFORMATIVE = 0
# endregion

# region Util Functions

def clean_colors(t: str) -> str:
    '''Cleans bash colors and attributes from text.'''
    # Foreground colors
    cfg:list[int] = [30, 31, 32, 33, 34, 35, 36, 37, 90, 91, 92, 93, 94, 95, \
        96, 97]
    # Background colors
    cbg:list[int] = [40, 41, 42, 43, 44, 45, 46, 47, 100, 101, 102, 103, 104, \
        105, 106, 107]
    # Attributes
    cattr:list[int] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    for code in cfg + cbg + cattr:
        t = t.replace(f"\033[{code}m", "")
    return t

def has_digits(t: str) -> bool:
    '''Check if t has any digits.'''
    return bool(re.search(r'\d', t))

def is_csrf_token(v: str) -> bool:
    '''Detects if a value is a csrf token.

    Rules:
        - >= 16 chars
        - Charset: a-z, A-Z, 0-9, _-=.
    '''
    csrf_regex: re.Pattern = re.compile(r'^[a-zA-Z0-9\-_.=]{16,}$')
    return bool(csrf_regex.match(v))

# endregion

# region Main Steps

def run_step_one(target: str) -> list:
    '''Run step one.'''
    # Etapa1: Ejecución del reconocimiento
    try:
        os.chdir("etapa1")
        recon_target_url: str = target
        cmd_recon:str  = f"{CMD_ENABLE_VENV} && " \
            f"python3 reconocimiento.py -w wl2.txt --workers 2 -u {recon_target_url}"
        recon_result: subprocess.CompletedProcess = subprocess.run(cmd_recon, \
            shell=True, executable=BASH, capture_output=True, text=True)
        recon_out: str = clean_colors(recon_result.stdout)
        # Procesar salida
        recon_log_file: str = list(
                filter(
                    lambda e: len(e) > 0,
                    recon_out.split("\n")
                )
            )[-1].replace("[Info] Results saved at: ", "")
        # Log file no encontrado
        if not os.path.exists(recon_log_file):
            print(f"[Error] File '{recon_log_file}' not found!")
            exit(1)
        # Abrir log file
        with open(recon_log_file, "r") as f:
            recon_data: list = json.load(f)
        os.chdir("../")
        return recon_data
    except Exception as e:
        os.chdir("../")
        # todo: log excepción
        return []

def run_step_two(target_ip: str) -> str:
    '''Run stop two'''
    try:
        # Etapa 2: Ejecución del escaneo automatizado
        os.chdir("etapa2")
        scan_target: str = "192.168.1.1"
        cmd_scan:str = f"{CMD_ENABLE_VENV} && python scanner.py -n {scan_target} -p 1-1000"
        scan_result: subprocess.CompletedProcess = subprocess.run(cmd_scan, shell=True, \
            executable=BASH, capture_output=True, text=True)
        scan_out: str = clean_colors(scan_result.stdout)
        os.chdir("../")
        return scan_out
    except Exception as e:
        os.chdir("../")
        # todo: log excepción
        return ""

def run_step_three_sqli() -> str:
    '''Run step three: sqli.'''
    # Etapa 3: Explotación ética de vulnerabilidades
    # SQLi
    try:
        os.chdir("etapa3/sqli/vulnerable-server")
        # Inicia el servidor PHP para simular el server vulnerable
        php_server: subprocess.Popen = subprocess.Popen(
                [
                    "php",
                    "-S",
                    "localhost:4000",
                    "server.php"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        os.chdir("../")
        cmd_sqli: str = f"{CMD_ENABLE_VENV} " \
            "&& python sqli-tester.py -t tests.json -u targets.txt"
        sqli_result: subprocess.CompletedProcess = subprocess.run(cmd_sqli, shell=True, \
            executable=BASH, capture_output=True, text=True)
        sqli_out: str = clean_colors(sqli_result.stdout)
        # Detiene el servidor vulnerable
        php_server.terminate()
        php_server.wait()
        os.chdir("../../")
        return sqli_out
    except Exception as e:
        os.chdir("../../")
        # todo log excepción
        return ""

def run_step_three_xss() -> str:
    '''Run step three: xss.'''
    # Etapa 3: Explotación ética de vulnerabilidades
    # XSS
    try:
        os.chdir("etapa3/xss/vulnerable-server")
        # Inicia el servidor PHP para simular el server vulnerable
        php_server: subprocess.Popen = subprocess.Popen(
                [
                    "php",
                    "-S",
                    "localhost:4000",
                    "server.php"
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        os.chdir("../")
        cmd_xss: str = f"{CMD_ENABLE_VENV} " \
            "&& python xss-tester.py -t tests.json -u targets.txt"
        xss_result: subprocess.CompletedProcess = subprocess.run(cmd_xss, shell=True, \
            executable=BASH, capture_output=True, text=True)
        xss_out: str = clean_colors(xss_result.stdout)
        # Detiene el servidor vulnerable
        php_server.terminate()
        php_server.wait()
        os.chdir("../../")
        return xss_out
    except Exception as e:
        os.chdir("../../")
        # todo log excepción
        return ""

# endregion

# region Report generation functions

def get_report_template() -> str:
    '''Reads report template from etapa5/reporte/template.html.'''
    os.chdir("etapa5/reporte/")
    template_file: str = "template.html"

    # Archivo template no existe
    if not os.path.exists(template_file):
        print(f"[Error] Report template file '{template_file}' do not exists!")
        exit(1)

    # Lee el template
    with open(template_file, "r") as f:
        content: str = f.read()
    os.chdir("../../")

    return content

def generate_pdf_report(html: str) -> None:
    '''Generate output PDF report.'''
    # Verifica y/o crea la carpeta de reportes
    if not os.path.exists(REPORT_OUTPUT_FOLDER):
        os.mkdir(REPORT_OUTPUT_FOLDER)

    # Genera el nombre del reporte
    dt: str = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    output_file: str = REPORT_OUTPUT_FILE.replace("[DT]", dt)

    # Leer e incrustar el CSS
    css_file = "format.dark.css" if "--dark" in argv else "format.css"
    css_file: str = f"etapa5/reporte/{css_file}"

    # Archivo css no existe
    if not os.path.exists(css_file):
        print(f"[Error] File '{css_file}' do not exists!")
        exit(1)

    # Lee el archivo
    with open(css_file, "r") as f:
        css_content: str = f.read()

    # Incrusta el CSS en el reporte html
    embedded_css: str = f"<style>{css_content}</style>"
    to_replace: str = "<link rel=\"stylesheet\" href=\"format.css\">"
    html = html.replace(to_replace, embedded_css)

    # Generar fecha y hora del reporte
    now: datetime = datetime.now()
    date: str = now.date().strftime("%d-%m-%Y")
    time: str = now.time().strftime("%H:%M:%S")

    # Reemplaza hora y fecha en el reporte
    html = html.replace("{DATE}", date) \
        .replace("{TIME}", time)

    # Genera reporte HTML para pruebas
    html_report_file: str = f"{output_file}.html"
    with open(html_report_file, "w") as f:
        f.write(html)

    # Genera el reporte
    options: dict = {
        'page-size': 'Letter',
        'orientation': 'Landscape',
        'margin-top': '10mm',
        'margin-right': '6mm',
        'margin-bottom': '10mm',
        'margin-left': '6mm'
    }
    pdfkit.from_string(html, output_file, options=options)

# endregion

def get_services_data() -> dict:
    '''Reads etapa5/services.json file.'''

    # Archivo puertos.json no existe
    if not os.path.exists(PORTS_FILE):
        print(f"[Error] File '{PORTS_FILE}' not exists!")
        exit(1)

    # Leer archivo puertos.json
    with open(PORTS_FILE, "r") as f:
        ports_data: list = json.load(f)
    # Convierte servicios en un diccionario {port, service}
    services: dict = {}
    for s in ports_data:
        try:
            # Se requiere expansión de rango: start-end
            # El servicio es repetido a lo largo de su expansión
            # region -----------------------------------------------------------
            if '-' in s["port"]:
                pfrom: str
                pto: str
                pfrom, pto = s["port"].split("-")
                prange: range = range(int(pfrom), int(pto) + 1)
                for p in prange:
                    services[p] = s
            # endregion --------------------------------------------------------

            # Puertos específicos
            # Se repite el servicio para cada puerto
            # region -----------------------------------------------------------
            elif ',' in s["port"]:
                ports: list[int] = [
                        int(p.strip())
                        for p in s["port"].split(',')
                    ]
                for p in ports:
                    services[p] = s
            # endregion --------------------------------------------------------
            # Flujo normal
            else:
                port: int = int(s["port"])
                services[port] = s
        # Por si hay un error en el archivo services.json
        except Exception as e:
            print(s["port"])
            print(e)
            continue
    return services

def step_one_analize_headers(url: str, headers: dict) -> None:
    '''Search for security findings at headers.'''
    # region Globals
    global FINDINGS, ROW_FINDING
    global EVIDENCES, ROW_EVIDENCE
    global TECH_RECOMMENDATIONS, ROW_TR
    global SL_CRITICAL
    global SL_HIGH
    global SL_MEDIUM
    global SL_LOW
    global SL_INFORMATIVE
    # endregion

    # Nombres de headers en minúsculas
    lc_headers: set = set([h.lower() for h in headers.keys()])

    # No se analizan versiones vulnerables
    # Para analizar: Server, X-Powered-By
    h_to_analize: set = set(["server", "x-powered-by"])
    # Impacto para los headers de análisis
    h_impact = {
        "Server": "Permite a un atacante conocer exactamente qué software corre" \
            " y buscar exploits específicos de esa versión.",
        "X-Powered-By": "Facilita ataques dirigidos, como exploits de " \
            "vulnerabilidades conocidas del lenguaje o framework."
    }
    for h_name, h_value in headers.items():
        # Header está en el listado para analizar
        if h_name.lower() in h_to_analize:
            # region Crea fila para tabla hallazgos
            # ------------------------------------------------------------------
            f_row: dict =  copy.deepcopy(ROW_FINDING)
            f_row["title"] = f"Exposición de información en header "\
                f"<b>{h_name}</b>"
            f_row["description"] = f"Se detectó <b>{h_value}</b> en el " \
                f"header <b>{h_name}</b>."
            f_row["tech_recommendation"].append(
                    f"Eliminar header <b>{h_name}</b> de la respuesta."
                )
            # Impacto generalista sin tener en cuenta si la versión se filtra
            f_row["impact"] = h_impact[h_name]

            # Criticidad Alta: Tiene la versión de algo
            if has_digits(headers["Server"]):
                SL_MEDIUM += 1
                f_row["severity"] = "Media"
            # Media baja, solo muestra la tecnología
            else:
                f_row["severity"] = "Baja"
                SL_LOW += 1

            # Guarda hallazgo
            FINDINGS.append(f_row)
            # endregion --------------------------------------------------------

            # region Crea fila para tabla Evidencias
            # ------------------------------------------------------------------
            e_row: dict = copy.deepcopy(ROW_EVIDENCE)
            e_row["title"] = f"Exposición de información en header "\
                f"<b>{h_name}</b>"
            e_row["description"] = f"Se detectó <b>{h_value}</b> en el " \
                f"header <b>{h_name}</b>."
            e_row["evidence"] = h_value
            e_row["url"] = url
            EVIDENCES.append(e_row)
            # endregion --------------------------------------------------------

            # region Crea fila para tabla Recomendaciones Técnicas
            # ------------------------------------------------------------------
            tr_row: dict = copy.deepcopy(ROW_TR)
            tr_row["title"] = f"Exposición de información en header "\
                f"<b>{h_name}</b>"
            tr_row["recommendation"] = f"Eliminar header <b>{h_name}</b> de la" \
                "respuesta."
            tr_row["responsible"] = "DevOps/Backend"
            tr_row["priority"] = "Media"
            TECH_RECOMMENDATIONS.append(tr_row)
            # endregion --------------------------------------------------------

    del h_to_analize

    # Analiza header Set-Cookie
    if 'set-cookie' in lc_headers:
        h_name: str = "Set-Cookie"
        h_value: str = headers["Set-Cookie"]
        
        # Parsea las cookies para analizarlas
        c: SimpleCookie = SimpleCookie()
        c.load(h_value)

        # flags
        f_secure: str = "<b>Secure</b>"
        f_http_only: str = "<b>HttpOnly</b>"
        f_same_site: str = "<b>SameSite</b>"

        # Procesa cookies en busca de ausencia de flags
        # Morsel objects:
        # https://docs.python.org/3/library/http.cookies.html#morsel-objects
        for c_name, o_morsel in c.items():
            html_c_name: str = f"<b>{c_name}</b>"

            # No tiene los flags HttpOnly y Secure?
            if not o_morsel["httponly"]:
                SL_HIGH += 1
                # region Crea fila para tabla hallazgos
                # --------------------------------------------------------------
                f_row: dict =  copy.deepcopy(ROW_FINDING)
                f_row["title"] = f"Cookie insegura: {html_c_name}"
                f_row["description"] = f"Cookie {html_c_name} sin flag " \
                    f"{f_http_only}."
                f_row["tech_recommendation"].append(
                    f"Agregar flag {f_http_only}."
                )
                f_row["severity"] = "Alta"
                f_row["impact"] = f"La cookie {html_c_name} puede ser enviada " \
                    "por HTTP."
                # Guarda hallazgo
                FINDINGS.append(f_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Evidencias
                # --------------------------------------------------------------
                e_row: dict = copy.deepcopy(ROW_EVIDENCE)
                e_row["title"] = f"Cookie insegura: {html_c_name}"
                e_row["description"] = f"Cookie {html_c_name} sin flag " \
                    f"{f_http_only}."
                e_row["evidence"] = o_morsel.value
                e_row["url"] = url
                EVIDENCES.append(e_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Recomendaciones Técnicas
                # --------------------------------------------------------------
                tr_row: dict = copy.deepcopy(ROW_TR)
                tr_row["title"] = f"Cookie insegura: {html_c_name}"
                tr_row["recommendation"] = f"Agregar flag {f_http_only}."
                tr_row["responsible"] = "Backend"
                tr_row["priority"] = "Alta"
                TECH_RECOMMENDATIONS.append(tr_row)
                # endregion ----------------------------------------------------

            # Cookie no tiene flag Secure
            if not o_morsel["secure"]:
                SL_HIGH += 1
                # region Crea fila para tabla hallazgos
                # --------------------------------------------------------------
                f_row: dict =  copy.deepcopy(ROW_FINDING)
                f_row["title"] = f"Cookie insegura: {html_c_name}"
                f_row["description"] = f"Cookie {html_c_name} sin flag " \
                    f"{f_secure}."
                f_row["tech_recommendation"].append(
                    f"Agregar flag {f_secure}."
                )
                f_row["severity"] = "Alta"
                f_row["impact"] = f"La cookie {html_c_name} puede ser leída " \
                    "desde JavaScript."
                # Guarda hallazgo
                FINDINGS.append(f_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Evidencias
                # --------------------------------------------------------------
                e_row: dict = copy.deepcopy(ROW_EVIDENCE)
                e_row["title"] = f"Cookie insegura: {html_c_name}"
                e_row["description"] = f"Cookie {html_c_name} sin flag " \
                    f"{f_secure}."
                e_row["evidence"] = o_morsel.value
                e_row["url"] = url
                EVIDENCES.append(e_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Recomendaciones Técnicas
                # --------------------------------------------------------------
                tr_row: dict = copy.deepcopy(ROW_TR)
                tr_row["title"] = f"Cookie insegura: {html_c_name}"
                tr_row["recommendation"] = f"Cookie {html_c_name} sin flag " \
                    f"{f_secure}."
                tr_row["responsible"] = "Backend"
                tr_row["priority"] = "Alta"
                TECH_RECOMMENDATIONS.append(tr_row)
                # endregion ----------------------------------------------------

            # Cookie no tiene flag SameSite
            # Cookie tiene configurado el flag SameSite a None
            if not o_morsel["samesite"] or "none" in \
                    o_morsel["samesite"].lower():
                SL_MEDIUM += 1
                # region Crea fila para tabla hallazgos
                # --------------------------------------------------------------
                f_row: dict =  copy.deepcopy(ROW_FINDING)
                f_row["title"] = f"Cookie insegura: {html_c_name}"
                f_row["description"] = f"Cookie {html_c_name} sin flag "\
                    f"{f_same_site}."
                f_row["tech_recommendation"].append(
                    f"Agregar flag {f_same_site}."
                )
                f_row["severity"] = "Medio"
                f_row["impact"] = f"La cookie {html_c_name} podría ser " \
                    "suceptible a tracking externo y ataques CRSF."
                # Guarda hallazgo
                FINDINGS.append(f_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Evidencias
                # --------------------------------------------------------------
                e_row: dict = copy.deepcopy(ROW_EVIDENCE)
                e_row["title"] = f"Cookie insegura: {html_c_name}"
                e_row["description"] = f"Cookie {html_c_name} sin flag "\
                    f"{f_same_site}."
                e_row["evidence"] = o_morsel.value
                e_row["url"] = url
                EVIDENCES.append(e_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Recomendaciones Técnicas
                # --------------------------------------------------------------
                tr_row: dict = copy.deepcopy(ROW_TR)
                tr_row["title"] = f"Cookie insegura: {html_c_name}"
                tr_row["recommendation"] = f"Cookie {html_c_name} sin flag "\
                    f"{f_same_site}."
                tr_row["responsible"] = "Backend"
                tr_row["priority"] = "Alta"
                TECH_RECOMMENDATIONS.append(tr_row)
                # endregion ----------------------------------------------------

    # Ausencia de header Content-Security-Policy (CSP)
    if not 'content-security-policy' in lc_headers:
        SL_LOW += 1
        # region Crea fila para tabla hallazgos
        # ----------------------------------------------------------------------
        f_row: dict =  copy.deepcopy(ROW_FINDING)
        f_row["title"] = f"Ausencia de header <b>Content-Security-Policy</b>"
        f_row["description"] = f"No hay restricciones para cargar scripts de " \
            "terceros, inline scripts, llamado a funciones como <b>eval</b> o " \
            "URLs <b>javascript:</b>"
        f_row["tech_recommendation"].append(
            f"Implementar header <b>Content-Security-Policy</b> con dominios " \
                "de confianza."
        )
        f_row["severity"] = "Baja"
        f_row["impact"] = f"Aumento en el riesgo de inyeccion XSS."
        # Guarda hallazgo
        FINDINGS.append(f_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Evidencias
        # ----------------------------------------------------------------------
        e_row: dict = copy.deepcopy(ROW_EVIDENCE)
        e_row["title"] = f"Ausencia de header <b>Content-Security-Policy</b>"
        e_row["description"] = f"No hay restricciones para cargar scripts de " \
            "terceros, inline scripts, llamado a funciones como <b>eval</b> o " \
            "URLs <b>javascript:</b>"
        e_row["evidence"] = "<b>Headers:</b> " + ", ".join( list(headers.keys()))
        e_row["url"] = url
        EVIDENCES.append(e_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Recomendaciones Técnicas
        # ----------------------------------------------------------------------
        tr_row: dict = copy.deepcopy(ROW_TR)
        tr_row["title"] = "Ausencia de header <b>Content-Security-Policy</b>"
        tr_row["recommendation"] = f"Implementar header " \
            "<b>Content-Security-Policy</b> con dominios de confianza."
        tr_row["responsible"] = "Devops/Frontend"
        tr_row["priority"] = "Alta"
        TECH_RECOMMENDATIONS.append(tr_row)
        # endregion ------------------------------------------------------------

    # Ausencia de header Strict-Transport-Security (HSTS)
    if not 'strict-transport-security' in lc_headers:
        SL_MEDIUM += 1
        html_header: str = "<b>Strict-Transport-Security</b>"
        # region Crea fila para tabla hallazgos
        # ----------------------------------------------------------------------
        f_row: dict =  copy.deepcopy(ROW_FINDING)
        f_row["title"] = f"Ausencia de header {html_header}"
        f_row["description"] = "No se está forzando la comunicación HTTPS " \
            f"debido a la ausencia del header {html_header}."
        f_row["tech_recommendation"].append(
                f"Configurar header {html_header} en URL."
            )
        f_row["tech_recommendation"].append(
                "Incluir flag IncludeSubDomains en configuración."
            )
        f_row["severity"] = "Media"
        f_row["impact"] = "Su ausencia permite a los atacantes realizar " \
            "<b>Man in the Middle</b>."
        FINDINGS.append(f_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Evidencias
        # ----------------------------------------------------------------------
        e_row: dict = copy.deepcopy(ROW_EVIDENCE)
        e_row["title"] = f"Ausencia de header {html_header}"
        e_row["description"] = "No se está forzando la comunicación HTTPS " \
            f"debido a la ausencia del header {html_header}."
        e_row["evidence"] = "<b>Headers:</b> " + ", ".join( list(headers.keys()))
        e_row["url"] = url
        EVIDENCES.append(e_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Recomendaciones Técnicas
        # ----------------------------------------------------------------------
        tr_row: dict = copy.deepcopy(ROW_TR)
        tr_row["title"] = f"Ausencia de header {html_header}"
        tr_row["recommendation"] = "Incluir flag IncludeSubDomains en "\
            "configuración."
        tr_row["responsible"] = "Devops"
        tr_row["priority"] = "Alta"
        TECH_RECOMMENDATIONS.append(tr_row)
        # endregion ------------------------------------------------------------

def step_one_search_csrf_token(url: str, forms: list[dict]) -> None:
    '''Search for the absence of CSRF token in form values.'''
    # region Globals
    global FINDINGS, ROW_FINDING
    global EVIDENCES, ROW_EVIDENCE
    global TECH_RECOMMENDATIONS, ROW_TR
    global SL_CRITICAL
    global SL_HIGH
    global SL_MEDIUM
    global SL_LOW
    global SL_INFORMATIVE
    # endregion

    # Procesa los forms
    for form in forms:
        # Salta forms vacíos
        if "elements" not in form:
            continue

        # Busca token CSRF en los valores del form
        has_csrf_token: bool = False
        for e in form["elements"]:
            # Este valor tiene un valor y dicho valor corresponde a
            # un token CSRF
            if "value" in e["attributes"] \
                    and is_csrf_token(e["attributes"]["value"]):
                has_csrf_token = True
                # Ahora que el token se encontró, se procede a verificar el
                # form siguiente
                break

        # Antes de verificar el form siguiente, se completarán las tablas
        # si no se encontró un token CSRF
        if not has_csrf_token:
            SL_HIGH += 1
            # region Crea fila para tabla hallazgos
            # ------------------------------------------------------------------
            f_row: dict =  copy.deepcopy(ROW_FINDING)
            f_row["title"] = "Falta de protección CSRF en formulario"
            f_row["description"] = "El formulario no implementa un token " \
                "CSRF, lo que permite a un atacante realizar solicitudes " \
                "maliciosas en nombre de un usuario autenticado."
            f_row["tech_recommendation"].append(
                    "Implementar un token CSRF único por sesión o por " \
                        "formulario, validando su presencia en cada " \
                        "solicitud POST."
                )
            f_row["tech_recommendation"].append(
                    " Alternativamente, usar cabeceras SameSite y técnicas " \
                        "de doble cookie para protección adicional."
                )
            f_row["severity"] = "Alto"
            f_row["impact"] = "Posible ejecución de acciones no autorizadas, " \
                "comprometiendo la integridad de la cuenta del usuario y de " \
                "los datos del sistema."
            FINDINGS.append(f_row)
            # endregion --------------------------------------------------------

            # region Crea fila para tabla Evidencias
            # ------------------------------------------------------------------
            # Obtiene los nombres de los elementos del form como evidencia
            form_elements = []
            for e in form["elements"]:
                for attr in e["attributes"]:
                    if "name" in attr:
                        form_elements.append(attr["name"])

            e_row: dict = copy.deepcopy(ROW_EVIDENCE)
            e_row["title"] = "Falta de protección CSRF en formulario"
            e_row["description"] = "El formulario no implementa un token " \
                "CSRF, lo que permite a un atacante realizar solicitudes " \
                "maliciosas en nombre de un usuario autenticado."
            e_row["evidence"] = "Elementos del form: " + ", ".join(form_elements)
            e_row["url"] = url
            EVIDENCES.append(e_row)
            # endregion --------------------------------------------------------

            # region Crea fila para tabla Recomendaciones Técnicas
            # ------------------------------------------------------------------
            tr_row: dict = copy.deepcopy(ROW_TR)
            tr_row["title"] = "Falta de protección CSRF en formulario"
            tr_row["recommendation"] = "Implementar token CSRF único por " \
                "formulario, validando su presencia en cada solicitud."
            tr_row["responsible"] = "Backend"
            tr_row["priority"] = "Alta"
            TECH_RECOMMENDATIONS.append(tr_row)
            # endregion --------------------------------------------------------

def step_two_parses_output(out: str) -> list[dict]:
    '''Parses output from step two.'''
    # region Busca los hosts activos
    is_hosts: Optional[re.Match] = re.search(
            r"active hosts\: ([\d]{1,4})",
            out.replace("\n", ""),
            re.IGNORECASE
        )
    if not is_hosts:
        return []
    # endregion

    # Eliminar headers del output
    out = out[out.find("Host"):]
    # Eliminar footer
    out = out[:out.find("\n\nDate")]
    # Divide (y filtra elementos vacíos) la salida port hosts
    out_hosts: list[str] = list(filter(bool, out.split("Host: ")))

    # Filtra solo servicios expuestos
    _re_service: re.Pattern = re.compile(
            r"Port: ([\d]{1,5}) -> open\n(.*)\n?", re.MULTILINE)
    hosts: list = []
    for o_host in out_hosts:
        _host: dict = {"ip": "", "services": []}
        # Divide la salida del host en múltiples líneas
        host_lines: list[str] = list(filter(bool, o_host.split("\n")))

        # Limpia cada línea
        host_lines = [e.strip() for e in host_lines]
        # Guarda la IP del host
        _host["ip"] = host_lines[0]

        # Extrae los puertos abiertos y sus servicios
        services: list = _re_service.findall("\n".join(host_lines[1:]))
        # Se encontraron servicios
        if services:
            for s in services:
                _host["services"].append({
                        "port": int(s[0]),
                        "details": s[1]
                    })
            # Solo agrega el host que tiene servicios activos a la lista
            hosts.append(_host)

    return hosts

def step_two_analyses_hosts(hosts: list[dict], known_services: dict) -> None:
    '''Analyses the services for each host in the list.'''
    # region Globals
    global FINDINGS, ROW_FINDING
    global EVIDENCES, ROW_EVIDENCE
    global TECH_RECOMMENDATIONS, ROW_TR
    global SL_CRITICAL
    global SL_HIGH
    global SL_MEDIUM
    global SL_LOW
    global SL_INFORMATIVE
    # endregion

    # Cada host tiene servicios, por lo que no se valida su existencia
    for host in hosts:
        h_ip: str = host["ip"]
        h_services: list[dict] = host["services"]
        # Agrega una fila a modo de título con la IP
        FINDINGS.append(f"<b>Host:</b> {h_ip}")
        TECH_RECOMMENDATIONS.append(f"<b>Host:</b> {h_ip}")
        # Procesa los servicios de la IP
        for s in h_services:
            s_port: int = s["port"]
            s_detail: str = s["details"]

            # Puerto existe en los servicios conocidos
            if s_port in known_services:
                service: dict = known_services[s_port]

                # region Nivel de criticidad
                # --------------------------------------------------------------
                match service["severity"]:
                    case "alta":
                        SL_HIGH += 1
                    case "media":
                        SL_MEDIUM += 1
                    case "baja":
                        SL_LOW += 1
                # endregion ----------------------------------------------------

                # region Crea fila para tabla hallazgos
                # --------------------------------------------------------------
                f_row: dict =  copy.deepcopy(ROW_FINDING)
                f_row["title"] = f"Puerto expuesto <b>{s_port}</b>"
                f_row["description"] = f"<b>Servicio: </b>" \
                    f"{service["description"]}."
                f_row["tech_recommendation"].append(
                    service["tech_recommendation"])
                f_row["severity"] = service["severity"].capitalize()
                f_row["impact"] = service["impact"]
                FINDINGS.append(f_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Evidencias
                # --------------------------------------------------------------
                e_row: dict = copy.deepcopy(ROW_EVIDENCE)
                e_row["title"] = f"Puerto expuesto <b>{s_port}</b>"
                e_row["description"] = f"<b>Servicio: </b>" \
                    f"{service["description"]}."
                e_row["evidence"] = f"<b>Detección nmap</b>: {s_detail}"
                e_row["url"] = f"IP: {h_ip}"
                EVIDENCES.append(e_row)
                # endregion ----------------------------------------------------

                # region Crea fila para tabla Recomendaciones Técnicas
                # --------------------------------------------------------------
                tr_row: dict = copy.deepcopy(ROW_TR)
                tr_row["title"] = f"Puerto expuesto <b>{s_port}</b>"
                tr_row["recommendation"] = service["tech_recommendation"]
                tr_row["responsible"] = "SysAdmin/DevOps"
                tr_row["priority"] = "Alta"
                TECH_RECOMMENDATIONS.append(tr_row)
                # endregion ----------------------------------------------------

def step_three_parses_test(t: str) -> str:
    '''Parses the SQLi test title.'''
    re_test: re.Pattern = re.compile(r"^Running test: (.*)$")
    test: Optional[re.Match] = re_test.search(t)
    if test:
        t = test.group(1)
    return t

def step_three_sqli_parses_output(out: str) -> list[dict]:
    '''Parses the SQLi output in Step Three.'''
    # Elimina mensaje [Info]
    out = out.replace("[Info] ", "")
    out_tests: str
    out_report: str
    # Separa los tests del reporte
    out_tests, out_report = out.split("\n\nReport:\n")

    # Separa los tests por URL
    # region -------------------------------------------------------------------
    url_tests: list = list(
            # Separa cada test por \n y filtra elementos vacíos
            list(
                    # Procesa el título de cada test ignorando la url
                    step_three_parses_test(tt)
                    for tt in filter(bool, t.split("\n"))
                )
            # Separa los tests por host y filtra elementos vacíos
            for t in filter(bool, out_tests.split("Testing: "))
        )
    url_tests = list(filter(bool, url_tests))
    # endregion ----------------------------------------------------------------

    # Separa los reportes por URL
    # region -------------------------------------------------------------------
    re_url_report: re.Pattern = re.compile(
    r"URL: (.*?)\n- Vulnerable\?: (Yes|No)\n?")
    reports: list = re_url_report.findall(out_report)
    vulnerable_urls: list[str] = [r[0] for r in reports if r[1] == 'Yes']
    # endregion ----------------------------------------------------------------

    # Crea objetos procesables
    # region -------------------------------------------------------------------
    _url_tests: list = []
    for t in url_tests:
        test: dict = {
            "url": t[0],
            "tests": t[1:],
            "vulnerable": t[0] in vulnerable_urls
        }
        _url_tests.append(test)
    # endregion ----------------------------------------------------------------

    return _url_tests

def step_three_sqli_analyses_urls(url_list: list[dict]) -> None:
    '''Analyses the vulnerable URLs in step three.'''
    # region Globals
    global FINDINGS, ROW_FINDING
    global EVIDENCES, ROW_EVIDENCE
    global TECH_RECOMMENDATIONS, ROW_TR
    global SL_CRITICAL
    global SL_HIGH
    global SL_MEDIUM
    global SL_LOW
    global SL_INFORMATIVE
    # endregion

    # Procesa las URLs vulnerables
    for url in url_list:
        # Nivel de criticidad
        SL_CRITICAL += 1

        # region Crea fila para tabla hallazgos
        # ----------------------------------------------------------------------
        f_row: dict =  copy.deepcopy(ROW_FINDING)
        f_row["title"] = f"URL vulnerable a SQLi."
        f_row["description"] = f"URL <b>{url["url"]}</b> permite ejecutar " \
            "consultas maliciosas contra la base de datos, exponiendo o " \
            "alterando información sensible."
        f_row["tech_recommendation"].append(
                "Implementar consultas parametrizadas(preparadas) en todas " \
                "las interacciones con la base de datos para mitigar SQLi."
            )
        f_row["severity"] = "Crítico"
        f_row["impact"] = "Acceso no autorizado a la base de datos, robo de " \
            "credenciales, modificación o eliminación de datos, escalamiento " \
            "de privilegios."
        FINDINGS.append(f_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Evidencias
        # ----------------------------------------------------------------------
        e_row: dict = copy.deepcopy(ROW_EVIDENCE)
        e_row["title"] = f"URL vulnerable a SQLi."
        e_row["description"] = f"URL <b>{url["url"]}</b> permite ejecutar " \
            "consultas maliciosas contra la base de datos, exponiendo o " \
            "alterando información sensible."
        e_row["evidence"] = "Payloads testeados: " + ", ".join(
                [f"<b>{t}</b>" for t in url["tests"]]
            )
        e_row["url"] = url["url"]
        EVIDENCES.append(e_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Recomendaciones Técnicas
        # ----------------------------------------------------------------------
        tr_row: dict = copy.deepcopy(ROW_TR)
        tr_row["title"] = f"URL vulnerable a SQLi."
        tr_row["recommendation"] = "Implementar consultas parametrizadas" \
                "(preparadas) en todas las interacciones con la base de " \
                "datos para mitigar SQLi."
        tr_row["responsible"] = "Backend"
        tr_row["priority"] = "Crítica"
        TECH_RECOMMENDATIONS.append(tr_row)
        # endregion ------------------------------------------------------------

def step_three_xss_parses_output(out: str) -> list[dict]:
    '''Parses the XSS output in Step Three.'''
    # Elimina mensaje [Info]
    out = out.replace("[Info] ", "")
    out_tests: str
    out_report: str
    # Separa los tests del reporte
    out_tests, out_report = out.split("\n\nReport:\n")

    # Separa los tests por URL
    # region -------------------------------------------------------------------
    url_tests: list = list(
            # Separa cada test por \n y filtra elementos vacíos
            list(
                    # Procesa el título de cada test ignorando la url
                    step_three_parses_test(tt)
                    for tt in filter(bool, t.split("\n"))
                )
            # Separa los tests por host y filtra elementos vacíos
            for t in filter(bool, out_tests.split("Testing: "))
        )
    url_tests = list(filter(bool, url_tests))
    # endregion ----------------------------------------------------------------

    # Separa los reportes por URL
    # region -------------------------------------------------------------------
    re_url_report: re.Pattern = re.compile(
    r"URL: (.*?)\n- Vulnerable\?: (Yes|No)\n?")
    reports: list = re_url_report.findall(out_report)
    vulnerable_urls: list[str] = [r[0] for r in reports if r[1] == 'Yes']
    # endregion ----------------------------------------------------------------

    # Crea objetos procesables
    # region -------------------------------------------------------------------
    _url_tests: list = []
    for t in url_tests:
        test: dict = {
            "url": t[0],
            "tests": t[1:],
            "vulnerable": t[0] in vulnerable_urls
        }
        _url_tests.append(test)
    # endregion ----------------------------------------------------------------

    return _url_tests

def step_three_xss_analyses_urls(url_list: list[dict]) -> None:
    '''Analyses the vulnerable URLs in step three.'''
    # region Globals
    global FINDINGS, ROW_FINDING
    global EVIDENCES, ROW_EVIDENCE
    global TECH_RECOMMENDATIONS, ROW_TR
    global SL_CRITICAL
    global SL_HIGH
    global SL_MEDIUM
    global SL_LOW
    global SL_INFORMATIVE
    # endregion

    # Procesa las URLs vulnerables
    for url in url_list:
        # Nivel de criticidad
        SL_HIGH += 1

        # region Crea fila para tabla hallazgos
        # ----------------------------------------------------------------------
        f_row: dict =  copy.deepcopy(ROW_FINDING)
        f_row["title"] = f"URL vulnerable a XSS."
        f_row["description"] = f"URL <b>{url["url"]}</b> permite inyectar y " \
            "ejecutar código JavaScript en el navegador de los usuarios, " \
            "comprometiendo su sesión o datos personales."
        f_row["tech_recommendation"].append(
                "Aplicar validación estricta y codificación de salida " \
                "(output encoding) en todos los parámetros que se muestran "\
                "en la interfaz para evitar XSS."
            )
        f_row["severity"] = "Crítico"
        f_row["impact"] = "Robo de cookies de sesión, redirección a sitios " \
            "maliciosos, manipulación de la interfaz, phishing interno."
        FINDINGS.append(f_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Evidencias
        # ----------------------------------------------------------------------
        e_row: dict = copy.deepcopy(ROW_EVIDENCE)
        e_row["title"] = f"URL vulnerable a XSS."
        e_row["description"] = f"URL <b>{url["url"]}</b> permite inyectar y " \
            "ejecutar código JavaScript en el navegador de los usuarios, " \
            "comprometiendo su sesión o datos personales."
        e_row["evidence"] = "Payloads testeados: " + ", ".join(
                [f"<b>{html.escape(t)}</b>" for t in url["tests"]]
            )
        e_row["url"] = url["url"]
        EVIDENCES.append(e_row)
        # endregion ------------------------------------------------------------

        # region Crea fila para tabla Recomendaciones Técnicas
        # ----------------------------------------------------------------------
        tr_row: dict = copy.deepcopy(ROW_TR)
        tr_row["title"] = f"URL vulnerable a XSS."
        tr_row["recommendation"] = "Aplicar validación estricta y " \
            "codificación de salida (output encoding) en todos los " \
            "parámetros que se muestran en la interfaz para evitar XSS."
        tr_row["responsible"] = "Backend"
        tr_row["priority"] = "Crítica"
        TECH_RECOMMENDATIONS.append(tr_row)
        # endregion ------------------------------------------------------------

def main() -> None:
    # region globals
    global FINDINGS
    global EVIDENCES
    global TECH_RECOMMENDATIONS
    global SL_CRITICAL
    global SL_HIGH
    global SL_MEDIUM
    global SL_LOW
    global SL_INFORMATIVE
    # Cambia al directorio del proyecto
    os.chdir("../")
    # endregion

    # region Etapa 1
    # --------------------------------------------------------------------------
    recon_out: list = run_step_one("http://testphp.vulnweb.com/")

    # Extrae headers por url
    recon_headers: list[dict] = [
            {"url": s["url"], "headers": s["headers"]}
            for s in recon_out
            if "headers" in s
        ]
    # Ejecutar análisis sobre headers
    for recon_element in recon_headers:
        re_url: str = recon_element["url"]
        re_headers: dict = recon_element["headers"]
        # Agrega fila con la URL para mejorar la legibilidad
        FINDINGS.append(f"<b>URL:</b> {re_url}")
        TECH_RECOMMENDATIONS.append(f"<b>URL:</b> {re_url}")
        # Analiza headers
        step_one_analize_headers(re_url, re_headers)

    # Ejecutar análisis sobre formularios
    # Se busca principalmente si hay o no un token anti CSRF
    recon_forms: list[dict] = [
            {"url": s["url"], "forms": s["forms"]}
            for s in recon_out
            if "forms" in s
        ]
    # Ejecutar análisis sobre forms
    for recon_element in recon_forms:
        re_url: str = recon_element["url"]
        re_forms: list[dict] = recon_element["forms"]

        # Solo procesa el form si tiene elementos
        if not len(re_forms):
            continue

        # Agrega fila con la URL para mejorar la legibilidad
        FINDINGS.append(f"<b>URL:</b> {re_url}")
        TECH_RECOMMENDATIONS.append(f"<b>URL:</b> {re_url}")
        # Analiza forms
        step_one_search_csrf_token(re_url, re_forms)
    # --------------------------------------------------------------------------
    # endregion ----------------------------------------------------------------

    # region Etapa 2
    # --------------------------------------------------------------------------
    rcon_services: str = run_step_two("192.168.1.1")
    known_services: dict = get_services_data()
    recon_hosts: list[dict] = step_two_parses_output(rcon_services)
    step_two_analyses_hosts(recon_hosts, known_services)
    # endregion ----------------------------------------------------------------

     # region Etapa 3 SQLi
    # --------------------------------------------------------------------------
    recon_sqli: str = run_step_three_sqli()
    recon_sqli_urls = step_three_sqli_parses_output(recon_sqli)
    step_three_sqli_analyses_urls(recon_sqli_urls)
    # endregion ----------------------------------------------------------------

    # region Etapa 3 XSS
    # --------------------------------------------------------------------------
    recon_xss: str = run_step_three_xss()
    recon_xss_urls = step_three_xss_parses_output(recon_xss)
    step_three_xss_analyses_urls(recon_xss_urls)
    # endregion ----------------------------------------------------------------

    # Obtener el template del reporte
    r_template: str = get_report_template()

    # region Procesar hallazgos en filas de tabla
    # --------------------------------------------------------------------------
    f_rows: list = []
    f_row_i: int = 1
    for i in range(len(FINDINGS)):
        # Hallazgo
        f = FINDINGS[i]
        # Agrega filas cabeceras para indicar la URL del hallazgo
        if type(f) == str:
            f_rows.append(
                    "<tr>" \
                    f"<td colspan=\"6\">{f}</td>"
                    "</tr>"
                )
        # Procesa fila con elementos
        else:
            # Procesa las recomendaciones técnicas
            te: str = "\n".join([
                    f"<li>{tr}</li>"
                    for tr in f["tech_recommendation"]
                ])
            f_rows.append(
                    "<tr>" \
                    f"<td class=\"text-center\">{f_row_i}</td>" \
                    f"<td>{f["title"]}</td>" \
                    f"<td>{f["description"]}</td>" \
                    f"<td class=\"text-center\">{f["severity"]}</td>" \
                    f"<td>{f["impact"]}</td>" \
                    f"<td> <ul>{te}</ul> </td>"
                    "</tr>"
                )
            f_row_i += 1
    del f_row_i
    # Agregar cuerpo a tabla hallazgos
    r_template = r_template.replace("{FINDINGS-ROWS}", "\n".join(f_rows))
    del f_rows
    # endregion ----------------------------------------------------------------

    # region Procesar evidencias en filas de tabla
    # --------------------------------------------------------------------------
    e_rows: list = []
    for i in range(len(EVIDENCES)):
        # Evidencia
        e = EVIDENCES[i]
        # Procesa fila con elementos
        e_rows.append(
                "<tr>" \
                f"<td>{i + 1}</td>" \
                f"<td>{e["title"]}</td>" \
                f"<td>{e["description"]}</td>" \
                f"<td>{e["evidence"]}</td>" \
                f"<td>{e["url"]}</td>" \
                "</tr>"
            )
    # Agregar cuerpo a tabla evidencias
    r_template = r_template.replace("{EVIDENCE-ROWS}", "\n".join(e_rows))
    del e_rows
    # endregion ----------------------------------------------------------------

    # region Procesar recomendaciones técnicas en filas de tabla
    # --------------------------------------------------------------------------
    tr_rows: list = []
    tr_row_i = 1
    for i in range(len(TECH_RECOMMENDATIONS)):
        # Recomendación Técnica
        tr = TECH_RECOMMENDATIONS[i]
        # Agrega filas cabeceras para indicar la URL del hallazgo
        if type(tr) == str:
            tr_rows.append(
                    "<tr>" \
                    f"<td colspan=\"6\">{tr}</td>"
                    "</tr>"
                )
        # Procesa fila con elementos
        else:
            tr_rows.append(
                    "<tr>" \
                    f"<td>{tr_row_i}</td>" \
                    f"<td>{tr["title"]}</td>" \
                    f"<td>{tr["recommendation"]}</td>" \
                    f"<td>{tr["responsible"]}</td>" \
                    f"<td>{tr["priority"]}</td>" \
                    "</tr>"
                )
            tr_row_i += 1
    del tr_row_i
    # Agregar cuerpo a tabla recomendaciones técnicas
    r_template = r_template.replace("{TECH-RECOMMENDATIONS-ROWS}",
        "\n".join(tr_rows))
    del tr_rows
    # endregion ----------------------------------------------------------------

    # region Procesar niveles de criticidad en tabla
    # --------------------------------------------------------------------------
    sl_rows: list = []
    # Los índices de sl_levels y sl_data coinciden
    sl_levels: list = [
            SL_CRITICAL,
            SL_HIGH,
            SL_MEDIUM,
            SL_LOW,
            SL_INFORMATIVE
        ]
    sl_data: list = [
            {
                "description": "Compromete de forma inmediata la " \
                    "confidencialidad, integridad o disponibilidad de " \
                    "sistemas y datos.",
                "examples": "Ejecución remota de código (RCE), inyección SQL " \
                    "sin autenticación, fuga masiva de datos sensibles.",
                "level": "Crítico"
            },
            {
                "description": "Puede ser explotado con relativa facilidad y " \
                    "causar impacto significativo.",
                "examples": "XSS almacenado, CSRF que permite acciones " \
                    "críticas, credenciales hardcodeadas.",
                "level": "Alto"
            },
            {
                "description": "Impacto moderado o requiere condiciones " \
                    "específicas para explotarse.",
                "examples": "XSS reflejado, exposición de rutas internas, " \
                    "uso de cifrado obsoleto (MD5, SHA1).",
                "level": "Medio"
            },
            {
                "description": "Bajo impacto, sin riesgo directo inmediato.",
                "examples": "Información de versión del servidor, mensajes " \
                    "de error detallados, encabezados de seguridad ausentes.",
                "level": "Bajo"
            },
            {
                "description": "No implica riesgo directo, pero puede ayudar " \
                    "a un atacante.",
                "examples": "Directorios listados, comentarios en código " \
                    "con pistas internas.",
                "level": "Informativo"
            }
        ]
    for i in range(len(sl_levels)):
        sl_level = sl_levels[i]
        sl_element = sl_data[i]
        if sl_level:
            # Agrega la fila a sl_rows
            sl_rows.append(
                    "<tr>" \
                    f"<td class=\"text-center\">{sl_element["level"]}</td>" \
                    f"<td>{sl_element["description"]}</td>" \
                    f"<td class=\"text-center\">{sl_level}</td>" \
                    f"<td>{sl_element["examples"]}</td>" \
                    "</tr>"
                )
    # Agregar cuerpo a tabla nivel de criticidad
    r_template = r_template.replace("{SEVERITY-LEVEL-ROWS}",
        "\n".join(sl_rows))
    del sl_rows
    # endregion ----------------------------------------------------------------

    # Genera el reporte en PDF
    generate_pdf_report(r_template)

if __name__ == "__main__":
    main()