# FiberHome HG6246R — Auditoría de seguridad y automatización DHCP

> **Acceso admin y reservas DHCP en routers FiberHome HG6246R sin llamar al ISP**  
> Firmware: **RP2952** · Operador: **CHL_MP** (Movistar / Mundo Pacífico Chile)  
> Auditoría autorizada sobre equipo propio, noviembre 2026

---

## ¿Qué es esto?

Si tienes un router **FiberHome HG6246R** con firmware RP2952 (común en Movistar y Mundo Pacífico Chile), este repositorio te da:

1. **Scripts para crear reservas DHCP** desde la cuenta `user/user1234` — sin necesitar la contraseña admin.
2. **Scripts para extraer la contraseña admin** del backup de configuración del router.
3. **Documentación completa** de las 7 vulnerabilidades encontradas y el proceso de criptoanálisis.

El control de acceso del router es **solo client-side**: la interfaz web oculta las opciones de DHCP y backup para el usuario normal, pero el backend acepta las operaciones sin validar el nivel del usuario.

---

## Inicio rápido

### Crear reservas DHCP para todos tus dispositivos

```bash
cd scripts
python3 dhcp_reserve_all.py --dry-run   # Ver qué haría sin cambiar nada
python3 dhcp_reserve_all.py              # Interactivo — pide confirmación antes de cada paso
```

### Extraer la contraseña admin

```bash
pip install pycryptodome   # Necesario para descifrado AES
python3 extract_admin_password.py
```

### Escanear el router

```bash
python3 fhscan.py    # Prueba todos los endpoints y reporta qué es accesible
```

### Alternativa solo con Bash (sin dependencias Python)

```bash
source login.sh                              # Login como user/user1234
./dhcp.sh hosts                              # Listar todos los dispositivos
./dhcp.sh add AA:BB:CC:DD:EE:FF 192.168.1.100  # Reservar una IP
./dhcp.sh list                               # Verificar
./dhcp.sh logout                             # Cerrar sesión
```

---

## Hallazgos de seguridad

| ID | Severidad | Hallazgo |
|----|-----------|----------|
| **S1** | Crítico | Escritura DHCP desde sesión user — `set_dhcp_lan_info` sin validación server-side |
| **S2** | Crítico | Backup de config descargable desde sesión user — `down_cfgfile` sin validación |
| **S3** | Alto | Cifrado trivial del backup — XOR con constante 9527, compartido entre modelos FiberHome |
| **S4** | Alto | Fuga masiva de información sin autenticación — 22+ endpoints exponen datos del router |
| **S5** | Alto | Clave AES hardcodeada en JavaScript público — misma clave/IV en todos los HG6246R |
| **S6** | Medio | `admin_management` accesible desde sesión user — escalamiento parcial de privilegios |
| **S7** | Bajo | HTTPS deshabilitado — todo el tráfico en texto claro por la LAN |

### Cadena de ataque completa

```
user/user1234 (credenciales por defecto, nivel 0)
        │
        ├──→ set_dhcp_lan_info (escribir reservas DHCP — no necesita admin)
        │
        └──→ down_cfgfile (descargar backup de config)
                  │
                  └──→ Descifrar XOR (constante 9527)
                            │
                            └──→ Descifrar AES-128-ECB (clave "ABCDEFGHIJKLMNOP")
                                      │
                                      └──→ WebSuperPassword = contraseña admin en texto claro
```

---

## Datos del router

| Propiedad | Valor |
|-----------|-------|
| Modelo | FiberHome HG6246R |
| Firmware | RP2952 (2022-05-31) |
| Kernel | Linux 4.1.52 aarch64 |
| Puerto web | 80 (solo HTTP, HTTPS deshabilitado) |
| Timeout de sesión | 300 s (5 min) |
| Sesiones concurrentes | 1 (mutex) |
| Usuario por defecto | `user` / `user1234` |
| Pool DHCP | 192.168.1.2 – 192.168.1.254 |
| Máx. reservas | 32 |
| Endpoint API | `/cgi-bin/ajax` (endpoint único, método en body o query) |

---

## Claves criptográficas (todas hardcodeadas)

### 1. Login web — AES-128-CBC (`fhencrypt`)

```
Key = IV = "opqrstuvwxyz{|}~"  (charCodes 111-126)
Hex:       6f707172737475767778797a7b7c7d7e
Modo:      AES-128-CBC, PKCS7, salida hex mayúsculas
Fuente:    aes.js → int_aes_iv() → fhencrypt()
```

### 2. Contenedor del backup — XOR

```
Algoritmo: XOR con contador
Constante: 9527
Fórmula:   start_val = size + 9527 - (size // 9527)
Por byte:  descifrado[j] = data[j] ^ ((start_val + j) & 0xFF)
Compartido: HG6145F1, HG6245D, AN5506-04-F (misma familia FiberHome)
```

### 3. Credenciales dentro de la config — AES-128-ECB

```
Clave:     "ABCDEFGHIJKLMNOP"  (hex: 4142434445464748494a4b4c4d4e4f50)
Modo:      AES-128-ECB, PKCS7
Se usa en: WiFi PSK, credenciales TR-069, contraseña admin dentro del config descifrado
```

### Verificación rápida

```bash
# Cifrar "user1234" — debe dar 851AC19A19A523A64F361CEFD6908AAF
printf 'user1234' | openssl enc -aes-128-cbc \
  -K 6f707172737475767778797a7b7c7d7e \
  -iv 6f707172737475767778797a7b7c7d7e \
  | xxd -p | tr -d '\n' | tr 'a-f' 'A-F'
```

---

## Referencia de la API AJAX

Todas las peticiones van a `/cgi-bin/ajax`. Headers obligatorios:

```
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: http://192.168.1.1
Referer: http://192.168.1.1/html/main_inter.html
```

**Trampas críticas** (cada una bloqueó las pruebas por horas):
- El parámetro `_=<random>` es **obligatorio** en cada request (cachebuster de `xhr.js`)
- Usar `get_refresh_sessionid` para obtener el sessionid del login, **NO** `get_operator`
- En POST, `ajaxmethod` va en el body, no en la URL

### Endpoints accesibles sin autenticación

| Método | Qué devuelve |
|--------|-------------|
| `get_base_info` | Firmware, serial, MAC, URL del ACS TR-069, kernel, potencia óptica |
| `get_factory_mode` | `super_userName: admin`, `admin_enable: 1`, LOID |
| `get_lan_status` | Todos los hosts LAN — MAC, IP, hostname (hasta 32) |
| `get_route_info` | Tabla conntrack completa (900+ líneas de conexiones activas) |
| `get_dhcp_lan_info` | Reservas DHCP estáticas |
| `get_ipv4_lan_info` | Rango del pool DHCP, gateway, lease time |
| `get_loid_phy_pwd` | Password LOID/PON (cifrada con AES, descifrable con la clave conocida) |
| `get_web_config` | Timeout de sesión, estado HTTPS, i18n |

Más 14 adicionales (ver `fhscan.py` para la lista completa).

### Endpoints que funcionan desde sesión user (no deberían)

| Método | Bug |
|--------|-----|
| `set_dhcp_lan_info` | **Escribe reservas DHCP desde nivel 0** — el hallazgo principal |
| `down_cfgfile` | **Descarga backup de config desde nivel 0** — lleva a la contraseña admin |
| `admin_management` | Responde a intentos de cambio de contraseña desde nivel 0 (valida `old_password` pero no nivel) |

### Endpoints muertos (diccionario HG6145F1)

Probados desde la base de exploits de Numb Team — **ninguno existe en firmware RP2952**:

`modify_password_not_check_oldpassword`, `modify_password_superadmin`, `set_single_xml_value`, `get_superadmin_userName`, `modify_password`, `get_value_by_xmlnode_new`, `get_config_backup_new`, `export_config`, `get_all_xml`, `triger_speedtest`, `do_jumplogin`

Todos devuelven `{}`.

---

## Scripts

| Script | Descripción | Necesita pycryptodome |
|--------|-------------|:---------------------:|
| `dhcp_reserve_all.py` | Descubre hosts + crea reservas DHCP (interactivo, con `--dry-run`) | No |
| `extract_admin_password.py` | Cadena completa: descarga config → descifra → extrae contraseña admin | Sí |
| `fhscan.py` | Escanea el router buscando todos los endpoints accesibles | No |
| `fhrouter.py` | Librería Python del cliente API (importar y usar en tus scripts) | No* |
| `fhcrypto.py` | Las tres capas de cifrado (fhencrypt, XOR, AES-ECB) | Sí |
| `login.sh` | Script Bash de login (hacerle source, luego usar `$SID` y `$COOKIES`) | No |
| `dhcp.sh` | CRUD DHCP en Bash (list, add, delete, hosts, logout) | No |

\* `fhrouter.py` funciona sin pycryptodome para el login por defecto `user/user1234` (la contraseña está pre-computada). Otras contraseñas la requieren.

---

## Rutas de ataque exploradas

La auditoría usó un enfoque multi-sesión estructurado. Cada ruta fue asignada a una sesión agente independiente ("hija") coordinada por una sesión padre ("madre"):

| Ruta | Objetivo | Resultado |
|------|----------|-----------|
| **B1** | Enumeración JS/HTML | ✓ 23 métodos AJAX, clave AES, mapa de ACL |
| **C** | Backdoor telnet (CVE-2021-27173) | ✗ Endpoint existe (403) pero requiere admin; puertos 23/26 cerrados |
| **A0** | Fuga de información sin autenticación | ✓ 22 endpoints exponen datos sin auth |
| **A** | Cambio de contraseña admin vía `admin_management` | ✗ Responde desde sesión user pero valida `old_password` |
| **B2** | Enumeración autenticada + PoC DHCP | ✓ **Escritura DHCP funciona desde sesión user** — backup descargable |
| **V** | Crear reservas DHCP reales | ✓ Todos los dispositivos reservados en sus IPs actuales |
| **G** | Criptoanálisis offline de la config | ✓ XOR+AES-ECB descifrados — contraseña admin recuperada |

**Estadísticas operacionales**: 0 intentos de login fallidos consumidos, 0 cambios persistentes (la reserva de prueba fue eliminada), internet nunca se interrumpió.

---

## Criptoanálisis (Ruta G)

El descifrado del backup tomó 10 intentos:

| # | Enfoque | Resultado |
|---|---------|-----------|
| 1-6 | Varios modos/claves AES | Basura |
| 7 | Autocorrelación / Kasiski | Período 256 detectado → flujo XOR |
| 8 | Análisis de frecuencia | Recuperación parcial de clave |
| 9 | Búsqueda en GitHub | Encontrada constante 9527 en otros tools FiberHome |
| **10** | **XOR con contador (9527)** | **Config UCI — 70+ bloques** |

La clave: **tamaño del archivo mod 16 ≠ 0** (11.461 bytes, mod 16 = 5) descarta inmediatamente cualquier cifrado de bloque. Entropía de 7,75 bits/byte (vs ~8,0 para AES) confirmó XOR.

Después del descifrado XOR, los valores de credenciales están cifrados una segunda vez con AES-128-ECB (clave `ABCDEFGHIJKLMNOP`). Ambas claves son compartidas entre toda la familia FiberHome.

👉 **Para la especificación matemática completa con lemas y pruebas formales, ver [docs/CRYPTO.md](docs/CRYPTO.md)**

---

## Lecciones aprendidas

1. **Control de acceso client-side no es control de acceso.** `access.js` oculta menús pero el backend no valida el nivel del caller.
2. **El parámetro `_=random` es obligatorio.** Sin él, el router rechaza el sessionid. Este requisito no documentado bloqueó las pruebas por horas.
3. **Usar `get_refresh_sessionid`, no `get_operator`, para el login.** Ambos devuelven un sessionid pero solo el primero funciona para `do_login`.
4. **El "cifrado" del backup de FiberHome es compartido entre toda la familia de productos.** La misma constante XOR (9527) y clave AES (`ABCDEFGHIJKLMNOP`) funcionan en HG6245D, HG6145F1, AN5506-04-F y HG6246R.
5. **La base de exploits del HG6145F1 no aplica.** Los 641 métodos de Numb Team no fueron encontrados en RP2952. Los modelos comparten el cifrado pero no la superficie de API.
6. **El análisis de entropía es el primer paso correcto para cifrado desconocido.** A 7,75 bits/byte, el archivo claramente no era AES — esto ahorró horas de prueba de claves.
7. **Anti-brute-force en `do_login` pero no en `admin_management`.** Un ataque de diccionario contra la contraseña admin podría correr indefinidamente por ese endpoint.

---

## Divulgación responsable

Estos hallazgos afectan equipos provistos por ISPs. Las vulnerabilidades están en el firmware (RP2952, compilado 2022-05-31) y no pueden ser corregidas por el usuario final. Se recomienda divulgación al ISP.

Si eres un ISP que despliega este equipo: el modelo de control de acceso necesita validación server-side. Las claves criptográficas hardcodeadas necesitan ser reemplazadas por claves por dispositivo. El cifrado XOR del backup necesita ser reemplazado por un cifrado real.

---

## Trabajo relacionado

- [Numb Team / HG6145F1](https://github.com/MrSmiiith/hg6145f1-full-access) — CVE-2026-37752 a 37760. Mismo framework, distinta superficie de API.
- Pierre Kim — CVE-2021-27165/27173/27177 (familia HG6245D). Backdoor telnet.
- [MrSmiiith / HG6245D config decryption](https://github.com/MrSmiiith/fiberhome-hg6245d) — Misma constante XOR 9527.

---

## Aviso legal

Esta auditoría fue realizada sobre hardware propiedad del autor, en su red doméstica, sin acceso a sistemas del ISP más allá del CPE. Los hallazgos son específicos al FiberHome HG6246R con firmware RP2952 y código de operador CHL_MP. Las técnicas documentadas aquí son para investigación de seguridad autorizada y fines educativos. **No las uses en equipos que no te pertenezcan.**

---

## Licencia

MIT
