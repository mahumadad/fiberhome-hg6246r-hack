# Hallazgos de seguridad — FiberHome HG6246R (RP2952)

Detalle de cada hallazgo. Para la tabla resumen, ver [README.md](../README.md).

---

## S1 — Escritura DHCP desde sesión user (Crítico)

**Endpoint afectado:** `set_dhcp_lan_info` (acciones: `add`, `edit`, `delete`)

**Descripción:** El archivo `access.js` de la interfaz web mapea `dhcp_lan_inter.html` a nivel
de acceso 2 (solo admin), ocultando la página de configuración DHCP para cuentas de usuario.
Sin embargo, el handler CGI del backend para `set_dhcp_lan_info` **no valida el nivel de acceso
del caller**. Cualquier sesión autenticada — incluyendo la cuenta por defecto `user/user1234`
(nivel 0) — puede crear, editar y eliminar reservas DHCP estáticas.

**Impacto:** Un atacante en la LAN con las credenciales por defecto puede:
- Asignar IPs estáticas a cualquier dispositivo, causando potenciales conflictos IP
- Redirigir el tráfico de un host asignando la IP del gateway a un dispositivo malicioso
- Agotar el límite de 32 reservas, impidiendo el uso legítimo por el administrador

**Prueba de concepto:**

```bash
# Después de login como user/user1234:
curl -s -b "sessionid=$SID" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
  -H "X-Requested-With: XMLHttpRequest" \
  "http://192.168.1.1/cgi-bin/ajax" \
  --data-urlencode "ajaxmethod=set_dhcp_lan_info" \
  --data-urlencode "action=add" \
  --data-urlencode "MACAddress=AA:BB:CC:DD:EE:FF" \
  --data-urlencode "IPAddress=192.168.1.200" \
  --data-urlencode "sessionid=$FRESH_SID" \
  --data-urlencode "_=0.123456"
# Respuesta: {"result":0} — reserva creada
```

**Causa raíz:** El control de acceso server-side no existe para este endpoint. La ACL se
aplica solo en el frontend JavaScript (`access.js`), que un caller por API evita completamente.

---

## S2 — Backup de config descargable desde sesión user (Crítico)

**Endpoints afectados:** `down_cfgfile` (trigger AJAX) + `/cgi-bin/download?usrconfig_conf`

**Descripción:** Mismo patrón que S1. La página de descarga de backup (`down_cfgfile.html`)
está mapeada a nivel 2 en `access.js`, pero el backend acepta tanto el trigger AJAX como la
descarga del archivo desde una sesión de nivel 0.

**Impacto:** Combinado con S3 (cifrado trivial del backup), esto da a cualquier usuario
de la LAN con credenciales por defecto acceso a:
- La contraseña admin (ver [CRYPTO.md](CRYPTO.md))
- La PSK WiFi de todos los SSIDs
- Credenciales TR-069 (gestión del ISP)
- La configuración completa del router

**Prueba de concepto:**

```bash
# Disparar preparación del backup
curl -s -b "sessionid=$SID" \
  "http://192.168.1.1/cgi-bin/ajax" \
  --data-urlencode "ajaxmethod=down_cfgfile" \
  --data-urlencode "sessionid=$FRESH_SID" \
  --data-urlencode "_=0.123456"

# Descargar el archivo
curl -s -o usrconfig_conf -b "sessionid=$SID" \
  "http://192.168.1.1/cgi-bin/download?usrconfig_conf"
# Resultado: 11.461 bytes de config cifrada
```

---

## S3 — Cifrado trivial del backup (Alto)

**Algoritmo:** XOR con contador, constante 9527

**Descripción:** El cifrado del backup de configuración es un simple XOR con un flujo de
claves predecible. Ver [CRYPTO.md](CRYPTO.md) §4 para el análisis matemático completo.

**Impacto:** El cifrado provee cero confidencialidad:
- No hay clave secreta — solo el tamaño del archivo y una constante pública
- Determinístico — el mismo archivo siempre produce el mismo texto cifrado
- Compartido entre toda la familia de productos FiberHome
- Documentado públicamente en GitHub desde 2020

---

## S4 — Fuga masiva de información sin autenticación (Alto)

**Endpoints afectados:** 22+ métodos AJAX

**Descripción:** La mayoría de los endpoints `GET` en `/cgi-bin/ajax` devuelven datos sin
requerir autenticación alguna (sin cookie de sesión, sin login).

**Datos expuestos sin autenticación:**

| Dato | Endpoint |
|------|----------|
| Nombre de superadmin (`admin`) | `get_factory_mode` |
| Dirección MAC | `get_base_info` |
| Número de serie | `get_base_info` |
| LOID | `get_base_info` |
| URL del ACS TR-069 | `get_base_info` |
| Versión de firmware | `get_base_info` |
| Versión del kernel | `get_base_info` |
| 27 hosts LAN (MAC + IP + hostname) | `get_lan_status` |
| 909 entradas conntrack (todas las conexiones activas) | `get_route_info` |
| Configuración del pool DHCP | `get_ipv4_lan_info` |
| Timeout de sesión | `get_web_config` |
| Estado de HTTPS (deshabilitado) | `get_web_config` |

**Impacto:** Cualquier persona en la LAN puede obtener fingerprint del router, enumerar
todos los dispositivos conectados, monitorear las conexiones activas y obtener la dirección
del servidor de gestión del ISP — todo sin credenciales.

---

## S5 — Clave AES hardcodeada en JavaScript público (Alto)

**Archivo afectado:** `/js/aes.js`

**Descripción:** La clave AES-128-CBC usada para cifrar contraseñas de login se genera en
`int_aes_iv()`, que devuelve un string determinístico derivado de charCodes 111-126. La
clave es idéntica al IV. Ambos se sirven a cualquier navegador que solicite el archivo
JavaScript — sin necesidad de autenticación.

**Impacto:**
- Contraseñas de login capturadas en la red (HTTP, puerto 80) pueden ser descifradas trivialmente
- La misma clave se usa en **todas** las unidades HG6246R, independiente del ISP o número de serie
- Las respuestas de la API que devuelven valores cifrados pueden ser descifradas offline

**Mitigación (no posible para el usuario final):** El firmware necesitaría claves por
dispositivo y HTTPS. Mientras HTTP sea el único transporte, el cifrado es cosmético
independientemente de la gestión de claves.

---

## S6 — admin_management accesible desde sesión user (Medio)

**Endpoint afectado:** `admin_management`

**Descripción:** El endpoint de cambio de contraseña admin responde a llamadas desde una
sesión de nivel usuario. Valida `old_password` (devolviendo `errorCode: -1` si no coincide)
pero **no valida** que el caller tenga privilegios de administrador.

**Impacto:**
- Confirma que el endpoint existe y es alcanzable desde nivel user
- No hay anti-brute-force en este endpoint (a diferencia de `do_login` que bloquea después de 3 fallos)
- Un ataque de diccionario contra la contraseña admin podría correr indefinidamente por este endpoint
- La diferencia en código de error (`-1` vs `-4` con/sin parámetro `username`) filtra
  información sobre la lógica de validación interna

---

## S7 — HTTPS deshabilitado (Bajo)

**Descripción:** `get_web_config` confirma `httpsenable: 0`. Todo el tráfico web,
incluyendo credenciales de login (aunque cifradas con AES, ver S5), transita por la LAN
en texto claro.

**Impacto:** Combinado con S5, cualquier dispositivo en la LAN puede capturar y descifrar
credenciales de login usando sniffing pasivo de red.
