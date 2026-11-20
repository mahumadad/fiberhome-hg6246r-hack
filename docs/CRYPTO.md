# Cifrado FiberHome HG6246R — Especificación matemática y criptoanálisis

El router FiberHome HG6246R (firmware RP2952) utiliza **tres capas de cifrado
independientes**, cada una con claves hardcodeadas en el firmware. Este documento
especifica cada algoritmo con precisión, demuestra las propiedades necesarias para su
inversión y documenta el proceso de criptoanálisis que permitió descifrar la configuración
del router sin fuerza bruta.

La implementación de referencia está en [`../scripts/fhcrypto.py`](../scripts/fhcrypto.py).

> Las fórmulas usan LaTeX (`$…$` y `$$…$$`), que GitHub renderiza en Markdown.

---

## 1. Mapa de capas

```
┌─────────────────────────────────────────────────────────────────┐
│  Capa 1: fhencrypt     — AES-128-CBC, password del login web   │
│  Capa 2: Config backup — XOR con contador (constante 9527)     │
│  Capa 3: Credenciales  — AES-128-ECB dentro del config         │
└─────────────────────────────────────────────────────────────────┘
```

La cadena de ataque completa para recuperar la contraseña admin es:

$$\mathtt{usrconfig\_conf} \xrightarrow{\text{Capa 2}^{-1}} \text{UCI config} \xrightarrow{\text{Capa 3}^{-1}} \text{WebSuperPassword en claro}$$

---

## 2. Notación

Sea $\mathbb{B} = \lbrace 0,1\rbrace^8 \cong \mathbb{Z}_{256}$ el conjunto de bytes.

Para un mensaje $M = (M_0, M_1, \dots, M_{n-1}) \in \mathbb{B}^n$, escribimos $|M| = n$ para su longitud en bytes.

$\oplus$ denota XOR bit a bit. $\lfloor \cdot \rfloor$ es la función piso. Para una
función $f$, $f^{-1}$ es su inversa cuando existe.

---

## 3. Capa 1 — fhencrypt (AES-128-CBC)

### 3.1 Definición

El cifrado de contraseñas para la interfaz web utiliza AES-128 en modo CBC con padding
PKCS#7. Tanto la clave como el vector de inicialización son la **misma cadena de 16
bytes**, hardcodeada en `aes.js`:

$$K = \text{IV} = (\mathtt{0x6F}, \mathtt{0x70}, \mathtt{0x71}, \dots, \mathtt{0x7E}) = \texttt{"opqrstuvwxyz\{|\}}\sim\texttt{"}$$

Generada por `int_aes_iv()`:

$$K_j = 111 + j \pmod{256}, \qquad j = 0, 1, \dots, 15.$$

Verificación: $K_0 = 111 = \texttt{0x6F}$ (`o`), $K_{15} = 126 = \texttt{0x7E}$ (`~`).

### 3.2 Padding PKCS#7

Sea $m = |P|$ la longitud del plaintext $P$ en bytes. PKCS#7 agrega $p$ bytes de relleno,
donde

$$p = 16 - (m \bmod 16).$$

Cada byte de relleno tiene el valor $p$. Si $m$ ya es múltiplo de 16, se agrega un bloque
completo de 16 bytes con valor $\texttt{0x10}$. El plaintext con padding es

$$P' = P \,\|\, \underbrace{(p, p, \dots, p)}_{p \text{ bytes}}, \qquad |P'| = m + p \equiv 0 \pmod{16}.$$

### 3.3 Cifrado CBC

Sea $P' = (P'_1, P'_2, \dots, P'_N)$ la secuencia de bloques de 16 bytes del plaintext con
padding, $N = |P'|/16$. El cifrado AES-128-CBC produce bloques de ciphertext $C_i$:

$$C_0 = \text{IV},$$
$$C_i = \text{AES}_K\big(P'_i \oplus C_{i-1}\big), \qquad i = 1, \dots, N.$$

El ciphertext final es $(C_1, \dots, C_N)$ (sin incluir el IV, que es conocido).

### 3.4 Salida

`fhencrypt` convierte el ciphertext a **hexadecimal en mayúsculas**:

$$\text{fhencrypt}(P) = \text{hexupper}\big(C_1 \,\|\, C_2 \,\|\, \cdots \,\|\, C_N\big).$$

### 3.5 Descifrado

El descifrado AES-CBC invierte cada paso:

$$P'_i = \text{AES}_K^{-1}(C_i) \oplus C_{i-1}, \qquad i = 1, \dots, N,$$

seguido de la remoción del padding PKCS#7: si el último byte de $P'$ tiene valor $p$ con
$1 \leq p \leq 16$, se verifican los últimos $p$ bytes y se eliminan.

### 3.6 Vectores de verificación

| Plaintext | Ciphertext (hex uppercase) |
|-----------|---------------------------|
| `""` (vacío, 0 bytes) | `9C04A49ED55BA927065F36A1BB18662C` |
| `"admin"` (5 bytes) | `71BF7F6D54A5D2C213A55E0E298B9D42` |
| `"user1234"` (8 bytes) | `851AC19A19A523A64F361CEFD6908AAF` |

**Observación (Key = IV).** La igualdad $K = \text{IV}$ es un defecto criptográfico: en CBC el
IV debe ser impredecible (idealmente aleatorio) para cada mensaje. Aquí es fijo, público
(servido en JavaScript) e idéntico a la clave, lo que reduce el esquema a ofuscación. Con
HTTP plano en puerto 80, cualquier observador en la LAN puede descifrar el tráfico de login.

---

## 4. Capa 2 — Cifrado del backup de configuración (XOR con contador)

### 4.1 Motivación del criptoanálisis

El archivo `usrconfig_conf` descargado del router es un blob opaco de $n = 11{,}461$ bytes.
El criptoanálisis siguió estas etapas:

#### 4.1.1 Descarte de cifrado de bloque

**Observación 1.** $n = 11{,}461$ y $n \bmod 16 = 5 \neq 0$. Todo cifrado de bloque de 16
bytes (AES, Camellia, etc.) produce salidas cuya longitud es múltiplo de 16 (con padding)
o exactamente igual al plaintext (modos de flujo como CTR). Un ciphertext de longitud
$5 \pmod{16}$ que no es ni múltiplo de 16 ni igual al plaintext descarta AES-CBC, AES-ECB
y cualquier modo con padding, incluyendo PKCS#7.

Intentos fallidos confirmaron empíricamente esto:

| # | Algoritmo | Resultado |
|---|-----------|-----------|
| 1 | AES-128-CBC, $K = \text{IV} = \texttt{opqrstuvwxyz}\lbrace\vert\rbrace\sim$ | Garbage |
| 2 | AES-128-ECB, misma clave | Garbage |
| 5 | AES-128-CBC, $K = \texttt{ABCDEFGHIJKLMNOP}$ | Garbage |
| 6 | AES-128-ECB, misma clave | Garbage (y $n \bmod 16 \neq 0$) |

#### 4.1.2 Análisis de entropía

La entropía de Shannon por byte se calcula como

$$H = -\sum_{b=0}^{255} p_b \log_2 p_b, \qquad p_b = \frac{|\{j : M_j = b\}|}{n}.$$

Para `usrconfig_conf` se obtuvo $H \approx 7.75$ bits/byte. Para referencia:

| Tipo de dato | Entropía típica |
|-------------|-----------------|
| AES ciphertext (teórico) | $\approx 8.0$ bits/byte |
| XOR con stream periódico | $7.0 - 7.9$ bits/byte |
| Texto ASCII | $4.5 - 5.5$ bits/byte |
| Archivo comprimido | $7.9 - 8.0$ bits/byte |

$H = 7.75$ es **demasiado baja para un cifrado de bloque** (que produce salida
pseudoaleatoria indistinguible de ruido uniforme) pero demasiado alta para texto plano.
Esto sugiere un **cifrado de flujo débil** o **XOR con clave corta/predecible**.

#### 4.1.3 Autocorrelación y análisis de Kasiski

Se calculó la autocorrelación del ciphertext con desplazamientos $\delta$:

$$\rho(\delta) = \sum_{j=0}^{n-\delta-1} \mathbb{1}\big[M_j = M_{j+\delta}\big].$$

Se detectó un pico claro en $\delta = 256$, lo que indica que el keystream tiene período
256. Para un XOR con keystream $S$:

$$C_j = P_j \oplus S_j, \qquad S_j = S_{j+256},$$

si el plaintext tiene estructura (como texto UCI), la correlación del ciphertext a
distancia 256 refleja la correlación del plaintext a esa distancia, amplificada por la
repetición del keystream.

#### 4.1.4 Identificación del algoritmo

Una búsqueda en repositorios públicos de GitHub reveló que múltiples modelos FiberHome
(HG6145F1, HG6245D, AN5506-04-F) comparten exactamente la misma rutina de
cifrado/descifrado de configuración, basada en la constante **9527**.

### 4.2 Definición formal

**Definición (cifrado XOR con contador).** Sea $M = (M_0, \dots, M_{n-1})$ el plaintext de
$n$ bytes y $\kappa = 9527$ la constante. El valor inicial del contador es

$$s = n + \kappa - \left\lfloor \frac{n}{\kappa} \right\rfloor.$$

El ciphertext $C$ se produce byte a byte:

$$\boxed{C_j = M_j \oplus \big((s + j) \bmod 256\big), \qquad j = 0, 1, \dots, n-1.}$$

**Proposición 1 (el descifrado es idéntico al cifrado).** Sea $D$ la función de
descifrado. Para todo $M \in \mathbb{B}^n$, $D(C) = M$.

*Prueba.* Como el keystream depende **solo de la longitud $n$** (no del contenido), y la
operación es XOR byte a byte, tenemos:

$$D(C)_j = C_j \oplus \big((s + j) \bmod 256\big) = \big(M_j \oplus (s+j)\big) \oplus (s+j) = M_j,$$

donde usamos $a \oplus a = 0$ y $b \oplus 0 = b$. Luego $D = E$ (la misma función cifra y
descifra). $\blacksquare$

### 4.3 Análisis del keystream

El keystream es la secuencia

$$S_j = (s + j) \bmod 256, \qquad j = 0, 1, \dots$$

Esto es simplemente un **contador módulo 256**, iniciado en $s \bmod 256$. Tiene período
exactamente 256, lo que explica el pico de autocorrelación observado.

**Proposición 2 (el keystream es una permutación cíclica de la identidad).** La secuencia
$(S_0, S_1, \dots, S_{255})$ es una permutación del conjunto $\lbrace 0, 1, \dots, 255\rbrace$.

*Prueba.* $S_j = (s + j) \bmod 256$ con $s$ fijo. Como la suma módulo 256 es una biyección

$$\mathbb{Z}_{256} \to \mathbb{Z}_{256}$$

para cada $s$ fijo (es una traslación en el grupo cíclico $\mathbb{Z}_{256}$), los 256 valores consecutivos son todos distintos. $\blacksquare$

### 4.4 Observaciones criptográficas

**El esquema no provee confidencialidad.** El keystream:

1. **No depende de una clave secreta.** El valor $s$ se calcula a partir de $n$ (la longitud
   del archivo, que el atacante conoce) y de $\kappa = 9527$ (una constante pública,
   documentada en GitHub desde al menos 2020).

2. **Tiene período 256.** Para un archivo de 11,461 bytes, el keystream se repite
   $\lfloor 11461/256 \rfloor = 44$ veces completas, lo que lo hace vulnerable a análisis
   de frecuencia estándar.

3. **Es determinista.** El mismo archivo produce siempre el mismo ciphertext. No hay IV, sal,
   ni nonce.

En términos de Kerckhoffs, es equivalente a **no cifrar**: la seguridad no depende del
secreto de la clave (no hay clave) sino del secreto del algoritmo, que es público.

### 4.5 Verificación empírica

Para $n = 11{,}461$ y $\kappa = 9527$:

$$s = 11{,}461 + 9{,}527 - \left\lfloor \frac{11{,}461}{9{,}527} \right\rfloor = 11{,}461 + 9{,}527 - 1 = 20{,}987.$$

$$s \bmod 256 = 20{,}987 \bmod 256 = 251.$$

El primer byte del keystream es $251 = \texttt{0xFB}$. Aplicando el descifrado se obtiene
un archivo que comienza con `config X_FH_Account` — formato UCI (OpenWrt), confirmando la
correctitud.

### 4.6 Valor de $\kappa$ (por qué 9527)

La constante 9527 no tiene significado criptográfico conocido. Es un número primo, $9527 \in \mathbb{P}$, pero su primalidad no se
explota en el algoritmo (la operación es módulo 256, no módulo 9527). Es probable que sea
una constante de debug o un valor arbitrario elegido durante el desarrollo.

**Verificación:** $9527 = 9527$ es efectivamente primo (no divisible por 2, 3, 5, 7, 11,
..., 97, donde $97^2 = 9409 < 9527 < 9801 = 99^2$).

---

## 5. Capa 3 — Credenciales en la configuración (AES-128-ECB)

### 5.1 Contexto

Dentro del archivo UCI descifrado (Capa 2), los valores sensibles (contraseñas WiFi,
credenciales TR-069, contraseña admin) están cifrados individualmente con AES-128-ECB.

### 5.2 Definición

Sea $V = (V_0, \dots, V_{m-1})$ un valor de credencial con padding PKCS#7, donde $m$ es
múltiplo de 16. La clave es

$$K_{\text{ecb}} = \texttt{"ABCDEFGHIJKLMNOP"} = (\texttt{0x41}, \texttt{0x42}, \dots, \texttt{0x50}).$$

El cifrado es AES-128 en modo ECB (Electronic Codebook):

$$C_i = \text{AES}_{K_{\text{ecb}}}(V_i), \qquad i = 1, \dots, m/16,$$

donde cada $V_i$ y $C_i$ son bloques de 16 bytes. El ciphertext se almacena como
**hexadecimal** (mayúsculas o minúsculas según el campo).

### 5.3 Descifrado

$$V_i = \text{AES}_{K_{\text{ecb}}}^{-1}(C_i), \qquad i = 1, \dots, m/16.$$

Seguido de remoción de padding PKCS#7.

### 5.4 Observación sobre ECB

AES-ECB cifra cada bloque de 16 bytes de forma independiente. Esto implica que **bloques
de plaintext idénticos producen bloques de ciphertext idénticos**. Para credenciales cortas
(< 16 bytes antes de padding, como la mayoría de contraseñas), solo hay un bloque, y el
modo ECB es equivalente a un cifrado de bloque simple.

Para el caso específico de `WebSuperPassword`:

$$|\texttt{"e61a5ccb"}| = 8 \text{ bytes} \xrightarrow{\text{PKCS\char`\#7}} 16 \text{ bytes} \xrightarrow{\text{AES}} 16 \text{ bytes} = 32 \text{ hex chars}.$$

### 5.5 Tabla de credenciales descifradas

| Campo en UCI config | Ciphertext (hex) | Plaintext |
|---------------------|-------------------|-----------|
| `WebSuperPassword` | `E2F4CCBC9E9D87A3B854E536E19363ED` | `e61a5ccb` |
| WiFi PSK (Lia / Lia 5G) | `84AE496A3DCE5698...` (32 B) | *(redacted)* |
| WiFi PSK (secondary) | `547065E6476CF6F4EF682849B75777E2` | *(redacted)* |
| MultiAP PreSharedKey | `807A74219EA61D3424073BDE62EA4FF2` | *(redacted)* |
| TR-069 ConnReqUsername | `7015A15BEAD6C7D5CF5B089F99399DEB` | *(redacted)* |
| TR-069 ConnReqPassword | `170C5402B56E5B4BDF857E369FA16E0B` | *(redacted)* |

### 5.6 Verificación one-liner

```bash
echo -n 'E2F4CCBC9E9D87A3B854E536E19363ED' \
  | xxd -r -p \
  | openssl enc -aes-128-ecb -d -nopad \
    -K 4142434445464748494a4b4c4d4e4f50 \
  | tr -d '\0-\37'
# Output: e61a5ccb
```

---

## 6. Cadena completa de descifrado

### 6.1 Teorema (recuperación de WebSuperPassword)

**Teorema.** Dado acceso al archivo `usrconfig_conf` de $n$ bytes descargado del router,
la contraseña admin $\text{WebSuperPassword}$ se recupera en tiempo $O(n)$ y espacio $O(n)$ sin
conocimiento de ningún secreto más allá de las constantes públicas $\kappa = 9527$ y
$K_{\text{ecb}} = \texttt{"ABCDEFGHIJKLMNOP"}$.

*Prueba (constructiva).*

1. **Descifrado XOR** (Capa 2): calcular $s = n + 9527 - \lfloor n/9527 \rfloor$ y
   aplicar $M_j = C_j \oplus ((s+j) \bmod 256)$ para $j = 0, \dots, n-1$. Costo: $O(n)$.

2. **Parseo UCI**: buscar la línea que contiene `WebSuperPassword` y extraer el valor
   hexadecimal $H$. Costo: $O(n)$ (búsqueda lineal).

3. **Descifrado AES-ECB** (Capa 3): convertir $H$ de hex a bytes, descifrar con
   $K_{\text{ecb}}$ usando AES-ECB inverso bloque por bloque, remover padding PKCS#7. Costo:
   $O(|H|/16)$ operaciones AES = $O(1)$ para contraseñas típicas (1-2 bloques).

El costo total es $O(n)$, dominado por el descifrado XOR. No se requiere fuerza bruta,
búsqueda de claves ni conocimiento del plaintext. $\blacksquare$

### 6.2 Diagrama

```
usrconfig_conf (11,461 bytes, encrypted)
         │
         │  XOR: C_j ⊕ ((n + 9527 - ⌊n/9527⌋ + j) mod 256)
         ▼
UCI config (plaintext, 11,461 bytes)
         │
         │  grep WebSuperPassword → "E2F4CCBC9E9D87A3B854E536E19363ED"
         ▼
AES-ECB hex value (32 hex chars = 16 bytes)
         │
         │  AES-128-ECB decrypt, key = "ABCDEFGHIJKLMNOP"
         ▼
"e61a5ccb" (admin password, 8 chars)
```

---

## 7. Proceso de criptoanálisis (bitácora cronológica)

El criptoanálisis se realizó **offline**, sin contacto adicional con el router después de
la descarga del backup. Los 10 intentos en orden:

| # | Hipótesis | Método | Resultado | Lección |
|---|-----------|--------|-----------|---------|
| 1 | AES-CBC con clave web | `openssl enc -aes-128-cbc` | Garbage | — |
| 2 | AES-ECB con clave web | `openssl enc -aes-128-ecb` | Garbage | — |
| 3 | Strip header + AES | Probar offsets 4,8,16 | Garbage | — |
| 4 | **Análisis de entropía** | Shannon entropy | **7.75 b/B** | No es AES ($\approx 8.0$) |
| 5 | AES-CBC clave ECB | `ABCDEFGHIJKLMNOP` | Garbage | — |
| 6 | AES-ECB clave ECB | `ABCDEFGHIJKLMNOP` | Garbage | **$n \bmod 16 = 5$** → no es bloque |
| 7 | **Autocorrelación** | Kasiski/autocorr | **Período 256** | XOR con keystream periódico |
| 8 | Análisis de frecuencia | XOR frequency attack | Parcial | — |
| 9 | **GitHub search** | "FiberHome decrypt config" | **Constante 9527** | Código público desde 2020 |
| 10 | **XOR con contador** | $C_j \oplus ((s+j) \bmod 256)$ | **✓ UCI config** | — |

### 7.1 Lecciones del proceso

**Lección 1: dimensionar antes de probar.** El chequeo $n \bmod 16$ (intento #6)
descartó AES-ECB de un golpe. El análisis de entropía (intento #4) descartó **todo cifrado
de bloque**. Estos dos filtros de 30 segundos cada uno habrían ahorrado los primeros 5
intentos.

**Lección 2: autocorrelación identifica el tipo de cifrado.** Un pico limpio en
$\delta = 256$ con ausencia de picos en otros desplazamientos indica un XOR con keystream
de período 256 — no un cifrado de bloque (uniforme), no Vigenère (picos en múltiplos del
período de clave), no RC4 (sin periodicidad).

**Lección 3: buscar en GitHub antes de criptoanalizar.** La constante 9527 estaba
documentada públicamente desde 2020 en al menos tres repositorios independientes para
modelos FiberHome distintos. La "seguridad" del esquema dependía del secreto del
algoritmo, que no era secreto.

---

## 8. Análisis comparativo con la familia FiberHome

La siguiente tabla resume los esquemas criptográficos de modelos FiberHome conocidos:

| Modelo | Firmware | Capa web (login) | Capa backup | Capa credenciales | Fuente |
|--------|----------|-------------------|-------------|-------------------|--------|
| HG6246R | RP2952 | AES-128-CBC, $K=\text{IV}$ | XOR ($\kappa=9527$) | AES-128-ECB | Este trabajo |
| HG6145F1 | RP4423 | AES-128-CBC, $K=\text{IV}$ | XOR ($\kappa=9527$) | AES-128-ECB | Numb Team |
| HG6245D | — | AES-128-CBC, $K=\text{IV}$ | XOR ($\kappa=9527$) | AES-128-ECB | MrSmiiith |
| AN5506-04-F | — | Desconocido | XOR ($\kappa=9527$) | AES-128-ECB | — |

Todas las claves son idénticas entre modelos:
- Capa web: $K = \text{IV} = \texttt{opqrstuvwxyz}\lbrace\vert\rbrace\sim$
- Capa backup: $\kappa = 9527$
- Capa credenciales: $K_{\text{ecb}} = \texttt{ABCDEFGHIJKLMNOP}$

Esto sugiere una **biblioteca de cifrado compartida** a nivel de SDK del fabricante, donde
las constantes se fijaron una vez y nunca se personalizaron por modelo ni por ISP.

---

## 9. Espacio de claves efectivo

| Capa | Espacio de claves nominal | Espacio de claves efectivo | Razón |
|------|---------------------------|---------------------------|-------|
| 1 (AES-CBC) | $2^{128}$ | $2^0 = 1$ | Clave fija, pública en JS |
| 2 (XOR) | $2^0 = 1$ | $2^0 = 1$ | No hay clave; solo longitud + constante |
| 3 (AES-ECB) | $2^{128}$ | $2^0 = 1$ | Clave fija, compartida entre modelos |

**Corolario.** Las tres capas combinadas proveen $2^0 = 1$ posible "clave". El esquema es
ofuscación, no cifrado en el sentido criptográfico moderno.
