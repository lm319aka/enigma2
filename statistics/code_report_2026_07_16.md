# Reporte de Código Enigma2: Análisis de Fallos, Vulnerabilidades y Rendimiento
Fecha: 16 de Julio de 2026

Este documento detalla un análisis de seguimiento y auditoría técnica del código del proyecto Enigma2. Se actualiza el estado de los problemas reportados en el informe del 11 de Julio de 2026 (clasificados como **Solucionados** o **Persistentes**), y se introducen **Nuevos Hallazgos** identificados durante la última fase de optimización y desarrollo.

---

## 📊 Resumen de Estado de Problemas Previos

| ID | Descripción del Problema | Gravedad | Estado Actual | Resolución / Acción Requerida |
| :--- | :--- | :--- | :--- | :--- |
| **1.1** | Overflow de Slicing con `btype` Grandes / Hashes Pequeños | Crítico | **Solucionado** | Resuelto mediante la implementación de expansión de claves / encadenamiento recursivo de hashes en `pwd_hashing.py`. |
| **1.2** | Reutilización de Keystream / Vulnerabilidad de Profundidad | Alto | **Persiste** | Requiere implementar un Vector de Inicialización (IV) o *nonce* aleatorio por sesión de cifrado. *Explicación técnica en Sección 1.2.* |
| **1.3** | Falta de Soporte para Metadata y Autodetección de Archivos | Alto | **Nuevo / Persiste** | Prerrequisito para KDF Salt. Necesidad de definir un formato de cabecera/metadata en archivos cifrados. |
| **1.4** | Crash por Mismatch de Tamaño en Descompresión | Medio | **Solucionado** | Resuelto tratando los arrays intermedios comprimidos como bytes planos (`np.uint8`) y realizando el casteo al tipo destino final al descifrar. |
| **1.5** | Falta de Implementación del Parámetro `chunk_size` | Medio | **Solucionado** | Implementado procesamiento por bloques en archivos mediante memory mapping (`np.memmap`) y soporte para detección dinámica con `-1`. |
| **2.1** | Ineficiencia de Memoria en `generate_noise` (`np.arange`) | Crítico | **Solucionado** | Reemplazado por selección directa de enteros aleatorios usando `noise_rng.integers(0, size)`. |
| **2.2** | Generación Masiva de Rotaciones Aleatorias en Memoria | Alto | **Solucionado** | Acotado por el tamaño máximo de los bloques procesados concurrentemente (`chunk_size`). |
| **2.3** | Reservas de Memoria Repetitivas y Castings en Aritmética | Alto | **Solucionado** | Implementados buffers preasignados dinámicamente con aislamiento en hilos y `np.mod` con `casting='unsafe'`. |
| **2.4** | Carga Completa en Memoria para Detección de Codificación | Medio | **Solucionado** | Detección limitada por defecto a un muestreo de los primeros 32 KB del archivo. |
| **3.1** | Falta de Autenticación de Mensajes / AEAD | Alto | **Nuevo** | Requiere implementar firma digital o HMAC. *Explicación técnica en Sección 3.1.* |
| **3.2** | Riesgos de Concurrencia en la Modificación del Logger de Raíz | Medio | **Solucionado** | Eliminado basicConfig global. Aislados todos los logs del paquete en el logger local `"enigma2"`. |
| **3.3** | Falta de captura amigable de excepciones de descompresión | Bajo | **Solucionado** | Encapsulada descompresión en un bloque `try-except` que relanza una excepción controlada `DecompressionError`. |

---

## 🔒 Parte 1: Fallos de Lógica y Vulnerabilidades de Seguridad

### 1.2 Reutilización de Keystream / Vulnerabilidad de Profundidad (Alto - **Persiste**)
* **Ubicación:** [_e2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/_e2_cipher.py) (`_encrypt_raw_data` / `_decrypt_raw_data`)
* **Descripción del Fallo:**
  El cifrador inicializa sus RNG usando únicamente el password y desplazamientos fijos. Si el usuario cifra dos archivos distintos con la misma clave, ambos cifrados compartirán exactamente la misma secuencia pseudoaleatoria (*keystream*).
  En un cifrado simétrico de flujo (XOR/adición modular), si $C_1 = P_1 \oplus K$ y $C_2 = P_2 \oplus K$, un atacante puede calcular $C_1 \oplus C_2 = P_1 \oplus P_2$. Esto elimina la clave y permite romper ambos mensajes mediante análisis de frecuencias.
* **Solución propuesta (Explicación técnica):**
  Implementar un **Vector de Inicialización (IV)** o *nonce* único generado de forma segura para cada cifrado (por ejemplo, 16 bytes aleatorios vía `os.urandom(16)`). Este IV no es secreto y se añade en la cabecera del archivo. Al descifrar, el IV se extrae de la cabecera y se combina (ej. mediante hash) con la clave maestra para derivar el desplazamiento RNG de esa sesión, garantizando que el *keystream* sea siempre diferente aunque la clave sea la misma.

### 1.3 Bloqueador de Diseño: Inserción de Metadata y Cabecera de Archivos (Alto - **Nuevo / Persiste**)
* **Ubicación:** [cli.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/cli.py) y [enigma2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/enigma2_cipher.py)
* **Descripción del Fallo:**
  Actualmente, para descifrar un archivo el usuario debe recordar e introducir de forma manual parámetros idénticos como `chunk_size`, `encoding`, `original_rotations` o si se usó compresión. Si algún parámetro difiere, el descifrado corromperá el archivo de salida silenciosamente. Además, no hay forma de autodetección rápida en el CLI para verificar si el archivo fue encriptado por Enigma2 ni para guardar una sal aleatoria para el KDF (Bug 1.3 anterior).
* **Solución propuesta:**
  Diseñar una clase `E2Metadata` e implementar una cabecera binaria estructurada que se anteponga al texto cifrado:
  1. Un marcador de firma inicial (ej. una cadena fija de 16 bytes `0x00` para denotar el inicio).
  2. Campos binarios empaquetados conteniendo: `chunk_size` (para fragmentación), algoritmo de compresión empleado, `encoding` original, `btype`, sal aleatoria del KDF, y un checksum del archivo original.
  3. Un marcador de firma de cierre (ej. cadena de 16 bytes `0xFF`).
  El CLI y la API leerán esta cabecera para configurar dinámicamente los parámetros de descifrado sin requerir intervención del usuario.

---

## ⚡ Parte 2: Cuellos de Botella de Rendimiento y Optimización

*Todos los cuellos de botella de rendimiento identificados previamente han sido resueltos y verificados.*

---

## 🔍 Parte 3: Nuevos Hallazgos e Identificaciones de Diseño (Julio 2026)

### 3.1 Falta de Autenticación de Mensajes / AEAD (Alto - **Nuevo**)
* **Descripción:**
  El cifrado Enigma2 carece de autenticidad. Al no usar un modo AEAD (Authenticated Encryption with Associated Data), el sistema no puede detectar si los bytes cifrados han sido alterados en tránsito. Un atacante activo puede modificar selectivamente los bytes del texto cifrado y el descifrador los procesará sin percatarse, lo cual compromete la integridad de la información.
* **Solución propuesta (Explicación técnica y matemática):**
  Para lograr integridad y autenticidad sin cambiar la lógica interna del flujo de cifrado, se recomienda el paradigma **Encrypt-then-MAC**. 
  Matemáticamente, tras cifrar el mensaje para obtener $C = \text{Encrypt}(P)$, se calcula un código MAC usando la función HMAC-SHA256:
  $$T = \text{HMAC}(K_{auth}, C)$$
  Donde $K_{auth}$ es una clave de autenticación independiente derivada de la clave maestra. El par $(C, T)$ se guarda en el archivo. Al descifrar, se calcula el HMAC sobre el texto cifrado recibido y se compara con $T$ en tiempo constante. Si no coinciden, se aborta la desencriptación, impidiendo ataques de manipulación de bits.

### 3.2 Riesgos de Concurrencia en la Modificación del Logger de Raíz (Medio - **Solucionado**)
* **Ubicación:** [_e2_cipher.py:L77-105](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/_e2_cipher.py#L77-105) y [enigma2_cipher.py:L10-14](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/enigma2_cipher.py#L10-14)
* **Resolución:**
  Se eliminaron por completo las llamadas globales a `logging.basicConfig(..., force=True)` y `logging.disable()` del ciclo de inicialización del cifrador. Ahora, toda la verbosidad se canaliza exclusivamente a través de un logger específico y aislado de la biblioteca (`logger = logging.getLogger("enigma2")`), asignando handlers individuales en caliente según el valor del parámetro `verbose` de cada instancia, garantizando la seguridad en entornos multi-hilo y previniendo la corrupción del sistema de logs global del host.

### 3.3 Falta de captura amigable de excepciones de descompresión en el CLI (Bajo - **Solucionado**)
* **Ubicación:** [compression.py:L102-109](file:///C:/CODE_FOLDER/enigma2/src/enigma2/utils/compression.py#L102-109)
* **Resolución:**
  Se encapsuló la llamada a la descompresión binaria en un bloque `try-except` dentro de `decompress_nparray` que captura excepciones del sistema tales como `zlib.error`, `gzip.BadGzipFile`, `bz2.BZ2Error` o `lzma.LZMAError`.
  Estas se transforman y relanzan bajo la excepción de alto nivel `DecompressionError` (definida en `_e2_exceptions.py`), permitiendo a las aplicaciones cliente y al CLI interceptar la falla limpiamente e indicar que la clave es incorrecta o los datos están corruptos, en lugar de colgarse mostrando volcados de depuración del intérprete de Python.


### 🔒 4. Explicación de Técnicas de Criptografía (1.2 y 3.1)                                                          
                                                                                                                        
#### 4.2 Reutilización de Keystream / Vulnerabilidad de Profundidad (Depth)                                            
                                                                                                                        
• ¿En qué consiste? Enigma2 actúa como un cifrado de flujo (donde los caracteres se transforman mediante una secuencia 
pseudoaleatoria o keystream generada por el RNG). Si cifras dos textos distintos (P₁ y P₂) con la misma contraseña y el
mismo estado inicial de RNG, ambos compartirán la misma secuencia de clave (S).                                        
Matemáticamente, los textos cifrados serán:                                                                            
                                                                                                                        
  C₁ = P₁ oplus S  y  C₂ = P₂ oplus S                                                                                  
                                                                                                                        
Un atacante que capture C₁ y C₂ puede hacer la operación XOR entre ellos:                                              
                                                                                                                        
  C₁ oplus C₂ = (P₁ oplus S) oplus (P₂ oplus S) = P₁ oplus P₂                                                          
                                                                                                                        
Al hacer esto, la secuencia de clave S se elimina por completo. A partir de P₁ oplus P₂, el atacante puede emplear     
técnicas como crib dragging (deslizar palabras probables en el flujo) para recuperar ambos textos planos originales sin
conocer la contraseña.                                                                                                 
                                                                                                                        
• ¿Qué aporta el Vector de Inicialización (IV)? Un IV es un número aleatorio de un solo uso (nonce) que se genera en   
cada cifrado. Aporta unicidad, asegurando que aunque cifras el mismo mensaje con la misma contraseña 100 veces, los 100
textos cifrados resultantes sean completamente distintos.                                                              
• ¿Cómo aplicarlo a Enigma2? Durante la encriptación, generamos 16 bytes aleatorios con  os.urandom(16) . Usamos su    
hash para desplazar o inicializar el estado del generador de rotaciones y guardamos el IV al principio del archivo.    
Durante la desencriptación, extraemos esos primeros 16 bytes de la cabecera y los usamos para re-inicializar el RNG    
exactamente en el mismo estado.                                                                                        
                                                                                                                        
#### 4.2 Falta de Autenticación de Mensajes / AEAD (Integridad)                                                        
                                                                                                                        
• Trasfondo matemático y manipulación de bits: Los cifrados de flujo puros son maleables. Si un atacante conoce parte  
del texto original (por ejemplo, que la cabecera de un archivo dice  "Origen: Servidor" ), puede calcular la diferencia
Δ para cambiarlo a  "Origen: Atacante" . Si aplica esa diferencia al texto cifrado:                                    
                                                                                                                        
  C' = C oplus Δ                                                                                                       
                                                                                                                        
Al descifrar, el receptor obtendrá:                                                                                    
                                                                                                                        
  P' = Decrypt (C') = (C oplus Δ) oplus S = (P oplus S oplus Δ) oplus S = P oplus Δ                                    
                                                                                                                        
El descifrado se ejecutará correctamente sin ningún error, pero los datos habrán sido modificados a voluntad del       
atacante de manera silenciosa.                                                                                         
                                                                                                                        
• Paradigma Encrypt-then-MAC (EtM): Para evitar esto, se utiliza un código de autenticación de mensajes (MAC) como     
HMAC-SHA256 .                                                                                                          
Matemáticamente:                                                                                                       
    1. Se cifra el texto original para obtener el ciphertext C.                                                        
    2. Se deriva una clave de autenticación Kₐᵤₜₕ a partir de la contraseña (independiente de la clave de cifrado).    
    3. Se calcula la firma de integridad: T = HMAC (Kₐᵤₜₕ,C).                                                          
    4. Se guarda (C,T) en el archivo.                                                                                  
    Al descifrar, primero se recalcula el HMAC sobre el texto cifrado recibido y se compara con T en tiempo constante. 
    Si no coinciden, el archivo se descarta inmediatamente, evitando que el descifrador procese datos manipulados.     
        