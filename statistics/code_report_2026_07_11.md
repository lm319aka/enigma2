# Reporte de Código Enigma2: Análisis de Fallos, Vulnerabilidades y Rendimiento
Fecha: 11 de Julio de 2026

Este documento detalla un análisis exhaustivo del código del proyecto Enigma2, dividiéndose en dos categorías principales: **Vulnerabilidades y Fallos de Lógica**, y **Cuellos de Botella de Rendimiento**. Ambas secciones han sido clasificadas en orden de gravedad/impacto, aportando explicaciones técnicas de los problemas y sus soluciones propuestas.

---

## 🔒 Parte 1: Fallos de Lógica y Vulnerabilidades de Seguridad (Ordenados por Gravedad)

### 1.1 Error de Desbordamiento de Slicing con `btype` Grandes / Hashes Pequeños (Crítico)
* **Ubicación:** [pwd_hashing.py:L114-122](file:///C:/CODE_FOLDER/enigma2/src/enigma2/pwd_hashing.py#L114-122) (`PwdBitChainSlicer.slices`)
* **Descripción del Fallo:**
  Cuando se utiliza un `btype` de gran tamaño (como `2**32` para `np.uint32`) y/o un algoritmo de hash más corto (como `sha256` en lugar del predeterminado `sha512`), el valor calculado para `end_idx_plugboard_size` (que depende de `log2(btype // 2)`) puede exceder la longitud total disponible de la subcadena de bits final `hex_chains[4]`.
  Esto provoca que el corte `hex_chains[4][end_idx_plugboard_size:]` retorne una cadena vacía `""`. Al intentar hacer la conversión entera con `int("", 2)`, Python lanza un error fatal en tiempo de ejecución: `ValueError: invalid literal for int() with base 2: ''`.
* **Solución:**
  Controlar de manera segura las subcadenas vacías resultantes de cortes fuera de límites. Si el fragmento de bits para el ruido está vacío, establecer por defecto `noise_size = 0`.
* **Código de Solución Propuesto:**
  ```python
  if elements_creation_params.noise_size is None:
      noise_part = hex_chains[4][end_idx_plugboard_size:]
      elements_creation_params.noise_size = int(noise_part, 2) if noise_part else 0
  ```

---

### 1.2 Reutilización de Keystream / Vulnerabilidad de Profundidad (Alto)
* **Ubicación:** [_e2_cipher.py:L141-177](file:///C:/CODE_FOLDER/enigma2/src/enigma2/_e2_cipher.py#L141-177) (`_encrypt`) y [enigma2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/enigma2_cipher.py)
* **Descripción del Fallo:**
  El cifrador inicializa y reinicia sus generadores de números aleatorios (`RNG`) usando un estado fijo derivado únicamente de la contraseña y los índices `global_start_op_index` / `local_start_op_index` (que por defecto son `0`).
  Si el usuario cifra múltiples mensajes independientes con la misma contraseña y no modifica manualmente los índices de desplazamiento, se generará exactamente el mismo flujo de claves (*keystream*). En criptografía, esto se conoce como una **vulnerabilidad de profundidad (depth)** y permite a un atacante con acceso a múltiples textos cifrados realizar análisis de frecuencias inter-mensaje o ataques de texto plano conocido (*known-plaintext attacks*) para romper la clave.
* **Solución:**
  Implementar la generación automática de un **Vector de Inicialización (IV)** o un valor único de un solo uso (*nonce*) de forma aleatoria para cada sesión de cifrado. Este IV debe ser concatenado al inicio del texto cifrado y utilizado para inicializar los desplazamientos del generador de números aleatorios de forma dinámica en cada operación.

---

### 1.3 Derivación de Sal Criterio-Determinista en KDF (Medio)
* **Ubicación:** [pwd_hashing.py:L38-44](file:///C:/CODE_FOLDER/enigma2/src/enigma2/pwd_hashing.py#L38-44) (`PwdBitChainSlicer.__init__`)
* **Descripción del Fallo:**
  Para la derivación de semillas mediante `PBKDF2-HMAC`, la sal (*salt*) se genera aplicando SHA-256 a la contraseña del usuario: `salt = hashlib.sha256(pwd_bytes).digest()`.
  El propósito fundamental de una sal criptográfica es ser **aleatoria y única** para cada cifrado, garantizando que el mismo password produzca derivados distintos y aunlando los ataques mediante tablas precalculadas (como las *Rainbow Tables*). Generar la sal determinísticamente a partir del propio password anula esta protección.
* **Solución:**
  Generar una sal verdaderamente aleatoria (`os.urandom(16)`) para cada cifrado, y guardarla junto con el archivo cifrado. Durante la desencriptación, se lee esta sal para alimentar la función PBKDF2.

---

### 1.4 Crash Potencial por Mismatch de Tamaño en Descompresión (Medio)
* **Ubicación:** [compression.py:L64-67](file:///C:/CODE_FOLDER/enigma2/src/enigma2/compression.py#L64-67) (`Compressor.compress_nparray`)
* **Descripción del Fallo:**
  Cuando se habilita la compresión de datos con `np.ndarray`, la función ejecuta `np.frombuffer` sobre los bytes comprimidos usando el `dtype` original de la data (ej. `np.uint32`).
  Si la cantidad de bytes devuelta por la compresión no es múltiplo exacto del tamaño del elemento del tipo de datos (por ejemplo, 4 bytes para `uint32`), `np.frombuffer` lanzará una excepción fatal: `ValueError: buffer size must be a multiple of element size`.
* **Solución:**
  Dado que la data comprimida carece de estructura típica del tipo de dato de origen, la data resultante de la compresión debe tratarse y cifrarse siempre como un array plano de bytes con `dtype=np.uint8` (y por ende `btype=256`), realizando la descompresión y el casteo al tipo original de vuelta únicamente tras finalizar el proceso de descifrado.

---

### 1.5 Falta de Implementación del Parámetro `chunk_size` (Medio)
* **Ubicación:** [_e2_cipher.py:L183-219](file:///C:/CODE_FOLDER/enigma2/src/enigma2/_e2_cipher.py#L183-219) (`encrypt_file` y `decrypt_file`)
* **Descripción del Fallo:**
  El parámetro `chunk_size` se define en los modelos `E2Params` y en las banderas CLI (`--chunk-size`), pero no está implementado en el código real de procesamiento de archivos. Las funciones `encrypt_file` y `decrypt_file` leen y procesan el archivo de manera íntegra en memoria mediante `np.fromfile`. En archivos de gran tamaño (GBs), esto provoca picos masivos de uso de memoria RAM que resultan en fallos por falta de memoria (Out-of-Memory).
* **Solución:**
  Implementar un bucle de lectura en bloques de tamaño `chunk_size` dentro de `encrypt_file` y `decrypt_file`, procesando cada segmento y actualizando secuencialmente el estado del RNG (`local_start_op_index`).

---

## ⚡ Parte 2: Cuellos de Botella de Rendimiento y Optimización (Ordenados por Impacto)

### 2.1 Ineficiencia Crítica de Memoria en `generate_noise` mediante `np.arange` (Crítico)
* **Ubicación:** [_e2_config.py:L263-274](file:///C:/CODE_FOLDER/enigma2/src/enigma2/_e2_config.py#L263-274) / `_E2Generator.generate_noise` en `_e2_cipher.py`
* **Descripción del Problema:**
  Para seleccionar índices aleatorios donde inyectar el ruido, el código ejecuta:
  `self.noise_rng.choice(np.arange(size), size=actual_noise_size, replace=True)`
  La instrucción `np.arange(size)` genera en memoria un array secuencial con el tamaño completo de la data. Si se cifra un archivo de 100 MB, esto crea un array intermedio de índices de 800 MB en la memoria RAM únicamente para tomar unas pocas posiciones de ruido, lo cual destruye el rendimiento y satura la CPU.
* **Solución:**
  Reemplazar el uso de `choice` con la generación directa de enteros aleatorios en el rango `[0, size)`. Esto elimina la asignación del array `np.arange` y reduce el uso de memoria a $O(\text{noise\_size})$ en lugar de $O(\text{size})$.
* **Código de Solución Propuesto:**
  ```python
  noise_indexes = self.noise_rng.integers(0, size, size=actual_noise_size)
  ```

---

### 2.2 Generación Masiva de Rotaciones Aleatorias en Memoria (Alto)
* **Ubicación:** [_e2_cipher.py:L161-164](file:///C:/CODE_FOLDER/enigma2/src/enigma2/_e2_cipher.py#L161-164) y `_E2Generator.generate_rotations`
* **Descripción del Problema:**
  En Enigma2 (modo no original), la función `generate_rotations` genera un array bidimensional completo con forma `(number_rotors, data_size)` de números enteros aleatorios.
  Para un archivo de 100 MB y 4 rotores, esto genera y almacena en memoria **400 millones** de enteros aleatorios. La generación de esta cantidad de números pseudoaleatorios de golpe consume una cantidad prohibitiva de tiempo de CPU y memoria.
* **Solución:**
  La solución definitiva es procesar los archivos en bloques pequeños utilizando `chunk_size` (por ejemplo, fragmentos de 64 KB). Esto reduce drásticamente el tamaño máximo de los arrays temporales de rotaciones, mejorando la localidad de la caché de CPU y manteniendo el consumo de memoria en límites insignificantes.

---

### 2.3 Reservas de Memoria Repetitivas y Castings en Aritmética Modular (Alto)
* **Ubicación:** [_e2_cipher.py:L81-96](file:///C:/CODE_FOLDER/enigma2/src/enigma2/_e2_cipher.py#L81-96) (`mod_add` y `mod_sub` de `_E2`)
* **Descripción del Problema:**
  En la clase base `_E2` (diseñada para custom `btypes`), las funciones de adición y sustracción modular se ejecutan para cada carácter de la data por cada uno de los rotores en bucle.
  Dentro de estas funciones, se realiza `np.empty_like(a, dtype=higher_encoding)` para asignar un nuevo buffer temporal en cada llamada, sumado a castings explícitos (`a.astype(higher_encoding)`). Asignar y liberar memoria dinámicamente decenas de veces por cada bloque de cifrado introduce una sobrecarga masiva de asignación y recolección de basura (*garbage collection*).
* **Solución:**
  Preasignar un único buffer temporal de trabajo al comienzo del proceso de cifrado (`_encrypt` / `_decrypt`) con el tamaño y tipo adecuados, y reutilizarlo en cada iteración del bucle de rotores para evitar reservas dinámicas de memoria. Además, para la sustracción modular, evitar el uso del lento operador modulo `%` (`np.mod`) utilizando lógica de ajuste simple condicional (`res[res < 0] += m`).

---

### 2.4 Carga Completa en Memoria para Detección de Codificación (Medio)
* **Ubicación:** [_e2_cipher.py:L210-214](file:///C:/CODE_FOLDER/enigma2/src/enigma2/_e2_cipher.py#L210-214) (`encrypt_file`)
* **Descripción del Problema:**
  Para auto-detectar la codificación de texto de un archivo, la función `find_file_encoding` (a través de `chardet` o similar) lee el archivo completo en memoria. Para archivos masivos, esto resulta en picos de consumo innecesarios antes de que comience el cifrado propiamente dicho.
* **Solución:**
  Limitar la lectura de muestreo para la detección de encoding a un buffer de tamaño fijo (ej. los primeros 32 KB del archivo), lo cual es estadísticamente suficiente para identificar la codificación sin penalización de memoria.

---

## 📝 Adenda: Feedback de Diseño y Clarificaciones sobre el Reporte (11 de Julio de 2026)

Tras la revisión del reporte, se han incorporado las siguientes clarificaciones y análisis de propuestas de diseño para la gestión de contraseñas y parámetros:

### 1. Reproducción del Bug 1.1 (Test Añadido)
* Se ha implementado un test unitario formal en [test_pwd_hashing.py](file:///C:/CODE_FOLDER/enigma2/tests/test_pwd_hashing.py#L186) denominado `test_pwd_slicer_large_btype_overflow`.
* Este test configura deliberadamente un `btype` grande (`2**32`) junto con un algoritmo de hash de baja longitud (`pbkdf2_sha256`) para provocar el desbordamiento de slicing y lanzar el error `ValueError: invalid literal for int() with base 2: ''`. Esto permite probar y validar cualquier corrección que se intente realizar sobre el Bug 1.1 de forma repetida.

### 2. Estado de los Bugs 1.4 y 2.4 (Clarificaciones)
* **Bug 1.4 (Compresión)**: Se confirma que este bug lógico está mitigado en el diseño actual, ya que el sistema restringe la compresión únicamente a `btypes` perfectos. Esto garantiza que la longitud y alineación de los bytes comprimidos queden contenidos dentro del espacio del tipo de dato (`dtype`) seleccionado, evitando desajustes de tamaño.
* **Bug 2.4 (Detección de Codificación)**: Se confirma que la lectura de muestra para la autodetección de encoding a través de `chardet` en `find_file_encoding` ya se encuentra correctamente acotada por defecto a los primeros 32,000 bytes.

### 3. Solución Vectorizada para la Inyección de Ruido (Mejora al Punto 2.1)
Para optimizar la inyección de ruido de forma económica (sin preasignar arrays vacíos gigantes de tamaño `size` y realizar una suma vectorial completa), se propone el uso de la función **`np.add.at`** de NumPy.
Esta función ejecuta sumas in-place vectorizadas directamente sobre índices específicos del array, acumulando de forma segura y sin necesidad de bucles de Python:
```python
# Solución vectorizada O(noise_size) de memoria y tiempo:
np.add.at(data_array, noise_indexes, noise_values)
np.mod(data_array, self.config.btype, out=data_array)
```

### 4. Evaluación de Propuestas para la Derivación de Parámetros de Password

#### Propuesta 1: Partición en 5 trozos con tamaño dinámico
* **Descripción:** Dividir la cadena de bits del hash en 4 partes iguales para semillas y una 5ª sección restante con bits fijos/dinámicos (`3` bits para rotores, `btype // 2` bits para la plugboard y `log2(btype) * 2` bits para ruido).
* **Inconvenientes:**
  1. **Insuficiencia crítica de bits (Imposibilidad Matemática):** Si se solicitan `btype // 2` bits para la plugboard (que representa 128 bits para `btype = 256`), el espacio de bits de la 5ª cadena de un hash de 512 bits (que solo tiene 52 bits libres) se agotará de inmediato, provocando fallos de desbordamiento. Incluso usando `log2(btype // 2)` bits, se corre el riesgo de desbordamiento si se eligen hashes más pequeños (como `sha256`).
  2. **Persistencia de bugs de desbordamiento**: Sigue expuesto a que variaciones del tamaño de hash o incrementos del `btype` rompan el slicing en tiempo de ejecución (Bug 1.1).

#### Propuesta 2 (Recomendada): Hashing encadenado / Expansión de Claves

* **Descripción:** Realizar un hashing maestro y luego derivar sucesivamente semillas secundarias de forma recursiva (`seed_1 = Hash(master)`, `seed_2 = Hash(seed_1)`, etc.), deduciendo los parámetros del último hash.
* **Ventajas:**
  * **Entropía infinita:** No hay escasez de bits, permitiendo instanciar cualquier tamaño de `btype` sin riesgo de desbordamiento de cadenas.
  * **Eliminación total del Bug 1.1:** Al no realizar cortes de subcadenas rígidas, se erradican los errores de slicing.
  * **Cero impacto en rendimiento:** hashes encadenados adicionales toman fracciones de microsegundo en comparación con las iteraciones de PBKDF2.
* **Sugerencia Adicional (Estándar Criptográfico):**
  En lugar de encadenamiento lineal, se aconseja aplicar **derivación mediante etiquetas de contexto** a partir de una única clave maestra (`K`), lo cual es el estándar industrial (HKDF):
  
  ```python
  seed_rotations = Hash(master_key + b"rotations")
  seed_rotors    = Hash(master_key + b"rotors")
  seed_plugboard = Hash(master_key + b"plugboard")
  seed_noise     = Hash(master_key + b"noise")
  
  # Parámetros numéricos escalados a partir de un hash específico para parámetros:
  seed_params    = Hash(master_key + b"params")
  number_rotors  = (int(seed_params[:8], 16) % (max_rotors - min_rotors)) + min_rotors
  ```
