# Reporte de Código Enigma2: Problemas y Vulnerabilidades Pendientes (v2.5.0)
Fecha: 16 de Julio de 2026

Este documento detalla los problemas de lógica, fallos de seguridad y vulnerabilidades que siguen **pendientes** de resolver en la versión **v2.5.0** de Enigma2. 

---

## 📊 Historial y Resumen de Estado de Problemas (v2.5.0)

| ID | Descripción del Problema | Gravedad | Estado | Resolución / Acción Pendiente |
| :--- | :--- | :--- | :--- | :--- |
| **1.1** | Overflow de Slicing con `btype` Grandes / Hashes Pequeños | Crítico | **Solucionado** | Resuelto mediante la implementación de expansión de claves / encadenamiento recursivo de hashes en `pwd_hashing.py`. |
| **1.2** | Reutilización de Keystream / Vulnerabilidad de Profundidad | Alto | **Pendiente** | Requiere implementar un Vector de Inicialización (IV) o *nonce* aleatorio por sesión de cifrado. *Detalles en Sección 1.2.* |
| **1.3** | Falta de Soporte para Metadata y Autodetección de Archivos | Alto | **Pendiente** | Prerrequisito para KDF Salt. Necesidad de definir un formato de cabecera/metadata en archivos cifrados. *Detalles en Sección 1.3.* |
| **1.4** | Crash por Mismatch de Tamaño en Descompresión | Medio | **Solucionado** | Resuelto tratando los bytes comprimidos como `np.uint8` y realizando el casteo al tipo destino final al descifrar. |
| **1.5** | Falta de Implementación del Parámetro `chunk_size` | Medio | **Solucionado** | Implementado procesamiento por bloques en archivos mediante memory mapping (`np.memmap`) y soporte para detección dinámica con `-1`. |
| **2.1** | Ineficiencia de Memoria en `generate_noise` (`np.arange`) | Crítico | **Solucionado** | Reemplazado por selección directa de enteros aleatorios usando `noise_rng.integers(0, size)`. |
| **2.2** | Generación Masiva de Rotaciones Aleatorias en Memoria | Alto | **Solucionado** | Acotado por el tamaño máximo de los bloques procesados concurrentemente (`chunk_size`). |
| **2.3** | Reservas de Memoria Repetitivas y Castings en Aritmética | Alto | **Solucionado** | Implementados buffers preasignados dinámicamente con aislamiento en hilos y `np.mod` con `casting='unsafe'`. |
| **2.4** | Carga Completa en Memoria para Detección de Codificación | Medio | **Solucionado** | Detección limitada por defecto a un muestreo de los primeros 32 KB del archivo. |
| **3.1** | Falta de Autenticación de Mensajes / AEAD | Alto | **Pendiente** | Requiere implementar firma digital o HMAC. *Detalles en Sección 3.1.* |
| **3.2** | Riesgos de Concurrencia en la Modificación del Logger de Raíz | Medio | **Solucionado** | Eliminado basicConfig global. Aislados todos los logs del paquete en el logger local `"enigma2"`. |
| **3.3** | Falta de captura amigable de excepciones de descompresión | Bajo | **Solucionado** | Encapsulada descompresión en un bloque `try-except` que relanza una excepción controlada `DecompressionError`. |

---

## 🔒 Análisis Detallado de Problemas Pendientes

### 1.2 Reutilización de Keystream / Vulnerabilidad de Profundidad (Alto - **Pendiente**)
* **Ubicación:** [_e2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/_e2_cipher.py) (`_encrypt_raw_data` / `_decrypt_raw_data`)
* **Descripción del Fallo:**
  El cifrador inicializa sus RNG usando únicamente el password y desplazamientos fijos. Si el usuario cifra dos archivos distintos con la misma clave, ambos cifrados compartirán exactamente la misma secuencia pseudoaleatoria (*keystream*).
  En un cifrado simétrico de flujo (XOR/adición modular), si $C_1 = P_1 \oplus K$ y $C_2 = P_2 \oplus K$, un atacante puede calcular:
  $$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$
  Esto elimina la clave de la ecuación y permite romper ambos mensajes mediante análisis de frecuencias o ataques de diccionario/texto plano conocido (*crib dragging*).
* **Solución propuesta (Explicación técnica):**
  Implementar un **Vector de Inicialización (IV)** o *nonce* único generado de forma segura para cada cifrado (por ejemplo, 16 bytes aleatorios vía `os.urandom(16)`). Este IV no es secreto y se añade en la cabecera del archivo. Al descifrar, el IV se extrae de la cabecera y se combina (ej. mediante hash) con la clave maestra para derivar el desplazamiento RNG de esa sesión, garantizando que el *keystream* sea siempre diferente aunque la clave sea la misma.

### 1.3 Bloqueador de Diseño: Inserción de Metadata y Cabecera de Archivos (Alto - **Pendiente**)
* **Ubicación:** [cli.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/cli.py) y [enigma2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/enigma2_cipher.py)
* **Descripción del Fallo:**
  Actualmente, para descifrar un archivo el usuario debe recordar e introducir de forma manual parámetros idénticos como `chunk_size`, `encoding`, `original_rotations` o si se usó compresión. Si algún parámetro difiere, el descifrado corromperá el archivo de salida silenciosamente. Además, no hay forma de autodetección rápida en el CLI para verificar si el archivo fue encriptado por Enigma2 ni para guardar una sal aleatoria para el KDF.
* **Solución propuesta:**
  Diseñar una clase `E2Metadata` e implementar una cabecera binaria estructurada que se anteponga al texto cifrado:
  1. Un marcador de firma inicial (ej. una cadena fija de 16 bytes `0x00` para denotar el inicio).
  2. Campos binarios empaquetados conteniendo: `chunk_size` (para fragmentación), algoritmo de compresión empleado, `encoding` original, `btype`, sal aleatoria del KDF, y un checksum del archivo original.
  3. Un marcador de firma de cierre (ej. cadena de 16 bytes `0xFF`).
  El CLI y la API leerán esta cabecera para configurar dinámicamente los parámetros de descifrado sin requerir intervención del usuario.

### 3.1 Falta de Autenticación de Mensajes / AEAD (Alto - **Pendiente**)
* **Descripción:**
  El cifrado Enigma2 carece de autenticidad. Al no usar un modo AEAD (Authenticated Encryption with Associated Data), el sistema no puede detectar si los bytes cifrados han sido alterados en tránsito. Un atacante activo puede modificar selectivamente los bytes del texto cifrado y el descifrador los procesará sin percatarse, lo cual compromete la integridad de la información (vulnerabilidad de maleabilidad).
* **Solución propuesta (Explicación técnica y matemática):**
  Para lograr integridad y autenticidad sin cambiar la lógica interna del flujo de cifrado, se recomienda el paradigma **Encrypt-then-MAC**. 
  Matemáticamente, tras cifrar el mensaje para obtener $C = \text{Encrypt}(P)$, se calcula un código MAC usando la función HMAC-SHA256:
  $$T = \text{HMAC}(K_{auth}, C)$$
  Donde $K_{auth}$ es una clave de autenticación independiente derivada de la clave maestra. El par $(C, T)$ se guarda en el archivo. Al descifrar, se calcula el HMAC sobre el texto cifrado recibido y se compara con $T$ en tiempo constante. Si no coinciden, se aborta la desencriptación, impidiendo ataques de manipulación de bits.

---

## 🛠️ Plan de Implementación de los Problemas Pendientes

Este anexo detalla los pasos, la lógica y el código completo propuesto para resolver los tres problemas de seguridad y lógica que quedan pendientes (1.2, 1.3 y 3.1) en la versión **v2.5.0** de Enigma2.

### 🔑 1.2 Detalle Profundo: Reutilización de Keystream / Vulnerabilidad de Profundidad (Alto)

#### Explicación Teórica del Problema
Enigma2 cifra la información mediante una secuencia pseudoaleatoria (*keystream*) derivada de un generador de números pseudoaleatorios (PRNG) de NumPy (`np.random.default_rng`). Los generadores se inicializan con semillas derivadas directamente del hash de la contraseña proporcionada por el usuario. 

Si un usuario cifra dos archivos diferentes ($P_1$ y $P_2$) con la misma contraseña y los mismos parámetros por defecto (es decir, el mismo `local_start_op_index`), las semillas resultantes serán idénticas y el cifrador generará exactamente el mismo *keystream* ($K$), las mismas rotaciones y la misma matriz de ruido. En un cifrado simétrico por flujo o basado en adición modular, las ecuaciones de cifrado para ambos archivos son:
$$C_1 = P_1 + K \pmod M$$
$$C_2 = P_2 + K \pmod M$$

Un atacante activo que intercepte ambos textos cifrados ($C_1$ y $C_2$) puede restar algebraicamente ambos mensajes para eliminar el *keystream* $K$:
$$C_1 - C_2 \pmod M = (P_1 + K) - (P_2 + K) \pmod M = P_1 - P_2 \pmod M$$

Al desaparecer la clave del cálculo, el atacante obtiene la relación directa entre los dos textos claros ($P_1 - P_2$). Si el atacante conoce o adivina parte del texto plano de uno de los archivos (*crib dragging*), o mediante análisis estadístico de frecuencias y diccionarios, puede recuperar ambos archivos originales por completo.

#### Dónde y Cómo Realizar la Operación
Para erradicar esta vulnerabilidad, debemos inyectar un **Vector de Inicialización (IV)** aleatorio de 16 bytes (generado de forma segura mediante `os.urandom(16)`) para cada operación de cifrado. Este IV se almacenará públicamente en la cabecera del archivo. Al descifrar, se lee el IV del archivo y se combina con la contraseña maestra del usuario.

El principal problema técnico es: **¿dónde y cómo integrar este IV de forma eficiente sin ralentizar el proceso ni corromper el flujo?**
1. **PBKDF2 es lento**: La contraseña maestra pasa por PBKDF2-HMAC-SHA512 con 100,000 iteraciones para obtener la clave derivada maestra. Ejecutar PBKDF2 en cada cifrado utilizando el IV como sal añadiría una latencia inaceptable de cientos de milisegundos por sesión de cifrado.
2. **Solución Óptima**: Ejecutar PBKDF2 una sola vez sobre la contraseña para derivar la clave maestra (`derived_key`). Luego, para cada sesión, derivar una clave de sesión rápida (`session_key`) calculando el hash rápido de la clave maestra concatenada con el IV:
   $$\text{session\_key} = \text{Hash}(\text{derived\_key} \mathbin{\Vert} \text{iv})$$
3. **Slicer de Semillas**: Modificar el inicializador de [PwdBitChainSlicer](file:///C:/CODE_FOLDER/enigma2/src/enigma2/hashing/pwd_hashing.py#L18) para aceptar el `iv` y calcular la `session_key`. Toda la derivación de semillas subsiguiente en `slices()` se basará en la `session_key`, lo que asegura semillas dinámicas y únicas.
4. **Instanciación Dinámica de la Sesión**: En [_e2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/_e2_cipher.py), implementamos el método `with_session(iv, kdf_salt)` para clonar la configuración y el cifrador con los parámetros específicos de la sesión, regenerando así todos los rotores y plugboards de forma única para ese cifrado.

#### Código Propuesto

##### 1. Modificaciones a [pwd_hashing.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/hashing/pwd_hashing.py)
Modificamos el inicializador y el método `slices` de la clase [PwdBitChainSlicer](file:///C:/CODE_FOLDER/enigma2/src/enigma2/hashing/pwd_hashing.py#L18):

```python
# Ubicación: src/enigma2/hashing/pwd_hashing.py

class PwdBitChainSlicer:
    def __init__(
            self, 
            pwd_bytes: bytes,
            btype: int,
            hash_alg: str = "pbkdf2_sha512",
            hash_iterations: int = 100_000,
            kdf_salt: Optional[bytes] = None,
            iv: Optional[bytes] = None
        ):
        real_hash_alg = hash_alg
        if hash_alg.startswith("pbkdf2_"):
            real_hash_alg = hash_alg[7:]

        if real_hash_alg not in hashlib.algorithms_available:
            raise InvalidHashAlgorithmError(f"Invalid hash algorithm: {hash_alg} not in {hashlib.algorithms_available}")

        self.__pwd_bytes = pwd_bytes
        self.__hash_alg = real_hash_alg
        self.__btype = btype

        # Si se proporciona sal del KDF (desde cabecera), la usamos; si no, derivamos una determinista por compatibilidad
        salt = kdf_salt if kdf_salt is not None else hashlib.sha256(pwd_bytes).digest()
        
        self.derived_key = hashlib.pbkdf2_hmac(
            hash_name=self.__hash_alg,
            password=pwd_bytes,
            salt=salt,
            iterations=hash_iterations
        )

        # Si hay un IV, derivamos una clave de sesión rápida combinando derived_key e IV
        if iv is not None:
            hasher = hashlib.new(self.__hash_alg)
            hasher.update(self.derived_key + iv)
            self.session_key = hasher.digest()
        else:
            self.session_key = self.derived_key

        self.__bitchain = self.generate_bitchain(self.session_key)
        self.__seeds_number: int = 4
        self.__seeds_space_on_hash: float = 0.9
        self.__main_seeds_len: int = int((len(self.__bitchain) * self.__seeds_space_on_hash) // self.__seeds_number)
        self.__hash_len: int = HashBitesLength()[self.__hash_alg]

        if self.__hash_len < MIN_HASH_LEN:
            raise HashLengthError(f"Hash length must be at least {MIN_HASH_LEN} bits: {self.__hash_len} < {MIN_HASH_LEN}")

    def slices(self) -> _E2ElementsCreationParams:
        elements_creation_params = _E2ElementsCreationParams()
        hash_func = lambda data: hashlib.new(self.__hash_alg, data).digest()
        
        # Derivamos las semillas de los rotores y plugboards usando session_key en lugar de derived_key
        seed_1_bytes = hash_func(self.session_key + b"rotations_seed")
        seed_2_bytes = hash_func(seed_1_bytes + b"rotors_seed")
        seed_3_bytes = hash_func(seed_2_bytes + b"plugboard_seed")
        seed_4_bytes = hash_func(seed_3_bytes + b"noise_seed")
        seed_5_bytes = hash_func(seed_4_bytes + b"number_rotors")
        seed_6_bytes = hash_func(seed_5_bytes + b"plugboard_size")
        seed_7_bytes = hash_func(seed_6_bytes + b"noise_size")

        if elements_creation_params.rotations_seed is None:
            elements_creation_params.rotations_seed = int.from_bytes(seed_1_bytes, byteorder="big")
        if elements_creation_params.rotors_seed is None:
            elements_creation_params.rotors_seed = int.from_bytes(seed_2_bytes, byteorder="big")
        if elements_creation_params.plugboard_seed is None:
            elements_creation_params.plugboard_seed = int.from_bytes(seed_3_bytes, byteorder="big")
        if elements_creation_params.noise_seed is None:
            elements_creation_params.noise_seed = int.from_bytes(seed_4_bytes, byteorder="big")
        
        seed_5_bitchain = self.generate_bitchain(seed_5_bytes)
        seed_6_bitchain = self.generate_bitchain(seed_6_bytes)
        seed_7_bitchain = self.generate_bitchain(seed_7_bytes)
        
        end_idx_number_rotors = self.__hash_len // 128
        end_idx_plugboard_size = int(log2(self.get_max_plugboard_len))
        end_idx_noise_size = int(log2(self.get_max_noise_size))

        if elements_creation_params.number_rotors is None:
            elements_creation_params.number_rotors = int(seed_5_bitchain[:end_idx_number_rotors], 2) + MIN_NUMBER_ROTORS
        if elements_creation_params.plugboard_size is None:
            elements_creation_params.plugboard_size = int(seed_6_bitchain[:end_idx_plugboard_size], 2)
        if elements_creation_params.noise_size is None:
            elements_creation_params.noise_size = int(seed_7_bitchain[:end_idx_noise_size], 2)

        return elements_creation_params
```

##### 2. Modificaciones a [model_params.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/config/model_params.py)
Añadimos `iv` y `kdf_salt` a la clase [_E2Params](file:///C:/CODE_FOLDER/enigma2/src/enigma2/config/model_params.py#L140):

```python
# Ubicación: src/enigma2/config/model_params.py

class _E2Params(BaseModel):
    # Campos existentes...
    pwd: bytes = None
    encoding: Optional[E2Encoding] = Field(default=None, validate_default=True)
    # ...
    
    # Nuevos campos para soporte de IV y KDF Salt
    iv: Optional[bytes] = None
    kdf_salt: Optional[bytes] = None

    @field_validator("iv", "kdf_salt", mode="before")
    @classmethod
    def parse_hex_bytes(cls, value: Any):
        if isinstance(value, str):
            try:
                return bytes.fromhex(value)
            except ValueError:
                return value.encode("utf-8")
        return value

    @field_serializer("iv")
    def serialize_iv(self, iv: Optional[bytes]) -> Optional[str]:
        return iv.hex() if iv is not None else None

    @field_serializer("kdf_salt")
    def serialize_kdf_salt(self, kdf_salt: Optional[bytes]) -> Optional[str]:
        return kdf_salt.hex() if kdf_salt is not None else None
```

##### 3. Modificaciones a [_e2_config.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/config/_e2_config.py)
Actualizamos la inicialización en la clase [_E2Config](file:///C:/CODE_FOLDER/enigma2/src/enigma2/config/_e2_config.py#L28):

```python
# Ubicación: src/enigma2/config/_e2_config.py

class _E2Config:
    def __init__(self, params: _E2Params) -> None:
        self.params = params
        self.dtype: np.dtype = np.dtype(params.dtype)
        self.btype: int = params.btype if params.btype is not None else E2TypesConversion.dtype2btype(self.dtype)

        self.pwd: bytes = params.pwd
        # Pasamos kdf_salt e iv al PwdBitChainSlicer
        self.pwd_slicer = PwdBitChainSlicer(
            pwd_bytes=self.pwd, 
            btype=self.btype, 
            hash_alg=params.hash_algorithm,
            kdf_salt=getattr(params, "kdf_salt", None),
            iv=getattr(params, "iv", None)
        )
        self.hash_pwd: str = self.pwd_slicer.derived_key.hex()
        # Resto del inicializador...
```

---

### 📦 1.3 Bloqueador de Diseño: Inserción de Metadata y Cabecera de Archivos (Alto)

#### Explicación Teórica del Diseño de Cabecera
Para evitar que el usuario deba recordar manualmente parámetros como el tamaño del bloque (`chunk_size`), algoritmo de compresión (`compression_alg`), codificación original (`encoding`), etc., diseñamos una cabecera binaria estructurada e inalterable. Utilizar el módulo `struct` de Python nos permite empaquetar variables en formatos binarios crudos sin depender de codificaciones de texto que podrían fallar o corromperse.

La estructura binaria del `E2Metadata` tiene un tamaño fijo de **122 bytes**, con los siguientes campos representados en orden Big-Endian (`>`):
1. **Magic de Inicio (8 bytes)**: Marca de firma inicial `b"ENIGMA2\x00"` para autodetección rápida.
2. **Tamaño del Bloque (8 bytes - int64)**: Almacena `chunk_size` (o `-2` si es `None`, `-1` para bloques automáticos).
3. **Algoritmo de Compresión (1 byte - uint8)**: Enum indexado de compresión.
4. **Encoding Original (16 bytes - string)**: Codificación del archivo de texto, rellena con bytes nulos (`\x00`).
5. **Base Numérica o Btype (8 bytes - uint64)**: Parámetro crucial `btype` del cifrador.
6. **Rotaciones Originales (1 byte - bool)**: Booleano que define si se utiliza el sistema de rotación original.
7. **Desplazamiento Global o Start Index (8 bytes - int64)**: Posición del índice de inicio en las rotaciones.
8. **Vector de Inicialización o IV (16 bytes - bytes)**: Valor aleatorio criptográfico para evitar la reutilización de keystream (Sección 1.2).
9. **Sal del KDF (16 bytes - bytes)**: Sal única usada para PBKDF2 en la derivación de clave.
10. **Checksum de Plaintext (32 bytes - bytes)**: Hash SHA-256 del texto plano original para verificar la correcta descompresión e integridad del texto tras descifrar.
11. **Magic de Cierre (8 bytes)**: Firma de cierre de cabecera `b"\xff\xff\xff\xff\xff\xff\xff\xff"`.

#### Código Propuesto: Nuevo archivo [metadata.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/utils/metadata.py)

```python
# Ubicación: src/enigma2/utils/metadata.py

import struct
from typing import Optional

class E2Metadata:
    # Formato struct: Big-Endian, 8 bytes char, int64, uint8, 16 bytes char, uint64, bool, int64, 16 bytes, 16 bytes, 32 bytes, 8 bytes char.
    FORMAT = ">8s q B 16s Q ? q 16s 16s 32s 8s"
    SIZE = struct.calcsize(FORMAT)
    
    MAGIC_START = b"ENIGMA2\x00"
    MAGIC_END = b"\xff\xff\xff\xff\xff\xff\xff\xff"
    
    COMPRESSION_MAP = {
        None: 0,
        "gzip": 1,
        "bz2": 2,
        "lzma": 3,
        "zlib": 4
    }
    COMPRESSION_REV_MAP = {v: k for k, v in COMPRESSION_MAP.items()}

    def __init__(
        self, 
        chunk_size: Optional[int], 
        compression_alg: Optional[str], 
        encoding: str, 
        btype: int, 
        original_rotations: bool, 
        global_start_op_index: int, 
        iv: bytes, 
        kdf_salt: bytes, 
        plaintext_checksum: bytes
    ):
        self.chunk_size = chunk_size
        self.compression_alg = compression_alg
        self.encoding = encoding
        self.btype = btype
        self.original_rotations = original_rotations
        self.global_start_op_index = global_start_op_index
        self.iv = iv
        self.kdf_salt = kdf_salt
        self.plaintext_checksum = plaintext_checksum

    def pack(self) -> bytes:
        comp_byte = self.COMPRESSION_MAP.get(self.compression_alg, 0)
        enc_bytes = self.encoding.encode("utf-8")[:16].ljust(16, b"\x00")
        c_size = self.chunk_size if self.chunk_size is not None else -2
        
        return struct.pack(
            self.FORMAT,
            self.MAGIC_START,
            c_size,
            comp_byte,
            enc_bytes,
            self.btype,
            self.original_rotations,
            self.global_start_op_index,
            self.iv,
            self.kdf_salt,
            self.plaintext_checksum,
            self.MAGIC_END
        )

    @classmethod
    def unpack(cls, data: bytes) -> "E2Metadata":
        if len(data) < cls.SIZE:
            raise ValueError("Datos demasiado cortos para desempaquetar la cabecera E2Metadata.")
            
        unpacked = struct.unpack(cls.FORMAT, data[:cls.SIZE])
        magic_start, chunk_size, comp_byte, enc_bytes, btype, orig_rot, global_start, iv, kdf_salt, checksum, magic_end = unpacked
        
        if magic_start != cls.MAGIC_START:
            raise ValueError("Firma inicial de cabecera inválida (no es un archivo cifrado con Enigma2).")
        if magic_end != cls.MAGIC_END:
            raise ValueError("Firma final de cabecera inválida.")
            
        compression_alg = cls.COMPRESSION_REV_MAP.get(comp_byte, None)
        encoding = enc_bytes.rstrip(b"\x00").decode("utf-8")
        c_size = None if chunk_size == -2 else chunk_size
        
        return cls(
            chunk_size=c_size,
            compression_alg=compression_alg,
            encoding=encoding,
            btype=btype,
            original_rotations=orig_rot,
            global_start_op_index=global_start,
            iv=iv,
            kdf_salt=kdf_salt,
            plaintext_checksum=checksum
        )
```

---

### 🛡️ 3.1 Falta de Autenticación de Mensajes / AEAD (Alto)

#### Explicación Teórica del Diseño Encrypt-then-MAC
Un cifrado simétrico sin autenticar es vulnerable a manipulaciones de bits en tránsito por parte de un atacante activo (vulnerabilidad de maleabilidad). Para mitigar este riesgo, implementamos la construcción criptográfica estándar de **Encrypt-then-MAC** utilizando un código de autenticación de mensajes basado en hash (**HMAC-SHA256**).

1. **Separación de Claves**: Cifrar y autenticar con la misma clave es una mala práctica. Por tanto, derivamos una clave de autenticación independiente ($K_{auth}$) a partir de la clave maestra calculando:
   $$K_{auth} = \text{Hash}(\text{derived\_key} \mathbin{\Vert} \text{b"authentication\_key"})$$
2. **Generación del Tag**: Tras realizar el cifrado del archivo, calculamos el tag de autenticación sobre la totalidad del payload cifrado:
   $$T = \text{HMAC-SHA256}(K_{auth}, \text{Cabecera Metadata} \mathbin{\Vert} \text{Criptograma})$$
   El tag de 32 bytes se añade al final del archivo de salida.
3. **Verificación en Tiempo Constante**: Al descifrar, leemos los últimos 32 bytes del archivo como el tag de autenticación. Calculamos el HMAC del resto del archivo y los comparamos. Para evitar ataques de canal lateral basados en el tiempo de respuesta (*timing attacks*), la comparación se efectúa utilizando la función segura `hmac.compare_digest`. Si no coincide, la operación se aborta de inmediato y no se descifra ninguna parte de la carga útil, impidiendo la manipulación de datos.

---

### 📜 Integración de Flujo Completo en [_e2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/_e2_cipher.py)

#### Lógica de Adaptación de np.memmap con Offset
Para mantener la eficiencia de memoria cuando se encriptan archivos gigantes usando `np.memmap`:
- En **Cifrado**: Primero escribimos la cabecera `E2Metadata` de 122 bytes en el archivo vacío. Luego, usamos `f.truncate(header_size + data_bytes_size)` para preasignar el tamaño total del archivo en disco. Finalmente, abrimos el mapeo de memoria en modo escritura `mode='r+'` aplicando un `offset=header_size`. Esto permite escribir los bloques cifrados de forma asíncrona directamente después de la cabecera sin copiar datos en RAM. Una vez finalizado el mapeo, calculamos el HMAC y anexamos los 32 bytes al final del archivo.
- En **Descifrado**: Leemos los primeros 122 bytes de cabecera y verificamos el HMAC leyendo los últimos 32 bytes. Si la integridad es válida, realizamos el mapeo del criptograma abriendo el archivo cifrado con `offset=header_size` y un tamaño total acotado por `file_size - header_size - 32`.

#### Código Propuesto para [_e2_cipher.py](file:///C:/CODE_FOLDER/enigma2/src/enigma2/core/_e2_cipher.py)

```python
# Ubicación: src/enigma2/core/_e2_cipher.py

import os
import hmac
import hashlib
from typing import Optional, Union
from pathlib import Path
import numpy as np

# Importamos la cabecera de metadatos y la factoría
from ..utils.metadata import E2Metadata
from ..config.model_params import E2Params
from ..utils.compression import Compressor

# ... resto de las importaciones y cuerpo de la clase _E2 ...

class _E2(_E2_RawData):
    # Métodos y constructores existentes...

    def with_session(self, iv: bytes, kdf_salt: bytes) -> "_E2":
        """
        Crea y retorna una copia del motor de cifrado configurado específicamente
        con el IV y la sal del KDF de la sesión actual.
        """
        new_params = self.params.model_copy()
        new_params.iv = iv
        new_params.kdf_salt = kdf_salt
        return self.__class__(new_params)

    @timed
    def encrypt_file(self, 
                     file_path: Union[str, Path], 
                     output_path: Optional[Union[str, Path]] = None,
                     detect_encoding: bool = False,
                     local_start_op_index: int = 0) -> Path:
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + ENCRYPTED_FILE_SUFFIX)
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / (file_path.name + ENCRYPTED_FILE_SUFFIX)

        # 1. Generación del IV y sal aleatoria única para esta sesión
        iv = os.urandom(16)
        kdf_salt = os.urandom(16)
        
        # 2. Computar checksum SHA-256 del archivo original para verificación posterior
        plaintext_hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                plaintext_hasher.update(chunk)
        plaintext_checksum = plaintext_hasher.digest()

        # 3. Crear motor de cifrado de sesión
        session_cipher = self.with_session(iv=iv, kdf_salt=kdf_salt)

        # 4. Empaquetar la cabecera de metadatos
        metadata = E2Metadata(
            chunk_size=session_cipher.config.chunk_size,
            compression_alg=getattr(session_cipher, "data_compression_alg", None),
            encoding=session_cipher.config.encoding,
            btype=session_cipher.config.btype,
            original_rotations=session_cipher.config.original_rotations,
            global_start_op_index=session_cipher.config.global_start_op_index + local_start_op_index,
            iv=iv,
            kdf_salt=kdf_salt,
            plaintext_checksum=plaintext_checksum
        )
        header_bytes = metadata.pack()

        # 5. Cifrado y escritura de datos
        if session_cipher.config.chunk_size is not None and getattr(session_cipher, "data_compression_alg", None) is None:
            # Flujo optimizado por bloques (memmap)
            if detect_encoding:
                file_encoding = find_file_encoding(file_path)
                dtype = encoding_dtype_map[file_encoding]
            else:
                dtype = session_cipher.config.dtype

            input_array = np.memmap(file_path, dtype=dtype, mode='r')
            data_bytes_size = input_array.nbytes
            
            # Escribir cabecera y truncar el archivo al tamaño correcto
            with open(output_path, 'wb') as f:
                f.write(header_bytes)
                f.truncate(len(header_bytes) + data_bytes_size)
            
            # Mapear memoria a partir del offset de la cabecera
            output_array = np.memmap(output_path, dtype=dtype, mode='r+', offset=len(header_bytes), shape=input_array.shape)
            
            session_cipher.__cipher_op_chunks(
                input_array=input_array,
                output_array=output_array,
                is_encrypt=True,
                local_start_op_index=local_start_op_index
            )
            output_array.flush()
            del input_array
            del output_array
        else:
            # Caída en memoria (compresión o archivos pequeños)
            if detect_encoding:
                file_encoding = find_file_encoding(file_path)
                data = np.fromfile(file_path, dtype=encoding_dtype_map[file_encoding])
            else:
                data = np.fromfile(file_path, dtype=session_cipher.config.dtype)
            
            # Compresión previa al cifrado si corresponde
            if getattr(session_cipher, "data_compression_alg", None) is not None:
                data = Compressor.compress_nparray(data, session_cipher.data_compression_alg)
                
            encrypted_data = session_cipher._encrypt(data, local_start_op_index)
            
            with open(output_path, 'wb') as f:
                f.write(header_bytes)
                encrypted_data.tofile(f)

        # 6. Calcular y anexar el tag HMAC (Encrypt-then-MAC)
        k_auth = hashlib.new(
            session_cipher.config.hash_algorithm, 
            session_cipher.config.pwd_slicer.derived_key + b"authentication_key"
        ).digest()
        
        mac = hmac.new(k_auth, digestmod=hashlib.sha256)
        with open(output_path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                mac.update(chunk)
        tag = mac.digest()

        # Escribir el tag al final del archivo
        with open(output_path, 'ab') as f:
            f.write(tag)
        
        return output_path

    @timed
    def decrypt_file(self, 
                      file_path: Union[str, Path], 
                      output_path: Optional[Union[str, Path]] = None,
                      local_start_op_index: int = 0) -> Path:
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        
        file_size = file_path.stat().st_size
        if file_size < E2Metadata.SIZE + 32:
            raise ValueError("El archivo es demasiado pequeño para ser un archivo cifrado Enigma2 válido.")

        # 1. Leer cabecera de metadatos
        with open(file_path, 'rb') as f:
            header_bytes = f.read(E2Metadata.SIZE)
        metadata = E2Metadata.unpack(header_bytes)

        # 2. Extraer el tag HMAC (últimos 32 bytes)
        with open(file_path, 'rb') as f:
            f.seek(file_size - 32)
            received_tag = f.read(32)

        # 3. Derivar clave de autenticación del usuario
        master_slicer = PwdBitChainSlicer(
            pwd_bytes=self.params.pwd,
            btype=metadata.btype,
            hash_alg=self.params.hash_algorithm,
            kdf_salt=metadata.kdf_salt
        )
        k_auth = hashlib.new(self.params.hash_algorithm, master_slicer.derived_key + b"authentication_key").digest()

        # 4. Verificar integridad con HMAC en tiempo constante
        mac = hmac.new(k_auth, digestmod=hashlib.sha256)
        bytes_to_read = file_size - 32
        with open(file_path, 'rb') as f:
            read_so_far = 0
            while read_so_far < bytes_to_read:
                chunk = f.read(min(65536, bytes_to_read - read_so_far))
                if not chunk:
                    break
                mac.update(chunk)
                read_so_far += len(chunk)
        calculated_tag = mac.digest()

        if not hmac.compare_digest(calculated_tag, received_tag):
            raise E2Error("Error de Integridad: El archivo ha sido manipulado o la contraseña es incorrecta.")

        # 5. Instanciar dinámicamente el motor de cifrado usando los metadatos de la cabecera
        session_params = E2Params(
            pwd=self.params.pwd,
            btype=metadata.btype,
            encoding=metadata.encoding,
            original_rotations=metadata.original_rotations,
            global_start_op_index=metadata.global_start_op_index,
            chunk_size=metadata.chunk_size,
            data_compression_alg=metadata.compression_alg,
            hash_algorithm=self.params.hash_algorithm,
            verbose=self.params.verbose,
            iv=metadata.iv,
            kdf_salt=metadata.kdf_salt
        )
        session_cipher = self.with_session(iv=metadata.iv, kdf_salt=metadata.kdf_salt)

        if output_path is None:
            output_path = file_path.with_name(file_path.name.replace(ENCRYPTED_FILE_SUFFIX, ""))
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / file_path.name.replace(ENCRYPTED_FILE_SUFFIX, "")

        # 6. Descifrar el criptograma
        ciphertext_bytes_len = file_size - E2Metadata.SIZE - 32
        if session_cipher.config.chunk_size is not None and getattr(session_cipher, "data_compression_alg", None) is None:
            # Descifrado por bloques (memmap)
            dtype = session_cipher.config.dtype
            itemsize = np.dtype(dtype).itemsize
            shape = (ciphertext_bytes_len // itemsize,)
            
            input_array = np.memmap(file_path, dtype=dtype, mode='r', offset=E2Metadata.SIZE, shape=shape)
            output_array = np.memmap(output_path, dtype=dtype, mode='w+', shape=shape)
            
            session_cipher.__cipher_op_chunks(
                input_array=input_array,
                output_array=output_array,
                is_encrypt=False,
                local_start_op_index=0
            )
            output_array.flush()
            del input_array
            del output_array
        else:
            # Descifrado en memoria
            with open(file_path, "rb") as f:
                f.seek(E2Metadata.SIZE)
                ciphertext_data = f.read(ciphertext_bytes_len)
            
            data = np.frombuffer(ciphertext_data, dtype=session_cipher.config.dtype)
            decrypted_data = session_cipher._decrypt(data, local_start_op_index=0)
            
            if getattr(session_cipher, "data_compression_alg", None) is not None:
                decrypted_data = Compressor.decompress_nparray(
                    decrypted_data, 
                    session_cipher.data_compression_alg, 
                    session_cipher.config.dtype
                )
            
            with open(output_path, "wb") as f:
                f.write(decrypted_data.tobytes())

        # 7. Validar el checksum del texto plano original
        plaintext_hasher = hashlib.sha256()
        with open(output_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                plaintext_hasher.update(chunk)
        decrypted_checksum = plaintext_hasher.digest()

        if decrypted_checksum != metadata.plaintext_checksum:
            if output_path.exists():
                output_path.unlink()
            raise E2Error("Error de Integridad: El checksum del texto plano descifrado no coincide.")

        return output_path
```