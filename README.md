# KAHIRNET

<img width="1672" height="941" alt="Kahirnet" src="https://github.com/user-attachments/assets/3fc15ce3-284c-4e9f-bc5e-007a68ca60a7" />


Reconocimiento de red local autorizado. Descubre hosts alcanzables,
encuentra puertos TCP abiertos, captura banners de servicio y — la parte
que la vuelve más que un port scanner — explica en lenguaje llano cuáles
de esos puertos abiertos son un problema y qué hacer al respecto.

Solo hace conexiones TCP comunes. Sin raw sockets, sin trucos SYN, sin
exploits, y no modifica nada en los hosts que toca. Corre sin privilegios
de administrador ni de root.

Creado por **xtr4ng3**. Parte de la suite OXLGR: WARDEN-11 vigila tu
superficie web, KAHIRNET vigila tu superficie de red.

## Por qué existe

La mayoría de los port scanners te dicen `3306/tcp open` y ahí terminan.
Eso sirve si ya sabés qué significa el puerto 3306. KAHIRNET está hecho
para que alguien que *no lo sabe* — una ONG chica, una escuela, cualquiera
que administra su propia red — pueda apuntarlo a su propio rango de
direcciones y entender el resultado: "tu base de datos es alcanzable
desde afuera, esto es por qué es peligroso, esto es lo que hay que
cambiar."

## Compilación

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

C++17, biblioteca estándar más sockets de la plataforma (Winsock en
Windows, POSIX en el resto). Sin dependencias externas. Compila en
Linux, Windows y macOS.

## Uso

```bash
kahirnet 192.168.1.0/24 --yes-authorized
kahirnet 192.168.1.1-50 --ports top --yes-authorized
kahirnet 10.0.0.5 --ports 1-1024 --report ./cases --yes-authorized
kahirnet host.example --ports 22,80,443 --no-banners --yes-authorized
```

| Forma del target | Significado |
|---|---|
| `192.168.1.1` | host único |
| `192.168.1.1-50` | rango de último octeto |
| `192.168.1.0/24` | bloque CIDR (hasta /22) |
| `a,b,10.0.0.5` | lista separada por comas |

| Opción | Efecto |
|---|---|
| `--ports <spec>` | `top`, `1-1024`, `22,80,443` (por defecto: `top`) |
| `--timeout <ms>` | timeout de conexión por puerto (por defecto: 800) |
| `--threads <n>` | conexiones concurrentes por host (por defecto: 64) |
| `--no-banners` | omite la captura de banners |
| `--report <dir>` | escribe HTML + JSON (por defecto: `reports`) |
| `--no-report` | solo consola |
| `--yes-authorized` | **obligatorio** — confirma que estás autorizado a escanear estos targets |

## Autorización

KAHIRNET se niega a correr sin `--yes-authorized`, siempre. Escanear una
red que no es tuya o para la que no tenés permiso escrito puede ser
ilegal y nunca es el propósito de esta herramienta. El flag es fricción
deliberada, el mismo control que usa WARDEN-11 antes de tocar un target
web.

## Qué reporta

Por cada puerto abierto: el servicio que suele encontrarse ahí, una
evaluación de exposición en lenguaje llano, y cualquier banner que el
servicio haya ofrecido. Después, un conjunto de notas de exposición —
los hallazgos de riesgo alto y medio, cada uno con su explicación y su
consejo concreto. Consola, más HTML y JSON.

La evaluación de exposición es un juicio de postura, no una afirmación
de vulnerabilidad: encontrar Telnet, RDP o una base de datos alcanzable
ya es el hallazgo en sí, sea o no que ese servicio en particular sea
explotable ahora mismo.

## Pruebas

- Verificado contra servicios reales escuchando en puertos estándar y
  no estándar, incluyendo captura de banners.
- Connect no bloqueante con espera acotada por `select()`, así que un
  puerto filtrado cuesta el timeout, no el período completo de
  reintentos SYN del sistema operativo.
- Parseo de targets y puertos validado: bloques CIDR de tamaño excesivo,
  rangos de puerto invertidos o fuera de rango, y entrada no numérica
  son todos rechazados con un mensaje claro.
- Limpio bajo AddressSanitizer y UndefinedBehaviorSanitizer escaneando
  miles de puertos a través de varios hosts con 128 workers concurrentes
  y captura de banners — el caso donde una data race o un comportamiento
  indefinido saldrían a la superficie.


## Licencia

<img width="300" height="159" alt="xtr4ng3" src="https://github.com/user-attachments/assets/d779c370-abfa-4f57-aa1d-a9306e6a3f1c" />


MIT · xtr4ng3
