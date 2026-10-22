# BitForce PHP Agent v2.0

Kit para diagnosticar y corregir **PHP2Shell** (CVE-2026-109618 y CVE-2026-109619, RCE sin autenticación en PHP 5.4 a 8.5.11) en servidores Linux de clientes.

| Archivo | Para qué sirve |
| --- | --- |
| `bitforce-php-agent.sh` | El agente. Se copia al servidor y se ejecuta allí. Un solo archivo, sin dependencias. |
| `bitforce-run.ps1` | Lanzador para **Windows**: ejecuta el agente en una lista de servidores y junta los reportes. |
| `bitforce-run.sh` | El mismo lanzador para Linux, macOS, WSL o Git Bash. |
| `servidores.ejemplo.txt` | Formato de la lista de servidores. |

## Versiones corregidas

| Rama | Mínima segura | Soporte de seguridad hasta |
| --- | --- | --- |
| 8.5 | 8.5.12 | 2029-12-31 |
| 8.4 | 8.4.27 | 2028-12-31 |
| 8.3 | 8.3.36 | 2027-12-31 |
| 8.2 | 8.2.35 | **2026-12-31** (vence en 2 meses) |
| 8.1 o anterior | sin parche upstream | vencido |

Debian, Ubuntu y RHEL aplican el parche **sin subir el número de versión**. Por ejemplo, Ubuntu 24.04 lo publicó como `8.3.6-0ubuntu0.24.04.13`: `php -v` sigue diciendo 8.3.6, pero el paquete ya está corregido. El agente lo detecta leyendo el changelog del paquete, no solo el número.

## Uso rápido

**Un servidor** (desde Windows con PowerShell, o desde cualquier terminal):

```bash
scp bitforce-php-agent.sh usuario@servidor:/tmp/
ssh -t usuario@servidor "sudo bash /tmp/bitforce-php-agent.sh"
```

**Varios servidores desde Windows:**

```powershell
powershell -ExecutionPolicy Bypass -File .\bitforce-run.ps1 -Servers .\servidores.txt
powershell -ExecutionPolicy Bypass -File .\bitforce-run.ps1 -Servers .\servidores.txt -Mode fix -AgentArgs '--yes'
```

**Varios servidores desde Linux, WSL o Git Bash:**

```bash
./bitforce-run.sh -f servidores.txt
./bitforce-run.sh -f servidores.txt -m fix -- --yes
```

Los reportes quedan en `reportes/<fecha>-<modo>/<servidor>/`, con un `resumen.csv` que se abre en Excel.

## Modos

| Modo | Qué hace | ¿Cambia el servidor? |
| --- | --- | --- |
| `diagnose` | Inventario de PHP, estado del parche, qué versión usa cada sitio, actualizaciones automáticas, Docker e indicadores de compromiso. | No |
| `fix` | Actualiza en la **misma rama**: respaldo, actualización conservando `php.ini` y pools, reinicio de PHP-FPM, Apache o LiteSpeed, y chequeo HTTP de cada sitio antes y después. | Sí, con confirmación |
| `plan --to 8.3` | Plan para cambiar de rama: sitios afectados, extensiones, `composer.json` y `composer.lock`, y código eliminado o deprecado entre versiones. | No |
| `stage --to 8.3` | Instala la rama nueva **en paralelo**: mismas extensiones, ajustes de `php.ini` y pools. Valida el código con `php -l` y `composer check-platform-reqs`. **Ningún sitio cambia.** | Sí, con confirmación |
| `switch --to 8.3 --site dominio.com` | Pasa uno o más sitios a la rama nueva. Si un sitio responde 5xx después del cambio, **revierte solo**. | Sí, con confirmación |
| `rollback` | Revierte el último `fix` o `switch`. | Sí, con confirmación |

Opciones útiles: `--yes` (sin preguntas), `--no-ioc` (más rápido), `--upstream-repo` (permite usar Sury, el PPA de Ondřej o Remi), `--app /ruta` (carpeta del proyecto para `plan` y `stage`) y `--all-sites`. La lista completa está en `bash bitforce-php-agent.sh --help`.

**Códigos de salida:** 0 OK · 1 requiere acción · 2 indicadores sospechosos · 3 error.

## Flujo recomendado

1. **Antes de tocar nada:** usuario SSH con sudo y snapshot del VPS más un volcado de la base de datos.
2. **Diagnóstico** (`diagnose`). Revisa o entrega el reporte `.txt` al cliente.
3. **Si el veredicto es SOSPECHOSO (código 2), no parches todavía.** Primero copia los archivos marcados y los logs, aísla el sitio y rota las credenciales. Parchear borra rastros y no elimina una webshell ya instalada.
4. **Parche en la misma rama** (`fix`), en una ventana de mantenimiento. Si la distro aún no publicó el parche, repite con `--upstream-repo`.
5. **Rama sin soporte (7.x, 8.0, 8.1) o 8.2 por vencer:** es un proyecto aparte.
   1. `plan --from 7.4 --to 8.3` y entrega del informe de compatibilidad al cliente.
   2. El cliente o su desarrollador corrige lo marcado como **ROTO** y actualiza dependencias en un entorno de prueba.
   3. `stage --from 7.4 --to 8.3`: instalación en paralelo, sin impacto.
   4. `switch --from 7.4 --to 8.3 --site sitio-de-prueba.com` y 24 a 48 horas de observación.
   5. `switch --from 7.4 --to 8.3 --all-sites`.
   6. Tras 1 o 2 semanas estables, desinstalar la rama vieja.
6. **Seguimiento:** activar actualizaciones automáticas (`unattended-upgrades` o `dnf-automatic`) y repetir el diagnóstico periódicamente.

## Qué detecta

- **Distribuciones:** Debian, Ubuntu, RHEL, AlmaLinux, Rocky, CentOS, Oracle Linux, Amazon Linux, Fedora, openSUSE/SLES y Alpine (en Alpine: `apk add bash`).
- **Origen de PHP:** repo de la distro, Sury, PPA de Ondřej, Remi (modular y SCL en paralelo), cPanel EasyApache (`ea-php`), CloudLinux `alt-php`, Plesk, LiteSpeed `lsphp`, aaPanel, DirectAdmin, CWP o compilado a mano.
- **Cómo se sirve cada sitio:** Apache con mod_php, Apache con PHP-FPM (por vhost o handler global), Nginx con PHP-FPM (incluye `upstream`), LiteSpeed/OpenLiteSpeed y Caddy. Relaciona cada sitio con el socket o puerto y con la versión exacta de PHP.
- **Reinicio pendiente:** procesos que siguen ejecutando el binario anterior aunque el paquete ya esté actualizado, que es el caso más común después de un `apt upgrade`.
- **Contenedores Docker** con PHP.
- **Indicadores de compromiso:** caídas de PHP (segfault) desde el 19 de octubre, archivos PHP recientes, patrones de webshell, PHP en carpetas de subida o imágenes, procesos raros o tareas cron de usuarios web, y ejecutables en `/tmp` o `/dev/shm`.

## Archivos que deja en el servidor

| Ruta | Contenido |
| --- | --- |
| `/var/tmp/bitforce/` | Reportes `.txt` y `.json` de cada ejecución |
| `/var/backups/bitforce-php/<id>/` | Respaldo de configuración (`etc.tgz`), versiones de paquetes y archivos modificados por `switch` |
| `/var/log/bitforce-php-agent.log` | Registro de cada comando ejecutado por `fix`, `stage`, `switch` y `rollback` |

## Pruebas realizadas y limitaciones

**Probado de punta a punta** en Ubuntu 24.04 con Nginx y Apache sobre PHP-FPM: `diagnose`, `fix` (incluido el backport real de Ubuntu y el caso de reinicio pendiente), `rollback` del fix, `plan`, `stage`, `switch` en Nginx y Apache, reversión automática ante un 502, `rollback` del switch, ejecución sin root y ambos lanzadores con varios servidores. Las funciones de versiones, restricciones de composer y rutas de cada distro tienen 36 pruebas unitarias.

**Ejecutado realmente en ubuntu 24 con nginx y debian con apache:** Simulado en RHEL y derivados, SUSE, Alpine y los paneles. **Se recomienda diagnosticar y revisar paso a paso antes de ejecutar cambios en PRD.**

Otras limitaciones:

- En **Plesk, DirectAdmin, CWP y aaPanel**, `fix` muestra las instrucciones del panel en lugar de actualizar, porque el panel gestiona PHP.
- `stage` no instala en paralelo en openSUSE/SLES, que ofrecen una sola versión de PHP, ni en servidores con panel.
- `switch` automatiza Nginx y Apache. LiteSpeed y Caddy se cambian desde su panel o configuración.
- El análisis de compatibilidad es **heurístico**: no reemplaza las pruebas de la aplicación. Las dependencias de `composer.lock` y `php -l` con la rama nueva sí son verificaciones reales.
- El chequeo HTTP prueba cada dominio contra `127.0.0.1` en el puerto del sitio. No detecta errores que solo aparezcan en páginas internas o con sesión iniciada.
