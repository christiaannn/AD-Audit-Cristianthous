# Diagnóstico Kerberos para Azure Files

`Invoke-AzureFilesKerberosDiagnostics.ps1` es un script de **PowerShell** independiente
que analiza, en profundidad y eslabón por eslabón, por qué falla la autenticación
**Kerberos / CIFS** al montar un recurso compartido de **Azure Files** por SMB, y
genera un **informe HTML autocontenido** con estilo Microsoft (Segoe UI / Fluent),
tablas filtrables y ordenables, resumen ejecutivo y un **análisis de causa raíz
priorizado**.

> Es un script **separado** del de auditoría de Active Directory
> (`Invoke-ADSecurityAudit.ps1`). No comparte estado ni se ejecuta junto a él.

## Síntoma que diagnostica

Montaje de `\\<cuenta>.file.core.windows.net\<share>` que falla en **todos** los
clientes Windows 11 (unidos a AD o a Entra) con:

| Código | Significado | Causa típica |
|--------|-------------|--------------|
| `0x80090303` | `SEC_E_TARGET_UNKNOWN` — destino desconocido/inalcanzable | El SPN `cifs/<cuenta>.file.core.windows.net` **no está registrado** en AD, o se monta con un nombre que no coincide con el SPN (privatelink, IP, alias) |
| `0x6fb` (1787) | `ERROR_NO_TRUST_SAM_ACCOUNT` | El objeto de identidad de AD que respalda la cuenta de almacenamiento **falta, está deshabilitado o su SID no coincide** con `AzureStorageSid` |

Que el fallo sea universal (AD **y** Entra) apunta a una causa del **lado
servidor/identidad** (SPN / objeto AD / tipos de cifrado), no a un problema por
equipo. El script está construido alrededor de esa hipótesis y la prueba.

## Qué comprueba (12 secciones)

1. **Contexto del sistema e identidad** — tipo de unión (`dsregcmd`), detección de
   escenario (AD DS / Entra DS / Entra Kerberos).
2. **Resolución DNS** del FQDN — cadena CNAME, detección de endpoint privado
   (privatelink), IPs.
3. **Conectividad de red** — TCP 445 (SMB) y 443.
4. **Sincronización de reloj** — desfase Kerberos contra el DC (leído de
   `RootDSE.currentTime`, sin permisos especiales).
5. **Configuración Kerberos del cliente** — `SupportedEncryptionTypes`,
   `CloudKerberosTicketRetrievalEnabled`, mapeos de realm (`ksetup`).
6. **/7. SPN y objeto de identidad en AD** — búsqueda LDAP del SPN
   `cifs/<cuenta>...`; detecta **ausente / duplicado / objeto deshabilitado**,
   decodifica `msDS-SupportedEncryptionTypes`, edad de la contraseña (kerb key), SID.
8. **Prueba de ticket Kerberos en vivo** — `klist get cifs/<cuenta>...` con captura
   y **traducción del código de error** exacto.
9. **Configuración de la cuenta de almacenamiento** (opcional, `Az.Storage`) —
   `DirectoryServiceOptions`, `ActiveDirectoryProperties`, y **verificación cruzada**
   de `SamAccountName` / `AzureStorageSid` contra el objeto AD encontrado.
10. **Prueba de montaje SMB** (opcional) — captura el error Win32 real.
11. **Eventos** SMBClient / LSA / Kerberos de los últimos 7 días.
12. **Análisis de causa raíz** — hipótesis priorizadas por confianza con pasos de
    remediación y enlaces a la documentación de Microsoft.

## Requisitos

- Windows PowerShell **5.1** o **PowerShell 7+** en un cliente Windows.
- **No requiere RSAT**: AD se consulta vía `System.DirectoryServices` (y `setspn`
  si está disponible). Ejecútelo en un equipo **unido al dominio** para validar el SPN.
- Ejecución **elevada** recomendada (acceso completo a eventos y servicio de tiempo).
- `Az.Storage` es **opcional** y solo se usa con `-StorageResourceGroup` (requiere
  `Connect-AzAccount`).

## Uso

```powershell
# Diagnóstico básico (informe en la carpeta actual)
.\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles -Verbose

# Completo: prueba de montaje, purga de tickets y carpeta de salida
.\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles `
    -FileShareName proyectos -IncludeMountTest -PurgeTickets -OutputPath C:\Temp

# Cruzar con la configuración real de la cuenta de almacenamiento (Az.Storage)
.\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles `
    -StorageResourceGroup rg-files -ExportCsv
```

Si la directiva de ejecución bloquea el script:
`powershell -ExecutionPolicy Bypass -File .\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles`

### Parámetros

| Parámetro | Predeterminado | Descripción |
|-----------|----------------|-------------|
| `-StorageAccountName` | *(obligatorio)* | Nombre de la cuenta de almacenamiento (solo la etiqueta) |
| `-FileShareName` | — | Nombre del share (para la prueba de montaje) |
| `-StorageSuffix` | `file.core.windows.net` | Sufijo del endpoint (cambia en nubes soberanas) |
| `-DomainController` | auto | DC concreto para las consultas AD/SPN/tiempo |
| `-StorageResourceGroup` | — | Grupo de recursos para leer la config vía `Az.Storage` |
| `-OutputPath` | carpeta actual | Carpeta de salida del HTML/CSV |
| `-MaxClockSkewSeconds` | `300` | Umbral de desfase de reloj |
| `-IncludeMountTest` | off | Monta el share realmente (acción opt-in; se desmonta) |
| `-PurgeTickets` | off | Purga la caché de tickets antes de la prueba en vivo |
| `-ExportCsv` | off | Exporta también cada dataset a CSV |

## Salida

- `AzureFiles_Kerberos_Diag_<timestamp>.html` — informe principal.
- `AzureFiles_Kerberos_CSV_<timestamp>\*.csv` — datasets (con `-ExportCsv`).

## Lectura del informe

El **resumen ejecutivo** muestra contadores por severidad y la tabla de hallazgos.
La sección **12. Análisis de causa raíz** destaca la **causa más probable** con su
porcentaje de confianza y lista, en orden, cada hipótesis con su evidencia y los
pasos exactos de remediación (`setspn`, `Join-AzStorageAccountForAuth`,
sincronización de kerb key, AES-256, etc.).

## Remediación rápida (causas más frecuentes de 0x80090303 / 0x6fb)

```powershell
# 1) ¿Existe el SPN? (ejecutar en un DC o equipo con RSAT)
setspn -Q cifs/contosofiles.file.core.windows.net

# 2) Si falta, registrarlo en el objeto AD que respalda la cuenta:
setspn -S cifs/contosofiles.file.core.windows.net <SamAccountNameDelObjeto>

# 3) Reparar/realinear la identidad completa (AzFilesHybrid):
#    crea el objeto AD, el SPN y sincroniza la kerb key
Join-AzStorageAccountForAuth -ResourceGroupName rg-files `
    -StorageAccountName contosofiles -DomainAccountType ComputerAccount

# 4) Rotar/sincronizar la kerb key si la contraseña del objeto quedó desfasada:
Update-AzStorageAccountADObjectPassword -RotateToKerbKey kerb2 `
    -ResourceGroupName rg-files -StorageAccountName contosofiles
```

> Monte **siempre** con el FQDN exacto `\\contosofiles.file.core.windows.net\<share>`.
> Usar el nombre `privatelink`, una IP o un alias rompe Kerberos (TARGET_UNKNOWN).

## Nota de seguridad

El informe contiene configuración sensible (SPN, SID, objetos de AD). **Trátelo como
confidencial**, guárdelo de forma segura y elimínelo cuando ya no sea necesario.
El script es **de solo lectura** salvo las acciones explícitamente opt-in
(`-PurgeTickets`, `-IncludeMountTest`).

## Documentación de Microsoft

- Habilitar AD DS para Azure Files:
  <https://learn.microsoft.com/azure/storage/files/storage-files-identity-ad-ds-enable>
- Solución de problemas de conexión de Azure Files (Windows):
  <https://learn.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems>
- Microsoft Entra Kerberos para identidades híbridas:
  <https://learn.microsoft.com/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable>
