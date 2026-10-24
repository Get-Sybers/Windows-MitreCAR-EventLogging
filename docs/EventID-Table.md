# CAR Event Log — the EventID table

> **GENERATED** by `python tools/carmodel.py generate` from the pinned model — do not edit by hand; edit `model/eventids.yaml` / `model/templates.yaml` or bump a pin and regenerate. `python tools/carmodel.py check` (CI) fails on drift.
>
> Pins — MITRE CAR data model: [`1b922fe1527d`](https://github.com/Get-Sybers/car/tree/1b922fe1527d956e222a99473472e594f10f610b) (`model/sources/car`, git submodule); Byakugan (schema source): [`8e151977a05d`](https://github.com/Get-Sybers/Byakugan/tree/8e151977a05d607b87ef852617058ee23967a6e0) (`model/sources/byakugan/PIN.yaml`).

## 1. At a glance

- **13 CAR objects**, **219 properties**, **73 (object, action) events**: 50 defined by the pinned CAR submodule (`car`), 23 added by `byakugan car-vocab` from the ATT&CK data-component overlay (`superset`). The three *promoted* objects in `car-actions.schema.json` (group, scheduled_job, user_account) have no CAR field set and are **reserved**, not defined — §7.
- **Provider** `Get-Sybers-MitreCAR` · **channel** `Get-Sybers-MitreCAR/Operational` (type Operational) · provider GUID `5bc454ac-3ed9-4b89-b9f4-af8202af0ed8` — proposed names, see `docs/Decisions.md` §D5.
- **EventID = object base + offset.** Offsets 1–49 are pinned-CAR actions, 50–99 are superset actions. **Task = EventID div 100** (the object). **Opcode = the action**, one value per action name across all objects. **Keyword = one bit per object.** Filter by object (Task or Keyword), by action (Opcode), or slice by ID range.
- **One typed template per object**, reused by all of that object's actions; every template opens with the 3-field sensor envelope (§5) followed by the object's complete CAR property set (§6). Unobserved fields are written empty — never inferred.

## 2. Objects → Task, ID range, Keyword

| Task | Object | EventIDs | Keyword | Properties | Events (car + superset) | Template | CAR description |
|---:|---|---|---|---:|---|---|---|
| 10 | **process** | 1000–1099 | `0x0000000000000001` | 29 | 6 (3 + 3) | `GSCAR_T_PROCESS` | A process is a running program on a computer. |
| 11 | **file** | 1100–1199 | `0x0000000000000002` | 26 | 10 (7 + 3) | `GSCAR_T_FILE` | A resource for storing information available to a computer program. |
| 12 | **flow** | 1200–1299 | `0x0000000000000004` | 27 | 6 (3 + 3) | `GSCAR_T_FLOW` | A sequence of packets from a source computer to a destination, which may be another host, a multicast group, or a broadcast domain. This may be captured at network or host level. |
| 13 | **registry** | 1300–1399 | `0x0000000000000008` | 11 | 8 (4 + 4) | `GSCAR_T_REGISTRY` | The registry is a system-defined database in which applications and system components store and retrieve configuration data. The data stored in the registry varies according to the version of Microsoft Windows. Applications use the registry API to retrieve, modify, or delete registry data. |
| 14 | **module** | 1400–1499 | `0x0000000000000010` | 13 | 4 (2 + 2) | `GSCAR_T_MODULE` | Modules correspond to executable (and potentially non-executable) content, and are loaded as a contiguous region of memory into the address space of a process. Each process will have the main image loaded as a module and shared libraries (DLLs in Windows) and their dependencies. |
| 15 | **thread** | 1500–1599 | `0x0000000000000020` | 15 | 4 (4 + 0) | `GSCAR_T_THREAD` | A thread of execution is the smallest sequence of programmed instructions that can be managed independently by a scheduler, which is typically part of the operating system. A thread is typically a component of a process. Multiple threads can exist within the same process and share resources such as memory, while different processes do not share these resources. The threads of a process share executable code instructions and context, such as the values of variables at any given moment. |
| 16 | **driver** | 1600–1699 | `0x0000000000000040` | 11 | 3 (2 + 1) | `GSCAR_T_DRIVER` | A driver is software that runs in the operating system kernel. Drivers are generally used to allow a computer to communicate with hardware devices but have access to important kernel resources. |
| 17 | **service** | 1700–1799 | `0x0000000000000080` | 10 | 9 (5 + 4) | `GSCAR_T_SERVICE` | Services, or a service application, can be started automatically at system boot, by a user through the services control panel applet, or by an application that uses service functions. Services can execute even when no user is logged into the system. |
| 18 | **user_session** | 1800–1899 | `0x0000000000000100` | 10 | 8 (5 + 3) | `GSCAR_T_USER_SESSION` | User sessions are the user activities undertaken on the computer in the course of conducting standard user actions. |
| 19 | **authentication** | 1900–1999 | `0x0000000000000200` | 19 | 3 (3 + 0) | `GSCAR_T_AUTHENTICATION` | An authentication event occurs whenever a user or process attempts to access a privileged system resource. Examples include logging into a system, or elevating privilege. |
| 20 | **socket** | 2000–2099 | `0x0000000000000400` | 10 | 3 (3 + 0) | `GSCAR_T_SOCKET` | Socket events are low-level events that may or may not result in a flow. Socket listenining events in particular can be helpful in detecting malicious activity. |
| 21 | **http** | 2100–2199 | `0x0000000000000800` | 17 | 4 (4 + 0) | `GSCAR_T_HTTP` | HTTP events represents requests made over the network via the HTTP protocol. |
| 22 | **email** | 2200–2299 | `0x0000000000001000` | 21 | 5 (5 + 0) | `GSCAR_T_EMAIL` | Email events are at the mail server level. |

## 3. Actions → Opcode

Custom opcodes occupy 10–238 (ETW reserves 0–9). Pinned-CAR action names were assigned alphabetically from 10; the five names only the superset adds follow.

| Opcode | Action | Provenance | Objects |
|---:|---|---|---|
| 10 | `access` | car | process, file, registry, service |
| 11 | `acl_modify` | car | file |
| 12 | `add` | car | registry |
| 13 | `bind` | car | socket |
| 14 | `block` | car | email |
| 15 | `close` | car | socket |
| 16 | `create` | car | process, file, flow, registry, thread, service, user_session |
| 17 | `delete` | car | file, registry, service, email |
| 18 | `deliver` | car | email |
| 19 | `end` | car | flow |
| 20 | `error` | car | authentication |
| 21 | `failure` | car | authentication |
| 22 | `get` | car | http |
| 23 | `key_edit` | car | registry |
| 24 | `listen` | car | socket |
| 25 | `load` | car | module, driver |
| 26 | `lock` | car | user_session |
| 27 | `login` | car | user_session |
| 28 | `logout` | car | user_session |
| 29 | `message` | car | flow |
| 30 | `modify` | car | process, file, registry, service |
| 31 | `pause` | car | service |
| 32 | `post` | car | http |
| 33 | `put` | car | http |
| 34 | `quarantine` | car | email |
| 35 | `read` | car | file |
| 36 | `reconnect` | car | user_session |
| 37 | `redirect` | car | email |
| 38 | `remote_create` | car | thread |
| 39 | `remove` | car | registry |
| 40 | `start` | car | flow, service |
| 41 | `stop` | car | service |
| 42 | `success` | car | authentication |
| 43 | `suspend` | car | thread |
| 44 | `terminate` | car | process, thread, user_session |
| 45 | `timestomp` | car | file |
| 46 | `tunnel` | car | http |
| 47 | `unload` | car | module, driver |
| 48 | `unlock` | car | user_session |
| 49 | `value_edit` | car | registry |
| 50 | `write` | car | file |
| 51 | `content` | superset | file, flow, module |
| 52 | `enumerate` | superset | service |
| 53 | `execute` | superset | process |
| 54 | `flow` | superset | flow |
| 55 | `metadata` | superset | process, file, module, driver, service, user_session |

## 4. The EventID table

Every (object, action) pair in the pinned model, numbered. *Sensor cards* = the pinned CAR `sensors/*.yaml` that claim the pair; *Byakugan evtx bindings* = Windows events Byakugan's reviewed overlay binds to the pair (‡ = heuristic). Both columns are **coverage evidence from the pinned sources**, not this project's writer map — that map is deliverable 5.

| EventID | Object | Action | Task | Opcode | Prov. | Symbol | Sensor cards | Byakugan evtx bindings |
|---:|---|---|---:|---:|---|---|---|---|
| **1001** | process | `create` | 10 | 16 | car | `GSCAR_PROCESS_CREATE` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 1); sysmon_11.0 (Event 1); sysmon_13 (Event 1) | Sysmon 1; Security 4688 |
| **1002** | process | `terminate` | 10 | 44 | car | `GSCAR_PROCESS_TERMINATE` | sysmon_10.4 (Event 5); sysmon_11.0 (Event 5); sysmon_13 (Event 5) | Security 4689; Sysmon 5 |
| **1003** | process | `access` | 10 | 10 | car | `GSCAR_PROCESS_ACCESS` |  | Sysmon 10; Security 4663 (PROCESS_VM_READ) |
| **1050** | process | `execute` | 10 | 53 | superset | `GSCAR_PROCESS_EXECUTE` |  | PowerShell 4103/4104 ‡; AppLocker EXE-and-DLL channel, allow decisions (8002) |
| **1051** | process | `metadata` | 10 | 55 | superset | `GSCAR_PROCESS_METADATA` |  |  |
| **1052** | process | `modify` | 10 | 30 | superset | `GSCAR_PROCESS_MODIFY` |  | Sysmon 25 |
| **1101** | file | `create` | 11 | 16 | car | `GSCAR_FILE_CREATE` | auditd_2.8; autoruns_13.98; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 11); sysmon_11.0 (Event 11); sysmon_13 (Event 11) | Sysmon 11 |
| **1102** | file | `delete` | 11 | 17 | car | `GSCAR_FILE_DELETE` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_11.0 (Event 23); sysmon_13 (Event 23) | Sysmon 23/26 |
| **1103** | file | `modify` | 11 | 30 | car | `GSCAR_FILE_MODIFY` | auditd_2.8; autoruns_13.98; osquery_4.1.2; osquery_4.6.0 | Security 1102 |
| **1104** | file | `timestomp` | 11 | 45 | car | `GSCAR_FILE_TIMESTOMP` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 2); sysmon_11.0 (Event 2); sysmon_13 (Event 2) | Sysmon 2 |
| **1105** | file | `read` | 11 | 35 | car | `GSCAR_FILE_READ` |  | Security 5145 |
| **1106** | file | `write` | 11 | 50 | car | `GSCAR_FILE_WRITE` | auditd_2.8; osquery_4.1.2; osquery_4.6.0 |  |
| **1107** | file | `acl_modify` | 11 | 11 | car | `GSCAR_FILE_ACL_MODIFY` |  | Security 4907 |
| **1150** | file | `access` | 11 | 10 | superset | `GSCAR_FILE_ACCESS` |  | Security 5140 |
| **1151** | file | `content` | 11 | 51 | superset | `GSCAR_FILE_CONTENT` |  |  |
| **1152** | file | `metadata` | 11 | 55 | superset | `GSCAR_FILE_METADATA` |  |  |
| **1201** | flow | `start` | 12 | 40 | car | `GSCAR_FLOW_START` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 3); sysmon_11.0 (Event 3); sysmon_13 (Event 3) | Sysmon 3 |
| **1202** | flow | `end` | 12 | 19 | car | `GSCAR_FLOW_END` | auditd_2.8; osquery_4.1.2; osquery_4.6.0 |  |
| **1203** | flow | `message` | 12 | 29 | car | `GSCAR_FLOW_MESSAGE` |  |  |
| **1250** | flow | `content` | 12 | 51 | superset | `GSCAR_FLOW_CONTENT` |  |  |
| **1251** | flow | `create` | 12 | 16 | superset | `GSCAR_FLOW_CREATE` |  |  |
| **1252** | flow | `flow` | 12 | 54 | superset | `GSCAR_FLOW_FLOW` |  |  |
| **1301** | registry | `add` | 13 | 12 | car | `GSCAR_REGISTRY_ADD` | autoruns_13.98; sysmon_10.4 (Event 12); sysmon_11.0 (Event 12); sysmon_13 (Event 12) | Sysmon 12 |
| **1302** | registry | `remove` | 13 | 39 | car | `GSCAR_REGISTRY_REMOVE` | sysmon_10.4 (Event 12); sysmon_11.0 (Event 12); sysmon_13 (Event 12) |  |
| **1303** | registry | `value_edit` | 13 | 49 | car | `GSCAR_REGISTRY_VALUE_EDIT` | autoruns_13.98; sysmon_13 (Event 13) | Sysmon 13 |
| **1304** | registry | `key_edit` | 13 | 23 | car | `GSCAR_REGISTRY_KEY_EDIT` | autoruns_13.98; sysmon_13 (Event 14) | Sysmon 14 |
| **1350** | registry | `access` | 13 | 10 | superset | `GSCAR_REGISTRY_ACCESS` |  |  |
| **1351** | registry | `create` | 13 | 16 | superset | `GSCAR_REGISTRY_CREATE` |  |  |
| **1352** | registry | `delete` | 13 | 17 | superset | `GSCAR_REGISTRY_DELETE` |  |  |
| **1353** | registry | `modify` | 13 | 30 | superset | `GSCAR_REGISTRY_MODIFY` |  |  |
| **1401** | module | `load` | 14 | 25 | car | `GSCAR_MODULE_LOAD` | sysmon_10.4 (Event 7); sysmon_11.0 (Event 7); sysmon_13 (Event 7) | Sysmon 7 |
| **1402** | module | `unload` | 14 | 47 | car | `GSCAR_MODULE_UNLOAD` |  |  |
| **1450** | module | `content` | 14 | 51 | superset | `GSCAR_MODULE_CONTENT` |  |  |
| **1451** | module | `metadata` | 14 | 55 | superset | `GSCAR_MODULE_METADATA` |  |  |
| **1501** | thread | `remote_create` | 15 | 38 | car | `GSCAR_THREAD_REMOTE_CREATE` | sysmon_10.4 (Event 8); sysmon_11.0 (Event 8); sysmon_13 (Event 8) | Sysmon 8 |
| **1502** | thread | `create` | 15 | 16 | car | `GSCAR_THREAD_CREATE` |  |  |
| **1503** | thread | `suspend` | 15 | 43 | car | `GSCAR_THREAD_SUSPEND` |  |  |
| **1504** | thread | `terminate` | 15 | 44 | car | `GSCAR_THREAD_TERMINATE` |  |  |
| **1601** | driver | `load` | 16 | 25 | car | `GSCAR_DRIVER_LOAD` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 6); sysmon_11.0 (Event 6); sysmon_13 (Event 6) | Sysmon 6 |
| **1602** | driver | `unload` | 16 | 47 | car | `GSCAR_DRIVER_UNLOAD` |  |  |
| **1650** | driver | `metadata` | 16 | 55 | superset | `GSCAR_DRIVER_METADATA` |  |  |
| **1701** | service | `create` | 17 | 16 | car | `GSCAR_SERVICE_CREATE` | autoruns_13.98 | Security 4697; System 7045 |
| **1702** | service | `delete` | 17 | 17 | car | `GSCAR_SERVICE_DELETE` | autoruns_13.98 |  |
| **1703** | service | `pause` | 17 | 31 | car | `GSCAR_SERVICE_PAUSE` |  |  |
| **1704** | service | `start` | 17 | 40 | car | `GSCAR_SERVICE_START` |  |  |
| **1705** | service | `stop` | 17 | 41 | car | `GSCAR_SERVICE_STOP` |  | System 7034/7036 |
| **1750** | service | `access` | 17 | 10 | superset | `GSCAR_SERVICE_ACCESS` |  |  |
| **1751** | service | `enumerate` | 17 | 52 | superset | `GSCAR_SERVICE_ENUMERATE` |  |  |
| **1752** | service | `metadata` | 17 | 55 | superset | `GSCAR_SERVICE_METADATA` |  |  |
| **1753** | service | `modify` | 17 | 30 | superset | `GSCAR_SERVICE_MODIFY` |  |  |
| **1801** | user_session | `lock` | 18 | 26 | car | `GSCAR_USER_SESSION_LOCK` |  |  |
| **1802** | user_session | `login` | 18 | 27 | car | `GSCAR_USER_SESSION_LOGIN` |  | Security 4624, interactive-class LogonType (2/7/10/11); System 7001 (Winlogon); TerminalServices-LocalSessionManager 21 (RDP) |
| **1803** | user_session | `logout` | 18 | 28 | car | `GSCAR_USER_SESSION_LOGOUT` |  | Security 4634 / 4647 |
| **1804** | user_session | `reconnect` | 18 | 36 | car | `GSCAR_USER_SESSION_RECONNECT` |  | Security 4778 (4779 = disconnect); TerminalServices-LocalSessionManager 25 |
| **1805** | user_session | `unlock` | 18 | 48 | car | `GSCAR_USER_SESSION_UNLOCK` |  |  |
| **1850** | user_session | `create` | 18 | 16 | superset | `GSCAR_USER_SESSION_CREATE` |  |  |
| **1851** | user_session | `metadata` | 18 | 55 | superset | `GSCAR_USER_SESSION_METADATA` |  | Security 4672 |
| **1852** | user_session | `terminate` | 18 | 44 | superset | `GSCAR_USER_SESSION_TERMINATE` |  |  |
| **1901** | authentication | `success` | 19 | 42 | car | `GSCAR_AUTHENTICATION_SUCCESS` |  | Security 4624; Security 4648 ‡; Security 4768 (Kerberos TGT); Security 4769 (Kerberos TGS) ‡; Security 4776 (NTLM) |
| **1902** | authentication | `failure` | 19 | 21 | car | `GSCAR_AUTHENTICATION_FAILURE` |  | Security 4625 |
| **1903** | authentication | `error` | 19 | 20 | car | `GSCAR_AUTHENTICATION_ERROR` |  |  |
| **2001** | socket | `bind` | 20 | 13 | car | `GSCAR_SOCKET_BIND` |  |  |
| **2002** | socket | `listen` | 20 | 24 | car | `GSCAR_SOCKET_LISTEN` |  |  |
| **2003** | socket | `close` | 20 | 15 | car | `GSCAR_SOCKET_CLOSE` |  |  |
| **2101** | http | `get` | 21 | 22 | car | `GSCAR_HTTP_GET` |  | BITS-Client 59/60 |
| **2102** | http | `post` | 21 | 32 | car | `GSCAR_HTTP_POST` |  |  |
| **2103** | http | `put` | 21 | 33 | car | `GSCAR_HTTP_PUT` |  |  |
| **2104** | http | `tunnel` | 21 | 46 | car | `GSCAR_HTTP_TUNNEL` |  |  |
| **2201** | email | `deliver` | 22 | 18 | car | `GSCAR_EMAIL_DELIVER` |  |  |
| **2202** | email | `block` | 22 | 14 | car | `GSCAR_EMAIL_BLOCK` |  |  |
| **2203** | email | `redirect` | 22 | 37 | car | `GSCAR_EMAIL_REDIRECT` |  |  |
| **2204** | email | `quarantine` | 22 | 34 | car | `GSCAR_EMAIL_QUARANTINE` |  |  |
| **2205** | email | `delete` | 22 | 17 | car | `GSCAR_EMAIL_DELETE` |  |  |

## 5. Envelope — the first fields of every template

Sensor-level fields, not CAR properties. Numbered as template data items (`%n` in message strings).

| # | Field | ETW type | Description |
|---:|---|---|---|
| 1 | `UtcTime` | `win:FILETIME` | The instant the underlying activity was observed, UTC — the source telemetry's own timestamp (ETW stamps TimeCreated separately when the event is logged). |
| 2 | `Host` | `win:UnicodeString` | Host identity of the observing machine — the FQDN when domain-joined, else the computer name. Present even on objects whose CAR property set has no fqdn/hostname. |
| 3 | `SourceProvider` | `win:UnicodeString` | Which live telemetry supplied this record (provider and event id). Lets a consumer judge how each field was populated; never inferred. |

## 6. Templates — one per object, the complete CAR property set

Field names, descriptions and examples are verbatim from the pinned CAR data model. The ETW type is this project's decision (`model/templates.yaml`): `win:UnicodeString` unless the *Basis* column says otherwise.

### 6.1 `process` — Task 10, EventIDs 1001, 1002, 1003, 1050, 1051, 1052

A process is a running program on a computer.

Source: `model/sources/car/data_model/process.yaml` · template `GSCAR_T_PROCESS` (32 data items incl. envelope) · keyword `0x0000000000000001` (`GSCAR_KW_PROCESS`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1001** | `create` | 16 | car | The event corresponding to a process creation in Windows. In the kernel, these are often captured with the callback [PsSetCreateProcessNotifyRoutine](https://msdn.microsoft.com/en-us/library/windows/hardware/ff559951%28v=vs.85%29.aspx). |
| **1002** | `terminate` | 44 | car | The event corresponding to a process destruction in Windows. In the kernel, these are also captured with the callback [PsSetCreateProcessNotifyRoutine](https://msdn.microsoft.com/en-us/library/windows/hardware/ff559951%28v=vs.85%29.aspx), but with a pointer to a NULL structure. |
| **1003** | `access` | 10 | car | The vent corresponding to a process accessing the memory space of another process. |
| **1050** | `execute` | 53 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1051** | `metadata` | 55 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1052** | `modify` | 30 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name of the host in which the process ran. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 5 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 6 | `command_line` | `win:UnicodeString` |  | The command line string contains all arguments passed to the process upon execution. | example.exe arg1 arg2 |
| 7 | `exe` | `win:UnicodeString` |  | The basename of the `image_path`. | example.exe |
| 8 | `image_path` | `win:UnicodeString` |  | The file path of the executable associated with this process. This may act as a pivot to [file:file_path](https://car.mitre.org/wiki/Data_Model/file#file_path). | C:\path\to\example.exe |
| 9 | `md5_hash` | `win:UnicodeString` |  | The MD5 hash of the contents of the file located at `image_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 10 | `sha1_hash` | `win:UnicodeString` |  | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 11 | `sha256_hash` | `win:UnicodeString` |  | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 12 | `parent_exe` | `win:UnicodeString` |  | The `exe` field of the parent process. This is a substring of `parent_image_path`. | example_parent.exe |
| 13 | `parent_image_path` | `win:UnicodeString` |  | The `image_path` field of the parent process. | C:\path\to\example_parent.exe |
| 14 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID for the process, represented in decimal notation. | 738 |
| 15 | `ppid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID for the process's parent, represented in decimal notation. In the parent process, this will be the `pid` field. | 1860 |
| 16 | `sid` | `win:UnicodeString` |  | The Windows security identifier of the `user` token that the process is running under. | S-1-5-18 |
| 17 | `signer` | `win:UnicodeString` |  | The name of the company that signed the file. | FooCorp |
| 18 | `user` | `win:UnicodeString` |  | The user token that process was created with. May be a local, domain or SYSTEM user. Formatted with "&lt;DOMAIN&gt;\&lt;USER&gt;". Individual threads in the process may gain more privilege or change tokens, so the active token in any thread is not necessarily the one the process was created under. | HOST1\LOCALUSER |
| 19 | `integrity_level` | `win:UnicodeString` |  | The Windows integrity level associated with the process. MUST be one of low, medium, high, or system. | High |
| 20 | `parent_command_line` | `win:UnicodeString` |  | All of the arguments passed to the parent process upon execution. | c:\windows\system32\dism.exe foo.xml |
| 21 | `current_working_directory` | `win:UnicodeString` |  | The absolute path to the current working directory of the process. | c:\temp |
| 22 | `env_vars` | `win:UnicodeString` |  | The environment variables within a process's memory space, as a string. | SHELL=/bin/zsh |
| 23 | `access_level` | `win:UInt32` → `win:HexInt32` | an access mask (CAR example 0x40) | Permissions level at which the target process is accessed. | 64 |
| 24 | `call_trace` | `win:UnicodeString` |  | Stack trace showing context of process open/access call. |  |
| 25 | `guid` | `win:GUID` | a GUID identifier (CAR example '{f81d4fae-…}'); minted by the sensor Sysmon-style when the source telemetry has none | Global unique identifier for the initiating process. | {f81d4fae-7dec-11d0-a765-00a0c91e6bf6} |
| 26 | `parent_guid` | `win:GUID` | a GUID identifier (CAR example '{f81d4fae-…}'); minted by the sensor Sysmon-style when the source telemetry has none | Global unique identifier of the parent of the initiating process. | {f81d4fae-7dec-11d0-a765-00a0c91e6bf6} |
| 27 | `signature_valid` | `win:Boolean` | a boolean indicator | Boolean indicator of whether signature is current and not revoked. | True |
| 28 | `target_guid` | `win:GUID` | a GUID identifier (CAR example '{f81d4fae-…}'); minted by the sensor Sysmon-style when the source telemetry has none | Global Unique Identifier for the target process (only for process access events). |  |
| 29 | `target_pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | ID of the target process (only for process access events). |  |
| 30 | `target_address` | `win:UnicodeString` |  | Specific address range which is accessed by another process. | 08048000-0804c000 |
| 31 | `target_name` | `win:UnicodeString` |  | Name of the process that is accessed. | C:\Windows\System32\winlogon.exe |
| 32 | `uid` | `win:UnicodeString` |  | User ID under which original process is running. | 509 |

### 6.2 `file` — Task 11, EventIDs 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1150, 1151, 1152

A resource for storing information available to a computer program.

Source: `model/sources/car/data_model/file.yaml` · template `GSCAR_T_FILE` (29 data items incl. envelope) · keyword `0x0000000000000002` (`GSCAR_KW_FILE`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1101** | `create` | 16 | car | The event corresponding to the creation of a file. |
| **1102** | `delete` | 17 | car | The event corresponding to the deletion of a file. |
| **1103** | `modify` | 30 | car | The event corresponding to the modification of a file or its metadata. |
| **1104** | `timestomp` | 45 | car | The modification of an attribute, such as creation time. The file metadata may change, but the contents of the file remain the same. |
| **1105** | `read` | 35 | car | The event corresponding to the accessing of a file to be read. |
| **1106** | `write` | 50 | car | The event corresponding to the accessing of a file in order to write new instructions or information into a file. |
| **1107** | `acl_modify` | 11 | car | The event corresponding with changing permissions on a file. |
| **1150** | `access` | 10 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1151** | `content` | 51 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1152** | `metadata` | 55 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `creation_time` | `win:FILETIME` | an absolute UTC timestamp; rendered as dateTime | The creation time of the file as described in UTC and including the date. | 05/14/2015 12:47:06 |
| 5 | `file_name` | `win:UnicodeString` |  | The name of the file. | MyWordDoc.docx |
| 6 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 7 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 8 | `image_path` | `win:UnicodeString` |  | The file system location of the executable that is associated with the pid that generated this event. | C:\Windows\system32\notepad.exe |
| 9 | `md5_hash` | `win:UnicodeString` |  | An MD5 hash of the contents of the file located at `image_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 10 | `sha1_hash` | `win:UnicodeString` |  | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 11 | `sha256_hash` | `win:UnicodeString` |  | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 12 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID for the process that generated this file event, represented in decimal notation. | 738 |
| 13 | `ppid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID of the parent process of the process associated with this file event, represented in decimal notation. | 1860 |
| 14 | `previous_creation_time` | `win:FILETIME` | an absolute UTC timestamp; rendered as dateTime | The creation_time associated with the file before it was changed for this file event. | 05/14/2015 12:47:06 |
| 15 | `signer` | `win:UnicodeString` |  | The company listed on the certificate of the program at `image_path` if that program is signed. | Microsoft Corporation |
| 16 | `user` | `win:UnicodeString` |  | The user context in which the thread that caused this event was running. May be a local, domain or SYSTEM user. Formatted as &lt;DOMAIN&gt;\&lt;USER&gt;. Because threads are allowed to impersonate users, this may be different than the user context of the process. | HOST1\LOCALUSER |
| 17 | `company` | `win:UnicodeString` |  | The name of the organization listed in the file located at `image_path`. |  |
| 18 | `file_path` | `win:UnicodeString` |  | The full path to the file on the file system. | C:\users\fakeuser\documents\MyFile. |
| 19 | `owner_uid` | `win:UnicodeString` |  | The user ID of the owner of the file. | 501 |
| 20 | `owner` | `win:UnicodeString` |  | The username of the owner of the file. | adam |
| 21 | `content` | `win:UnicodeString` |  | The contents of the file. | Hello World |
| 22 | `extension` | `win:UnicodeString` |  | The file extension of the file. | .docx |
| 23 | `gid` | `win:UnicodeString` |  | The group ID of the file. | 801 |
| 24 | `group` | `win:UnicodeString` |  | The group owner of the file. | admin |
| 25 | `link_target` | `win:UnicodeString` |  | The target path of a symbolic link. | C:\my_special_file.exe |
| 26 | `mime_type` | `win:UnicodeString` |  | The MIME type of the file. | PE |
| 27 | `mode` | `win:UnicodeString` |  | The mode or permissions set of the file. | 0644 (linux) or NTFS ACL |
| 28 | `signature_valid` | `win:Boolean` | a boolean indicator | Boolean indicator of whether the signature is valid; empty if file is not signed. | True |
| 29 | `uid` | `win:UnicodeString` |  | The user ID or SID for the acting entity. | S-1-5-18 |

### 6.3 `flow` — Task 12, EventIDs 1201, 1202, 1203, 1250, 1251, 1252

A sequence of packets from a source computer to a destination, which may be another host, a multicast group, or a broadcast domain. This may be captured at network or host level.

Source: `model/sources/car/data_model/flow.yaml` · template `GSCAR_T_FLOW` (30 data items incl. envelope) · keyword `0x0000000000000004` (`GSCAR_KW_FLOW`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1201** | `start` | 40 | car | The event corresponding to the beginning of collection of flow data in a given time period. |
| **1202** | `end` | 19 | car | The event corresponding to the ending of collection of flow data in a given time period. |
| **1203** | `message` | 29 | car | A flow message pertains to any event between start and end when content is sent over the connection (may imply TCP). This often implies use of traffic content collected via PCAP or a similar mechanism. |
| **1250** | `content` | 51 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1251** | `create` | 16 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1252** | `flow` | 54 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 5 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 6 | `content` | `win:UnicodeString` |  | The ASCII printable characters of the flow. This corresponds to content from PCAP data or similar formats. | GET https://www.google.com/ HTTP/1.1 |
| 7 | `dest_ip` | `win:UnicodeString` |  | The destination IP address of the flow. | 192.168.1.5 |
| 8 | `dest_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | The destination port of the flow. | 192.168.1.5 |
| 9 | `src_ip` | `win:UnicodeString` |  | The source IP address of the flow. | 10.0.0.54 |
| 10 | `src_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | The source port of the flow. | 50438 |
| 11 | `start_time` | `win:FILETIME` | an absolute UTC timestamp; rendered as dateTime | The starting time date stamp, in UTC, of the flow data. | 05/14/2015 11:59:59 PM |
| 12 | `end_time` | `win:FILETIME` | an absolute UTC timestamp; rendered as dateTime | The datetime stamp, in UTC, when the flow ended. | 05/15/2015 03:59:53.176 AM |
| 13 | `exe` | `win:UnicodeString` |  | The basename of the `image_path`. This will need to be collected from the host. | Chrome.exe |
| 14 | `image_path` | `win:UnicodeString` |  | The file system path of the process that opened the flow. This will need to be collected from the host. | C:\path\to\example.exe |
| 15 | `packet_count` | `win:UInt64` | a packet count | The total packet count seen at time of logging. | 4 |
| 16 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The total packet count seen at time of logging. | 738 |
| 17 | `ppid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID for the process’s parent that owns the socket responsible for the flow, represented in decimal notation. This will need to be collected from the host. | 1860 |
| 18 | `proto_info` | `win:UnicodeString` |  | A text decoded version of traffic in the flow specific to the protocol. The application layer information from the flow parsed according to the protocol in question. For instance, SMB information or HTTP headers and content. | SMB2 Write Request Len:165 Off:0 Fileusername\private\filename.pptx, SRVSVC NetShareGetInfo response |
| 19 | `user` | `win:UnicodeString` |  | The user that ran the process. | HOST1\LOCALUSER |
| 20 | `src_fqdn` | `win:UnicodeString` |  | The fully qualified domain name that corresponds to `src_ip`. | src_domain.example.com |
| 21 | `src_hostname` | `win:UnicodeString` |  | The hostname that corresponds to `src_ip`. | src_example |
| 22 | `dest_fqdn` | `win:UnicodeString` |  | The fully qualified domain name that corresponds to `dest_ip`. | dest_example.example.com |
| 23 | `dest_hostname` | `win:UnicodeString` |  | The hostname that corresponds to `dest_ip`. | dest_example |
| 24 | `application_protocol` | `win:UnicodeString` |  | Name of the layer 7 protocol contained within the flow. | HTTP |
| 25 | `in_bytes` | `win:UInt64` | a byte count | Integer value of total number of bytes received. | 13200 |
| 26 | `out_bytes` | `win:UInt64` | a byte count | Integer value of total number of bytes sent. | 1337 |
| 27 | `network_direction` | `win:UnicodeString` |  | Direction of the original of the flow initiator, relative to network perimiter. | in (flow originated outside the network and was directed into it) |
| 28 | `tcp_flags` | `win:UnicodeString` |  | flags turned on in the TCP header. | ACK, PSH |
| 29 | `transport_protocol` | `win:UnicodeString` |  | Layer 4 protocol contained within the flow. | TCP |
| 30 | `uid` | `win:UnicodeString` |  | User ID or SID of the flow-handling entity. | S-1-5-18 |

### 6.4 `registry` — Task 13, EventIDs 1301, 1302, 1303, 1304, 1350, 1351, 1352, 1353

The registry is a system-defined database in which applications and system components store and retrieve configuration data. The data stored in the registry varies according to the version of Microsoft Windows. Applications use the registry API to retrieve, modify, or delete registry data.

Source: `model/sources/car/data_model/registry.yaml` · template `GSCAR_T_REGISTRY` (14 data items incl. envelope) · keyword `0x0000000000000008` (`GSCAR_KW_REGISTRY`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1301** | `add` | 12 | car | The event corresponding to the act of adding a registry key, hive, type, or value. |
| **1302** | `remove` | 39 | car | The event corresponding to the act of deleting an existing registry key, hive, type, or value. |
| **1303** | `value_edit` | 49 | car | The event corresponding to the act of editing the content of an existing registry value. |
| **1304** | `key_edit` | 23 | car | The event corresponding to the act of editing the name of an existing registry key. |
| **1350** | `access` | 10 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1351** | `create` | 16 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1352** | `delete` | 17 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1353** | `modify` | 30 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name for the host on which the registry access took place. | HOST1.EXAMPLE_DOMAIN.COM |
| 5 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 6 | `key` | `win:UnicodeString` |  | The registry key of the event. Similar to a folder in a traditional file system. | HKLM\SYSTEM\CurrentControlSet\services\RpcSs |
| 7 | `value` | `win:UnicodeString` |  | The descriptive name for the data being stored. | InstalledVersion |
| 8 | `data` | `win:UnicodeString` |  | The content of `value`, typically a text string. | \%SystemRoot%\system32\svchost.exe -k rpcss |
| 9 | `type` | `win:UnicodeString` |  | The type of data being stored in `value`. Types include binary data, 32 bit numbers, strings, etc. | REG_BINARY |
| 10 | `hive` | `win:UnicodeString` |  | The logical group of keys, subkeys, and values in the registry. | HKEY_CURRENT_USER |
| 11 | `image_path` | `win:UnicodeString` |  | Inherited from the [process](https://car.mitre.org/data_model/process) that made the registry access. | C:\path\to\example.exe |
| 12 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | Inherited from the [process](https://car.mitre.org/data_model/process) that made the registry access. | 738 |
| 13 | `user` | `win:UnicodeString` |  | The user in the context of the process that performed the action on the registry key. | HOST1\LOCALUSER |
| 14 | `new_content` | `win:UnicodeString` |  | The data within the new value, or the new name of a key, after an edit event. | \%SystemRoot%\system32\svchost.exe, HKLM\SYSTEM\CurrentControlSet\services\RpcSs |

### 6.5 `module` — Task 14, EventIDs 1401, 1402, 1450, 1451

Modules correspond to executable (and potentially non-executable) content, and are loaded as a contiguous region of memory into the address space of a process. Each process will have the main image loaded as a module and shared libraries (DLLs in Windows) and their dependencies.

Source: `model/sources/car/data_model/module.yaml` · template `GSCAR_T_MODULE` (16 data items incl. envelope) · keyword `0x0000000000000010` (`GSCAR_KW_MODULE`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1401** | `load` | 25 | car | A module load event occurs when a PE image (dll or exe) is loaded into a process. |
| **1402** | `unload` | 47 | car | When the module is unloaded from memory, upon destruction of the process or by calling an API such as FreeLibrary, the unload event is triggered. |
| **1450** | `content` | 51 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1451** | `metadata` | 55 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 5 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 6 | `base_address` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | A hex address indicating where the module is loaded into the process’s virtual address space. | 18446735277684027392 |
| 7 | `image_path` | `win:UnicodeString` |  | The file system location of the process image. | C:\path\to\example.exe |
| 8 | `md5_hash` | `win:UnicodeString` |  | The MD5 hash of the contents of the file located at `module_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 9 | `sha1_hash` | `win:UnicodeString` |  | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 10 | `sha256_hash` | `win:UnicodeString` |  | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 11 | `module_path` | `win:UnicodeString` |  | The full file system path to the module loaded into the memory space of the process. | C:\windows\system32\kernel32.exe |
| 12 | `module_name` | `win:UnicodeString` |  | The name of the file where the module is loaded on disk. This is also the string that is used internally by the program to lookup information about the module. | kernel32.exe |
| 13 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | Process ID of the process in which the module is loaded (or unloaded). | 738 |
| 14 | `signer` | `win:UnicodeString` |  | The name of the organization which signed the module. | Microsoft Corporation |
| 15 | `tid` | `win:UInt32` → `win:TID` | a thread id | The thread ID of the thread responsible for the load or unload event. | 50 |
| 16 | `signature_valid` | `win:Boolean` | a boolean indicator | Boolean indicator of whether the signature is current and not revoked | True |

### 6.6 `thread` — Task 15, EventIDs 1501, 1502, 1503, 1504

A thread of execution is the smallest sequence of programmed instructions that can be managed independently by a scheduler, which is typically part of the operating system. A thread is typically a component of a process. Multiple threads can exist within the same process and share resources such as memory, while different processes do not share these resources. The threads of a process share executable code instructions and context, such as the values of variables at any given moment.

Source: `model/sources/car/data_model/thread.yaml` · template `GSCAR_T_THREAD` (18 data items incl. envelope) · keyword `0x0000000000000020` (`GSCAR_KW_THREAD`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1501** | `remote_create` | 38 | car | A subset of thread create events that correspond to thread injection, that is, when a process creates a thread in another process. For a remote_create event the src_pid and tgt_pid are different. |
| **1502** | `create` | 16 | car | The event corresponding to the act of creating a new thread. |
| **1503** | `suspend` | 43 | car | The event corresponding to the act of suspending a thread which is currently running. |
| **1504** | `terminate` | 44 | car | The event corresponding to the act of terminating a running thread. |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `hostname` | `win:UnicodeString` |  | The hostname of the active host, without the domain. | HOST1 |
| 5 | `src_pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID of the process that created the thread. | 6016 |
| 6 | `src_tid` | `win:UInt32` → `win:TID` | a thread id | The thread ID of the thread that created the event. | 9012 |
| 7 | `tgt_pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID of the process in which the new thread runs. | 232 |
| 8 | `tgt_tid` | `win:UInt32` → `win:TID` | a thread id | The thread ID of the new thread that was created. | 6964 |
| 9 | `stack_base` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | The base address of the thread's stack. | 18446735827508301824 |
| 10 | `stack_limit` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | The limit of the thread's stack. | 18446735827508277248 |
| 11 | `start_address` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | The memory address at which the thread's execution starts. | 18446735827446645728 |
| 12 | `user` | `win:UnicodeString` |  | The user context in which the source thread was running. May be a local, domain or SYSTEM user. Formatted as &lt;DOMAIN&gt;\&lt;USER&gt;. Because threads are allowed to impersonate users, this may be different than the user context of the process. | HOST1\LOCALUSER |
| 13 | `user_stack_base` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | The base address of the thread's stack. | 0 |
| 14 | `user_stack_limit` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | The limit of the thread's stack. | 0 |
| 15 | `start_function` | `win:UnicodeString` |  | The function at `start_address`. | LoadLibrary |
| 16 | `start_module` | `win:UnicodeString` |  | The module in which `start_address` resides. | C:\windows\system32\ntdll.dll |
| 17 | `start_module_name` | `win:UnicodeString` |  | The short name of the `start_module`. | ntdll.dll |
| 18 | `uid` | `win:UnicodeString` |  | The ID of SID of the user who directly or indirectly acted on the thread | S-1-5-18 |

### 6.7 `driver` — Task 16, EventIDs 1601, 1602, 1650

A driver is software that runs in the operating system kernel. Drivers are generally used to allow a computer to communicate with hardware devices but have access to important kernel resources.

Source: `model/sources/car/data_model/driver.yaml` · template `GSCAR_T_DRIVER` (14 data items incl. envelope) · keyword `0x0000000000000040` (`GSCAR_KW_DRIVER`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1601** | `load` | 25 | car | The event corresponding to the operating system kernel loading a driver into memory. |
| **1602** | `unload` | 47 | car | The event corresponding to the operating system kernel unloading a driver from memory. |
| **1650** | `metadata` | 55 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name of the host in which the process ran. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 5 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 6 | `base_address` | `win:UInt64` → `win:HexInt64` | a virtual address (CAR examples are 0x-prefixed hex); 64-bit regardless of process bitness | A hex address indicating where the driver is loaded into the kernel. | 18446735277684027392 |
| 7 | `image_path` | `win:UnicodeString` |  | The file system location of the driver. | C:\Windows\System32\drivers\scsiport.sys |
| 8 | `md5_hash` | `win:UnicodeString` |  | The MD5 hash of the contents of the file located at `image_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 9 | `sha1_hash` | `win:UnicodeString` |  | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 10 | `sha256_hash` | `win:UnicodeString` |  | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 11 | `module_name` | `win:UnicodeString` |  | The name of the driver or program. | NvStreamKms.sys |
| 12 | `signer` | `win:UnicodeString` |  | The name of the organization which signed the driver. | Microsoft Corporation |
| 13 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The Process ID that loaded or unloaded the driver | 1533 |
| 14 | `signature_valid` | `win:Boolean` | a boolean indicator | Boolean indicator of whether the driver is signed and whether the signature is current and not revoked | True |

### 6.8 `service` — Task 17, EventIDs 1701, 1702, 1703, 1704, 1705, 1750, 1751, 1752, 1753

Services, or a service application, can be started automatically at system boot, by a user through the services control panel applet, or by an application that uses service functions. Services can execute even when no user is logged into the system.

Source: `model/sources/car/data_model/service.yaml` · template `GSCAR_T_SERVICE` (13 data items incl. envelope) · keyword `0x0000000000000080` (`GSCAR_KW_SERVICE`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1701** | `create` | 16 | car | The event corresponding to the act of creating a new service. |
| **1702** | `delete` | 17 | car | The event corresponding to the act of deleting a service. |
| **1703** | `pause` | 31 | car | The event corresponding to the act of pausing a currently running service. |
| **1704** | `start` | 40 | car | The event corresponding to the act of starting a new service. |
| **1705** | `stop` | 41 | car | The event corresponding to the act of stopping a service that is currently running. |
| **1750** | `access` | 10 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1751** | `enumerate` | 52 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1752** | `metadata` | 55 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1753** | `modify` | 30 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 5 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 6 | `user` | `win:UnicodeString` |  | The user token that service was created with. | HOST1\LOCALUSER |
| 7 | `command_line` | `win:UnicodeString` |  | The command line that service is started with. | C:\windows\system32\svchost.exe -k rpcss |
| 8 | `exe` | `win:UnicodeString` |  | The executable for the service. | svchost.exe |
| 9 | `image_path` | `win:UnicodeString` |  | Where in the file system the service executable is located. | C:\path\to\example.exe |
| 10 | `name` | `win:UnicodeString` |  | The name of the service. | RpcSs |
| 11 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID for the process of the service, represented in decimal notation. | 718 |
| 12 | `ppid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | The process ID of the process’s parent or the service, represented in decimal notation. In the parent process, this will be the pid field. | 1860 |
| 13 | `uid` | `win:UnicodeString` |  | The ID of SID of the user who acted on the service | S-1-5-18 |

### 6.9 `user_session` — Task 18, EventIDs 1801, 1802, 1803, 1804, 1805, 1850, 1851, 1852

User sessions are the user activities undertaken on the computer in the course of conducting standard user actions.

Source: `model/sources/car/data_model/user_session.yaml` · template `GSCAR_T_USER_SESSION` (13 data items incl. envelope) · keyword `0x0000000000000100` (`GSCAR_KW_USER_SESSION`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1801** | `lock` | 26 | car | The event corresponding to the act of a user locking a machine such that they are still logged into the machine but unable to access it without re-entering credentials, effectively entering the machine into a locked state. |
| **1802** | `login` | 27 | car | The event corresponding to the act of a user logging into a machine. |
| **1803** | `logout` | 28 | car | The event corresponding to the act of a user logging out of a machine. |
| **1804** | `reconnect` | 36 | car | The event corresponding to the act of a user reconnecting when an RDP session disconnects but the user is not logged off. |
| **1805** | `unlock` | 48 | car | The event corresponding to the act of a user unlocking a machine currently in a locked state. |
| **1850** | `create` | 16 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1851** | `metadata` | 55 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |
| **1852** | `terminate` | 44 | superset | ATT&CK data-component action added by car-vocab; the pinned CAR submodule does not define it for this object |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `dest_ip` | `win:UnicodeString` |  | The destination IP address of the user session. Only applicable to remote or RDP sessions. | 192.168.1.5 |
| 5 | `dest_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | The destination port of the user session. Only applicable to remote or RDP sessions. | 1900 |
| 6 | `hostname` | `win:UnicodeString` |  | The hostname of the host, without the domain. | HOST1 |
| 7 | `login_id` | `win:UInt64` → `win:HexInt64` | a logon id — a 64-bit LUID (CAR example 0xf61f3) | A hex value corresponding to the session. The logon id will persist until logout occurs. | 1008115 |
| 8 | `src_ip` | `win:UnicodeString` |  | The source IP address of the user session. Only applicable to remote or RDP sessions. | 10.0.0.54 |
| 9 | `src_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | The source port of the user session. Only applicable to remote or RDP sessions. | 50438 |
| 10 | `user` | `win:UnicodeString` |  | The user affiliated with the session. May be a local, domain or SYSTEM user. | HOST1\LOCALUSER |
| 11 | `login_type` | `win:UnicodeString` |  | The type of login that was accomplished or attempted | interactive,local,rdp,remote |
| 12 | `uid` | `win:UnicodeString` |  | ID or SID of the user for which a session event ocurred | S-1-5-18 |
| 13 | `login_successful` | `win:Boolean` | a boolean indicator | Boolean indicator of whether a login attempt was successful | False |

### 6.10 `authentication` — Task 19, EventIDs 1901, 1902, 1903

An authentication event occurs whenever a user or process attempts to access a privileged system resource. Examples include logging into a system, or elevating privilege.

Source: `model/sources/car/data_model/authentication.yaml` · template `GSCAR_T_AUTHENTICATION` (22 data items incl. envelope) · keyword `0x0000000000000200` (`GSCAR_KW_AUTHENTICATION`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **1901** | `success` | 42 | car | The event corresponding to an authentication service responding positively to an authentication request. |
| **1902** | `failure` | 21 | car | The event corresponding to an authentication service responding negatively to an authentication request. |
| **1903** | `error` | 20 | car | The event corresponding to the case when an authentication request results in any kind of unexpected error. |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `app_name` | `win:UnicodeString` |  | Name of the application that made the authentication request | ssh, win:local |
| 5 | `method` | `win:UnicodeString` |  | The authentication method that was used. | SMAL, Kerberos |
| 6 | `auth_service` | `win:UnicodeString` |  | The name of the service that was utilized to accomplish authentication | Okta, ActiveDirectory |
| 7 | `auth_target` | `win:UnicodeString` |  | machine for which authentication was requested; may be different than the host that the request is made from. | HOST2 |
| 8 | `target_ad_domain` | `win:UnicodeString` |  | The Active Directory domain within which authentication was requested. | ad.mitre.org |
| 9 | `decision_reason` | `win:UnicodeString` |  | The justification for approving or denying an authentication request. | password is invalid |
| 10 | `response_time` | `win:UInt32` | a duration in milliseconds (CAR example '12ms') | Duration of time it took for an authentication response to be received. | 12ms |
| 11 | `fqdn` | `win:UnicodeString` |  | The fully qualified domain name for the host from which authentication was requested. | HOST1.mitre.org |
| 12 | `hostname` | `win:UnicodeString` |  | Hostname of the host from which authentication was requested. | HOST1 |
| 13 | `ad_domain` | `win:UnicodeString` |  | Active Directory domain from which the authentication request was generated; may differ from the target_ad_domain. | ad2.mitre.org |
| 14 | `uid` | `win:UnicodeString` |  | User ID for the process that initiated the authentication request. | S-1-5-18 |
| 15 | `user_role` | `win:UnicodeString` |  | IPAM access control role for the user that initiated the authentication request. | DNS Record Administrator Role |
| 16 | `user_type` | `win:UnicodeString` |  | type of user that initiated the request. | Administrator, Standard, Guest |
| 17 | `user` | `win:UnicodeString` |  | Name of the user that initiated the request. | HOST1\LOCALUSER1 |
| 18 | `user_agent` | `win:UnicodeString` |  | The user agent through which the request was made. | aws-cli/2.0.0 Python/3.7.4 Darwin/18.7.0 botocore/2.0.0dev4 |
| 19 | `target_uid` | `win:UnicodeString` |  | User ID for the user being authenticated. | S-1-5-19 |
| 20 | `target_user_role` | `win:UnicodeString` |  | IPAM access control role for the user being authenticated; this only pertains to privilege escalation events where the current user is not necessarily the same as the target user. | System Administrator Role |
| 21 | `target_user_type` | `win:UnicodeString` |  | type of user that was authenticated; this only pertains to privilege escalation events where the current user is not necessarily the same as the target user. | Administrator, Standard, Guest |
| 22 | `target_user` | `win:UnicodeString` |  | Name of the user being authenticated; this only pertains to privilage escalation events where the current user is not necessarily the same as the target user. | HOST1\LOCALUSER2 |

### 6.11 `socket` — Task 20, EventIDs 2001, 2002, 2003

Socket events are low-level events that may or may not result in a flow. Socket listenining events in particular can be helpful in detecting malicious activity.

Source: `model/sources/car/data_model/socket.yaml` · template `GSCAR_T_SOCKET` (13 data items incl. envelope) · keyword `0x0000000000000400` (`GSCAR_KW_SOCKET`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **2001** | `bind` | 13 | car | The event corresponding to a socket binding to a specific address |
| **2002** | `listen` | 24 | car | The event corresponding to a socket being opened into a listening status, usually on a specific local port. |
| **2003** | `close` | 15 | car | The event corresponding to a socket being closed. |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `pid` | `win:UInt32` → `win:PID` | a process id (decimal in CAR) | ID of the process that acted on the socket | 3930 |
| 5 | `image_path` | `win:UnicodeString` |  | Path to the executable that initiated the socket event. | C:/user/adam/malware.exe |
| 6 | `success` | `win:Boolean` | a boolean indicator | Boolean indicator of whether the socket event was successful (e.g. the socket was created as requested) | True |
| 7 | `family` | `win:UnicodeString` |  | The type of socket in question | AF_UNIX, AF_INET, AF_INET6 |
| 8 | `protocol` | `win:UnicodeString` |  | The type of connection that was attempted on the socket | TCP |
| 9 | `local_address` | `win:UnicodeString` |  | IP address on which the socket will accept connections; does not include the port number. | 10.0.211.200 |
| 10 | `local_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | Port number on which the socket is bound at the local end. This pertains to TCP and UDP sockets but not IP sockets. | 48777 |
| 11 | `remote_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | Port number on which the socket is bound at the remote end. | 559 |
| 12 | `remote_address` | `win:UnicodeString` |  | IP address with which the socket is communicating on the remote end. | 199.121.21.20 |
| 13 | `local_path` | `win:UnicodeString` |  | In the case that a socket is used for local interprocess communication, the socket binds to a local filepath, and will usually be visible in the filesystem. This is the case with AF_UNIX type sockets. | /tmp/foo |

### 6.12 `http` — Task 21, EventIDs 2101, 2102, 2103, 2104

HTTP events represents requests made over the network via the HTTP protocol.

Source: `model/sources/car/data_model/http.yaml` · template `GSCAR_T_HTTP` (20 data items incl. envelope) · keyword `0x0000000000000800` (`GSCAR_KW_HTTP`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **2101** | `get` | 22 | car | The event corresponding to an HTTP GET request. |
| **2102** | `post` | 32 | car | The event corresponding to an HTTP POST request. |
| **2103** | `put` | 33 | car | The event corresponding to an HTTP PUT request. |
| **2104** | `tunnel` | 46 | car | The event corresponding to an HTTP TUNNEL request. |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `hostname` | `win:UnicodeString` |  | hostname on which the request was seen. | HOST1 |
| 5 | `request_body_bytes` | `win:UInt64` | a byte count | Integer value corresponding to the total number of bytes in the request. | 180 |
| 6 | `http_version` | `win:UnicodeString` |  | HTTP version that is specified in the header. | 1.1 |
| 7 | `request_body_content` | `win:UnicodeString` |  | Body of the HTTP request; usually specifies the exact content being requested. |  |
| 8 | `request_referrer` | `win:UnicodeString` |  | The URL from which the request was referred, if applicable. | http://cnn.com |
| 9 | `requester_ip_address` | `win:UnicodeString` |  | IP address from which the request was made. | 10.0.211.200 |
| 10 | `response_body_bytes` | `win:UInt64` | a byte count | Integer value corresponding to the total number of bytes in the response. | 2910 |
| 11 | `response_body_content` | `win:UnicodeString` |  | Content of the response (does not include header). |  |
| 12 | `response_status_code` | `win:UInt16` | an HTTP status code | HTTP protocol status code in response header | 200 |
| 13 | `url_full` | `win:UnicodeString` |  | URL to which the HTTP request was sent | https://www.mitre.org/about/corporate-overview |
| 14 | `url_domain` | `win:UnicodeString` |  | Domain portion of the URL. | www.mitre.org |
| 15 | `url_remainder` | `win:UnicodeString` |  | the path after the root domain | /about/corporate-overview |
| 16 | `url_scheme` | `win:UnicodeString` |  | type of user that initiated the request. | https |
| 17 | `user_agent_full` | `win:UnicodeString` |  | User agent string associated with the request | HOST1\LOCALUSER1 |
| 18 | `user_agent_name` | `win:UnicodeString` |  | The user agent through which the request was made. | Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36 |
| 19 | `user_agent_device` | `win:UnicodeString` |  | Device type from which request was made, identified by user_agent substring | SM-G930VC (Samgsung Galaxy S7) |
| 20 | `user_agent_version` | `win:UnicodeString` |  | User Agent Version. Note that some User Agent strings may not label versions in the same way. | 4.0 |

### 6.13 `email` — Task 22, EventIDs 2201, 2202, 2203, 2204, 2205

Email events are at the mail server level.

Source: `model/sources/car/data_model/email.yaml` · template `GSCAR_T_EMAIL` (24 data items incl. envelope) · keyword `0x0000000000001000` (`GSCAR_KW_EMAIL`)

| EventID | Action | Opcode | Prov. | CAR action description |
|---:|---|---:|---|---|
| **2201** | `deliver` | 18 | car | The event corresponding to an email being sent to an end recipient. |
| **2202** | `block` | 14 | car | The event corresponding to an email being blocked by the email server. |
| **2203** | `redirect` | 37 | car | The event corresponding to an email being redirected. |
| **2204** | `quarantine` | 34 | car | The event corresponding to an email being quarantined for security reasons. |
| **2205** | `delete` | 17 | car | The event corresponding to an email being deleted. |

| # | Field | ETW type | Basis | CAR description | Example |
|---:|---|---|---|---|---|
| 4 | `action_reason` | `win:UnicodeString` |  | The rationale given for blocking, redirecting, or quarantining an email. | Malformed Message |
| 5 | `attachment_name` | `win:UnicodeString` |  | Filename of any email attachment that may exist. | cuddly-cats.pdf |
| 6 | `attachment_size` | `win:UInt64` | a byte count | Filesize of the attachment. | 567 Kb |
| 7 | `attachment_mime_type` | `win:UnicodeString` |  | The MIME type of the attachment. | .docx |
| 8 | `dest_ip` | `win:UnicodeString` |  | The destination IP address for the email. | 221.174.222.111 |
| 9 | `dest_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | The destination port for the email. | 993 |
| 10 | `dest_address` | `win:UnicodeString` |  | Recipient email address, taken from the SMTP "Recipient" field. | adam@example.com |
| 11 | `date` | `win:FILETIME` | an absolute UTC timestamp; rendered as dateTime | SMTP date header, which is actually a date time group. | Thu Jul 18 09:30:00 PDT 2019 |
| 12 | `server_relay` | `win:UnicodeString` |  | The Received portion of the SMTP header, which provides the chain of hosts that the email passed through during delivery; each link usually contains an IP address, domain, and datetime group. |  |
| 13 | `from` | `win:UnicodeString` |  | Displayed sender name from the Message Information header; can be easily forged. | eve@trusted-advisors.com |
| 14 | `smtp_uid` | `win:UnicodeString` |  | Distint ID used to distinguish emails. | MN2PR09MB4876CCE7F183A83E6BA1C4C1CBF50@PP34399.prod.outlook.com |
| 15 | `message_links` | `win:UnicodeString` |  | URLs extracted from the email body. | https://www.cnn.com |
| 16 | `src_address` | `win:UnicodeString` |  | Email address of the sender, taken from the "Sender" SMTP field. | eve@example.com |
| 17 | `src_domain` | `win:UnicodeString` |  | The domain portion of the src_address. | example.com |
| 18 | `return_address` | `win:UnicodeString` |  | Email address to which replies should be sent, also known as Return-Path or Reply-To; may differ from the src_address. | eve_secondary@example.com |
| 19 | `message_body` | `win:UnicodeString` |  | Content of the email, not including subject. | Hello World |
| 20 | `subject` | `win:UnicodeString` |  | Subject line of the email. | Lo0k Younger Whl1e L0slng We19ht!! |
| 21 | `src_ip` | `win:UnicodeString` |  | Originating IP address. | 172.183.195.200 |
| 22 | `src_port` | `win:UInt16` | a TCP/UDP port; plain unsignedShort (win:Port would expect network byte order) | Originating port. | 1248 |
| 23 | `message_type` | `win:UnicodeString` |  | Content protocol of the message body | html |
| 24 | `to` | `win:UnicodeString` |  | the content of the To field in the email header; does not necessarily match up with real recipients. | adam@example.com |

## 7. Reserved — defined by number only

| Task | Range | Keyword | Name | Why reserved |
|---:|---|---|---|---|
| 23 | 2300–2399 | `0x0000000000002000` | **group** | promoted object in `car-actions.schema.json` with actions `create`, `delete`, `enumerate`, `metadata`, `modify` but **no CAR field set** in the pinned model — no template can be derived without inventing fields |
| 24 | 2400–2499 | `0x0000000000004000` | **scheduled_job** | promoted object in `car-actions.schema.json` with actions `create`, `delete`, `metadata`, `modify` but **no CAR field set** in the pinned model — no template can be derived without inventing fields |
| 25 | 2500–2599 | `0x0000000000008000` | **user_account** | promoted object in `car-actions.schema.json` with actions `create`, `delete`, `metadata`, `modify` but **no CAR field set** in the pinned model — no template can be derived without inventing fields |
| 90 | 9000–9099 | `0x0000800000000000` | sensor | sensor self-events (not CAR): service start/stop, configuration, provider enabled/silent, event drops, PPL availability — the 'going silent is a signal' hazard (brief §7) |

## 8. What the generator enforces

- the object set is identical in the pinned CAR submodule, `car-vocab.json` and the registry;
- every (object, action) in `car-vocab` has exactly one EventID and no EventID is outside it; the recorded provenance matches the pinned submodule; `car` offsets stay in 1–49 and `superset` in 50–99; Task = EventID div 100;
- `car-actions.schema.json` agrees with `car-vocab` for the 13 CAR objects and adds exactly the registry's promoted objects;
- one Opcode per action name in 10–238, one single-bit Keyword per object in bits 0–47, all unique;
- every typed field exists in the pinned model, every rule exists, envelope names never collide with CAR fields, and no template exceeds 99 data items;
- the submodule checkout and index match `PIN.yaml`; the committed outputs match a fresh generation.
