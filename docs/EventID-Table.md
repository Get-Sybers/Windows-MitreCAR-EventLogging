# CAR Event Log — the EventID table

> **GENERATED** by `python tools/carmodel.py generate` from the pinned model — do not edit by hand; edit `model/eventids.yaml` / `model/templates.yaml` or bump a pin and regenerate. `python tools/carmodel.py check` (CI) fails on drift.
>
> Pins — MITRE CAR data model: [`1b922fe1527d`](https://github.com/Get-Sybers/car/tree/1b922fe1527d956e222a99473472e594f10f610b) (`model/sources/car`, git submodule); Byakugan (schema source): [`8e151977a05d`](https://github.com/Get-Sybers/Byakugan/tree/8e151977a05d607b87ef852617058ee23967a6e0) (`model/sources/byakugan/PIN.yaml`).

## 1. At a glance

- **13 CAR objects**, **219 properties**, **73 (object, action) events**: 50 defined by the pinned CAR submodule (`car`), 23 added by `byakugan car-vocab` from the ATT&CK data-component overlay (`superset`) — each overlay action is shown with the ATT&CK data component it derives from. The three *promoted* objects in `car-actions.schema.json` (group, scheduled_job, user_account) have no CAR field set and are **reserved**, not defined — §6.
- **An event is the CAR object (Task), the action (Opcode) and the object's complete property set** — nothing else. Observed time and host are the event's own `TimeCreated` and `Computer`, plus the CAR `fqdn`/`hostname` properties where the model has them.
- **Every property is `win:UnicodeString`** with a declared value **format** (§5): the brief requires *empty = not observed*, which only a string can express (an ETW integer, boolean or FILETIME cannot be empty, and the model itself uses the empty state — `file.signature_valid`: *empty if file is not signed*).
- **Numbering follows the pinned sources' own order** (`model/eventids.yaml` header): EventID = object base + offset, offsets 1–49 for pinned-CAR actions and 50–99 for overlay actions, both in car-vocab (alphabetical) order; **Task** = the object's ordinal; **Opcode** = the action, one value per name across all objects; **Keyword** = one bit per object. Filter by object (Task or Keyword), by action (Opcode), or slice by ID range.
- **Provider** `Get-Sybers-MitreCAR` · **channel** `Get-Sybers-MitreCAR/Operational` (type Operational) · provider GUID `5bc454ac-3ed9-4b89-b9f4-af8202af0ed8` · manifest `manifest/GetSybersMitreCar.man` → `GetSybersMitreCar.dll`.

## 2. Objects → Task, ID range, Keyword

| Task | Object | EventIDs | Keyword | Properties | Events (car + superset) | Template | ATT&CK data source | CAR description |
|---:|---|---|---|---:|---|---|---|---|
| 1 | **process** | 1000–1099 | `0x0000000000000001` | 29 | 6 (3 + 3) | `GSCAR_T_PROCESS` | Process | A process is a running program on a computer. |
| 2 | **file** | 1100–1199 | `0x0000000000000002` | 26 | 10 (7 + 3) | `GSCAR_T_FILE` | File | A resource for storing information available to a computer program. |
| 3 | **flow** | 1200–1299 | `0x0000000000000004` | 27 | 6 (3 + 3) | `GSCAR_T_FLOW` | Network Traffic | A sequence of packets from a source computer to a destination, which may be another host, a multicast group, or a broadcast domain. This may be captured at network or host level. |
| 4 | **registry** | 1300–1399 | `0x0000000000000008` | 11 | 8 (4 + 4) | `GSCAR_T_REGISTRY` | Windows Registry | The registry is a system-defined database in which applications and system components store and retrieve configuration data. The data stored in the registry varies according to the version of Microsoft Windows. Applications use the registry API to retrieve, modify, or delete registry data. |
| 5 | **module** | 1400–1499 | `0x0000000000000010` | 13 | 4 (2 + 2) | `GSCAR_T_MODULE` | Module | Modules correspond to executable (and potentially non-executable) content, and are loaded as a contiguous region of memory into the address space of a process. Each process will have the main image loaded as a module and shared libraries (DLLs in Windows) and their dependencies. |
| 6 | **thread** | 1500–1599 | `0x0000000000000020` | 15 | 4 (4 + 0) | `GSCAR_T_THREAD` | — | A thread of execution is the smallest sequence of programmed instructions that can be managed independently by a scheduler, which is typically part of the operating system. A thread is typically a component of a process. Multiple threads can exist within the same process and share resources such as memory, while different processes do not share these resources. The threads of a process share executable code instructions and context, such as the values of variables at any given moment. |
| 7 | **driver** | 1600–1699 | `0x0000000000000040` | 11 | 3 (2 + 1) | `GSCAR_T_DRIVER` | Driver | A driver is software that runs in the operating system kernel. Drivers are generally used to allow a computer to communicate with hardware devices but have access to important kernel resources. |
| 8 | **user_session** | 1700–1799 | `0x0000000000000080` | 10 | 8 (5 + 3) | `GSCAR_T_USER_SESSION` | Logon Session | User sessions are the user activities undertaken on the computer in the course of conducting standard user actions. |
| 9 | **service** | 1800–1899 | `0x0000000000000100` | 10 | 9 (5 + 4) | `GSCAR_T_SERVICE` | Service | Services, or a service application, can be started automatically at system boot, by a user through the services control panel applet, or by an application that uses service functions. Services can execute even when no user is logged into the system. |
| 10 | **authentication** | 1900–1999 | `0x0000000000000200` | 19 | 3 (3 + 0) | `GSCAR_T_AUTHENTICATION` | — | An authentication event occurs whenever a user or process attempts to access a privileged system resource. Examples include logging into a system, or elevating privilege. |
| 11 | **email** | 2000–2099 | `0x0000000000000400` | 21 | 5 (5 + 0) | `GSCAR_T_EMAIL` | — | Email events are at the mail server level. |
| 12 | **http** | 2100–2199 | `0x0000000000000800` | 17 | 4 (4 + 0) | `GSCAR_T_HTTP` | — | HTTP events represents requests made over the network via the HTTP protocol. |
| 13 | **socket** | 2200–2299 | `0x0000000000001000` | 10 | 3 (3 + 0) | `GSCAR_T_SOCKET` | — | Socket events are low-level events that may or may not result in a flow. Socket listenining events in particular can be helpful in detecting malicious activity. |

## 3. Actions → Opcode

Custom opcodes occupy 10–239 (ETW reserves 0–9). Pinned-CAR action names are alphabetical from 10; the five names only the overlay adds follow.

| Opcode | Action | Provenance | Objects |
|---:|---|---|---|
| 10 | `access` | car | process, file, registry, service |
| 11 | `acl_modify` | car | file |
| 12 | `add` | car | registry |
| 13 | `bind` | car | socket |
| 14 | `block` | car | email |
| 15 | `close` | car | socket |
| 16 | `create` | car | process, file, flow, registry, thread, user_session, service |
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
| 55 | `metadata` | superset | process, file, module, driver, user_session, service |

## 4. The EventID table

Every (object, action) pair in the pinned model, numbered. *Sensor cards* = the pinned CAR `sensors/*.yaml` that claim the pair; *Byakugan evtx bindings* = Windows events Byakugan's reviewed overlay binds to the pair (‡ = heuristic). Both columns are **coverage evidence from the pinned sources**, not this project's writer map — that map is deliverable 5. Definitions per action are in §5.

| EventID | Object | Action | Task | Opcode | Prov. | Symbol | Sensor cards | Byakugan evtx bindings |
|---:|---|---|---:|---:|---|---|---|---|
| **1001** | process | `access` | 1 | 10 | car | `GSCAR_PROCESS_ACCESS` |  | Sysmon 10; Security 4663 (PROCESS_VM_READ) |
| **1002** | process | `create` | 1 | 16 | car | `GSCAR_PROCESS_CREATE` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 1); sysmon_11.0 (Event 1); sysmon_13 (Event 1) | Sysmon 1; Security 4688 |
| **1003** | process | `terminate` | 1 | 44 | car | `GSCAR_PROCESS_TERMINATE` | sysmon_10.4 (Event 5); sysmon_11.0 (Event 5); sysmon_13 (Event 5) | Security 4689; Sysmon 5 |
| **1050** | process | `execute` | 1 | 53 | superset | `GSCAR_PROCESS_EXECUTE` |  | PowerShell 4103/4104 ‡; AppLocker EXE-and-DLL channel, allow decisions (8002) |
| **1051** | process | `metadata` | 1 | 55 | superset | `GSCAR_PROCESS_METADATA` |  |  |
| **1052** | process | `modify` | 1 | 30 | superset | `GSCAR_PROCESS_MODIFY` |  | Sysmon 25 |
| **1101** | file | `acl_modify` | 2 | 11 | car | `GSCAR_FILE_ACL_MODIFY` |  | Security 4907 |
| **1102** | file | `create` | 2 | 16 | car | `GSCAR_FILE_CREATE` | auditd_2.8; autoruns_13.98; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 11); sysmon_11.0 (Event 11); sysmon_13 (Event 11) | Sysmon 11 |
| **1103** | file | `delete` | 2 | 17 | car | `GSCAR_FILE_DELETE` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_11.0 (Event 23); sysmon_13 (Event 23) | Sysmon 23/26 |
| **1104** | file | `modify` | 2 | 30 | car | `GSCAR_FILE_MODIFY` | auditd_2.8; autoruns_13.98; osquery_4.1.2; osquery_4.6.0 | Security 1102 |
| **1105** | file | `read` | 2 | 35 | car | `GSCAR_FILE_READ` |  | Security 5145 |
| **1106** | file | `timestomp` | 2 | 45 | car | `GSCAR_FILE_TIMESTOMP` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 2); sysmon_11.0 (Event 2); sysmon_13 (Event 2) | Sysmon 2 |
| **1107** | file | `write` | 2 | 50 | car | `GSCAR_FILE_WRITE` | auditd_2.8; osquery_4.1.2; osquery_4.6.0 |  |
| **1150** | file | `access` | 2 | 10 | superset | `GSCAR_FILE_ACCESS` |  | Security 5140 |
| **1151** | file | `content` | 2 | 51 | superset | `GSCAR_FILE_CONTENT` |  |  |
| **1152** | file | `metadata` | 2 | 55 | superset | `GSCAR_FILE_METADATA` |  |  |
| **1201** | flow | `end` | 3 | 19 | car | `GSCAR_FLOW_END` | auditd_2.8; osquery_4.1.2; osquery_4.6.0 |  |
| **1202** | flow | `message` | 3 | 29 | car | `GSCAR_FLOW_MESSAGE` |  |  |
| **1203** | flow | `start` | 3 | 40 | car | `GSCAR_FLOW_START` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 3); sysmon_11.0 (Event 3); sysmon_13 (Event 3) | Sysmon 3 |
| **1250** | flow | `content` | 3 | 51 | superset | `GSCAR_FLOW_CONTENT` |  |  |
| **1251** | flow | `create` | 3 | 16 | superset | `GSCAR_FLOW_CREATE` |  |  |
| **1252** | flow | `flow` | 3 | 54 | superset | `GSCAR_FLOW_FLOW` |  |  |
| **1301** | registry | `add` | 4 | 12 | car | `GSCAR_REGISTRY_ADD` | autoruns_13.98; sysmon_10.4 (Event 12); sysmon_11.0 (Event 12); sysmon_13 (Event 12) | Sysmon 12 |
| **1302** | registry | `key_edit` | 4 | 23 | car | `GSCAR_REGISTRY_KEY_EDIT` | autoruns_13.98; sysmon_13 (Event 14) | Sysmon 14 |
| **1303** | registry | `remove` | 4 | 39 | car | `GSCAR_REGISTRY_REMOVE` | sysmon_10.4 (Event 12); sysmon_11.0 (Event 12); sysmon_13 (Event 12) |  |
| **1304** | registry | `value_edit` | 4 | 49 | car | `GSCAR_REGISTRY_VALUE_EDIT` | autoruns_13.98; sysmon_13 (Event 13) | Sysmon 13 |
| **1350** | registry | `access` | 4 | 10 | superset | `GSCAR_REGISTRY_ACCESS` |  |  |
| **1351** | registry | `create` | 4 | 16 | superset | `GSCAR_REGISTRY_CREATE` |  |  |
| **1352** | registry | `delete` | 4 | 17 | superset | `GSCAR_REGISTRY_DELETE` |  |  |
| **1353** | registry | `modify` | 4 | 30 | superset | `GSCAR_REGISTRY_MODIFY` |  |  |
| **1401** | module | `load` | 5 | 25 | car | `GSCAR_MODULE_LOAD` | sysmon_10.4 (Event 7); sysmon_11.0 (Event 7); sysmon_13 (Event 7) | Sysmon 7 |
| **1402** | module | `unload` | 5 | 47 | car | `GSCAR_MODULE_UNLOAD` |  |  |
| **1450** | module | `content` | 5 | 51 | superset | `GSCAR_MODULE_CONTENT` |  |  |
| **1451** | module | `metadata` | 5 | 55 | superset | `GSCAR_MODULE_METADATA` |  |  |
| **1501** | thread | `create` | 6 | 16 | car | `GSCAR_THREAD_CREATE` |  |  |
| **1502** | thread | `remote_create` | 6 | 38 | car | `GSCAR_THREAD_REMOTE_CREATE` | sysmon_10.4 (Event 8); sysmon_11.0 (Event 8); sysmon_13 (Event 8) | Sysmon 8 |
| **1503** | thread | `suspend` | 6 | 43 | car | `GSCAR_THREAD_SUSPEND` |  |  |
| **1504** | thread | `terminate` | 6 | 44 | car | `GSCAR_THREAD_TERMINATE` |  |  |
| **1601** | driver | `load` | 7 | 25 | car | `GSCAR_DRIVER_LOAD` | auditd_2.8; osquery_4.1.2; osquery_4.6.0; sysmon_10.4 (Event 6); sysmon_11.0 (Event 6); sysmon_13 (Event 6) | Sysmon 6 |
| **1602** | driver | `unload` | 7 | 47 | car | `GSCAR_DRIVER_UNLOAD` |  |  |
| **1650** | driver | `metadata` | 7 | 55 | superset | `GSCAR_DRIVER_METADATA` |  |  |
| **1701** | user_session | `lock` | 8 | 26 | car | `GSCAR_USER_SESSION_LOCK` |  |  |
| **1702** | user_session | `login` | 8 | 27 | car | `GSCAR_USER_SESSION_LOGIN` |  | Security 4624, interactive-class LogonType (2/7/10/11); System 7001 (Winlogon); TerminalServices-LocalSessionManager 21 (RDP) |
| **1703** | user_session | `logout` | 8 | 28 | car | `GSCAR_USER_SESSION_LOGOUT` |  | Security 4634 / 4647 |
| **1704** | user_session | `reconnect` | 8 | 36 | car | `GSCAR_USER_SESSION_RECONNECT` |  | Security 4778 (4779 = disconnect); TerminalServices-LocalSessionManager 25 |
| **1705** | user_session | `unlock` | 8 | 48 | car | `GSCAR_USER_SESSION_UNLOCK` |  |  |
| **1750** | user_session | `create` | 8 | 16 | superset | `GSCAR_USER_SESSION_CREATE` |  |  |
| **1751** | user_session | `metadata` | 8 | 55 | superset | `GSCAR_USER_SESSION_METADATA` |  | Security 4672 |
| **1752** | user_session | `terminate` | 8 | 44 | superset | `GSCAR_USER_SESSION_TERMINATE` |  |  |
| **1801** | service | `create` | 9 | 16 | car | `GSCAR_SERVICE_CREATE` | autoruns_13.98 | Security 4697; System 7045 |
| **1802** | service | `delete` | 9 | 17 | car | `GSCAR_SERVICE_DELETE` | autoruns_13.98 |  |
| **1803** | service | `pause` | 9 | 31 | car | `GSCAR_SERVICE_PAUSE` |  |  |
| **1804** | service | `start` | 9 | 40 | car | `GSCAR_SERVICE_START` |  |  |
| **1805** | service | `stop` | 9 | 41 | car | `GSCAR_SERVICE_STOP` |  | System 7034/7036 |
| **1850** | service | `access` | 9 | 10 | superset | `GSCAR_SERVICE_ACCESS` |  |  |
| **1851** | service | `enumerate` | 9 | 52 | superset | `GSCAR_SERVICE_ENUMERATE` |  |  |
| **1852** | service | `metadata` | 9 | 55 | superset | `GSCAR_SERVICE_METADATA` |  |  |
| **1853** | service | `modify` | 9 | 30 | superset | `GSCAR_SERVICE_MODIFY` |  |  |
| **1901** | authentication | `error` | 10 | 20 | car | `GSCAR_AUTHENTICATION_ERROR` |  |  |
| **1902** | authentication | `failure` | 10 | 21 | car | `GSCAR_AUTHENTICATION_FAILURE` |  | Security 4625 |
| **1903** | authentication | `success` | 10 | 42 | car | `GSCAR_AUTHENTICATION_SUCCESS` |  | Security 4624; Security 4648 ‡; Security 4768 (Kerberos TGT); Security 4769 (Kerberos TGS) ‡; Security 4776 (NTLM) |
| **2001** | email | `block` | 11 | 14 | car | `GSCAR_EMAIL_BLOCK` |  |  |
| **2002** | email | `delete` | 11 | 17 | car | `GSCAR_EMAIL_DELETE` |  |  |
| **2003** | email | `deliver` | 11 | 18 | car | `GSCAR_EMAIL_DELIVER` |  |  |
| **2004** | email | `quarantine` | 11 | 34 | car | `GSCAR_EMAIL_QUARANTINE` |  |  |
| **2005** | email | `redirect` | 11 | 37 | car | `GSCAR_EMAIL_REDIRECT` |  |  |
| **2101** | http | `get` | 12 | 22 | car | `GSCAR_HTTP_GET` |  | BITS-Client 59/60 |
| **2102** | http | `post` | 12 | 32 | car | `GSCAR_HTTP_POST` |  |  |
| **2103** | http | `put` | 12 | 33 | car | `GSCAR_HTTP_PUT` |  |  |
| **2104** | http | `tunnel` | 12 | 46 | car | `GSCAR_HTTP_TUNNEL` |  |  |
| **2201** | socket | `bind` | 13 | 13 | car | `GSCAR_SOCKET_BIND` |  |  |
| **2202** | socket | `close` | 13 | 15 | car | `GSCAR_SOCKET_CLOSE` |  |  |
| **2203** | socket | `listen` | 13 | 24 | car | `GSCAR_SOCKET_LISTEN` |  |  |

## 5. Templates — one per object, the complete CAR property set

Field names, descriptions and examples are verbatim from the pinned CAR data model. Every data item is `win:UnicodeString`; an empty string means *not observed*. The **Format** column is this project's decision (`model/templates.yaml`), fixed by the CAR description or example:

| Format | Rule | Basis |
|---|---|---|
| `text` | free text | as observed — names, paths, '&lt;DOMAIN&gt;\&lt;USER&gt;', free text; the writer truncates long text so a record stays well under the ~30 KB render limit |
| `int` | `^[0-9]+$` | a decimal integer — CAR: 'represented in decimal notation' (ids, ports, counts, byte sizes, status codes) |
| `int_ms` | `^[0-9]+$` | a duration in whole milliseconds (CAR example '12ms') |
| `hex` | `^[0-9a-f]+$` | lower-case hex digits, no prefix — CAR: hashes 'in hex notation, without the 0x prefix' |
| `hexaddr` | `^0x[0-9A-Fa-f]+$` | 0x-prefixed hex — CAR examples: addresses 0xFFFFF8000405F000, access_level 0x40, login_id 0xf61f3 |
| `utc_time` | `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$` | a UTC instant as ISO 8601 'YYYY-MM-DDTHH:MM:SS.fffZ' — CAR: 'in UTC and including the date' (the examples' locale display form is not used) |
| `bool` | `^(true|false)$` | 'true' or 'false' (CAR examples); empty when not observed — the model's own tri-state |
| `guid` | `^\{[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$` | a GUID in registry format with braces (CAR example) — written only when the source telemetry supplies one, never minted |
| `ip` | free text | an IP address as text: IPv4 dotted-quad or RFC 5952 IPv6 (brief §6: no native IP type) |

### 5.1 `process` — Task 1, EventIDs 1001, 1002, 1003, 1050, 1051, 1052

A process is a running program on a computer.

ATT&CK data source *Process*: Information about instances of computer programs that are being executed by at least one thread.

Source: `model/sources/car/data_model/process.yaml` · template `GSCAR_T_PROCESS` (29 data items) · keyword `0x0000000000000001` (`GSCAR_KW_PROCESS`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1001** | `access` | 10 | car | The vent corresponding to a process accessing the memory space of another process. *(also ATT&CK: “process access”)* |
| **1002** | `create` | 16 | car | The event corresponding to a process creation in Windows. In the kernel, these are often captured with the callback [PsSetCreateProcessNotifyRoutine](https://msdn.microsoft.com/en-us/library/windows/hardware/ff559951%28v=vs.85%29.aspx). *(also ATT&CK: “process creation”)* |
| **1003** | `terminate` | 44 | car | The event corresponding to a process destruction in Windows. In the kernel, these are also captured with the callback [PsSetCreateProcessNotifyRoutine](https://msdn.microsoft.com/en-us/library/windows/hardware/ff559951%28v=vs.85%29.aspx), but with a pointer to a NULL structure. *(also ATT&CK: “process termination”)* |
| **1050** | `execute` | 53 | superset | ATT&CK data component “OS api execution”: A process executed operating system api functions. |
| **1051** | `metadata` | 55 | superset | ATT&CK data component “process metadata”: Data and information that describe a process (Such as environment variables) and activity around it. |
| **1052** | `modify` | 30 | superset | ATT&CK data component “process modification”: A process was modified. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `fqdn` | `text` | The fully qualified domain name of the host in which the process ran. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 2 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 3 | `command_line` | `text` | The command line string contains all arguments passed to the process upon execution. | example.exe arg1 arg2 |
| 4 | `exe` | `text` | The basename of the `image_path`. | example.exe |
| 5 | `image_path` | `text` | The file path of the executable associated with this process. This may act as a pivot to [file:file_path](https://car.mitre.org/wiki/Data_Model/file#file_path). | C:\path\to\example.exe |
| 6 | `md5_hash` | `hex` | The MD5 hash of the contents of the file located at `image_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 7 | `sha1_hash` | `hex` | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 8 | `sha256_hash` | `hex` | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 9 | `parent_exe` | `text` | The `exe` field of the parent process. This is a substring of `parent_image_path`. | example_parent.exe |
| 10 | `parent_image_path` | `text` | The `image_path` field of the parent process. | C:\path\to\example_parent.exe |
| 11 | `pid` | `int` | The process ID for the process, represented in decimal notation. | 738 |
| 12 | `ppid` | `int` | The process ID for the process's parent, represented in decimal notation. In the parent process, this will be the `pid` field. | 1860 |
| 13 | `sid` | `text` | The Windows security identifier of the `user` token that the process is running under. | S-1-5-18 |
| 14 | `signer` | `text` | The name of the company that signed the file. | FooCorp |
| 15 | `user` | `text` | The user token that process was created with. May be a local, domain or SYSTEM user. Formatted with "&lt;DOMAIN&gt;\&lt;USER&gt;". Individual threads in the process may gain more privilege or change tokens, so the active token in any thread is not necessarily the one the process was created under. | HOST1\LOCALUSER |
| 16 | `integrity_level` | `text` | The Windows integrity level associated with the process. MUST be one of low, medium, high, or system. | High |
| 17 | `parent_command_line` | `text` | All of the arguments passed to the parent process upon execution. | c:\windows\system32\dism.exe foo.xml |
| 18 | `current_working_directory` | `text` | The absolute path to the current working directory of the process. | c:\temp |
| 19 | `env_vars` | `text` | The environment variables within a process's memory space, as a string. | SHELL=/bin/zsh |
| 20 | `access_level` | `hexaddr` | Permissions level at which the target process is accessed. | 64 |
| 21 | `call_trace` | `text` | Stack trace showing context of process open/access call. |  |
| 22 | `guid` | `guid` | Global unique identifier for the initiating process. | {f81d4fae-7dec-11d0-a765-00a0c91e6bf6} |
| 23 | `parent_guid` | `guid` | Global unique identifier of the parent of the initiating process. | {f81d4fae-7dec-11d0-a765-00a0c91e6bf6} |
| 24 | `signature_valid` | `bool` | Boolean indicator of whether signature is current and not revoked. | True |
| 25 | `target_guid` | `guid` | Global Unique Identifier for the target process (only for process access events). |  |
| 26 | `target_pid` | `int` | ID of the target process (only for process access events). |  |
| 27 | `target_address` | `text` | Specific address range which is accessed by another process. | 08048000-0804c000 |
| 28 | `target_name` | `text` | Name of the process that is accessed. | C:\Windows\System32\winlogon.exe |
| 29 | `uid` | `text` | User ID under which original process is running. | 509 |

### 5.2 `file` — Task 2, EventIDs 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1150, 1151, 1152

A resource for storing information available to a computer program.

ATT&CK data source *File*: Information about file objects (All file systems) that represent computer resources that can be managed by the I/O system. This data source can be used as a reference to extend the concepts of other data sources such as driver, module, and network share.

Source: `model/sources/car/data_model/file.yaml` · template `GSCAR_T_FILE` (26 data items) · keyword `0x0000000000000002` (`GSCAR_KW_FILE`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1101** | `acl_modify` | 11 | car | The event corresponding with changing permissions on a file. |
| **1102** | `create` | 16 | car | The event corresponding to the creation of a file. *(also ATT&CK: “file creation”)* |
| **1103** | `delete` | 17 | car | The event corresponding to the deletion of a file. *(also ATT&CK: “file deletion”)* |
| **1104** | `modify` | 30 | car | The event corresponding to the modification of a file or its metadata. *(also ATT&CK: “file modification”)* |
| **1105** | `read` | 35 | car | The event corresponding to the accessing of a file to be read. |
| **1106** | `timestomp` | 45 | car | The modification of an attribute, such as creation time. The file metadata may change, but the contents of the file remain the same. |
| **1107** | `write` | 50 | car | The event corresponding to the accessing of a file in order to write new instructions or information into a file. |
| **1150** | `access` | 10 | superset | ATT&CK data component “file access”: A file was opened or accessed. |
| **1151** | `content` | 51 | superset | ATT&CK data component “file content”: Data contained in a file. |
| **1152** | `metadata` | 55 | superset | ATT&CK data component “file metadata”: Data and information that describe a file and activity around it. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `creation_time` | `utc_time` | The creation time of the file as described in UTC and including the date. | 05/14/2015 12:47:06 |
| 2 | `file_name` | `text` | The name of the file. | MyWordDoc.docx |
| 3 | `fqdn` | `text` | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 4 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 5 | `image_path` | `text` | The file system location of the executable that is associated with the pid that generated this event. | C:\Windows\system32\notepad.exe |
| 6 | `md5_hash` | `hex` | An MD5 hash of the contents of the file located at `image_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 7 | `sha1_hash` | `hex` | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 8 | `sha256_hash` | `hex` | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 9 | `pid` | `int` | The process ID for the process that generated this file event, represented in decimal notation. | 738 |
| 10 | `ppid` | `int` | The process ID of the parent process of the process associated with this file event, represented in decimal notation. | 1860 |
| 11 | `previous_creation_time` | `utc_time` | The creation_time associated with the file before it was changed for this file event. | 05/14/2015 12:47:06 |
| 12 | `signer` | `text` | The company listed on the certificate of the program at `image_path` if that program is signed. | Microsoft Corporation |
| 13 | `user` | `text` | The user context in which the thread that caused this event was running. May be a local, domain or SYSTEM user. Formatted as &lt;DOMAIN&gt;\&lt;USER&gt;. Because threads are allowed to impersonate users, this may be different than the user context of the process. | HOST1\LOCALUSER |
| 14 | `company` | `text` | The name of the organization listed in the file located at `image_path`. |  |
| 15 | `file_path` | `text` | The full path to the file on the file system. | C:\users\fakeuser\documents\MyFile. |
| 16 | `owner_uid` | `text` | The user ID of the owner of the file. | 501 |
| 17 | `owner` | `text` | The username of the owner of the file. | adam |
| 18 | `content` | `text` | The contents of the file. | Hello World |
| 19 | `extension` | `text` | The file extension of the file. | .docx |
| 20 | `gid` | `text` | The group ID of the file. | 801 |
| 21 | `group` | `text` | The group owner of the file. | admin |
| 22 | `link_target` | `text` | The target path of a symbolic link. | C:\my_special_file.exe |
| 23 | `mime_type` | `text` | The MIME type of the file. | PE |
| 24 | `mode` | `text` | The mode or permissions set of the file. | 0644 (linux) or NTFS ACL |
| 25 | `signature_valid` | `bool` | Boolean indicator of whether the signature is valid; empty if file is not signed. | True |
| 26 | `uid` | `text` | The user ID or SID for the acting entity. | S-1-5-18 |

### 5.3 `flow` — Task 3, EventIDs 1201, 1202, 1203, 1250, 1251, 1252

A sequence of packets from a source computer to a destination, which may be another host, a multicast group, or a broadcast domain. This may be captured at network or host level.

ATT&CK data source *Network Traffic*: Network traffic, either summarized (e.g., as netflow) or captured in some format (e.g., as PCAP). This may be captured at the endpoint or network level.

Source: `model/sources/car/data_model/flow.yaml` · template `GSCAR_T_FLOW` (27 data items) · keyword `0x0000000000000004` (`GSCAR_KW_FLOW`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1201** | `end` | 19 | car | The event corresponding to the ending of collection of flow data in a given time period. |
| **1202** | `message` | 29 | car | A flow message pertains to any event between start and end when content is sent over the connection (may imply TCP). This often implies use of traffic content collected via PCAP or a similar mechanism. |
| **1203** | `start` | 40 | car | The event corresponding to the beginning of collection of flow data in a given time period. |
| **1250** | `content` | 51 | superset | ATT&CK data component “network traffic content”: Information about the content of network packets and the protocols associated to them, either captured on the wire or on an endpoint. |
| **1251** | `create` | 16 | superset | ATT&CK data component “network connection creation”: Information about the creation of a network connection, either captured on the wire or on an endpoint. |
| **1252** | `flow` | 54 | superset | ATT&CK data component “network traffic flow”: Information about the flow of network packets in a network connection, either captured on the wire or on an endpoint. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `fqdn` | `text` | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 2 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 3 | `content` | `text` | The ASCII printable characters of the flow. This corresponds to content from PCAP data or similar formats. | GET https://www.google.com/ HTTP/1.1 |
| 4 | `dest_ip` | `ip` | The destination IP address of the flow. | 192.168.1.5 |
| 5 | `dest_port` | `int` | The destination port of the flow. | 192.168.1.5 |
| 6 | `src_ip` | `ip` | The source IP address of the flow. | 10.0.0.54 |
| 7 | `src_port` | `int` | The source port of the flow. | 50438 |
| 8 | `start_time` | `utc_time` | The starting time date stamp, in UTC, of the flow data. | 05/14/2015 11:59:59 PM |
| 9 | `end_time` | `utc_time` | The datetime stamp, in UTC, when the flow ended. | 05/15/2015 03:59:53.176 AM |
| 10 | `exe` | `text` | The basename of the `image_path`. This will need to be collected from the host. | Chrome.exe |
| 11 | `image_path` | `text` | The file system path of the process that opened the flow. This will need to be collected from the host. | C:\path\to\example.exe |
| 12 | `packet_count` | `int` | The total packet count seen at time of logging. | 4 |
| 13 | `pid` | `int` | The total packet count seen at time of logging. | 738 |
| 14 | `ppid` | `int` | The process ID for the process’s parent that owns the socket responsible for the flow, represented in decimal notation. This will need to be collected from the host. | 1860 |
| 15 | `proto_info` | `text` | A text decoded version of traffic in the flow specific to the protocol. The application layer information from the flow parsed according to the protocol in question. For instance, SMB information or HTTP headers and content. | SMB2 Write Request Len:165 Off:0 Fileusername\private\filename.pptx, SRVSVC NetShareGetInfo response |
| 16 | `user` | `text` | The user that ran the process. | HOST1\LOCALUSER |
| 17 | `src_fqdn` | `text` | The fully qualified domain name that corresponds to `src_ip`. | src_domain.example.com |
| 18 | `src_hostname` | `text` | The hostname that corresponds to `src_ip`. | src_example |
| 19 | `dest_fqdn` | `text` | The fully qualified domain name that corresponds to `dest_ip`. | dest_example.example.com |
| 20 | `dest_hostname` | `text` | The hostname that corresponds to `dest_ip`. | dest_example |
| 21 | `application_protocol` | `text` | Name of the layer 7 protocol contained within the flow. | HTTP |
| 22 | `in_bytes` | `int` | Integer value of total number of bytes received. | 13200 |
| 23 | `out_bytes` | `int` | Integer value of total number of bytes sent. | 1337 |
| 24 | `network_direction` | `text` | Direction of the original of the flow initiator, relative to network perimiter. | in (flow originated outside the network and was directed into it) |
| 25 | `tcp_flags` | `text` | flags turned on in the TCP header. | ACK, PSH |
| 26 | `transport_protocol` | `text` | Layer 4 protocol contained within the flow. | TCP |
| 27 | `uid` | `text` | User ID or SID of the flow-handling entity. | S-1-5-18 |

### 5.4 `registry` — Task 4, EventIDs 1301, 1302, 1303, 1304, 1350, 1351, 1352, 1353

The registry is a system-defined database in which applications and system components store and retrieve configuration data. The data stored in the registry varies according to the version of Microsoft Windows. Applications use the registry API to retrieve, modify, or delete registry data.

ATT&CK data source *Windows Registry*: Information about configuration data used by applications and system components.

Source: `model/sources/car/data_model/registry.yaml` · template `GSCAR_T_REGISTRY` (11 data items) · keyword `0x0000000000000008` (`GSCAR_KW_REGISTRY`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1301** | `add` | 12 | car | The event corresponding to the act of adding a registry key, hive, type, or value. |
| **1302** | `key_edit` | 23 | car | The event corresponding to the act of editing the name of an existing registry key. |
| **1303** | `remove` | 39 | car | The event corresponding to the act of deleting an existing registry key, hive, type, or value. |
| **1304** | `value_edit` | 49 | car | The event corresponding to the act of editing the content of an existing registry value. |
| **1350** | `access` | 10 | superset | ATT&CK data component “windows registry key access”: A registry key was accessed. |
| **1351** | `create` | 16 | superset | ATT&CK data component “windows registry key creation”: A registry key was created. |
| **1352** | `delete` | 17 | superset | ATT&CK data component “windows registry key deletion”: A registry key was deleted. |
| **1353** | `modify` | 30 | superset | ATT&CK data component “windows registry key modification”: A registry key was modified. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `fqdn` | `text` | The fully qualified domain name for the host on which the registry access took place. | HOST1.EXAMPLE_DOMAIN.COM |
| 2 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 3 | `key` | `text` | The registry key of the event. Similar to a folder in a traditional file system. | HKLM\SYSTEM\CurrentControlSet\services\RpcSs |
| 4 | `value` | `text` | The descriptive name for the data being stored. | InstalledVersion |
| 5 | `data` | `text` | The content of `value`, typically a text string. | \%SystemRoot%\system32\svchost.exe -k rpcss |
| 6 | `type` | `text` | The type of data being stored in `value`. Types include binary data, 32 bit numbers, strings, etc. | REG_BINARY |
| 7 | `hive` | `text` | The logical group of keys, subkeys, and values in the registry. | HKEY_CURRENT_USER |
| 8 | `image_path` | `text` | Inherited from the [process](https://car.mitre.org/data_model/process) that made the registry access. | C:\path\to\example.exe |
| 9 | `pid` | `int` | Inherited from the [process](https://car.mitre.org/data_model/process) that made the registry access. | 738 |
| 10 | `user` | `text` | The user in the context of the process that performed the action on the registry key. | HOST1\LOCALUSER |
| 11 | `new_content` | `text` | The data within the new value, or the new name of a key, after an edit event. | \%SystemRoot%\system32\svchost.exe, HKLM\SYSTEM\CurrentControlSet\services\RpcSs |

### 5.5 `module` — Task 5, EventIDs 1401, 1402, 1450, 1451

Modules correspond to executable (and potentially non-executable) content, and are loaded as a contiguous region of memory into the address space of a process. Each process will have the main image loaded as a module and shared libraries (DLLs in Windows) and their dependencies.

ATT&CK data source *Module*: Information about module files consisting of one or more classes and interfaces, such as portable executable (PE) format executables/dynamic link libraries (DLL), executable and linkable format (ELF) executables/shared libraries, and Mach-O format executables/shared libraries.

Source: `model/sources/car/data_model/module.yaml` · template `GSCAR_T_MODULE` (13 data items) · keyword `0x0000000000000010` (`GSCAR_KW_MODULE`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1401** | `load` | 25 | car | A module load event occurs when a PE image (dll or exe) is loaded into a process. *(also ATT&CK: “module load”)* |
| **1402** | `unload` | 47 | car | When the module is unloaded from memory, upon destruction of the process or by calling an API such as FreeLibrary, the unload event is triggered. |
| **1450** | `content` | 51 | superset | ATT&CK data component “module content”: Data contained in a module such as sections and segments. |
| **1451** | `metadata` | 55 | superset | ATT&CK data component “module metadata”: Data and information that describe a module and activity around it such as header and signature. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `fqdn` | `text` | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 2 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 3 | `base_address` | `hexaddr` | A hex address indicating where the module is loaded into the process’s virtual address space. | 18446735277684027392 |
| 4 | `image_path` | `text` | The file system location of the process image. | C:\path\to\example.exe |
| 5 | `md5_hash` | `hex` | The MD5 hash of the contents of the file located at `module_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 6 | `sha1_hash` | `hex` | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 7 | `sha256_hash` | `hex` | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 8 | `module_path` | `text` | The full file system path to the module loaded into the memory space of the process. | C:\windows\system32\kernel32.exe |
| 9 | `module_name` | `text` | The name of the file where the module is loaded on disk. This is also the string that is used internally by the program to lookup information about the module. | kernel32.exe |
| 10 | `pid` | `int` | Process ID of the process in which the module is loaded (or unloaded). | 738 |
| 11 | `signer` | `text` | The name of the organization which signed the module. | Microsoft Corporation |
| 12 | `tid` | `int` | The thread ID of the thread responsible for the load or unload event. | 50 |
| 13 | `signature_valid` | `bool` | Boolean indicator of whether the signature is current and not revoked | True |

### 5.6 `thread` — Task 6, EventIDs 1501, 1502, 1503, 1504

A thread of execution is the smallest sequence of programmed instructions that can be managed independently by a scheduler, which is typically part of the operating system. A thread is typically a component of a process. Multiple threads can exist within the same process and share resources such as memory, while different processes do not share these resources. The threads of a process share executable code instructions and context, such as the values of variables at any given moment.

Source: `model/sources/car/data_model/thread.yaml` · template `GSCAR_T_THREAD` (15 data items) · keyword `0x0000000000000020` (`GSCAR_KW_THREAD`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1501** | `create` | 16 | car | The event corresponding to the act of creating a new thread. |
| **1502** | `remote_create` | 38 | car | A subset of thread create events that correspond to thread injection, that is, when a process creates a thread in another process. For a remote_create event the src_pid and tgt_pid are different. |
| **1503** | `suspend` | 43 | car | The event corresponding to the act of suspending a thread which is currently running. |
| **1504** | `terminate` | 44 | car | The event corresponding to the act of terminating a running thread. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `hostname` | `text` | The hostname of the active host, without the domain. | HOST1 |
| 2 | `src_pid` | `int` | The process ID of the process that created the thread. | 6016 |
| 3 | `src_tid` | `int` | The thread ID of the thread that created the event. | 9012 |
| 4 | `tgt_pid` | `int` | The process ID of the process in which the new thread runs. | 232 |
| 5 | `tgt_tid` | `int` | The thread ID of the new thread that was created. | 6964 |
| 6 | `stack_base` | `hexaddr` | The base address of the thread's stack. | 18446735827508301824 |
| 7 | `stack_limit` | `hexaddr` | The limit of the thread's stack. | 18446735827508277248 |
| 8 | `start_address` | `hexaddr` | The memory address at which the thread's execution starts. | 18446735827446645728 |
| 9 | `user` | `text` | The user context in which the source thread was running. May be a local, domain or SYSTEM user. Formatted as &lt;DOMAIN&gt;\&lt;USER&gt;. Because threads are allowed to impersonate users, this may be different than the user context of the process. | HOST1\LOCALUSER |
| 10 | `user_stack_base` | `hexaddr` | The base address of the thread's stack. | 0 |
| 11 | `user_stack_limit` | `hexaddr` | The limit of the thread's stack. | 0 |
| 12 | `start_function` | `text` | The function at `start_address`. | LoadLibrary |
| 13 | `start_module` | `text` | The module in which `start_address` resides. | C:\windows\system32\ntdll.dll |
| 14 | `start_module_name` | `text` | The short name of the `start_module`. | ntdll.dll |
| 15 | `uid` | `text` | The ID of SID of the user who directly or indirectly acted on the thread | S-1-5-18 |

### 5.7 `driver` — Task 7, EventIDs 1601, 1602, 1650

A driver is software that runs in the operating system kernel. Drivers are generally used to allow a computer to communicate with hardware devices but have access to important kernel resources.

ATT&CK data source *Driver*: Information associated with device drivers, or computer programs that operate or control a particular type of device that is attached to a computer.

Source: `model/sources/car/data_model/driver.yaml` · template `GSCAR_T_DRIVER` (11 data items) · keyword `0x0000000000000040` (`GSCAR_KW_DRIVER`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1601** | `load` | 25 | car | The event corresponding to the operating system kernel loading a driver into memory. *(also ATT&CK: “driver load”, “driver unload”)* |
| **1602** | `unload` | 47 | car | The event corresponding to the operating system kernel unloading a driver from memory. |
| **1650** | `metadata` | 55 | superset | ATT&CK data component “driver metadata”: Data and information that describe a driver and activity around it such as driver issues reporting and driver integrity (Page hash, code) checking. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `fqdn` | `text` | The fully qualified domain name of the host in which the process ran. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 2 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 3 | `base_address` | `hexaddr` | A hex address indicating where the driver is loaded into the kernel. | 18446735277684027392 |
| 4 | `image_path` | `text` | The file system location of the driver. | C:\Windows\System32\drivers\scsiport.sys |
| 5 | `md5_hash` | `hex` | The MD5 hash of the contents of the file located at `image_path`. The field is in hex notation, without the 0x prefix. | 5eb63bbbe01eeed093cb22bb8f5acdc3 |
| 6 | `sha1_hash` | `hex` | The SHA1 hash of the contents of the file located at `image_path`. | 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed |
| 7 | `sha256_hash` | `hex` | The SHA256 hash of the contents of the file located at `image_path`. | 68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728 |
| 8 | `module_name` | `text` | The name of the driver or program. | NvStreamKms.sys |
| 9 | `signer` | `text` | The name of the organization which signed the driver. | Microsoft Corporation |
| 10 | `pid` | `int` | The Process ID that loaded or unloaded the driver | 1533 |
| 11 | `signature_valid` | `bool` | Boolean indicator of whether the driver is signed and whether the signature is current and not revoked | True |

### 5.8 `user_session` — Task 8, EventIDs 1701, 1702, 1703, 1704, 1705, 1750, 1751, 1752

User sessions are the user activities undertaken on the computer in the course of conducting standard user actions.

ATT&CK data source *Logon Session*: Information about logon sessions being created or terminated by accounts (Local, Domain, or Cloud), interactively or over the network, in order to interact with network resources, applications, or services.

Source: `model/sources/car/data_model/user_session.yaml` · template `GSCAR_T_USER_SESSION` (10 data items) · keyword `0x0000000000000080` (`GSCAR_KW_USER_SESSION`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1701** | `lock` | 26 | car | The event corresponding to the act of a user locking a machine such that they are still logged into the machine but unable to access it without re-entering credentials, effectively entering the machine into a locked state. |
| **1702** | `login` | 27 | car | The event corresponding to the act of a user logging into a machine. |
| **1703** | `logout` | 28 | car | The event corresponding to the act of a user logging out of a machine. |
| **1704** | `reconnect` | 36 | car | The event corresponding to the act of a user reconnecting when an RDP session disconnects but the user is not logged off. |
| **1705** | `unlock` | 48 | car | The event corresponding to the act of a user unlocking a machine currently in a locked state. |
| **1750** | `create` | 16 | superset | ATT&CK data component “logon session creation”: A logon session for a user was created. |
| **1751** | `metadata` | 55 | superset | ATT&CK data component “logon session metadata”: Data and information that describe a logon session (such as logon type) and activity within it. |
| **1752** | `terminate` | 44 | superset | ATT&CK data component “logon session termination”: A logon session for a user was terminated. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `dest_ip` | `ip` | The destination IP address of the user session. Only applicable to remote or RDP sessions. | 192.168.1.5 |
| 2 | `dest_port` | `int` | The destination port of the user session. Only applicable to remote or RDP sessions. | 1900 |
| 3 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 4 | `login_id` | `hexaddr` | A hex value corresponding to the session. The logon id will persist until logout occurs. | 1008115 |
| 5 | `src_ip` | `ip` | The source IP address of the user session. Only applicable to remote or RDP sessions. | 10.0.0.54 |
| 6 | `src_port` | `int` | The source port of the user session. Only applicable to remote or RDP sessions. | 50438 |
| 7 | `user` | `text` | The user affiliated with the session. May be a local, domain or SYSTEM user. | HOST1\LOCALUSER |
| 8 | `login_type` | `text` | The type of login that was accomplished or attempted | interactive,local,rdp,remote |
| 9 | `uid` | `text` | ID or SID of the user for which a session event ocurred | S-1-5-18 |
| 10 | `login_successful` | `bool` | Boolean indicator of whether a login attempt was successful | False |

### 5.9 `service` — Task 9, EventIDs 1801, 1802, 1803, 1804, 1805, 1850, 1851, 1852, 1853

Services, or a service application, can be started automatically at system boot, by a user through the services control panel applet, or by an application that uses service functions. Services can execute even when no user is logged into the system.

ATT&CK data source *Service*: Information about software programs that run in the background and typically start with the operating system.

Source: `model/sources/car/data_model/service.yaml` · template `GSCAR_T_SERVICE` (10 data items) · keyword `0x0000000000000100` (`GSCAR_KW_SERVICE`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1801** | `create` | 16 | car | The event corresponding to the act of creating a new service. *(also ATT&CK: “service creation”)* |
| **1802** | `delete` | 17 | car | The event corresponding to the act of deleting a service. |
| **1803** | `pause` | 31 | car | The event corresponding to the act of pausing a currently running service. |
| **1804** | `start` | 40 | car | The event corresponding to the act of starting a new service. |
| **1805** | `stop` | 41 | car | The event corresponding to the act of stopping a service that is currently running. |
| **1850** | `access` | 10 | superset | ATT&CK data component “service access”: A service/daemon was opened or accessed. |
| **1851** | `enumerate` | 52 | superset | ATT&CK data component “service enumeration”: A service/daemon was listed. |
| **1852** | `metadata` | 55 | superset | ATT&CK data component “service metadata”: Data and information that describe a service and activity around it. |
| **1853** | `modify` | 30 | superset | ATT&CK data component “service modification”: A service/daemon was modified. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `fqdn` | `text` | The fully qualified domain name of the host. Contains the hostname appended with the domain. | HOST1.EXAMPLE_DOMAIN.COM |
| 2 | `hostname` | `text` | The hostname of the host, without the domain. | HOST1 |
| 3 | `user` | `text` | The user token that service was created with. | HOST1\LOCALUSER |
| 4 | `command_line` | `text` | The command line that service is started with. | C:\windows\system32\svchost.exe -k rpcss |
| 5 | `exe` | `text` | The executable for the service. | svchost.exe |
| 6 | `image_path` | `text` | Where in the file system the service executable is located. | C:\path\to\example.exe |
| 7 | `name` | `text` | The name of the service. | RpcSs |
| 8 | `pid` | `int` | The process ID for the process of the service, represented in decimal notation. | 718 |
| 9 | `ppid` | `int` | The process ID of the process’s parent or the service, represented in decimal notation. In the parent process, this will be the pid field. | 1860 |
| 10 | `uid` | `text` | The ID of SID of the user who acted on the service | S-1-5-18 |

### 5.10 `authentication` — Task 10, EventIDs 1901, 1902, 1903

An authentication event occurs whenever a user or process attempts to access a privileged system resource. Examples include logging into a system, or elevating privilege.

Source: `model/sources/car/data_model/authentication.yaml` · template `GSCAR_T_AUTHENTICATION` (19 data items) · keyword `0x0000000000000200` (`GSCAR_KW_AUTHENTICATION`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **1901** | `error` | 20 | car | The event corresponding to the case when an authentication request results in any kind of unexpected error. |
| **1902** | `failure` | 21 | car | The event corresponding to an authentication service responding negatively to an authentication request. |
| **1903** | `success` | 42 | car | The event corresponding to an authentication service responding positively to an authentication request. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `app_name` | `text` | Name of the application that made the authentication request | ssh, win:local |
| 2 | `method` | `text` | The authentication method that was used. | SMAL, Kerberos |
| 3 | `auth_service` | `text` | The name of the service that was utilized to accomplish authentication | Okta, ActiveDirectory |
| 4 | `auth_target` | `text` | machine for which authentication was requested; may be different than the host that the request is made from. | HOST2 |
| 5 | `target_ad_domain` | `text` | The Active Directory domain within which authentication was requested. | ad.mitre.org |
| 6 | `decision_reason` | `text` | The justification for approving or denying an authentication request. | password is invalid |
| 7 | `response_time` | `int_ms` | Duration of time it took for an authentication response to be received. | 12ms |
| 8 | `fqdn` | `text` | The fully qualified domain name for the host from which authentication was requested. | HOST1.mitre.org |
| 9 | `hostname` | `text` | Hostname of the host from which authentication was requested. | HOST1 |
| 10 | `ad_domain` | `text` | Active Directory domain from which the authentication request was generated; may differ from the target_ad_domain. | ad2.mitre.org |
| 11 | `uid` | `text` | User ID for the process that initiated the authentication request. | S-1-5-18 |
| 12 | `user_role` | `text` | IPAM access control role for the user that initiated the authentication request. | DNS Record Administrator Role |
| 13 | `user_type` | `text` | type of user that initiated the request. | Administrator, Standard, Guest |
| 14 | `user` | `text` | Name of the user that initiated the request. | HOST1\LOCALUSER1 |
| 15 | `user_agent` | `text` | The user agent through which the request was made. | aws-cli/2.0.0 Python/3.7.4 Darwin/18.7.0 botocore/2.0.0dev4 |
| 16 | `target_uid` | `text` | User ID for the user being authenticated. | S-1-5-19 |
| 17 | `target_user_role` | `text` | IPAM access control role for the user being authenticated; this only pertains to privilege escalation events where the current user is not necessarily the same as the target user. | System Administrator Role |
| 18 | `target_user_type` | `text` | type of user that was authenticated; this only pertains to privilege escalation events where the current user is not necessarily the same as the target user. | Administrator, Standard, Guest |
| 19 | `target_user` | `text` | Name of the user being authenticated; this only pertains to privilage escalation events where the current user is not necessarily the same as the target user. | HOST1\LOCALUSER2 |

### 5.11 `email` — Task 11, EventIDs 2001, 2002, 2003, 2004, 2005

Email events are at the mail server level.

Source: `model/sources/car/data_model/email.yaml` · template `GSCAR_T_EMAIL` (21 data items) · keyword `0x0000000000000400` (`GSCAR_KW_EMAIL`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **2001** | `block` | 14 | car | The event corresponding to an email being blocked by the email server. |
| **2002** | `delete` | 17 | car | The event corresponding to an email being deleted. |
| **2003** | `deliver` | 18 | car | The event corresponding to an email being sent to an end recipient. |
| **2004** | `quarantine` | 34 | car | The event corresponding to an email being quarantined for security reasons. |
| **2005** | `redirect` | 37 | car | The event corresponding to an email being redirected. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `action_reason` | `text` | The rationale given for blocking, redirecting, or quarantining an email. | Malformed Message |
| 2 | `attachment_name` | `text` | Filename of any email attachment that may exist. | cuddly-cats.pdf |
| 3 | `attachment_size` | `int` | Filesize of the attachment. | 567 Kb |
| 4 | `attachment_mime_type` | `text` | The MIME type of the attachment. | .docx |
| 5 | `dest_ip` | `ip` | The destination IP address for the email. | 221.174.222.111 |
| 6 | `dest_port` | `int` | The destination port for the email. | 993 |
| 7 | `dest_address` | `text` | Recipient email address, taken from the SMTP "Recipient" field. | adam@example.com |
| 8 | `date` | `utc_time` | SMTP date header, which is actually a date time group. | Thu Jul 18 09:30:00 PDT 2019 |
| 9 | `server_relay` | `text` | The Received portion of the SMTP header, which provides the chain of hosts that the email passed through during delivery; each link usually contains an IP address, domain, and datetime group. |  |
| 10 | `from` | `text` | Displayed sender name from the Message Information header; can be easily forged. | eve@trusted-advisors.com |
| 11 | `smtp_uid` | `text` | Distint ID used to distinguish emails. | MN2PR09MB4876CCE7F183A83E6BA1C4C1CBF50@PP34399.prod.outlook.com |
| 12 | `message_links` | `text` | URLs extracted from the email body. | https://www.cnn.com |
| 13 | `src_address` | `text` | Email address of the sender, taken from the "Sender" SMTP field. | eve@example.com |
| 14 | `src_domain` | `text` | The domain portion of the src_address. | example.com |
| 15 | `return_address` | `text` | Email address to which replies should be sent, also known as Return-Path or Reply-To; may differ from the src_address. | eve_secondary@example.com |
| 16 | `message_body` | `text` | Content of the email, not including subject. | Hello World |
| 17 | `subject` | `text` | Subject line of the email. | Lo0k Younger Whl1e L0slng We19ht!! |
| 18 | `src_ip` | `ip` | Originating IP address. | 172.183.195.200 |
| 19 | `src_port` | `int` | Originating port. | 1248 |
| 20 | `message_type` | `text` | Content protocol of the message body | html |
| 21 | `to` | `text` | the content of the To field in the email header; does not necessarily match up with real recipients. | adam@example.com |

### 5.12 `http` — Task 12, EventIDs 2101, 2102, 2103, 2104

HTTP events represents requests made over the network via the HTTP protocol.

Source: `model/sources/car/data_model/http.yaml` · template `GSCAR_T_HTTP` (17 data items) · keyword `0x0000000000000800` (`GSCAR_KW_HTTP`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **2101** | `get` | 22 | car | The event corresponding to an HTTP GET request. |
| **2102** | `post` | 32 | car | The event corresponding to an HTTP POST request. |
| **2103** | `put` | 33 | car | The event corresponding to an HTTP PUT request. |
| **2104** | `tunnel` | 46 | car | The event corresponding to an HTTP TUNNEL request. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `hostname` | `text` | hostname on which the request was seen. | HOST1 |
| 2 | `request_body_bytes` | `int` | Integer value corresponding to the total number of bytes in the request. | 180 |
| 3 | `http_version` | `text` | HTTP version that is specified in the header. | 1.1 |
| 4 | `request_body_content` | `text` | Body of the HTTP request; usually specifies the exact content being requested. |  |
| 5 | `request_referrer` | `text` | The URL from which the request was referred, if applicable. | http://cnn.com |
| 6 | `requester_ip_address` | `ip` | IP address from which the request was made. | 10.0.211.200 |
| 7 | `response_body_bytes` | `int` | Integer value corresponding to the total number of bytes in the response. | 2910 |
| 8 | `response_body_content` | `text` | Content of the response (does not include header). |  |
| 9 | `response_status_code` | `int` | HTTP protocol status code in response header | 200 |
| 10 | `url_full` | `text` | URL to which the HTTP request was sent | https://www.mitre.org/about/corporate-overview |
| 11 | `url_domain` | `text` | Domain portion of the URL. | www.mitre.org |
| 12 | `url_remainder` | `text` | the path after the root domain | /about/corporate-overview |
| 13 | `url_scheme` | `text` | type of user that initiated the request. | https |
| 14 | `user_agent_full` | `text` | User agent string associated with the request | HOST1\LOCALUSER1 |
| 15 | `user_agent_name` | `text` | The user agent through which the request was made. | Mozilla/5.0 (Linux; Android 7.0; SM-G930VC Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/58.0.3029.83 Mobile Safari/537.36 |
| 16 | `user_agent_device` | `text` | Device type from which request was made, identified by user_agent substring | SM-G930VC (Samgsung Galaxy S7) |
| 17 | `user_agent_version` | `text` | User Agent Version. Note that some User Agent strings may not label versions in the same way. | 4.0 |

### 5.13 `socket` — Task 13, EventIDs 2201, 2202, 2203

Socket events are low-level events that may or may not result in a flow. Socket listenining events in particular can be helpful in detecting malicious activity.

Source: `model/sources/car/data_model/socket.yaml` · template `GSCAR_T_SOCKET` (10 data items) · keyword `0x0000000000001000` (`GSCAR_KW_SOCKET`)

| EventID | Action | Opcode | Prov. | Definition |
|---:|---|---:|---|---|
| **2201** | `bind` | 13 | car | The event corresponding to a socket binding to a specific address |
| **2202** | `close` | 15 | car | The event corresponding to a socket being closed. |
| **2203** | `listen` | 24 | car | The event corresponding to a socket being opened into a listening status, usually on a specific local port. |

| # | Field | Format | CAR description | Example |
|---:|---|---|---|---|
| 1 | `pid` | `int` | ID of the process that acted on the socket | 3930 |
| 2 | `image_path` | `text` | Path to the executable that initiated the socket event. | C:/user/adam/malware.exe |
| 3 | `success` | `bool` | Boolean indicator of whether the socket event was successful (e.g. the socket was created as requested) | True |
| 4 | `family` | `text` | The type of socket in question | AF_UNIX, AF_INET, AF_INET6 |
| 5 | `protocol` | `text` | The type of connection that was attempted on the socket | TCP |
| 6 | `local_address` | `ip` | IP address on which the socket will accept connections; does not include the port number. | 10.0.211.200 |
| 7 | `local_port` | `int` | Port number on which the socket is bound at the local end. This pertains to TCP and UDP sockets but not IP sockets. | 48777 |
| 8 | `remote_port` | `int` | Port number on which the socket is bound at the remote end. | 559 |
| 9 | `remote_address` | `ip` | IP address with which the socket is communicating on the remote end. | 199.121.21.20 |
| 10 | `local_path` | `text` | In the case that a socket is used for local interprocess communication, the socket binds to a local filepath, and will usually be visible in the filesystem. This is the case with AF_UNIX type sockets. | /tmp/foo |

## 6. Reserved — defined by number only

| Task | Range | Keyword | Name | Why reserved |
|---:|---|---|---|---|
| 14 | 2300–2399 | `0x0000000000002000` | **group** | promoted object in `car-actions.schema.json` with actions `create`, `delete`, `enumerate`, `metadata`, `modify` but **no CAR field set** in the pinned model — no template can be derived without inventing fields |
| 15 | 2400–2499 | `0x0000000000004000` | **scheduled_job** | promoted object in `car-actions.schema.json` with actions `create`, `delete`, `metadata`, `modify` but **no CAR field set** in the pinned model — no template can be derived without inventing fields |
| 16 | 2500–2599 | `0x0000000000008000` | **user_account** | promoted object in `car-actions.schema.json` with actions `create`, `delete`, `metadata`, `modify` but **no CAR field set** in the pinned model — no template can be derived without inventing fields |
| 99 | 9000–9099 | `0x0000800000000000` | sensor | sensor self-events (not CAR): service start/stop, configuration, provider enabled/silent, event drops, protected-provider availability — the 'going silent is a signal' hazard (brief §7) |

## 7. The manifest

`manifest/GetSybersMitreCar.man` is generated from this model: the provider, one Operational channel, 13 tasks, 46 opcodes, 13 keywords, 13 templates and 73 events, with an en-US string table whose event messages list every property (`field: %n`). It compiles with `mc.exe` into a code-free resource DLL (`GetSybersMitreCar.dll`) that `wevtutil im` registers — see `scripts/`.

## 8. What the generator enforces, and where the limits come from

- the object set is identical in the pinned CAR submodule, `car-vocab.json` and the registry;
- for every object, pinned CAR actions ∪ ATT&CK-derived actions (Byakugan's `_action_for`, ported verbatim) == `car-vocab` — so every overlay action is traceable to a named data component;
- every (object, action) in `car-vocab` has exactly one EventID and no EventID is outside it; the recorded provenance matches the pinned submodule; `car` offsets stay in 1–49 and `superset` in 50–99; Task, base and Keyword follow the object's ordinal;
- `car-actions.schema.json` agrees with `car-vocab` for the 13 CAR objects and adds exactly the registry's promoted objects;
- one Opcode per action name, one single-bit Keyword per object, provider/channel names legal, all symbols unique;
- every formatted field exists in the pinned model and every format exists; no template exceeds the insertion-string or data-descriptor limits;
- the submodule checkout and index match `PIN.yaml`; the committed outputs match a fresh generation.

Limits, read from the MicrosoftDocs repositories (the `docs` branch heads on 2026-10-24):

| Fact | Source |
|---|---|
| custom opcode values 10–239 | [`MicrosoftDocs/win32` `desktop-src/WES/eventmanifestschema-opcodetype-complextype.md`](https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/WES/eventmanifestschema-opcodetype-complextype.md) |
| task values 1–239 | [`MicrosoftDocs/win32` `desktop-src/WES/eventmanifestschema-tasktype-complextype.md`](https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/WES/eventmanifestschema-tasktype-complextype.md) |
| keyword mask: a single bit, bits 0–47 | [`MicrosoftDocs/win32` `desktop-src/WES/eventmanifestschema-keywordtype-complextype.md`](https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/WES/eventmanifestschema-keywordtype-complextype.md) |
| event message: at most 100 insertion strings | [`MicrosoftDocs/win32` `desktop-src/WES/eventmanifestschema-eventdefinitiontype-complextype.md`](https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/WES/eventmanifestschema-eventdefinitiontype-complextype.md) |
| channel name &lt; 255 characters, no &gt; &lt; & " \| \ : ` ? * or control characters; Operational channels share one ETW session | [`MicrosoftDocs/win32` `desktop-src/WES/eventmanifestschema-channeltype-complextype.md`](https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/WES/eventmanifestschema-channeltype-complextype.md) |
| win:UnicodeString renders as xs:string, win:Xml or win:Json | [`MicrosoftDocs/win32` `desktop-src/WES/eventmanifestschema-inputtype-complextype.md`](https://github.com/MicrosoftDocs/win32/blob/ca8274decead49403d70ceeed4af8d4ca74eaf11/desktop-src/WES/eventmanifestschema-inputtype-complextype.md) |
| EventWrite: at most 128 data descriptors; an event larger than 64 KB minus header fails | [`MicrosoftDocs/sdk-api` `sdk-api-src/content/evntprov/nf-evntprov-eventwrite.md`](https://github.com/MicrosoftDocs/sdk-api/blob/656e9656bfaef34dd29cd7ee9e1146aec17e924c/sdk-api-src/content/evntprov/nf-evntprov-eventwrite.md) |
