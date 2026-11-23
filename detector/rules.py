"""Rule detection thuần văn bản cho TV3, Mốc 4 R01-R04.

Các hàm trong module này không thực thi hoặc giải mã command/script nhận từ
dữ liệu thu thập.
"""

import ntpath
import re
import shlex
from typing import Any, Dict, List


R01 = "R01"
R02 = "R02"
R03 = "R03"
R04 = "R04"
ENABLED_RULE_IDS = (R01, R02, R03, R04)
NOT_IMPLEMENTED_RULE_IDS = ()

R01_REASON = (
    "PowerShell được gọi trực tiếp với tham số -EncodedCommand; "
    "nội dung mã hóa không được thực thi hoặc giải mã."
)
R02_REASON = (
    "PowerShell được gọi trực tiếp với tham số -WindowStyle và giá trị Hidden."
)
R03_REASON = (
    "Đích thực thi được cấu hình nằm trong Temp, AppData, Downloads hoặc Users\\Public "
    "theo chính sách lab; Detector không xác minh file, quyền hoặc lần thực thi thực tế."
)
R04_REASON = (
    "VBScript tạo WScript.Shell và dùng chính đối tượng đó gọi Run/Exec "
    "để khởi chạy shell tĩnh theo chính sách lab."
)
R04_SUPPORTED_SHELLS = {"cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}


def _strip_outer_quotes(value: str) -> str:
    """Bỏ một cặp nháy bao ngoài token, không thay đổi giá trị bằng chứng."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _tokenize_command_line(command_line: str) -> List[str]:
    """Tách token ở mức đủ hẹp cho lệnh Windows trực tiếp.

    Đây không phải shell parser hoàn chỉnh. Nếu chuỗi có nháy không cân bằng,
    hàm trả về lỗi để Engine ghi insufficient_data thay vì suy đoán.
    """
    try:
        return shlex.split(command_line, posix=False)
    except ValueError as exc:
        raise ValueError("command_line có dấu nháy không cân bằng") from exc


def _is_powershell_executable(token: str) -> bool:
    """Xác định executable trực tiếp là Windows PowerShell hoặc PowerShell."""
    executable = _strip_outer_quotes(token).strip().replace("/", "\\")
    name = ntpath.basename(executable).lower()
    return name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}


def _result(
    rule_id: str, status: str, reason: str, evidence=None, notes=None,
    unavailable_fields=None, unanalysed_forms=None,
) -> Dict[str, Any]:
    """Tạo kết quả rule nhất quán cho Engine và API công khai."""
    return {
        "rule_id": rule_id,
        "status": status,
        "reason": reason,
        "evidence": [] if evidence is None else evidence,
        "notes": [] if notes is None else notes,
        "unavailable_fields": [] if unavailable_fields is None else unavailable_fields,
        "unanalysed_forms": [] if unanalysed_forms is None else unanalysed_forms,
    }


def _direct_powershell_context(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Phân tích executable và tham số PowerShell dùng chung cho R01/R02.

    ``argument_limit`` là ranh giới token các rule được phép xem. Các token
    sau -Command, -File hoặc --% là payload/script arguments, không phải
    tham số PowerShell cấp cao trong phạm vi Mốc 2.
    """
    consumer = subscription.get("consumer")
    if consumer is None:
        return {
            "status": "insufficient_data",
            "reason": "Thiếu consumer nên không có dữ liệu lời gọi lệnh.",
            "unavailable_fields": ["consumer"],
        }
    if not isinstance(consumer, dict):
        return {
            "status": "insufficient_data",
            "reason": "consumer không phải đối tượng nên không thể phân tích lời gọi lệnh.",
            "unavailable_fields": ["consumer"],
        }

    command_line = consumer.get("command_line")
    consumer_type = consumer.get("type")
    if command_line is None:
        if (
            isinstance(consumer_type, str)
            and consumer_type.strip()
            and consumer_type.strip().lower() != "commandlineeventconsumer"
        ):
            return {
                "status": "not_applicable",
                "reason": "Mốc 2 chỉ phân tích consumer.command_line; Consumer này không phải CommandLineEventConsumer.",
                "unavailable_fields": [],
            }
        return {
            "status": "insufficient_data",
            "reason": "Thiếu consumer.command_line để xác định lời gọi PowerShell.",
            "unavailable_fields": ["consumer.command_line"],
        }
    if not isinstance(command_line, str) or not command_line.strip():
        return {
            "status": "insufficient_data",
            "reason": "consumer.command_line phải là văn bản không rỗng để phân tích lời gọi PowerShell.",
            "unavailable_fields": ["consumer.command_line"],
        }

    try:
        tokens = _tokenize_command_line(command_line)
    except ValueError as exc:
        return {
            "status": "insufficient_data",
            "reason": str(exc),
            "unavailable_fields": ["consumer.command_line.parseability"],
        }
    if not tokens:
        return {
            "status": "insufficient_data",
            "reason": "consumer.command_line không chứa executable để phân tích.",
            "unavailable_fields": ["consumer.command_line"],
        }
    if not _is_powershell_executable(tokens[0]):
        notes = []
        lower_command = command_line.lower()
        if "powershell" in lower_command or "-encodedcommand" in lower_command or "-windowstyle" in lower_command:
            notes.append(
                "Có nhắc đến PowerShell hoặc tham số trong văn bản, nhưng executable trực tiếp "
                "không phải PowerShell nên không coi đó là tham số rule."
            )
        return {
            "status": "not_applicable",
            "reason": "Executable trực tiếp trong consumer.command_line không phải PowerShell.",
            "notes": notes,
            "unavailable_fields": [],
        }

    argument_limit = len(tokens)
    boundary = None
    boundary_token = None
    for index, raw_token in enumerate(tokens[1:], start=1):
        token = _strip_outer_quotes(raw_token).strip()
        token_lower = token.lower()
        if token == "--%":
            argument_limit = index
            boundary = "--%"
            boundary_token = raw_token
            break
        if token_lower in {"-command", "-c", "-file"}:
            argument_limit = index
            boundary = token_lower
            boundary_token = raw_token
            break
    return {
        "status": "ready",
        "command_line": command_line,
        "tokens": tokens,
        "argument_limit": argument_limit,
        "boundary": boundary,
        "boundary_token": boundary_token,
        "unavailable_fields": [],
    }


def _option_occurrences(context: Dict[str, Any], option: str) -> List[int]:
    """Trả vị trí option đầy đủ trước ranh giới payload/script arguments."""
    return [
        index for index in range(1, context["argument_limit"])
        if _strip_outer_quotes(context["tokens"][index]).strip().lower() == option
    ]


def _option_value(context: Dict[str, Any], index: int):
    """Lấy giá trị option khi token kế tiếp còn thuộc vùng tham số hợp lệ."""
    next_index = index + 1
    if next_index >= context["argument_limit"]:
        return None
    raw_value = context["tokens"][next_index]
    value = _strip_outer_quotes(raw_value).strip()
    if not value or value.startswith("-"):
        return None
    return raw_value, value


def _context_result(rule_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """Ánh xạ trạng thái dùng chung sang kết quả của rule cụ thể."""
    return _result(
        rule_id,
        context["status"],
        context["reason"],
        notes=context.get("notes"),
        unavailable_fields=context.get("unavailable_fields"),
    )


def _not_matched_notes(context: Dict[str, Any], option: str) -> List[str]:
    """Nêu rõ vì sao option chỉ xuất hiện sau payload không được tính."""
    notes = []
    if context.get("boundary") and option in context["command_line"].lower():
        notes.append(
            f"{option} xuất hiện sau {context['boundary_token']}; "
            "Mốc 2 không coi payload/script arguments là tham số PowerShell cấp cao."
        )
    return notes


def evaluate_r01(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Đánh giá R01 trên lời gọi PowerShell trực tiếp ở consumer.command_line."""
    context = _direct_powershell_context(subscription)
    if context["status"] != "ready":
        return _context_result(R01, context)

    occurrences = _option_occurrences(context, "-encodedcommand")
    missing_value = False
    for index in occurrences:
        value = _option_value(context, index)
        if value is None:
            missing_value = True
            continue
        return _result(
            R01,
            "matched",
            R01_REASON,
            evidence=[{
                "field": "consumer.command_line",
                "value": context["command_line"],
                "matched_text": context["tokens"][index],
            }],
        )
    if missing_value:
        return _result(
            R01,
            "insufficient_data",
            "-EncodedCommand không có đối số mã hóa không rỗng để xác nhận cấu hình R01.",
            unavailable_fields=["consumer.command_line.-EncodedCommand.value"],
        )
    return _result(
        R01,
        "not_matched",
        "Đã phân tích lời gọi PowerShell trực tiếp nhưng không có tham số đầy đủ -EncodedCommand.",
        notes=_not_matched_notes(context, "-encodedcommand"),
    )


def evaluate_r02(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Đánh giá R02 trên lời gọi PowerShell trực tiếp ở consumer.command_line."""
    context = _direct_powershell_context(subscription)
    if context["status"] != "ready":
        return _context_result(R02, context)

    occurrences = _option_occurrences(context, "-windowstyle")
    missing_value = False
    for index in occurrences:
        value = _option_value(context, index)
        if value is None:
            missing_value = True
            continue
        raw_value, plain_value = value
        if plain_value.lower() == "hidden":
            return _result(
                R02,
                "matched",
                R02_REASON,
                evidence=[{
                    "field": "consumer.command_line",
                    "value": context["command_line"],
                    "matched_text": f"{context['tokens'][index]} {raw_value}",
                }],
            )
    if missing_value:
        return _result(
            R02,
            "insufficient_data",
            "-WindowStyle không có giá trị không rỗng để xác nhận cấu hình R02.",
            unavailable_fields=["consumer.command_line.-WindowStyle.value"],
        )
    return _result(
        R02,
        "not_matched",
        "Đã phân tích lời gọi PowerShell trực tiếp nhưng không có -WindowStyle Hidden ở mức tham số.",
        notes=_not_matched_notes(context, "-windowstyle"),
    )


def _append_unique(values: List[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _path_groups_from_segments(segments: List[str]) -> List[str]:
    """Nhận diện đúng thành phần thư mục của bốn nhóm path trong policy lab."""
    groups = []
    for index in range(len(segments) - 1):
        if segments[index] == "users" and segments[index + 1] == "public":
            _append_unique(groups, "Users\\Public")
    if "appdata" in segments:
        _append_unique(groups, "AppData")
    if "downloads" in segments:
        _append_unique(groups, "Downloads")
    if "temp" in segments:
        _append_unique(groups, "Temp")
    return groups


def _classify_static_windows_path(raw_target: str) -> Dict[str, Any]:
    """Phân loại path theo ngữ nghĩa Windows mà không truy cập filesystem local.

    Chỉ path drive/UNC hoặc biến môi trường tĩnh đã biết mới được suy luận.
    Path tương đối và biến lạ được giữ ngoài phạm vi để tránh suy đoán sai.
    """
    target = _strip_outer_quotes(raw_target).strip()
    normalized = target.replace("/", "\\")
    lower = normalized.lower()
    known_prefixes = (
        ("%localappdata%", ["AppData"]),
        ("%appdata%", ["AppData"]),
        ("%temp%", ["Temp"]),
        ("%tmp%", ["Temp"]),
        ("%public%", ["Users\\Public"]),
        ("%userprofile%", []),
    )
    groups = []
    path_for_segments = lower
    for prefix, prefix_groups in known_prefixes:
        if lower == prefix or lower.startswith(prefix + "\\"):
            groups.extend(prefix_groups)
            path_for_segments = lower[len(prefix):].lstrip("\\")
            if not path_for_segments:
                return {"state": "not_file", "target": target}
            break
    else:
        if re.search(r"%[^%]+%", lower):
            return {"state": "unknown_variable", "target": target}
        if not (re.match(r"^[a-z]:\\", lower) or lower.startswith("\\\\")):
            return {"state": "relative", "target": target}

    segments = [part for part in path_for_segments.split("\\") if part]
    if not segments or segments[-1] in {"temp", "appdata", "downloads", "public"}:
        return {"state": "not_file", "target": target}
    for group in _path_groups_from_segments(segments):
        _append_unique(groups, group)
    return {"state": "static", "target": target, "groups": groups}


def _looks_path_like(raw_target: str) -> bool:
    """Phân biệt token path với tên lệnh bare như powershell.exe hoặc echo."""
    target = _strip_outer_quotes(raw_target).strip()
    return (
        "\\" in target or "/" in target or target.startswith("%") or
        bool(re.match(r"^[a-zA-Z]:", target))
    )


def _add_execution_target(
    assessment: Dict[str, Any], field: str, value: str, raw_target: str, role: str,
) -> None:
    """Ghi nhận một đích thực thi chỉ khi nó tĩnh và ngữ cảnh đã xác định."""
    classified = _classify_static_windows_path(raw_target)
    state = classified["state"]
    if state == "static":
        assessment["supported_targets"] += 1
        if classified["groups"]:
            assessment["evidence"].append({
                "field": field,
                "value": value,
                "matched_text": raw_target,
                "execution_target": classified["target"],
                "execution_role": role,
                "path_groups": classified["groups"],
            })
        return
    reasons = {
        "relative": "Đường dẫn tương đối/bare không cho biết nó nằm trong nhóm path lab nào.",
        "unknown_variable": "Biến môi trường chưa biết không được mở rộng bằng môi trường của máy chạy Detector.",
        "not_file": "Giá trị tĩnh chỉ biểu diễn thư mục, chưa xác định chương trình hoặc script cần thực thi.",
    }
    assessment["unanalysed_forms"].append({
        "field": field,
        "reason": reasons[state],
    })


def _token_basename(raw_target: str) -> str:
    target = _strip_outer_quotes(raw_target).strip().replace("/", "\\")
    return ntpath.basename(target).lower()


def _extract_r03_targets(consumer: Dict[str, Any]) -> Dict[str, Any]:
    """Trích đích thực thi tĩnh từ các source R03 hỗ trợ trong Mốc 3."""
    assessment = {
        "evidence": [], "notes": [], "unanalysed_forms": [],
        "unavailable_fields": [], "supported_targets": 0,
    }
    consumer_type = consumer.get("type")
    consumer_type_lower = consumer_type.strip().lower() if isinstance(consumer_type, str) else ""
    executable_path = consumer.get("executable_path")
    configured_executable = None
    if isinstance(executable_path, str) and executable_path.strip():
        if consumer_type_lower == "commandlineeventconsumer":
            configured_executable = executable_path
            _add_execution_target(
                assessment, "consumer.executable_path", executable_path,
                executable_path, "configured_executable",
            )
        else:
            assessment["unanalysed_forms"].append({
                "field": "consumer.executable_path",
                "reason": "Mốc 3 chỉ xem ExecutablePath là đích thực thi với CommandLineEventConsumer.",
            })

    command_line = consumer.get("command_line")
    command_executable = None
    if command_line is None:
        if consumer_type_lower == "commandlineeventconsumer" and configured_executable is None:
            assessment["unavailable_fields"].append("consumer.command_line")
    elif not isinstance(command_line, str) or not command_line.strip():
        assessment["unavailable_fields"].append("consumer.command_line")
    else:
        try:
            tokens = _tokenize_command_line(command_line)
        except ValueError:
            assessment["unavailable_fields"].append("consumer.command_line.parseability")
            tokens = []
        if tokens:
            command_executable = tokens[0]
            executable_name = _token_basename(command_executable)
            if _looks_path_like(command_executable):
                _add_execution_target(
                    assessment, "consumer.command_line", command_line,
                    command_executable, "direct_executable",
                )
            if _is_powershell_executable(command_executable):
                for index, raw_token in enumerate(tokens[1:], start=1):
                    token = _strip_outer_quotes(raw_token).strip().lower()
                    if token in {"--%", "-command", "-c"}:
                        if token in {"-command", "-c"}:
                            assessment["unanalysed_forms"].append({
                                "field": "consumer.command_line",
                                "reason": "Nội dung PowerShell -Command là script động, không được phân tích R03.",
                            })
                        break
                    if token == "-file":
                        if index + 1 >= len(tokens) or _strip_outer_quotes(tokens[index + 1]).strip().startswith("-"):
                            assessment["unavailable_fields"].append(
                                "consumer.command_line.-File.value"
                            )
                        else:
                            _add_execution_target(
                                assessment, "consumer.command_line", command_line,
                                tokens[index + 1], "powershell_file",
                            )
                        break
            elif executable_name in {"cmd", "cmd.exe"}:
                for index, raw_token in enumerate(tokens[1:], start=1):
                    if _strip_outer_quotes(raw_token).strip().lower() == "/c":
                        if index + 1 >= len(tokens):
                            assessment["unavailable_fields"].append(
                                "consumer.command_line.cmd_/c.value"
                            )
                        elif _looks_path_like(tokens[index + 1]):
                            _add_execution_target(
                                assessment, "consumer.command_line", command_line,
                                tokens[index + 1], "cmd_c_target",
                            )
                        break
            elif executable_name in {"cscript", "cscript.exe", "wscript", "wscript.exe"}:
                for raw_token in tokens[1:]:
                    if _strip_outer_quotes(raw_token).strip().startswith("/"):
                        continue
                    if _looks_path_like(raw_token):
                        _add_execution_target(
                            assessment, "consumer.command_line", command_line,
                            raw_token, "script_host_file",
                        )
                        break

    script_file_name = consumer.get("script_file_name")
    if isinstance(script_file_name, str) and script_file_name.strip():
        if consumer_type_lower == "activescripteventconsumer":
            _add_execution_target(
                assessment, "consumer.script_file_name", script_file_name,
                script_file_name, "active_script_file",
            )
        else:
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_file_name",
                "reason": "Mốc 3 chỉ xem ScriptFileName là đích thực thi với ActiveScriptEventConsumer.",
            })

    if configured_executable is not None and command_executable is not None:
        configured_name = _token_basename(configured_executable)
        command_name = _token_basename(command_executable)
        if configured_name and command_name and configured_name != command_name:
            assessment["notes"].append(
                "consumer.executable_path và executable trực tiếp trong consumer.command_line "
                "chỉ ra hai chương trình khác nhau; R03 giữ bằng chứng của từng đích tĩnh "
                "và không suy đoán trường nào sẽ thắng khi chạy."
            )
    return assessment


def evaluate_r03(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Đánh giá R03 từ các đích chương trình/script tĩnh, có ngữ cảnh thực thi."""
    consumer = subscription.get("consumer")
    if consumer is None or not isinstance(consumer, dict):
        return _result(
            R03,
            "insufficient_data",
            "Thiếu consumer để xác định đích thực thi cho R03.",
            unavailable_fields=["consumer"],
        )
    assessment = _extract_r03_targets(consumer)
    if assessment["evidence"]:
        return _result(
            R03,
            "matched",
            R03_REASON,
            evidence=assessment["evidence"],
            notes=assessment["notes"],
            unavailable_fields=assessment["unavailable_fields"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    if assessment["unavailable_fields"]:
        return _result(
            R03,
            "insufficient_data",
            "Thiếu dữ liệu cần thiết để xác định đích thực thi tĩnh cho R03.",
            notes=assessment["notes"],
            unavailable_fields=assessment["unavailable_fields"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    if assessment["supported_targets"]:
        return _result(
            R03,
            "not_matched",
            "Đã kiểm tra các đích thực thi tĩnh hỗ trợ nhưng không nằm trong nhóm path R03.",
            notes=assessment["notes"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    return _result(
        R03,
        "not_applicable",
        "Không có đích thực thi tĩnh thuộc dạng R03 hỗ trợ để kết luận.",
        notes=assessment["notes"],
        unanalysed_forms=assessment["unanalysed_forms"],
    )


_VBS_CREATE_OBJECT = re.compile(
    r'^\s*(?:set\s+)?(?P<variable>[A-Za-z_]\w*)\s*=\s*'
    r'createobject\s*\(\s*"(?P<progid>(?:""|[^"])*)"\s*\)\s*$',
    re.IGNORECASE,
)
_VBS_ASSIGNMENT = re.compile(r'^\s*(?:set\s+)?(?P<variable>[A-Za-z_]\w*)\s*=', re.IGNORECASE)
_VBS_CALL = re.compile(
    r'^\s*(?P<variable>[A-Za-z_]\w*)\s*\.\s*(?P<method>run|exec)\b(?P<arguments>.*)$',
    re.IGNORECASE,
)
_VBS_DIRECT_CREATE_CALL = re.compile(
    r'^\s*createobject\s*\(\s*"(?P<progid>(?:""|[^"])*)"\s*\)\s*\.\s*(?:run|exec)\b',
    re.IGNORECASE,
)


def _vbscript_code(line: str) -> str:
    """Bỏ comment VBScript ngoài chuỗi mà không coi dấu nháy trong chuỗi là comment."""
    result = []
    in_string = False
    index = 0
    while index < len(line):
        character = line[index]
        if character == '"':
            result.append(character)
            if in_string and index + 1 < len(line) and line[index + 1] == '"':
                result.append('"')
                index += 2
                continue
            in_string = not in_string
        elif character == "'" and not in_string:
            break
        else:
            result.append(character)
        index += 1
    code = "".join(result)
    if re.match(r"^\s*rem(?:\s|$)", code, re.IGNORECASE):
        return ""
    return code


def _has_vbscript_statement_separator(code: str) -> bool:
    """Nhận diện dấu ``:`` ngoài chuỗi, vì nhiều câu lệnh một dòng ngoài scope."""
    in_string = False
    index = 0
    while index < len(code):
        character = code[index]
        if character == '"':
            if in_string and index + 1 < len(code) and code[index + 1] == '"':
                index += 2
                continue
            in_string = not in_string
        elif character == ":" and not in_string:
            return True
        index += 1
    return False


def _parse_vbscript_static_string(arguments: str):
    """Lấy đối số lệnh dạng string literal đầu tiên của Run/Exec.

    String nối bằng ``&``, biến, hoặc string chưa đóng được coi là dạng động.
    """
    text = arguments.lstrip()
    if text.startswith("("):
        text = text[1:].lstrip()
    if not text.startswith('"'):
        return None, "Đối số Run/Exec không phải string literal tĩnh."
    value = []
    index = 1
    while index < len(text):
        character = text[index]
        if character == '"':
            if index + 1 < len(text) and text[index + 1] == '"':
                value.append('"')
                index += 2
                continue
            literal = text[:index + 1]
            trailing = text[index + 1:].lstrip()
            if trailing.startswith("&"):
                return None, "Đối số Run/Exec ghép chuỗi động bằng &."
            return {"command": "".join(value), "literal": literal}, None
        value.append(character)
        index += 1
    return None, "String literal của Run/Exec chưa đóng."


def _parse_vbscript_r04(script_text: str) -> Dict[str, Any]:
    """Phân tích tập con VBScript tĩnh cho quan hệ WScript.Shell -> Run/Exec."""
    assessment = {
        "evidence": [], "notes": [], "unanalysed_forms": [],
        "active_shell_seen": False, "active_call_seen": False,
        "static_non_shell_call_seen": False, "unsupported_form_seen": False,
    }
    active_shells = {}
    for line_number, raw_line in enumerate(script_text.splitlines(), start=1):
        code = _vbscript_code(raw_line)
        stripped = code.strip()
        if not stripped:
            continue
        if stripped.endswith("_"):
            assessment["unsupported_form_seen"] = True
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_text",
                "reason": f"Dòng {line_number} dùng line-continuation, nằm ngoài cú pháp VBScript tĩnh hỗ trợ.",
            })
            continue

        if _has_vbscript_statement_separator(code):
            assessment["unsupported_form_seen"] = True
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_text",
                "reason": (
                    f"Dòng {line_number} có nhiều câu lệnh phân tách bằng :; "
                    "R04 chỉ phân tích một câu lệnh tĩnh trên mỗi dòng."
                ),
            })
            continue

        direct_call = _VBS_DIRECT_CREATE_CALL.match(stripped)
        if direct_call and direct_call.group("progid").replace('""', '"').lower() == "wscript.shell":
            assessment["unsupported_form_seen"] = True
            assessment["active_call_seen"] = True
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_text",
                "reason": (
                    f"Dòng {line_number} gọi Run/Exec trực tiếp trên CreateObject; "
                    "R04 chỉ nối lời gọi qua biến được gán WScript.Shell."
                ),
            })
            continue

        creation = _VBS_CREATE_OBJECT.match(stripped)
        if creation:
            variable = creation.group("variable").lower()
            progid = creation.group("progid").replace('""', '"').lower()
            if progid == "wscript.shell":
                active_shells[variable] = {
                    "variable": creation.group("variable"),
                    "matched_text": raw_line.strip(),
                }
                assessment["active_shell_seen"] = True
            else:
                active_shells.pop(variable, None)
            continue

        assignment = _VBS_ASSIGNMENT.match(stripped)
        if assignment:
            active_shells.pop(assignment.group("variable").lower(), None)
            continue

        call = _VBS_CALL.match(stripped)
        if not call:
            continue
        variable = call.group("variable").lower()
        if variable not in active_shells:
            continue
        assessment["active_call_seen"] = True
        parsed, error = _parse_vbscript_static_string(call.group("arguments"))
        if error is not None:
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_text",
                "reason": f"Dòng {line_number}: {error}",
            })
            continue
        try:
            tokens = _tokenize_command_line(parsed["command"])
        except ValueError:
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_text",
                "reason": f"Dòng {line_number}: command string tĩnh có dấu nháy không cân bằng.",
            })
            continue
        if not tokens:
            assessment["unanalysed_forms"].append({
                "field": "consumer.script_text",
                "reason": f"Dòng {line_number}: command string tĩnh không có executable.",
            })
            continue
        shell_name = _token_basename(tokens[0])
        if shell_name not in R04_SUPPORTED_SHELLS:
            assessment["static_non_shell_call_seen"] = True
            assessment["notes"].append(
                f"Dòng {line_number}: {active_shells[variable]['variable']}.{call.group('method')} "
                f"có target tĩnh {tokens[0]!r}, không thuộc shell R04 hỗ trợ."
            )
            continue
        creation_evidence = {
            "field": "consumer.script_text",
            "value": script_text,
            "matched_text": active_shells[variable]["matched_text"],
            "evidence_role": "wscript_shell_creation",
            "variable": active_shells[variable]["variable"],
        }
        call_evidence = {
            "field": "consumer.script_text",
            "value": script_text,
            "matched_text": raw_line.strip(),
            "evidence_role": "wscript_shell_call",
            "method": call.group("method").lower(),
            "variable": active_shells[variable]["variable"],
            "execution_target": _strip_outer_quotes(tokens[0]).strip(),
            "shell_name": shell_name,
            "command_literal": parsed["literal"],
        }
        assessment["evidence"].extend((creation_evidence, call_evidence))
    return assessment


def evaluate_r04(subscription: Dict[str, Any]) -> Dict[str, Any]:
    """Đánh giá quan hệ VBScript tĩnh WScript.Shell -> Run/Exec cho R04."""
    consumer = subscription.get("consumer")
    if consumer is None or not isinstance(consumer, dict):
        return _result(
            R04,
            "insufficient_data",
            "Thiếu consumer để phân tích script R04.",
            unavailable_fields=["consumer"],
        )
    script_text = consumer.get("script_text")
    script_file_name = consumer.get("script_file_name")
    consumer_type = consumer.get("type")
    is_active_script = (
        isinstance(consumer_type, str)
        and consumer_type.strip().lower() == "activescripteventconsumer"
    )
    if not is_active_script:
        return _result(
            R04,
            "not_applicable",
            "R04 chỉ áp dụng cho ActiveScriptEventConsumer có script_text VBScript.",
        )
    if script_text is None:
        forms = []
        if isinstance(script_file_name, str) and script_file_name.strip():
            forms.append({
                "field": "consumer.script_file_name",
                "reason": "R04 cần script_text; Detector không mở ScriptFileName trên máy chạy để suy ra nội dung script.",
            })
        return _result(
            R04,
            "insufficient_data",
            "Thiếu consumer.script_text để phân tích hành vi R04.",
            unavailable_fields=["consumer.script_text"],
            unanalysed_forms=forms,
        )
    if not isinstance(script_text, str) or not script_text.strip():
        return _result(
            R04,
            "insufficient_data",
            "consumer.script_text phải là văn bản không rỗng để phân tích R04.",
            unavailable_fields=["consumer.script_text"],
        )
    scripting_engine = consumer.get("scripting_engine")
    if scripting_engine is None or not isinstance(scripting_engine, str) or not scripting_engine.strip():
        return _result(
            R04,
            "insufficient_data",
            "Thiếu consumer.scripting_engine để xác nhận cú pháp VBScript của R04.",
            unavailable_fields=["consumer.scripting_engine"],
        )
    if scripting_engine.strip().lower() != "vbscript":
        return _result(
            R04,
            "not_applicable",
            "R04 Mốc 4 chỉ phân tích cú pháp VBScript tĩnh.",
            unanalysed_forms=[{
                "field": "consumer.scripting_engine",
                "reason": f"Scripting engine {scripting_engine!r} chưa thuộc cú pháp R04 hỗ trợ.",
            }],
        )

    assessment = _parse_vbscript_r04(script_text)
    if assessment["evidence"]:
        return _result(
            R04,
            "matched",
            R04_REASON,
            evidence=assessment["evidence"],
            notes=assessment["notes"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    if assessment["active_call_seen"] and not assessment["static_non_shell_call_seen"]:
        return _result(
            R04,
            "not_applicable",
            "WScript.Shell gọi Run/Exec nhưng command đích không tĩnh hoặc chưa thuộc shell R04 hỗ trợ.",
            notes=assessment["notes"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    if assessment["static_non_shell_call_seen"]:
        return _result(
            R04,
            "not_matched",
            "Đã xác định WScript.Shell gọi Run/Exec nhưng target tĩnh không thuộc shell R04 hỗ trợ.",
            notes=assessment["notes"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    if assessment["unsupported_form_seen"]:
        return _result(
            R04,
            "not_applicable",
            "Script có cú pháp VBScript ngoài phạm vi R04 nên không được suy đoán kết quả.",
            notes=assessment["notes"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    if assessment["active_shell_seen"]:
        return _result(
            R04,
            "not_matched",
            "Đã xác định WScript.Shell nhưng không có Run/Exec của chính biến đó trước khi biến bị gán lại hoặc script kết thúc.",
            notes=assessment["notes"],
            unanalysed_forms=assessment["unanalysed_forms"],
        )
    return _result(
        R04,
        "not_matched",
        "Đã phân tích VBScript tĩnh nhưng không có quan hệ WScript.Shell -> Run/Exec phù hợp R04.",
        unanalysed_forms=assessment["unanalysed_forms"],
    )


def not_implemented_result(rule_id: str) -> Dict[str, Any]:
    """Biểu diễn minh bạch rule chưa thuộc phạm vi hiện tại."""
    return _result(
        rule_id,
        "not_implemented",
        f"{rule_id} chưa được triển khai trong phạm vi hiện tại.",
    )


def evaluate_subscription(subscription: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Trả kết quả toàn bộ rule theo thứ tự cố định, hiện đánh giá R01-R04."""
    results = {
        R01: evaluate_r01(subscription),
        R02: evaluate_r02(subscription),
        R03: evaluate_r03(subscription),
        R04: evaluate_r04(subscription),
    }
    for rule_id in NOT_IMPLEMENTED_RULE_IDS:
        results[rule_id] = not_implemented_result(rule_id)
    return results
