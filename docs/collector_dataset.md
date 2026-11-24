# Hướng dẫn sử dụng và xử lý lỗi

Chạy các lệnh tại thư mục gốc dự án bằng PowerShell. Sử dụng Python 3.9 trở lên. Thu thập WMI và Event Log trên Windows VM; chuẩn hóa dataset và kiểm thử giả lập có thể chạy trên máy thật.

**1. Chuẩn bị file**

- Đặt `wmi_collector.py`, `eventlog_collector.py`, `normalizer.py` trong `collector/`.
- Đặt `test_collector.py` trong `tests/`.
- Giải nén dataset để có `dataset/labels.json`, `dataset/benign/` và `dataset/suspicious/`.
- Đặt schema của nhóm tại `schemas/subscription.schema.json`.

Kiểm tra Python.

```powershell
python --version
```

**2. Thu thập trên Windows VM**

Thu thập WMI.

```powershell
python -X utf8 collector/wmi_collector.py --output output/wmi_snapshot.json
```

Thu Event Log trong 24 giờ gần nhất, tối đa 1.000 sự kiện mỗi nguồn.

```powershell
python -X utf8 collector/eventlog_collector.py --hours 24 --max-events 1000 --output output/eventlogs.json
```

Nếu chỉ cần WMI-Activity và Sysmon, chọn nguồn như sau.

```powershell
python -X utf8 collector/eventlog_collector.py --source wmi --source sysmon --output output/eventlogs.json
```

Ngay sau mỗi lệnh Python, xem mã thoát.

```powershell
$LASTEXITCODE
```

| Mã | Cách xử lý |
|---|---|
| `0` | Tiếp tục bước kế tiếp |
| `1` | Đọc thông báo lỗi và sửa trước khi tiếp tục |
| `2` ở Event Log Collector | JSON đã lưu có nguồn thiếu, lỗi hoặc vượt giới hạn; kiểm tra `sources` |

**3. Chuẩn hóa dữ liệu**

Khi đã có hai file kết quả, chạy lệnh sau.

```powershell
python -X utf8 collector/normalizer.py --wmi output/wmi_snapshot.json --eventlogs output/eventlogs.json --output output/normalized.json
```

Nếu chỉ có kết quả WMI, chạy riêng.

```powershell
python -X utf8 collector/normalizer.py --wmi output/wmi_snapshot.json --output output/normalized.json
```

Đọc kết quả và các vấn đề cần xử lý.

```powershell
$result = Get-Content output/normalized.json -Raw -Encoding UTF8 | ConvertFrom-Json
$result.normalization_status
$result.counts
$result.issues
$result.rejected_records
```

Dùng `$result.subscriptions` để xem các Subscription và `$result.events` để xem các sự kiện. Nếu Normalizer trả mã `2`, kiểm tra `issues` và `rejected_records` trước khi sử dụng kết quả.

Để giữ nhiều lần thực nghiệm, thay đường dẫn đầu ra bằng `output/RUN001/...`, `output/RUN002/...` và dùng đúng đường dẫn đó ở lệnh chuẩn hóa.

**4. Sử dụng dataset**

Chuẩn hóa một mẫu.

```powershell
python -X utf8 collector/normalizer.py --wmi dataset/suspicious/sample_s001.json --output output/sample_s001_normalized.json
```

Chuẩn hóa toàn bộ 24 mẫu bằng cách dán nguyên khối dưới đây vào PowerShell.

```powershell
@'
import json
from pathlib import Path
from collector.normalizer import normalize_data

paths = sorted(Path("dataset/benign").glob("*.json"))
paths += sorted(Path("dataset/suspicious").glob("*.json"))
if len(paths) != 24:
    raise SystemExit(f"Cần 24 mẫu của bộ hiện tại, tìm thấy {len(paths)}")

samples = [json.loads(path.read_text(encoding="utf-8-sig")) for path in paths]
result = normalize_data(wmi_data=samples)
output = Path("output/dataset_normalized.json")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(result["normalization_status"], result["counts"])
'@ | python -X utf8 -
```

Kết quả dự kiến có 24 Subscription và 0 bản ghi bị từ chối.

Khi kiểm thử Detector, dùng các mẫu có `split = development` để phát triển rules và `split = evaluation` để đánh giá sau khi chốt rules. Tra `labels.json` theo `subscription_id` để đối chiếu kết quả. Nhãn và đường dẫn phân loại chỉ dùng ở bước đánh giá.

Dataset hiện là dữ liệu mô phỏng. Nếu dựng kịch bản trên VM, đọc `prerequisites` trong nhãn của từng mẫu để chuẩn bị các file hoặc cấu hình được yêu cầu.

**5. Chạy kiểm thử**

Chạy kiểm thử giả lập.

```powershell
python -X utf8 -m unittest discover -s tests -p test_collector.py -v
```

Nếu Python bản Store/UWP báo `PermissionError` với `%TEMP%`, tạo một thư mục
rỗng trong workspace bằng PowerShell rồi dùng runner sau. Runner chỉ dùng thư
mục được truyền cho test hiện tại, không thay đổi ACL hay đụng các thư mục
`tests/tmp*` bị khóa.

```powershell
$scratch = Join-Path $PWD "tests\.collector_test_scratch"
if (Test-Path -LiteralPath $scratch) { throw "Scratch directory already exists" }
New-Item -ItemType Directory -Path $scratch | Out-Null
python -X utf8 tests/run_collector_tests.py --temp-dir $scratch
Remove-Item -LiteralPath $scratch
```

Bật thêm kiểm thử đọc dữ liệu thực tế trên Windows VM.

```powershell
$env:D12_RUN_LIVE_TESTS = "1"
python -X utf8 -m unittest discover -s tests -p test_collector.py -v
Remove-Item Env:D12_RUN_LIVE_TESTS
```

Nếu hai ca Windows hiển thị `skipped` khi chạy chế độ mặc định, tiếp tục đọc kết quả các ca còn lại. Nếu có `FAIL` hoặc `ERROR`, xem tên ca và traceback để xác định bước gặp lỗi.

Để kiểm tra thu đúng PoC, tạo kịch bản theo hướng dẫn của TV1, chạy lại Collector và đối chiếu tên Filter, Consumer, đường dẫn Binding và hành động đã cấu hình với kết quả thu được.

**6. Xử lý lỗi**

| Hiện tượng | Cách xử lý |
|---|---|
| Không nhận lệnh `python` | Kiểm tra cài đặt Python và PATH; thử `py --version`, rồi dùng `py` thay `python` nếu phù hợp |
| `can't open file` hoặc thiếu module | Mở PowerShell tại thư mục gốc dự án; kiểm tra các file trong `collector/` và `tests/` |
| Báo yêu cầu Windows | Chạy WMI Collector và Event Log Collector trên Windows VM |
| `access_denied` | Mở lại PowerShell bằng Run as administrator trên VM rồi thử lại; nếu còn lỗi, kiểm tra quyền tài khoản với nguồn dữ liệu |
| `KeyError: 'Name'` khi thu WMI | Cập nhật Collector: lỗi này có thể do PowerShell tuần tự hóa chính `SWbemObjectSet` thay vì từng instance. Bản sửa đọc từng `SWbemObject` qua `ItemIndex`; nếu dữ liệu nguồn vẫn thiếu trường bắt buộc, Collector sẽ dừng với tên trường thiếu thay vì tạo bản ghi rỗng. |
| Sysmon báo `missing` | Kiểm tra Sysmon đã được cài và có kênh log; nếu chỉ cần WMI-Activity, chạy với `--source wmi` |
| `timeout` | Thử tăng `--timeout 120`; với Event Log, giảm `--hours` hoặc `--max-events` nếu truy vấn quá lớn |
| `truncated=true` | Tăng `--max-events` hoặc thu hẹp khoảng thời gian; chạy lại và xem trường `sources` |
| Kết quả rỗng | Kiểm tra thời điểm chạy PoC, khoảng `--hours`, nguồn log, cấu hình ghi nhận và namespace |
| Subscription có `incomplete` | Xem `missing_objects`, đối chiếu tham chiếu Binding và các danh sách Filter/Consumer; thử thu lại khi cấu hình đã ổn định |
| Normalizer có `partial` | Đọc `issues`, `rejected_records` và `collection_metadata` để xác định nguồn lỗi |
| JSON không hợp lệ | Kiểm tra dấu phẩy, dấu ngoặc, khóa trùng và lưu file bằng UTF-8 |
| Thiếu thuộc tính Consumer sau chuẩn hóa | Xem `raw.consumer`; với dữ liệu WMI Collector, xem thêm `raw.consumer.properties` |
| Lỗi khi kiểm tra schema | Kiểm tra từng Subscription với schema hiện có, đặc biệt trường `null` và trường mở rộng; Normalizer hiện chưa tự nạp schema |
| Lệnh thất bại nhưng file kết quả vẫn còn | Kiểm tra mã thoát và thời điểm trong file vì có thể đang xem kết quả lần trước |
| Không ghi được file | Kiểm tra quyền ghi thư mục và ứng dụng đang giữ file; thử đường dẫn đầu ra khác |
| Tiếng Việt hiển thị lỗi | Chạy với `python -X utf8` và đọc JSON bằng `Get-Content -Encoding UTF8` |

Xem chi tiết trạng thái từng nguồn Event Log.

```powershell
$logs = Get-Content output/eventlogs.json -Raw -Encoding UTF8 | ConvertFrom-Json
$logs.sources | Format-List source, status, channel_enabled, truncated, error
```

Xem tham số của từng chương trình.

```powershell
python -X utf8 collector/wmi_collector.py --help
python -X utf8 collector/eventlog_collector.py --help
python -X utf8 collector/normalizer.py --help
```
